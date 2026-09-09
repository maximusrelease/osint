import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import Callable, List, Optional, Set
import httpx
import holehe.core
from backend.config import get_settings
from backend.schemas.search import SearchRecord
from backend.services.providers.base import BaseIntelligenceProvider, ProviderResult

logger = logging.getLogger("backend.services.providers.holehe")

_CACHED_HOLEHE_FUNCTIONS: Optional[List[Callable]] = None


def get_holehe_functions() -> List[Callable]:
    """Lazy-load and cache Holehe module functions."""
    global _CACHED_HOLEHE_FUNCTIONS
    if _CACHED_HOLEHE_FUNCTIONS is None:
        try:
            modules = holehe.core.import_submodules("holehe.modules")
            _CACHED_HOLEHE_FUNCTIONS = holehe.core.get_functions(modules)
            logger.info("Loaded %d Holehe OSINT platform modules.", len(_CACHED_HOLEHE_FUNCTIONS))
        except Exception as e:
            logger.error("Failed to import Holehe modules: %s", str(e), exc_info=True)
            _CACHED_HOLEHE_FUNCTIONS = []
    return _CACHED_HOLEHE_FUNCTIONS


class HoleheProvider(BaseIntelligenceProvider):
    """
    Integration provider for Holehe (megadose/holehe).
    Checks if an email is attached to an account on 120+ platforms (e.g., GitHub, Twitter, Instagram, Spotify).
    """

    @property
    def provider_id(self) -> str:
        return "holehe_osint"

    @property
    def display_name(self) -> str:
        return "Holehe Email OSINT"

    @property
    def supported_types(self) -> Set[str]:
        return {"email"}

    def is_enabled(self) -> bool:
        settings = get_settings()
        return getattr(settings, "HOLEHE_ENABLED", True)

    async def execute(self, query: str, query_type: str) -> ProviderResult:
        start_time = time.perf_counter()
        clean_query = query.strip()
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if query_type not in self.supported_types or "@" not in clean_query:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=True,
                records=[],
                execution_time_ms=0.0,
            )

        settings = get_settings()
        timeout_seconds = float(getattr(settings, "HOLEHE_TIMEOUT_SECONDS", 8.0))
        max_concurrency = int(getattr(settings, "HOLEHE_MAX_CONCURRENCY", 30))
        only_detected = bool(getattr(settings, "HOLEHE_ONLY_DETECTED", True))

        functions = get_holehe_functions()
        if not functions:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=False,
                records=[],
                error_message="Holehe modules unavailable or failed to initialize.",
                execution_time_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
            )

        records: List[SearchRecord] = []
        out_results: List[dict] = []
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _run_module(func: Callable, client: httpx.AsyncClient) -> None:
            async with semaphore:
                try:
                    await asyncio.wait_for(
                        func(clean_query, client, out_results),
                        timeout=timeout_seconds + 2.0,
                    )
                except Exception as exc:
                    mod_name = getattr(func, "__name__", "unknown_module")
                    logger.debug("Holehe module '%s' encountered error: %s", mod_name, str(exc))

        client_timeout = httpx.Timeout(timeout_seconds, connect=4.0)
        limits = httpx.Limits(max_connections=max_concurrency + 10, max_keepalive_connections=max_concurrency)

        try:
            async with httpx.AsyncClient(timeout=client_timeout, limits=limits, follow_redirects=True) as client:
                tasks = [_run_module(func, client) for func in functions]
                await asyncio.gather(*tasks, return_exceptions=True)

            for item in out_results:
                if not isinstance(item, dict):
                    continue

                raw_name = str(item.get("name") or "Platform")
                platform_name = raw_name.replace("_", " ").title()
                domain = str(item.get("domain") or f"{raw_name}.com")
                method = str(item.get("method") or "registration")
                exists = bool(item.get("exists", False))
                rate_limited = bool(item.get("rateLimit", False))
                email_recovery = item.get("emailrecovery")
                phone_recovery = item.get("phoneNumber")

                if exists:
                    details = {
                        "Platform": platform_name,
                        "Domain": domain,
                        "Account Status": "Registered / Active",
                        "Detection Method": method,
                        "Engine": "Holehe v1.61 (megadose/holehe)",
                    }
                    if email_recovery:
                        details["Recovery Email Hint"] = str(email_recovery)
                    if phone_recovery:
                        details["Recovery Phone Hint"] = str(phone_recovery)

                    records.append(
                        SearchRecord(
                            source=self.display_name,
                            record_type="PLATFORM_DISCOVERY",
                            identifier=clean_query,
                            title=f"Account Detected on {platform_name}",
                            description=f"Holehe confirmed registered account on {domain} (method: {method}).",
                            details=details,
                            tags=["HOLEHE", "ACCOUNT_DISCOVERY", raw_name.upper()],
                            risk_level="Medium",
                            risk_score=45,
                            timestamp=now_iso,
                        )
                    )
                elif not exists and not only_detected and not rate_limited:
                    records.append(
                        SearchRecord(
                            source=self.display_name,
                            record_type="PLATFORM_DISCOVERY",
                            identifier=clean_query,
                            title=f"Available on {platform_name}",
                            description=f"Holehe found no account on {domain}.",
                            details={
                                "Platform": platform_name,
                                "Domain": domain,
                                "Account Status": "Available (Unregistered)",
                                "Engine": "Holehe v1.61 (megadose/holehe)",
                            },
                            tags=["HOLEHE", "AVAILABLE", raw_name.upper()],
                            risk_level="Clean",
                            risk_score=0,
                            timestamp=now_iso,
                        )
                    )

            # Sort records alphabetically by platform name
            records.sort(key=lambda r: r.title)

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=True,
                records=records,
                execution_time_ms=round(elapsed_ms, 2),
            )

        except Exception as e:
            logger.error("Holehe provider execution error: %s", str(e), exc_info=True)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=False,
                records=[],
                error_message=f"Holehe execution error: {str(e)}",
                execution_time_ms=round(elapsed_ms, 2),
            )
