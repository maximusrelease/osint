import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import List, Set
import aiohttp
from omniscan.platforms import EmailQueryable, Platforms, UsernameQueryable
from omniscan.util import init_checkers, query as omniscan_query
from backend.schemas.search import SearchRecord
from backend.services.providers.base import BaseIntelligenceProvider, ProviderResult

logger = logging.getLogger("backend.services.providers.omniscan")


class OmniScanProvider(BaseIntelligenceProvider):
    """
    Integration provider for the official omniscan OSINT package (HubDamian95/omniscan).
    Executes live platform account discovery for emails and usernames across supported networks.
    """

    @property
    def provider_id(self) -> str:
        return "omniscan_package"

    @property
    def display_name(self) -> str:
        return "OmniScan OSINT Engine (HubDamian95)"

    @property
    def supported_types(self) -> Set[str]:
        return {"email", "username"}

    def is_enabled(self) -> bool:
        return True

    async def execute(self, query: str, query_type: str) -> ProviderResult:
        start_time = time.perf_counter()
        clean_query = query.strip()
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if query_type not in self.supported_types:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=True,
                records=[],
                execution_time_ms=0.0,
            )

        records: List[SearchRecord] = []
        is_email = query_type == "email"

        try:
            timeout = aiohttp.ClientTimeout(total=8.0, connect=3.0)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                checkers = init_checkers(session)
                tasks = []
                platforms_dispatched = []

                for platform in Platforms:
                    if is_email and issubclass(platform.value, EmailQueryable):
                        tasks.append(omniscan_query(clean_query, platform, checkers))
                        platforms_dispatched.append(platform)
                    elif not is_email and issubclass(platform.value, UsernameQueryable):
                        tasks.append(omniscan_query(clean_query, platform, checkers))
                        platforms_dispatched.append(platform)

                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    for platform, res in zip(platforms_dispatched, results):
                        platform_name = platform.value.__name__

                        if isinstance(res, Exception):
                            logger.debug("OmniScan platform %s error: %s", platform_name, str(res))
                            continue

                        if not res or not getattr(res, "success", False):
                            # Skip platforms that failed or timed out to avoid false positives
                            continue

                        is_available = getattr(res, "available", True)
                        is_valid = getattr(res, "valid", True)
                        msg = getattr(res, "message", None) or ""
                        link = getattr(res, "link", None)

                        if is_valid and not is_available:
                            # Account is taken / registered on this platform
                            records.append(
                                SearchRecord(
                                    source=self.display_name,
                                    record_type="PLATFORM_DISCOVERY",
                                    identifier=clean_query,
                                    title=f"Account Detected on {platform_name}",
                                    description=f"OmniScan verified registered account on {platform_name}. Status: {msg or 'Account is in use.'}",
                                    details={
                                        "Platform": platform_name,
                                        "Account Status": "Registered / In Use",
                                        "Profile URL": link or f"https://{platform_name.lower()}.com",
                                        "Query Status": "Verified",
                                        "Engine": "OmniScan v2.0.6 (HubDamian95)",
                                    },
                                    tags=["OMNISCAN", "ACCOUNT_DISCOVERY", platform_name.upper()],
                                    risk_level="Medium",
                                    risk_score=45,
                                    timestamp=now_iso,
                                )
                            )
                        elif is_valid and is_available:
                            # Account is not registered on this platform
                            records.append(
                                SearchRecord(
                                    source=self.display_name,
                                    record_type="PLATFORM_DISCOVERY",
                                    identifier=clean_query,
                                    title=f"Available on {platform_name}",
                                    description=f"OmniScan verified that no account is registered on {platform_name}.",
                                    details={
                                        "Platform": platform_name,
                                        "Account Status": "Available (Unregistered)",
                                        "Profile URL": link or "N/A",
                                        "Engine": "OmniScan v2.0.6 (HubDamian95)",
                                    },
                                    tags=["OMNISCAN", "AVAILABLE", platform_name.upper()],
                                    risk_level="Clean",
                                    risk_score=0,
                                    timestamp=now_iso,
                                )
                            )

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=True,
                records=records,
                execution_time_ms=round(elapsed_ms, 2),
            )

        except Exception as e:
            logger.error("OmniScan provider execution error: %s", str(e), exc_info=True)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=False,
                records=[],
                error_message=f"OmniScan engine error: {str(e)}",
                execution_time_ms=round(elapsed_ms, 2),
            )
