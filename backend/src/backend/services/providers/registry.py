import asyncio
import logging
import time
from typing import Dict, List, Optional
from backend.schemas.search import ProviderTelemetry, SearchRecord, SearchResponse
from backend.services.providers.base import BaseIntelligenceProvider, ProviderResult
from backend.services.providers.disposable_email_provider import DisposableEmailProvider
from backend.services.providers.holehe_provider import HoleheProvider
from backend.services.providers.mail_dns_provider import MailDNSProvider
from backend.services.providers.omniscan_provider import OmniScanProvider
from backend.services.providers.phone_intelligence_provider import PhoneIntelligenceProvider
from backend.services.providers.threat_feed_provider import ThreatFeedProvider
from backend.services.providers.xposedornot_provider import XposedOrNotProvider

logger = logging.getLogger("backend.services.providers.registry")


class IntelligenceRegistry:
    """Registry maintaining active OSINT and intelligence providers."""

    def __init__(self):
        self._providers: Dict[str, BaseIntelligenceProvider] = {}

    def register(self, provider: BaseIntelligenceProvider) -> None:
        """Register a new intelligence provider."""
        self._providers[provider.provider_id] = provider
        logger.info("Registered intelligence provider: %s (%s)", provider.provider_id, provider.display_name)

    def unregister(self, provider_id: str) -> Optional[BaseIntelligenceProvider]:
        """Unregister an intelligence provider."""
        removed = self._providers.pop(provider_id, None)
        if removed:
            logger.info("Unregistered intelligence provider: %s", provider_id)
        return removed

    def get_providers_for_type(self, query_type: str) -> List[BaseIntelligenceProvider]:
        """Return all enabled providers supporting the given query type."""
        active: List[BaseIntelligenceProvider] = []
        for p in self._providers.values():
            if p.is_enabled() and query_type in p.supported_types:
                active.append(p)
        return active

    def get_all_providers(self) -> List[BaseIntelligenceProvider]:
        """Return all registered providers."""
        return list(self._providers.values())


class IntelligenceAggregator:
    """
    Asynchronous Aggregator executing multiple intelligence providers concurrently.
    Guarantees strict fault isolation: failure or slowness of one provider never
    blocks or disrupts other providers.
    """

    def __init__(self, registry: IntelligenceRegistry):
        self.registry = registry

    async def execute_search(self, query: str, query_type: str) -> SearchResponse:
        """
        Query all eligible OmniScan providers concurrently using asyncio.gather with fault isolation.
        """
        start_total = time.perf_counter()
        clean_query = query.strip()
        providers = self.registry.get_providers_for_type(query_type)

        if not providers:
            return SearchResponse(
                success=True,
                type=query_type,
                query=clean_query,
                engine="BluOsint Multi-Tool Engine",
                execution_time_ms=0.0,
                total_results=0,
                records=[],
                providers_queried=[],
                providers_succeeded=[],
                providers_failed=[],
                tool_telemetry=[],
                message=f"No active BluOsint providers available for search type '{query_type}'.",
            )

        providers_queried = [p.display_name for p in providers]
        providers_succeeded: List[str] = []
        providers_failed: List[str] = []
        aggregated_records: List[SearchRecord] = []
        tool_telemetry: List[ProviderTelemetry] = []

        # Run all provider queries concurrently with return_exceptions=True for 100% isolation
        tasks = [p.execute(clean_query, query_type) for p in providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for provider, res in zip(providers, results):
            if isinstance(res, Exception):
                logger.error("Provider '%s' raised uncaught exception: %s", provider.display_name, str(res))
                providers_failed.append(provider.display_name)
                tool_telemetry.append(
                    ProviderTelemetry(
                        provider_id=provider.provider_id,
                        display_name=provider.display_name,
                        status="failed",
                        execution_time_ms=0.0,
                        records_count=0,
                        summary=f"Unavailable: {str(res)}",
                    )
                )
            elif isinstance(res, ProviderResult):
                if res.success:
                    providers_succeeded.append(provider.display_name)
                    aggregated_records.extend(res.records)
                    rec_count = len(res.records)
                    
                    # Generate concise telemetry summary
                    if rec_count == 0:
                        summary_msg = "Clean / No Exposures Located"
                        status_label = "clean"
                    else:
                        summary_msg = f"{rec_count} intelligence record{'s' if rec_count != 1 else ''} found"
                        status_label = "succeeded"

                    tool_telemetry.append(
                        ProviderTelemetry(
                            provider_id=provider.provider_id,
                            display_name=provider.display_name,
                            status=status_label,
                            execution_time_ms=res.execution_time_ms,
                            records_count=rec_count,
                            summary=summary_msg,
                        )
                    )
                else:
                    logger.warning("Provider '%s' reported failure: %s", provider.display_name, res.error_message)
                    providers_failed.append(provider.display_name)
                    tool_telemetry.append(
                        ProviderTelemetry(
                            provider_id=provider.provider_id,
                            display_name=provider.display_name,
                            status="failed",
                            execution_time_ms=res.execution_time_ms,
                            records_count=0,
                            summary=res.error_message or "Tool reported error",
                        )
                    )
            else:
                providers_failed.append(provider.display_name)

        total_elapsed_ms = round((time.perf_counter() - start_total) * 1000.0, 2)
        total = len(aggregated_records)
        message = f"BluOsint scanned {len(providers_queried)} tools: found {total} record{'s' if total != 1 else ''} across {len(providers_succeeded)} active tool{'s' if len(providers_succeeded) != 1 else ''}."
        if providers_failed:
            message += f" ({len(providers_failed)} tool temporarily unavailable)"

        return SearchResponse(
            success=True,
            type=query_type,
            query=clean_query,
            engine="BluOsint Multi-Tool Engine",
            execution_time_ms=total_elapsed_ms,
            total_results=total,
            records=aggregated_records,
            providers_queried=providers_queried,
            providers_succeeded=providers_succeeded,
            providers_failed=providers_failed,
            tool_telemetry=tool_telemetry,
            message=message,
        )


# Global registry and aggregator initialized with all available free-tier providers
registry = IntelligenceRegistry()
registry.register(OmniScanProvider())
registry.register(HoleheProvider())
registry.register(XposedOrNotProvider())
registry.register(MailDNSProvider())
registry.register(DisposableEmailProvider())
registry.register(PhoneIntelligenceProvider())
registry.register(ThreatFeedProvider())

aggregator = IntelligenceAggregator(registry)
