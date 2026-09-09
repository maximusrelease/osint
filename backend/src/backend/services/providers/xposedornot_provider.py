import time
from typing import List, Set
from backend.schemas.search import SearchRecord
from backend.services.providers.base import BaseIntelligenceProvider, ProviderResult
from backend.services.xposedornot import xposedornot_service


class XposedOrNotProvider(BaseIntelligenceProvider):
    """Provider adapter for XposedOrNot Data Breach API."""

    @property
    def provider_id(self) -> str:
        return "xposedornot"

    @property
    def display_name(self) -> str:
        return "XposedOrNot Breach Intelligence"

    @property
    def supported_types(self) -> Set[str]:
        return {"email"}

    def is_enabled(self) -> bool:
        return True

    async def execute(self, query: str, query_type: str) -> ProviderResult:
        start_time = time.perf_counter()
        if query_type not in self.supported_types:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=True,
                records=[],
                execution_time_ms=0.0,
            )

        try:
            res = await xposedornot_service.check_email_breaches(query)
            records: List[SearchRecord] = []

            for b in res.breaches:
                details_dict = {}
                if b.domain:
                    details_dict["Domain"] = b.domain
                if b.industry:
                    details_dict["Industry"] = b.industry
                if b.xposed_records:
                    details_dict["Impacted Accounts"] = f"{b.xposed_records:,}"
                if b.password_risk:
                    details_dict["Password Risk"] = b.password_risk
                if b.verified:
                    details_dict["Verified Status"] = b.verified
                if b.xposed_date:
                    details_dict["Breach Date"] = b.xposed_date
                if b.references:
                    details_dict["Advisory Reference"] = b.references

                records.append(
                    SearchRecord(
                        source=self.display_name,
                        record_type="DATA_BREACH",
                        identifier=query,
                        title=b.breach,
                        description=b.details or f"Identified in {b.breach} breach index.",
                        details=details_dict,
                        tags=b.xposed_data,
                        risk_level=res.risk_label or "High",
                        risk_score=res.risk_score,
                        logo_url=b.logo,
                        timestamp=b.xposed_date,
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
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=False,
                records=[],
                error_message=str(getattr(e, "detail", str(e))),
                execution_time_ms=round(elapsed_ms, 2),
            )
