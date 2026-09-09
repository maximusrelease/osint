from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Set
import phonenumbers
from phonenumbers import carrier, geocoder, phonenumberutil
from backend.schemas.search import SearchRecord
from backend.services.providers.base import BaseIntelligenceProvider, ProviderResult

logger = logging.getLogger("backend.services.providers.phone_intel")

NUMBER_TYPE_MAP = {
    phonenumberutil.PhoneNumberType.MOBILE: "Mobile / Cellular",
    phonenumberutil.PhoneNumberType.FIXED_LINE: "Fixed Line / Landline",
    phonenumberutil.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
    phonenumberutil.PhoneNumberType.TOLL_FREE: "Toll Free",
    phonenumberutil.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
    phonenumberutil.PhoneNumberType.SHARED_COST: "Shared Cost",
    phonenumberutil.PhoneNumberType.VOIP: "VoIP / Virtual Number",
    phonenumberutil.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
    phonenumberutil.PhoneNumberType.PAGER: "Pager",
    phonenumberutil.PhoneNumberType.UAN: "Universal Access Number (UAN)",
    phonenumberutil.PhoneNumberType.VOICEMAIL: "Voicemail",
    phonenumberutil.PhoneNumberType.UNKNOWN: "Unknown Line Type",
}


class PhoneIntelligenceProvider(BaseIntelligenceProvider):
    """
    International Phone Number & Telecom Carrier OSINT Provider.
    Utilizes Google libphonenumber metadata to extract carrier, country, line type, and E.164 formatting.
    """

    @property
    def provider_id(self) -> str:
        return "phone_intel"

    @property
    def display_name(self) -> str:
        return "Phone & Carrier Intelligence"

    @property
    def supported_types(self) -> Set[str]:
        return {"phone"}

    def is_enabled(self) -> bool:
        return True

    async def execute(self, query: str, query_type: str) -> ProviderResult:
        start_time = time.perf_counter()
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        clean_number = query.strip()

        # Parse with default region if not pre-pended with +
        try:
            default_region = "US" if not clean_number.startswith("+") else None
            parsed = phonenumbers.parse(clean_number, default_region)
        except Exception as e:
            logger.warning("Failed to parse phone number %s: %s", clean_number, str(e))
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=True,
                records=[],
                execution_time_ms=0.0,
            )

        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)

        e164_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        international_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        national_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

        country_name = geocoder.description_for_number(parsed, "en") or "Unknown Country"
        region_code = phonenumberutil.region_code_for_number(parsed) or "Unknown"
        carrier_name = carrier.name_for_number(parsed, "en") or "Unspecified Telecom Carrier"

        raw_type = phonenumberutil.number_type(parsed)
        line_type = NUMBER_TYPE_MAP.get(raw_type, "Unknown Line Type")

        tags = ["TELECOM_INTEL", "PHONE"]
        if region_code:
            tags.append(f"REGION_{region_code}")
        if "VoIP" in line_type:
            tags.append("VOIP_NUMBER")
        elif "Mobile" in line_type:
            tags.append("MOBILE_CELLULAR")

        risk_level = "Clean"
        risk_score = 10
        if "VoIP" in line_type:
            risk_level = "Medium"
            risk_score = 50
        elif not is_valid:
            risk_level = "Low"
            risk_score = 30

        details: Dict[str, Any] = {
            "E.164 Identifier": e164_format,
            "International Format": international_format,
            "National Format": national_format,
            "Geographic Location": f"{country_name} ({region_code})",
            "Telecom Carrier / Network": carrier_name,
            "Line Classification": line_type,
            "ITU Validation Status": "Valid Number" if is_valid else ("Possible Number" if is_possible else "Invalid Format"),
        }

        records = [
            SearchRecord(
                source=self.display_name,
                record_type="TELECOM_CARRIER_INTEL",
                identifier=query,
                title=f"Telecom Intel: {international_format} ({country_name})",
                description=f"Carrier: {carrier_name} | Type: {line_type} | Region: {country_name} ({region_code})",
                details=details,
                tags=tags,
                risk_level=risk_level,
                risk_score=risk_score,
                timestamp=now_iso,
            )
        ]

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return ProviderResult(
            provider_id=self.provider_id,
            provider_name=self.display_name,
            success=True,
            records=records,
            execution_time_ms=round(elapsed_ms, 2),
        )
