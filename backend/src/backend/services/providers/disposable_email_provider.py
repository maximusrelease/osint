from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Set
from backend.schemas.search import SearchRecord
from backend.services.providers.base import BaseIntelligenceProvider, ProviderResult

# Curated list of high-velocity disposable and burner mail domains
DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "guerrillamail.com",
    "guerrillamail.net",
    "guerrillamail.org",
    "guerrillamailblock.com",
    "sharklasers.com",
    "grr.la",
    "10minutemail.com",
    "10minutemail.net",
    "tempmail.com",
    "temp-mail.org",
    "tempmail.net",
    "yopmail.com",
    "yopmail.fr",
    "yopmail.net",
    "trashmail.com",
    "trashmail.net",
    "getnada.com",
    "throwawaymail.com",
    "dispostable.com",
    "maildrop.cc",
    "inboxkitten.com",
    "burnermail.io",
    "mohmal.com",
    "fakeinbox.com",
    "fakemailgenerator.com",
    "crazymailing.com",
    "emailondeck.com",
    "nada.ltd",
    "tempr.email",
    "discard.email",
    "spambog.com",
}

FREE_CONSUMER_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "protonmail.com",
    "proton.me",
    "pm.me",
    "zoho.com",
    "fastmail.com",
    "aol.com",
    "mail.com",
    "gmx.com",
    "gmx.net",
}


class DisposableEmailProvider(BaseIntelligenceProvider):
    """
    Disposable, Burner, and Temporary Email Provider.
    Analyzes email addresses to verify deliverability classification and fraud risk.
    """

    @property
    def provider_id(self) -> str:
        return "disposable_email"

    @property
    def display_name(self) -> str:
        return "Email Reputation & Burner Detection"

    @property
    def supported_types(self) -> Set[str]:
        return {"email", "domain"}

    def is_enabled(self) -> bool:
        return True

    def _extract_domain(self, query: str, query_type: str) -> str:
        clean = query.strip().lower()
        if query_type == "email" and "@" in clean:
            return clean.split("@", 1)[1].strip()
        return clean.split("/")[0].strip()

    async def execute(self, query: str, query_type: str) -> ProviderResult:
        start_time = time.perf_counter()
        domain = self._extract_domain(query, query_type)
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if not domain:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=True,
                records=[],
                execution_time_ms=0.0,
            )

        is_disposable = domain in DISPOSABLE_DOMAINS
        is_free_consumer = domain in FREE_CONSUMER_DOMAINS
        is_corporate = not is_disposable and not is_free_consumer

        if is_disposable:
            classification = "Disposable / Burner Email Service"
            risk_level = "High"
            risk_score = 85
            tags = ["DISPOSABLE_INBOX", "HIGH_FRAUD_RISK", "BURNER_MAIL"]
            desc = f"Warning: The domain '{domain}' is an identified temporary/burner email provider often associated with fraudulent registrations and throwaway accounts."
        elif is_free_consumer:
            classification = "Free Consumer Email Service"
            risk_level = "Clean"
            risk_score = 10
            tags = ["FREE_MAIL_PROVIDER", "CONSUMER_MAIL", "NON_DISPOSABLE"]
            desc = f"The domain '{domain}' is a reputable public consumer email provider."
        else:
            classification = "Corporate / Custom Domain Email"
            risk_level = "Clean"
            risk_score = 5
            tags = ["CORPORATE_DOMAIN", "ENTERPRISE", "NON_DISPOSABLE"]
            desc = f"The domain '{domain}' is recognized as a dedicated corporate or custom business domain."

        details: Dict[str, Any] = {
            "Domain": domain,
            "Classification": classification,
            "Disposable / Burner Status": "Yes (Flagged)" if is_disposable else "No (Verified Clean)",
            "Fraud & Abuse Risk": "Elevated" if is_disposable else "Low",
            "Account Persistence": "Temporary" if is_disposable else "Permanent",
        }

        records = [
            SearchRecord(
                source=self.display_name,
                record_type="EMAIL_REPUTATION",
                identifier=query,
                title=f"Reputation Check: {domain} ({classification})",
                description=desc,
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
