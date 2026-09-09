import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional, Set
import dns.resolver
import httpx
from backend.schemas.search import SearchRecord
from backend.services.providers.base import BaseIntelligenceProvider, ProviderResult

logger = logging.getLogger("backend.services.providers.mail_dns")

MAIL_SIGNATURES = [
    ("google", "Google Workspace / Gmail"),
    ("googlemail", "Google Workspace / Gmail"),
    ("aspmx.l.google.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365 / Outlook"),
    ("protection.outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint Enterprise Mail Protection"),
    ("mimecast.com", "Mimecast Secure Email Gateway"),
    ("protonmail.ch", "Proton Mail (Encrypted)"),
    ("proton.me", "Proton Mail (Encrypted)"),
    ("zoho.com", "Zoho Mail"),
    ("messagingengine.com", "Fastmail"),
    ("icloud.com", "Apple iCloud Mail"),
    ("amazonaws.com", "Amazon WorkMail / SES"),
    ("mandrillapp.com", "Mailchimp / Mandrill"),
    ("sendgrid.net", "Twilio SendGrid"),
]


def identify_mail_host(mx_hosts: List[str]) -> str:
    """Identify the mail service provider from MX hostnames."""
    mx_joined = " ".join(mx_hosts).lower()
    for signature, label in MAIL_SIGNATURES:
        if signature in mx_joined:
            return label
    return "Custom / Self-Hosted Mail Server" if mx_hosts else "No Mail Servers Configured"


class MailDNSProvider(BaseIntelligenceProvider):
    """
    DNS & Mail Exchange (MX / SPF / DMARC) Intelligence Provider.
    Queries mail routing, security policies, and hosting providers for domains/emails.
    """

    @property
    def provider_id(self) -> str:
        return "mail_dns"

    @property
    def display_name(self) -> str:
        return "Mail & DNS Intelligence"

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

    def _query_dns_local(self, domain: str) -> Dict[str, Any]:
        """Perform DNS lookups using dnspython."""
        results = {
            "mx": [],
            "spf": None,
            "dmarc": None,
        }
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        # Query MX records
        try:
            answers = resolver.resolve(domain, "MX")
            sorted_mx = sorted(answers, key=lambda r: r.preference)
            results["mx"] = [f"{r.exchange.to_text().rstrip('.')} (Priority: {r.preference})" for r in sorted_mx]
        except Exception:
            pass

        # Query SPF / TXT records
        try:
            txt_answers = resolver.resolve(domain, "TXT")
            for r in txt_answers:
                text = "".join([t.decode() if isinstance(t, bytes) else str(t) for t in r.strings])
                if text.startswith("v=spf1"):
                    results["spf"] = text
                    break
        except Exception:
            pass

        # Query DMARC record (_dmarc.domain)
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            for r in dmarc_answers:
                text = "".join([t.decode() if isinstance(t, bytes) else str(t) for t in r.strings])
                if "v=DMARC1" in text:
                    results["dmarc"] = text
                    break
        except Exception:
            pass

        return results

    async def _query_dns_doh_fallback(self, domain: str) -> Dict[str, Any]:
        """Query Cloudflare DNS-over-HTTPS as an asynchronous fallback."""
        results = {"mx": [], "spf": None, "dmarc": None}
        headers = {"Accept": "application/dns-json"}

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                # MX Query
                r_mx = await client.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX", headers=headers)
                if r_mx.status_code == 200:
                    ans = r_mx.json().get("Answer", [])
                    results["mx"] = [item.get("data", "").rstrip(".") for item in ans if item.get("data")]

                # TXT / SPF Query
                r_txt = await client.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT", headers=headers)
                if r_txt.status_code == 200:
                    ans = r_txt.json().get("Answer", [])
                    for item in ans:
                        txt_val = item.get("data", "").strip('"')
                        if txt_val.startswith("v=spf1"):
                            results["spf"] = txt_val
                            break

                # DMARC Query
                r_dmarc = await client.get(f"https://cloudflare-dns.com/dns-query?name=_dmarc.{domain}&type=TXT", headers=headers)
                if r_dmarc.status_code == 200:
                    ans = r_dmarc.json().get("Answer", [])
                    for item in ans:
                        txt_val = item.get("data", "").strip('"')
                        if "v=DMARC1" in txt_val:
                            results["dmarc"] = txt_val
                            break
        except Exception as e:
            logger.warning("DoH fallback query error: %s", str(e))

        return results

    async def execute(self, query: str, query_type: str) -> ProviderResult:
        start_time = time.perf_counter()
        domain = self._extract_domain(query, query_type)
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if not domain or "." not in domain:
            return ProviderResult(
                provider_id=self.provider_id,
                provider_name=self.display_name,
                success=True,
                records=[],
                execution_time_ms=0.0,
            )

        # Execute local resolver in thread pool with DoH fallback
        try:
            dns_data = await asyncio.to_thread(self._query_dns_local, domain)
            if not dns_data.get("mx") and not dns_data.get("spf") and not dns_data.get("dmarc"):
                dns_data = await self._query_dns_doh_fallback(domain)
        except Exception:
            dns_data = await self._query_dns_doh_fallback(domain)

        mx_records = dns_data.get("mx") or []
        spf_record = dns_data.get("spf")
        dmarc_record = dns_data.get("dmarc")
        mail_host = identify_mail_host(mx_records)

        # Risk assessment based on mail security posture
        tags = ["MAIL_INTEL", "DNS"]
        if "Google" in mail_host:
            tags.append("GOOGLE_WORKSPACE")
        elif "Microsoft" in mail_host:
            tags.append("MICROSOFT_365")
        elif "Proton" in mail_host:
            tags.append("ENCRYPTED_MAIL")

        has_dmarc = bool(dmarc_record)
        has_spf = bool(spf_record)
        has_mx = len(mx_records) > 0

        risk_level = "Clean"
        risk_score = 10
        if not has_mx:
            risk_level = "Medium"
            risk_score = 40
        elif not has_spf or not has_dmarc:
            risk_level = "Low"
            risk_score = 25

        details: Dict[str, Any] = {
            "Domain": domain,
            "Primary Mail Host": mail_host,
            "MX Routing Count": f"{len(mx_records)} server(s)",
            "SPF Security Policy": spf_record or "Missing (Vulnerable to spoofing)",
            "DMARC Enforcement": dmarc_record or "Missing (No DMARC policy configured)",
        }

        if mx_records:
            details["Active MX Servers"] = ", ".join(mx_records[:3])

        records = [
            SearchRecord(
                source=self.display_name,
                record_type="MAIL_SECURITY_POSTURE",
                identifier=query,
                title=f"Mail Infrastructure: {domain} ({mail_host})",
                description=f"Identified mail exchange infrastructure for {domain}. SPF: {'Configured' if has_spf else 'Missing'}, DMARC: {'Configured' if has_dmarc else 'Missing'}.",
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
