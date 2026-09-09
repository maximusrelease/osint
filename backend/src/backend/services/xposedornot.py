import html
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional
import httpx
from fastapi import HTTPException, status
from backend.config import get_settings
from backend.schemas.breach import BreachCheckResponse, BreachDetail

logger = logging.getLogger("backend.services.xposedornot")

EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")


def mask_email(email: str) -> str:
    """Mask email for privacy in server logs (e.g., u***r@domain.com)."""
    if not email or "@" not in email:
        return "***"
    parts = email.split("@", 1)
    user = parts[0]
    domain = parts[1]
    if len(user) <= 2:
        masked_user = user[0] + "***"
    else:
        masked_user = user[0] + "***" + user[-1]
    return f"{masked_user}@{domain}"


def parse_exposed_data(raw_data: Any) -> List[str]:
    """Parse exposed data types whether provided as a list or a delimited string."""
    if isinstance(raw_data, list):
        return [str(item).strip() for item in raw_data if str(item).strip()]
    if isinstance(raw_data, str) and raw_data.strip():
        # Split by semicolon or comma
        parts = re.split(r"[;,]", raw_data)
        return [p.strip() for p in parts if p.strip()]
    return []


def format_logo_url(logo: Optional[str]) -> Optional[str]:
    """Format logo path to fully qualified URL if needed."""
    if not logo:
        return None
    logo_clean = logo.strip()
    if logo_clean.startswith("http://") or logo_clean.startswith("https://"):
        return logo_clean
    return f"https://xposedornot.com/static/logos/{logo_clean}"


class XposedOrNotService:
    """Service client for the XposedOrNot data breach API."""

    def __init__(self):
        self.settings = get_settings()

    async def check_email_breaches(self, email: str) -> BreachCheckResponse:
        """Query XposedOrNot breach analytics API for the given email address."""
        if not email or not isinstance(email, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address must be a valid non-empty string.",
            )

        clean_email = email.strip().lower()
        if not EMAIL_REGEX.match(clean_email):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Invalid email format. Please provide a valid email (e.g. user@example.com).",
            )

        masked = mask_email(clean_email)
        encoded_email = urllib.parse.quote(clean_email)
        base_url = self.settings.XPOSEDORNOT_API_BASE_URL.rstrip("/")
        url = f"{base_url}/breach-analytics?email={encoded_email}"

        headers = {
            "Accept": "application/json",
            "User-Agent": "OSINT-Intel-Platform/2.0 (XposedOrNot Integration)",
        }

        try:
            async with httpx.AsyncClient(timeout=self.settings.XPOSEDORNOT_TIMEOUT_SECONDS) as client:
                logger.info("Querying XposedOrNot for masked identifier: %s", masked)
                response = await client.get(url, headers=headers)
                status_code = response.status_code

            logger.info("XposedOrNot response status: %d for %s", status_code, masked)

            # 404 Not Found -> Clean email
            if status_code == 404:
                return BreachCheckResponse(
                    success=True,
                    breached=False,
                    count=0,
                    email=clean_email,
                    risk_score=0,
                    risk_label="Clean",
                    breaches=[],
                    message="Good news - no data breach records were found for this email address.",
                )

            # 200 OK -> Process analytics payload
            if status_code == 200:
                data = response.json()
                return self._parse_analytics_response(clean_email, data)

            # 429 Rate Limit
            if status_code == 429:
                logger.warning("XposedOrNot rate limit encountered for %s", masked)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="XposedOrNot API rate limit reached. Please wait a moment before trying again.",
                )

            # Upstream 5xx error
            logger.error("XposedOrNot upstream error (Status: %d) for %s", status_code, masked)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"XposedOrNot upstream service returned status code {status_code}.",
            )

        except httpx.TimeoutException:
            logger.error("XposedOrNot request timed out for %s", masked)
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Connection to XposedOrNot timed out. Please try again later.",
            )
        except httpx.RequestError as e:
            logger.error("XposedOrNot network request error: %s", str(e))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Network communication failure connecting to XposedOrNot: {type(e).__name__}",
            )

    def _parse_analytics_response(self, email: str, data: Dict[str, Any]) -> BreachCheckResponse:
        """Parse XposedOrNot breach analytics JSON into structured BreachCheckResponse."""
        breach_metrics = data.get("BreachMetrics")
        exposed_breaches = data.get("ExposedBreaches")
        breaches_summary = data.get("BreachesSummary") or {}

        # Detect clean / no-breach condition
        # When clean, BreachMetrics and ExposedBreaches are null, and BreachesSummary site is "" or null
        site_summary = breaches_summary.get("site") if isinstance(breaches_summary, dict) else ""
        has_breaches = bool(exposed_breaches or breach_metrics or site_summary)

        if not has_breaches or (breach_metrics is None and exposed_breaches is None and not site_summary):
            return BreachCheckResponse(
                success=True,
                breached=False,
                count=0,
                email=email,
                risk_score=0,
                risk_label="Clean",
                breaches=[],
                message="Good news - no data breach records were found for this email address.",
            )

        # Parse risk metrics if present
        risk_score: Optional[int] = None
        risk_label: Optional[str] = None
        if isinstance(breach_metrics, dict):
            risk_list = breach_metrics.get("risk")
            if isinstance(risk_list, list) and len(risk_list) > 0 and isinstance(risk_list[0], dict):
                risk_score = risk_list[0].get("risk_score")
                risk_label = risk_list[0].get("risk_label")

        # Parse detailed breach cards
        breach_items: List[BreachDetail] = []
        if isinstance(exposed_breaches, dict):
            details_list = exposed_breaches.get("breaches_details")
            if isinstance(details_list, list):
                for item in details_list:
                    if not isinstance(item, dict):
                        continue
                    breach_name = item.get("breach") or "Unknown Breach"
                    raw_desc = item.get("details") or item.get("xposure_desc")
                    cleaned_desc = html.unescape(raw_desc).strip() if raw_desc else None

                    detail = BreachDetail(
                        breach=breach_name,
                        details=cleaned_desc,
                        domain=item.get("domain"),
                        industry=item.get("industry"),
                        logo=format_logo_url(item.get("logo")),
                        password_risk=item.get("password_risk"),
                        references=item.get("references"),
                        searchable=str(item.get("searchable")) if item.get("searchable") is not None else None,
                        verified=str(item.get("verified")) if item.get("verified") is not None else None,
                        xposed_data=parse_exposed_data(item.get("xposed_data")),
                        xposed_date=str(item.get("xposed_date")) if item.get("xposed_date") is not None else None,
                        xposed_records=item.get("xposed_records"),
                    )
                    breach_items.append(detail)

        # If detailed items empty but site summary exists
        if not breach_items and site_summary:
            sites = [s.strip() for s in site_summary.split(";") if s.strip()]
            for s in sites:
                breach_items.append(BreachDetail(breach=s))

        count = len(breach_items)
        risk_suffix = f" [Risk Level: {risk_label}]" if risk_label else ""
        message = f"Warning: This email address was detected in {count} data breach incident{'s' if count != 1 else ''}.{risk_suffix}"

        return BreachCheckResponse(
            success=True,
            breached=True,
            count=count,
            email=email,
            risk_score=risk_score,
            risk_label=risk_label,
            breaches=breach_items,
            message=message,
        )


xposedornot_service = XposedOrNotService()
