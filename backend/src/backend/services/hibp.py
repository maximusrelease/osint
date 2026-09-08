import html
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional
import httpx
from fastapi import HTTPException, status

from backend.config import get_settings
from backend.schemas.breach import BreachCheckResponse, BreachItem

logger = logging.getLogger("backend.services.hibp")

# RFC 5322 compliant practical email regex
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)
TAG_RE = re.compile(r"<[^>]+>")


def mask_email(email: str) -> str:
    """Mask email for privacy-safe logging without leaking PII."""
    try:
        parts = email.split("@")
        if len(parts) != 2:
            return "***"
        local, domain = parts
        if len(local) <= 2:
            masked_local = local[0] + "***"
        else:
            masked_local = local[0] + "***" + local[-1]
        return f"{masked_local}@{domain}"
    except Exception:
        return "***"


def sanitize_description(raw_desc: Optional[str]) -> Optional[str]:
    """Clean HTML tags and decode HTML entities in breach descriptions."""
    if not raw_desc:
        return None
    # Decode HTML entities first (e.g. &lt;b&gt; -> <b>, &quot; -> ")
    unescaped = html.unescape(raw_desc)
    # Strip HTML tags
    cleaned = TAG_RE.sub("", unescaped)
    return cleaned.strip()


class HIBPService:
    def __init__(self) -> None:
        self.settings = get_settings()

    def normalize_and_validate_email(self, email: Optional[str]) -> str:
        """
        Validate and normalize email address.
        Rejects missing or invalid email with HTTP 400.
        """
        if not email or not isinstance(email, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address is required.",
            )

        normalized = email.strip().lower()

        if not normalized:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address cannot be blank.",
            )

        if len(normalized) > 320 or not EMAIL_REGEX.match(normalized):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email address format.",
            )

        return normalized

    async def check_breach(self, email: str) -> BreachCheckResponse:
        """
        Check Have I Been Pwned API for breach records for the given email.
        """
        normalized_email = self.normalize_and_validate_email(email)
        masked = mask_email(normalized_email)

        api_key = self.settings.HIBP_API_KEY.strip()
        if not api_key:
            logger.warning("HIBP API key is missing in backend configuration.")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="HIBP API key is not configured on the server. Please set HIBP_API_KEY in the environment.",
            )

        encoded_account = urllib.parse.quote(normalized_email)
        url = f"{self.settings.HIBP_API_BASE_URL.rstrip('/')}/breachedaccount/{encoded_account}?truncateResponse=false"

        headers = {
            "hibp-api-key": api_key,
            "user-agent": self.settings.HIBP_USER_AGENT,
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self.settings.HIBP_TIMEOUT_SECONDS) as client:
                response = await client.get(url, headers=headers)

            status_code = response.status_code
            logger.info("HIBP query completed for masked identifier: %s (Status: %d)", masked, status_code)

            # 404: Account not breached (Clean)
            if status_code == status.HTTP_404_NOT_FOUND:
                return BreachCheckResponse(
                    success=True,
                    pwned=False,
                    count=0,
                    email=normalized_email,
                    breaches=[],
                    message="Good news — no pwnage found! No breach records were detected for this email address.",
                )

            # 200: Account found in breaches
            if status_code == status.HTTP_200_OK:
                raw_breaches: List[Dict[str, Any]] = response.json()
                breach_items: List[BreachItem] = []

                for b in raw_breaches:
                    breach_items.append(
                        BreachItem(
                            name=b.get("Name", "Unknown"),
                            title=b.get("Title", b.get("Name", "Unknown Breach")),
                            domain=b.get("Domain"),
                            breach_date=b.get("BreachDate"),
                            added_date=b.get("AddedDate"),
                            modified_date=b.get("ModifiedDate"),
                            pwn_count=b.get("PwnCount"),
                            description=sanitize_description(b.get("Description")),
                            data_classes=b.get("DataClasses", []),
                            is_verified=b.get("IsVerified", True),
                            is_fabricated=b.get("IsFabricated", False),
                            is_sensitive=b.get("IsSensitive", False),
                            is_retired=b.get("IsRetired", False),
                            is_spam_list=b.get("IsSpamList", False),
                            logo_path=b.get("LogoPath"),
                        )
                    )

                count = len(breach_items)
                return BreachCheckResponse(
                    success=True,
                    pwned=True,
                    count=count,
                    email=normalized_email,
                    breaches=breach_items,
                    message=f"Pwned! Found {count} breach incident{'s' if count != 1 else ''} associated with this email address.",
                )

            # 400: Bad Request from HIBP
            if status_code == status.HTTP_400_BAD_REQUEST:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid request format sent to breach verification service.",
                )

            # 401 / 403: Invalid or unauthorized API key / Forbidden
            if status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN):
                logger.error("HIBP authentication failed (Status: %d). Verify HIBP_API_KEY and User-Agent.", status_code)
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Breach verification provider authentication failed. Please check backend API key configuration.",
                )

            # 429: Rate limited
            if status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                retry_after = response.headers.get("Retry-After", "few")
                logger.warning("HIBP rate limit encountered. Retry-After: %s", retry_after)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded on breach verification provider. Please try again in {retry_after} seconds.",
                )

            # 503 / 5xx: Service Unavailable
            if status_code >= 500:
                logger.error("HIBP upstream server error: %d", status_code)
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Have I Been Pwned service is temporarily unavailable. Please try again later.",
                )

            # Any other unexpected code
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Unexpected response status from breach intelligence provider ({status_code}).",
            )

        except httpx.TimeoutException:
            logger.error("HIBP API request timed out for masked identifier: %s", masked)
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Breach intelligence request timed out. Please try again.",
            )
        except httpx.RequestError as e:
            logger.error("HIBP network error: %s", type(e).__name__)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Unable to establish connection to breach intelligence provider.",
            )


hibp_service = HIBPService()
