import re
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from backend.schemas.search import SearchRecord, SearchRequest, SearchResponse

router = APIRouter()

EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
PHONE_REGEX = re.compile(r"^\+?[0-9\s\-\(\)]{7,20}$")


@router.post(
    "/search",
    response_model=SearchResponse,
    summary="Execute Intelligence Search",
    description="Search by username, email, or phone identifier.",
)
async def execute_search(request: SearchRequest) -> SearchResponse:
    query = request.query.strip()
    if not query:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Search query cannot be empty.",
        )

    if request.type == "email":
        if not EMAIL_REGEX.match(query):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Invalid email address format.",
            )
    elif request.type == "phone":
        if not PHONE_REGEX.match(query):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Invalid phone number format. Please include a valid numeric number.",
            )
    elif request.type == "username":
        if len(query) < 2:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Username must be at least 2 characters.",
            )

    # Simulated intelligence records for testing/demonstration
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Generate realistic intelligence records safely
    records = [
        SearchRecord(
            source="Breach Index #849",
            record_type=request.type.upper(),
            identifier=query,
            details={
                "Status": "Exposed in legacy leak",
                "Hash Type": "SHA-256 (Salted)",
                "Security Recommendation": "Rotate associated credentials",
            },
            timestamp=now_iso,
        ),
        SearchRecord(
            source="Public Threat Intel Feed",
            record_type="OSINT_CORRELATION",
            identifier=query,
            details={
                "Confidence Score": "High (94%)",
                "Observed Mentions": "14 forum indexes",
                "Status": "Verified entry",
            },
            timestamp=now_iso,
        ),
    ]

    return SearchResponse(
        success=True,
        type=request.type,
        query=query,
        total_results=len(records),
        records=records,
        message=f"Found {len(records)} correlated records for '{query}'.",
    )
