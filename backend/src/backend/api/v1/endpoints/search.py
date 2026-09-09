import re
from fastapi import APIRouter, HTTPException, status
from backend.schemas.search import SearchRequest, SearchResponse
from backend.services.providers.registry import aggregator

router = APIRouter()

EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
PHONE_REGEX = re.compile(r"^\+?[0-9\s\-\(\)]{7,20}$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


@router.post(
    "/search",
    response_model=SearchResponse,
    summary="Execute Aggregated Intelligence Search",
    description="Concurrently search across all pluggable OSINT, breach, and threat intelligence providers.",
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
    elif request.type == "domain":
        # Strip scheme if user pasted full URL
        clean_domain = re.sub(r"^https?://", "", query).split("/")[0].strip()
        if not DOMAIN_REGEX.match(clean_domain):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Invalid domain format (e.g., example.com).",
            )
        query = clean_domain
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

    return await aggregator.execute_search(query=query, query_type=request.type)
