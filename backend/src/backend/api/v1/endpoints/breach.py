from fastapi import APIRouter, Body, HTTPException, status
from backend.schemas.breach import BreachCheckRequest, BreachCheckResponse
from backend.services.hibp import hibp_service

router = APIRouter()


@router.post(
    "/breach-check",
    response_model=BreachCheckResponse,
    summary="Check Email in HIBP Breaches",
    description="Check whether an email address has been exposed in data breaches via Have I Been Pwned API.",
    responses={
        200: {"description": "Breach intelligence check successfully executed."},
        400: {"description": "Email address is missing or invalid format."},
        429: {"description": "Rate limit reached on breach provider."},
        502: {"description": "Breach provider authentication or communication failure."},
        503: {"description": "HIBP service unavailable or API key unconfigured."},
    },
)
async def check_email_breach(
    payload: BreachCheckRequest = Body(
        ...,
        examples=[{"email": "user@example.com"}],
    )
) -> BreachCheckResponse:
    if not payload or not payload.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email field is required.",
        )
    return await hibp_service.check_breach(payload.email)
