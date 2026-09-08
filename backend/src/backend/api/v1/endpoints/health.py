from fastapi import APIRouter
from backend.config import get_settings
from backend.schemas.health import HealthResponse

router = APIRouter()
settings = get_settings()


@router.get("/health", response_model=HealthResponse, summary="Service Health Check")
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        project=settings.PROJECT_NAME,
    )
