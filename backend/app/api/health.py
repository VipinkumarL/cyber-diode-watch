"""Health check endpoint."""

from fastapi import APIRouter

from ..ml.model import get_model_info, is_model_loaded
from ..models.schemas import HealthResponse

router = APIRouter()


@router.get("/api/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return backend status and service information."""
    model_loaded = is_model_loaded()

    return HealthResponse(
        status="ok",
        model_loaded=model_loaded,
        db_status="in_memory",
    )
