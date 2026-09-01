"""Health check endpoint."""

from fastapi import APIRouter

from ..ml.model import get_model_info, get_model_source, is_model_loaded
from ..models.schemas import HealthResponse

router = APIRouter()


@router.get("/api/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return backend status, model information, and service health."""
    model_loaded = is_model_loaded()
    model_source = get_model_source() if model_loaded else ""

    return HealthResponse(
        status="ok",
        model_loaded=model_loaded,
        model_source=model_source,
        db_status="in_memory",
    )
