"""Health check endpoint."""

from fastapi import APIRouter

from ..models.schemas import HealthResponse

router = APIRouter()


@router.get("/api/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return backend status and service information."""
    return HealthResponse(
        status="ok",
        model_loaded=False,  # No ML model loaded yet
        db_status="in_memory",
    )
