"""Statistics and metrics endpoints."""

from fastapi import APIRouter

from ..models.schemas import StatisticsResponse, SystemMetrics
from ..services import store

router = APIRouter()


@router.get("/api/statistics", response_model=StatisticsResponse)
async def get_statistics() -> StatisticsResponse:
    """Return combined flow, alert, and incident statistics."""
    return StatisticsResponse(
        flows=store.get_flow_stats(),
        alerts=store.get_alert_stats(),
        incidents=store.get_incident_stats(),
    )


@router.get("/api/metrics", response_model=SystemMetrics)
async def get_metrics() -> SystemMetrics:
    """Return a system metrics snapshot."""
    metrics = store.record_metrics()
    return metrics
