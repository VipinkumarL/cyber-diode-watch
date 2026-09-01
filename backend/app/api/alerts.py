"""Alert retrieval endpoints."""

from fastapi import APIRouter, HTTPException, Query

from ..models.schemas import Alert, AlertsResponse
from ..services import store

router = APIRouter()


@router.get("/api/alerts", response_model=AlertsResponse)
async def list_alerts(limit: int = Query(default=50, ge=1, le=5000)) -> AlertsResponse:
    """Return recent alerts and aggregate statistics."""
    alerts = store.get_alerts(limit)
    stats = store.get_alert_stats()
    return AlertsResponse(alerts=alerts, stats=stats)


@router.get("/api/alerts/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str) -> Alert:
    """Return a single alert by ID."""
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert
