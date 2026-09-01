"""Incident retrieval endpoints."""

from fastapi import APIRouter, HTTPException, Query

from ..models.schemas import Incident, IncidentsResponse
from ..services import store

router = APIRouter()


@router.get("/api/incidents", response_model=IncidentsResponse)
async def list_incidents(
    limit: int = Query(default=50, ge=1, le=5000),
) -> IncidentsResponse:
    """Return recent incidents and aggregate statistics."""
    incidents = store.get_incidents(limit)
    stats = store.get_incident_stats()
    return IncidentsResponse(incidents=incidents, stats=stats)


@router.get("/api/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str) -> Incident:
    """Return a single incident by ID."""
    incident = store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident
