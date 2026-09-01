"""Detector status endpoint."""

from fastapi import APIRouter

from ..detection.pipeline import pipeline
from ..models.schemas import DetectorInfo

router = APIRouter()


@router.get("/api/detectors", response_model=list[DetectorInfo])
async def list_detectors() -> list[DetectorInfo]:
    """Return the status of all SIH26145 detection modules."""
    return pipeline.get_all_detectors()
