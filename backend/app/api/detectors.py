"""Detector status endpoint."""

from fastapi import APIRouter

from ..detection.ddos import DDoSDetector
from ..models.schemas import DetectorInfo

router = APIRouter()

# Detector registry — add new detectors here as they are implemented
_detectors: list[DetectorInfo] = [
    DDoSDetector().get_info(),
    DetectorInfo(
        name="C2 Beaconing",
        threatClass="C2_Beaconing",
        status="NOT_IMPLEMENTED",
        method="Statistical Periodicity Scoring",
        description=(
            "Detects command-and-control beaconing patterns using "
            "inter-arrival time analysis. Interface ready, not implemented."
        ),
    ),
    DetectorInfo(
        name="DGA/DNS Tunnelling",
        threatClass="DGA_DNS_Tunneling",
        status="NOT_IMPLEMENTED",
        method="Domain Entropy + N-gram Analysis",
        description=(
            "Identifies DGA-generated domains and DNS tunneling using "
            "character distribution analysis. Interface ready, not implemented."
        ),
    ),
    DetectorInfo(
        name="Encrypted Malware",
        threatClass="Encrypted_Malware",
        status="NOT_IMPLEMENTED",
        method="JA3/JA4 Fingerprinting + Timing",
        description=(
            "Metadata-only detection of malware in encrypted sessions. "
            "Never decrypts payloads. Interface ready, not implemented."
        ),
    ),
    DetectorInfo(
        name="Reconnaissance",
        threatClass="Reconnaissance",
        status="NOT_IMPLEMENTED",
        method="Port Fan-out + Scan Rate Analysis",
        description=(
            "Detects port scanning and reconnaissance using passive flow "
            "metadata. Interface ready, not implemented."
        ),
    ),
    DetectorInfo(
        name="Data Exfiltration",
        threatClass="Data_Exfiltration",
        status="NOT_IMPLEMENTED",
        method="Outbound/Inbound Ratio + Volume Analysis",
        description=(
            "Identifies potential data exfiltration via unusual outbound "
            "traffic patterns. Interface ready, not implemented."
        ),
    ),
]


@router.get("/api/detectors", response_model=list[DetectorInfo])
async def list_detectors() -> list[DetectorInfo]:
    """Return the status of all SIH26145 detection modules."""
    return _detectors
