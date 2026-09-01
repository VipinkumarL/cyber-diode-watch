"""
SIH26145 — Cyber-Diode-Watch FastAPI Backend.

Passive cybersecurity monitoring system backend.
Receives strictly one-directional stream of network flow data.
Never sends traffic, probes, or mitigation commands back.

Run:
    cd backend
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000

API docs:
    http://localhost:8000/docs
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    alerts,
    detectors,
    flows,
    health,
    incidents,
    predict,
    replay,
    statistics,
    websocket,
)
from app.ml.model import load_model

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SIH26145 — Cyber-Diode-Watch",
    description=(
        "AI-Based Detection of Cyber Threats in Unidirectional IP Traffic. "
        "Passive monitoring backend — read-only ingest, no return path."
    ),
    version="0.2.0",
)

# ── CORS — allow the Vite dev server to connect ───────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Mount routers ─────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(flows.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(statistics.router)
app.include_router(detectors.router)
app.include_router(predict.router)
app.include_router(replay.router)
app.include_router(websocket.router)


@app.on_event("startup")
async def startup_event() -> None:
    """Load the ML model on startup."""
    model_loaded = load_model()
    if model_loaded:
        logger.info("ML model loaded successfully — ML predictions active")
    else:
        logger.warning(
            "ML model not found — running with baseline detectors only. "
            "Train a model with: python -m training.train"
        )


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint — confirms the backend is running."""
    return {
        "service": "SIH26145 Cyber-Diode-Watch",
        "status": "passive_monitoring_active",
        "docs": "/docs",
    }
