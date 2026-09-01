# SIH26145 — Cyber-Diode-Watch Backend

Python + FastAPI backend for the AI-Based Detection of Cyber Threats in
Unidirectional IP Traffic project (SIH2026 Problem Statement SIH26145).

This is a **passive monitoring backend** — it never sends traffic, probes hosts,
performs active mitigation, or decrypts payloads.

---

## Quick Start

```bash
cd backend

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn main:app --reload --port 8000
```

The API docs are available at **http://localhost:8000/docs**.

---

## Connecting to the Frontend

1. In the frontend root, create a `.env` file:

```
VITE_API_BASE_URL=http://localhost:8000
```

2. Run the frontend:

```bash
cd ..
bun install
bun run dev
```

The frontend will automatically connect to the backend for data reads,
replay control, and WebSocket events.

---

## Architecture

```
backend/
├── main.py                 # FastAPI app, CORS, router mounting
├── requirements.txt
├── app/
│   ├── api/                # Route handlers (one per resource)
│   │   ├── health.py       # GET /api/health
│   │   ├── flows.py        # POST/GET /api/flows
│   │   ├── alerts.py       # GET /api/alerts, /api/alerts/{id}
│   │   ├── incidents.py    # GET /api/incidents, /api/incidents/{id}
│   │   ├── statistics.py   # GET /api/statistics, /api/metrics
│   │   ├── detectors.py    # GET /api/detectors
│   │   ├── predict.py      # POST /api/predict
│   │   ├── replay.py       # POST /api/replay/{start,stop,pause,reset}
│   │   └── websocket.py    # WS /ws/traffic
│   ├── models/
│   │   └── schemas.py      # Pydantic models matching frontend types
│   ├── services/
│   │   └── store.py        # Thread-safe in-memory data store
│   ├── detection/
│   │   ├── base.py         # Detector interface (ABC)
│   │   └── ddos.py         # DDoS detector (NOT_IMPLEMENTED placeholder)
│   ├── features/
│   │   └── common.py       # Feature extraction utilities
│   └── replay/
│       └── engine.py       # Synthetic flow generators
└── tests/                  # pytest test suite
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service info |
| GET | `/api/health` | Backend health + model status |
| POST | `/api/flows` | Ingest a flow record |
| GET | `/api/flows?limit=N` | List recent flows + stats |
| GET | `/api/alerts?limit=N` | List recent alerts + stats |
| GET | `/api/alerts/{id}` | Get alert by ID |
| GET | `/api/incidents?limit=N` | List incidents + stats |
| GET | `/api/incidents/{id}` | Get incident by ID |
| GET | `/api/statistics` | Combined flow/alert/incident stats |
| GET | `/api/metrics` | System metrics snapshot |
| GET | `/api/detectors` | Detector status for all 6 categories |
| POST | `/api/predict` | Run detection on a flow |
| POST | `/api/replay/start` | Start synthetic replay |
| POST | `/api/replay/pause` | Pause replay |
| POST | `/api/replay/stop` | Stop replay |
| POST | `/api/replay/reset` | Reset replay + clear data |
| WS | `/ws/traffic` | Live flow/alert/metrics stream |

---

## Running Tests

```bash
cd backend
python3 -m pytest tests/ -v
```

---

## What's Implemented

- ✅ FastAPI application with CORS
- ✅ Pydantic models matching all frontend TypeScript interfaces
- ✅ Thread-safe in-memory data store
- ✅ Flow ingestion and retrieval with statistics
- ✅ Alert storage and retrieval with statistics
- ✅ Incident storage and retrieval with statistics
- ✅ Statistics and system metrics endpoints
- ✅ Detector registry with status for all 6 threat categories
- ✅ Prediction endpoint (interface only — no ML model)
- ✅ Replay control endpoints
- ✅ WebSocket endpoint for live event streaming
- ✅ Synthetic flow generators (Normal, DDoS, C2, DNS, Recon, Exfil)
- ✅ Feature extraction utilities
- ✅ 28 passing tests

---

## What's NOT Implemented (Placeholders)

| Component | Status | Notes |
|-----------|--------|-------|
| DDoS Detection | `NOT_IMPLEMENTED` | Interface ready. Needs CICIDS2017 model training. |
| C2 Beaconing | `NOT_IMPLEMENTED` | Interface defined. Needs periodicity analysis. |
| DGA/DNS Tunneling | `NOT_IMPLEMENTED` | Interface defined. Needs domain entropy analysis. |
| Encrypted Malware | `NOT_IMPLEMENTED` | Interface defined. Needs JA3/JA4 fingerprinting. |
| Reconnaissance | `NOT_IMPLEMENTED` | Interface defined. Needs port fan-out analysis. |
| Data Exfiltration | `NOT_IMPLEMENTED` | Interface defined. Needs outbound/inbound ratio. |
| ML Model Loading | Not started | Needs joblib model file + loading logic. |
| Database | Not started | Currently in-memory only. PostgreSQL-ready schema. |
| Replay Engine (server-side) | Not started | Client-side replay works. Server-side needs asyncio loop. |

---

## Safety Requirements

This backend enforces the SIH26145 passive monitoring requirements:

- ✅ Read-only ingest — only receives flow records, never probes
- ✅ No return path — never sends traffic toward monitored networks
- ✅ No active probing — no SYN packets, port scans, or ARP requests
- ✅ No payload decryption — analysis uses metadata only
- ✅ No inline mitigation — no blocking, rate limiting, or firewall rules
- ✅ Safe synthetic data only — replay uses generated flow records
