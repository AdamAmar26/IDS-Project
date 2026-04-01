# Behavior-Based Intrusion Detection & Alert Intelligence Platform

A Windows-first, single-host behavior-based IDS that collects live telemetry,
engineers windowed features, detects anomalies with Isolation Forest + SHAP
explainability, maps detections to MITRE ATT&CK, enriches with threat
intelligence, generates analyst narratives via Ollama LLM, and exposes
everything through a FastAPI API (REST + WebSocket) and Next.js dashboard.

## Architecture

```
Telemetry Collector  -->  SQLite (Alembic migrations)
        |
  Feature Pipeline
        |
  Isolation Forest + SHAP Explainer  -->  Alerts
        |
  Threat Intel Enricher  -->  IP reputation hits
        |
  MITRE ATT&CK Mapper  -->  Tactic / technique tags
        |
  Correlation Engine  -->  Incidents
        |
  Ollama LLM Explainer (fallback: templates)  -->  Narratives
        |
  FastAPI (REST + WebSocket + JWT + Prometheus)
        |
  Next.js 14 + TypeScript + Tailwind Dashboard
```

## Quick Start (native Windows)

### 1. Install backend dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Install frontend dependencies

```bash
cd frontend
npm install
```

### 3. (Optional) Start Ollama for LLM explanations

```bash
ollama serve
ollama pull llama3
```

If Ollama is not running, the system falls back to deterministic template
explanations automatically.

### 4. Start the API server

For full telemetry (including Security event log for login tracking), run
as **Administrator**:

```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 5. Start the dashboard

```bash
cd frontend
npm run dev
```

Open **http://localhost:3000** to view the dashboard.

## Quick Start (Docker)

```bash
docker compose up --build
```

- API: http://localhost:8000
- Dashboard: http://localhost:3000
- Ollama: http://localhost:11434

> **Important:** Docker containers run on Linux and cannot access
> Windows Security event logs. Use the native Python startup path above
> for the real Windows telemetry demo experience.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/events` | Raw telemetry events (filterable) |
| GET | `/features` | Feature windows (filterable) |
| GET | `/alerts` | Anomaly alerts (filterable) |
| GET | `/incidents` | Correlated incidents (filterable) |
| GET | `/incidents/{id}` | Single incident with MITRE + threat intel |
| PATCH | `/incidents/{id}/status` | Update incident status |
| GET | `/hosts/{id}` | Host baseline vs current |
| GET | `/metrics/summary` | System-wide metrics (JSON) |
| GET | `/metrics` | Prometheus metrics (text format) |
| POST | `/auth/token` | JWT authentication |
| POST | `/admin/train` | Force-train the model now |
| POST | `/admin/simulate` | Inject synthetic attack scenario |
| GET | `/health` | API health + telemetry status |
| WS | `/ws/events` | Real-time alert/incident WebSocket stream |

## Dashboard Pages

- **Overview** — KPI cards, anomaly trend chart, live WebSocket feed, recent alerts table
- **Incidents** — incident list with severity/MITRE badges, LLM-generated narrative, suggested actions
- **ATT&CK Matrix** — interactive heatmap of MITRE tactics x techniques with detection counts
- **Network** — outbound connection charts, traffic volume, top connected processes
- **Telemetry Explorer** — raw event and feature window tables with column filters

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Configuration (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `IDS_HOST_ID` | hostname | Host identifier |
| `IDS_DB_PATH` | `data/ids.db` | SQLite database path |
| `IDS_WINDOW_SECONDS` | `30` | Feature window duration |
| `IDS_MODEL_PATH` | `data/isolation_forest.pkl` | Model artifact path |
| `IDS_MIN_TRAINING_SAMPLES` | `20` | Windows before model trains |
| `IDS_CONTAMINATION` | `0.05` | Isolation Forest contamination |
| `IDS_API_HOST` | `0.0.0.0` | API bind address |
| `IDS_API_PORT` | `8000` | API port |
| `IDS_API_KEY` | *(empty = disabled)* | Optional API key for auth |
| `IDS_RETRAIN_HOURS` | `24` | Hours between automatic retrains |
| `IDS_OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `IDS_OLLAMA_MODEL` | `llama3` | LLM model name |
| `IDS_JWT_SECRET` | `change-me-in-production` | JWT signing secret |
| `IDS_JWT_EXPIRE_MINUTES` | `60` | JWT token TTL |
| `IDS_ADMIN_USERNAME` | `admin` | Auth username |
| `IDS_ADMIN_PASSWORD` | `admin` | Auth password |
| `IDS_ABUSEIPDB_KEY` | *(empty = disabled)* | AbuseIPDB API key |

## Stack

- **Python** — core language
- **FastAPI** — typed backend API with WebSocket support
- **Next.js 14** — React/TypeScript dashboard (App Router)
- **Tailwind CSS** — utility-first styling
- **scikit-learn** — Isolation Forest anomaly detection
- **SHAP** — TreeExplainer for ML feature attribution
- **Ollama** — local LLM for analyst narrative generation
- **SQLite + Alembic** — event storage + schema migrations
- **psutil** — host and network telemetry
- **Prometheus** — metrics exposition
- **Docker Compose** — containerized deployment
- **GitHub Actions** — CI pipeline (lint + test + build)
