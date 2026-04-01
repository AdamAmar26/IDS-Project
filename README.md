# Behavior-Based Intrusion Detection & Alert Intelligence Platform

A Windows-first, single-host behavior-based IDS that collects live telemetry,
engineers windowed features, detects anomalies with Isolation Forest, correlates
alerts into incidents, explains them deterministically, and exposes everything
through a FastAPI API and Dash dashboard.

## Architecture

```
Telemetry Collector  -->  SQLite
        |
  Feature Pipeline
        |
  Isolation Forest  -->  Alerts
        |
  Correlation Engine  -->  Incidents
        |
  Explanation Engine  -->  Summaries
        |
  FastAPI  <-->  Dash Dashboard
```

## Quick Start (native Windows)

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt

cd ../dashboard
pip install -r requirements.txt
```

### 2. Start the API server

For full telemetry (including Security event log for login tracking), run
as **Administrator**:

```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Without admin rights the system still works but falls back to
`psutil.users()` for login detection and cannot capture failed logins or
UAC elevations.

The API starts, initializes the SQLite database, and begins the telemetry
collection loop. During the first ~25 minutes (50 x 30-second windows) the
system collects baseline behavior. After that the Isolation Forest model is
trained and anomaly detection activates.

### 3. Start the dashboard

In a separate terminal:

```bash
cd dashboard
python app.py
```

Open **http://localhost:8050** to view the dashboard.

## Quick Start (Docker)

```bash
docker compose up --build
```

- API: http://localhost:8000
- Dashboard: http://localhost:8050

> **Important:** Docker containers run on Linux and cannot access
> Windows Security event logs or collect accurate Windows host telemetry.
> Use the native Python startup path above for the real demo experience.
> Docker packaging is provided for portability and CI, not as the primary
> runtime for Windows telemetry collection.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/events` | Raw telemetry events (filterable) |
| GET | `/features` | Feature windows (filterable) |
| GET | `/alerts` | Anomaly alerts (filterable) |
| GET | `/incidents` | Correlated incidents (filterable) |
| GET | `/incidents/{id}` | Single incident detail |
| PATCH | `/incidents/{id}/status` | Update incident status |
| GET | `/hosts/{id}` | Host baseline vs current |
| GET | `/metrics` | System-wide metrics |
| POST | `/admin/train` | Force-train the model now |
| GET | `/health` | API health + telemetry status |

## Dashboard Pages

- **Overview** — metric cards, anomaly trend chart, recent alerts table
- **Host Detail** — baseline vs current feature comparison, feature window timeline
- **Incidents** — incident list with severity badges, detail panel with explanation
- **Telemetry Explorer** — raw event and feature window tables with filters

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
| `IDS_MIN_TRAINING_SAMPLES` | `50` | Windows before model trains |
| `IDS_CONTAMINATION` | `0.05` | Isolation Forest contamination |
| `IDS_API_HOST` | `0.0.0.0` | API bind address |
| `IDS_API_PORT` | `8000` | API port |
| `IDS_API_URL` | `http://localhost:8000` | Dashboard → API URL |
| `IDS_API_KEY` | *(empty = disabled)* | Optional API key for auth |
| `IDS_RETRAIN_HOURS` | `24` | Hours between automatic retrains |

## Stack

- **Python** — core language
- **FastAPI** — typed backend API
- **Dash** — interactive dashboard
- **scikit-learn** — Isolation Forest anomaly detection
- **SQLite** — event, feature, alert, and incident storage
- **psutil** — host and network telemetry
- **Docker** — containerized deployment
