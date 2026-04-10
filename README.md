# Behavior-Based Intrusion Detection System (IDS)

## Overview

This project is a **behavior-based intrusion detection system** that monitors host and network activity to identify suspicious behavior without relying on static signatures.

The system uses **anomaly detection (Isolation Forest)** combined with **event correlation over time** to detect potential security incidents and generate **explainable alerts**.

It is designed as a modular platform combining **systems monitoring, data processing, and machine learning** with a real-time dashboard for analysis.

---

## Key Features

* Real-time host telemetry collection (CPU, processes, network activity)
* Feature engineering over time windows
* Anomaly detection using Isolation Forest
* Event correlation to group anomalies into incidents
* Explainable alerts with human-readable summaries
* REST API backend (FastAPI)
* Interactive dashboard (Next.js)

---

## Architecture

The system follows a layered architecture:

Telemetry → Feature Engineering → Anomaly Detection → Correlation → Explanation → Dashboard

### Components

* **Telemetry Collector**

  * Collects host activity (processes, CPU, connections, login events)

* **Feature Pipeline**

  * Aggregates raw events into structured features over time windows

* **Detection Engine**

  * Uses Isolation Forest to identify anomalous behavior

* **Correlation Layer**

  * Groups multiple anomalies into higher-level incidents

* **Explanation Layer**

  * Generates readable summaries explaining why alerts were triggered

* **Dashboard**

  * Displays alerts, incidents, and system activity

---

## Example Detection Scenario

Simulated a port scanning attack:

* High number of outbound connections in a short time window
* Large number of unique destination ports

The anomaly detection model flagged the behavior as abnormal.

The correlation layer grouped related anomalies and generated an incident:

> Host generated 52 connections to 18 different ports within 60 seconds, significantly exceeding its baseline behavior.

Severity: High

---

## Data Pipeline

The system processes data in several stages:

1. **Collection**

   * Host and network telemetry is collected in real time

2. **Processing**

   * Raw logs are parsed and cleaned

3. **Feature Engineering**

   * Data is aggregated into time windows (e.g., 60 seconds)
   * Example features:

     * number of connections
     * unique destination ports
     * failed login attempts
     * CPU usage

4. **Detection**

   * Isolation Forest assigns anomaly scores to each time window

5. **Post-Processing**

   * Alerts are generated and correlated into incidents

---

## Technology Stack

* **Backend:** Python, FastAPI
* **Machine Learning:** scikit-learn (Isolation Forest)
* **Data Processing:** pandas, numpy
* **Frontend:** Next.js
* **Storage:** SQLite
* **Deployment:** Docker

---

## API Endpoints (examples)

* `GET /alerts` — list detected anomalies
* `GET /incidents` — list correlated incidents
* `POST /events` — ingest telemetry data
* `GET /hosts/{id}` — host-specific insights

---

## Evaluation

The system was tested using simulated attack scenarios:

* Port scanning behavior
* Brute-force login attempts

Metrics (approximate):

* Detection rate: high for strong anomalies (e.g., port scans)
* False positives: moderate, reduced through correlation layer

---

## Implemented vs Planned

### Implemented

* Telemetry collection (host metrics and activity)
* Feature engineering pipeline
* Isolation Forest anomaly detection
* Alert generation system
* Basic correlation logic
* FastAPI backend
* Next.js dashboard

### Planned Improvements

* Advanced MITRE ATT&CK mapping
* External threat intelligence enrichment
* Automated response actions (SOAR)
* Advanced explainability (feature importance, LLM refinement)
* Multi-host monitoring

---

## Security Note

This project uses a simplified authentication system for demonstration purposes.
It is not intended as a production-ready authentication or security solution.

---

## Quick Start (native Windows)

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env — set IDS_JWT_SECRET and IDS_ADMIN_PASSWORD to strong values
```

### 2. Install backend dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 3. Install frontend dependencies

```bash
cd frontend
npm install
```

### 4. Configure frontend auto-login (development only)

Create `frontend/.env.local` for automatic JWT authentication during development:

```bash
NEXT_PUBLIC_IDS_USERNAME=admin
NEXT_PUBLIC_IDS_PASSWORD=admin
```

This file is gitignored and never committed. Without it, you must log in
manually via the Settings page or the `/auth/token` endpoint.

### 5. (Optional) Start Ollama for LLM explanations

```bash
ollama serve
ollama pull llama3
```

If Ollama is not running, the system falls back to deterministic template
explanations and a data-driven threat briefing automatically.

### 6. Start the API server

For full telemetry (including Security event log for login tracking), run
as **Administrator**:

```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 7. Start the dashboard

```bash
cd frontend
npm run dev
```

Open **http://localhost:3000** to view the dashboard.

---

## Future Work

This project will evolve toward a more advanced detection platform with:

* multi-host distributed monitoring
* improved anomaly detection models
* richer incident analysis
* enhanced dashboard capabilities

---

## Author

Adam Amar
Computer Science

