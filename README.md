# Behavior-Based Intrusion Detection & Alert Intelligence Platform

A Windows-first, single-host behavior-based IDS that collects live telemetry,
engineers windowed features (17-dimensional), detects anomalies with Isolation
Forest + SHAP explainability, maps detections to MITRE ATT&CK (20+
techniques), enriches with threat intelligence (local + AbuseIPDB + auto-updated
feeds), generates analyst narratives via Ollama LLM, supports analyst feedback
loops, and exposes everything through a hardened FastAPI API (REST + WebSocket)
and Next.js dashboard.

## Architecture

```
Telemetry Collector  -->  SQLite (Alembic migrations, retention policy)
        |
  Feature Pipeline (17 features incl. privileged processes, parent-child, DNS)
        |
  Isolation Forest + SHAP Explainer  -->  Alerts + Analyst Verdict Feedback
        |
  Threat Intel Enricher (local + AbuseIPDB + auto-updated feeds)
        |
  MITRE ATT&CK Mapper (20+ techniques, kill-chain tracking)
        |
  Correlation Engine (10 rules)  -->  Incidents + Notes
        |
  Ollama LLM Explainer (fallback: templates)  -->  Narratives
        |
  FastAPI (REST + WebSocket + JWT + Rate Limiting + Prometheus)
        |
  Next.js 14 + TypeScript + Tailwind Dashboard
```

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

### 4. (Optional) Start Ollama for LLM explanations

```bash
ollama serve
ollama pull llama3
```

If Ollama is not running, the system falls back to deterministic template
explanations automatically.

### 5. Start the API server

For full telemetry (including Security event log for login tracking), run
as **Administrator**:

```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 6. Start the dashboard

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
| GET | `/events` | Raw telemetry events (paginated, filterable) |
| GET | `/features` | Feature windows (paginated, filterable) |
| GET | `/alerts` | Anomaly alerts (paginated, filterable by verdict) |
| PATCH | `/alerts/{id}/verdict` | Mark alert as true/false positive |
| GET | `/incidents` | Correlated incidents (paginated, filterable) |
| GET | `/incidents/{id}` | Single incident with MITRE + threat intel + kill chain |
| PATCH | `/incidents/{id}/status` | Update incident status |
| GET | `/incidents/{id}/notes` | List analyst notes for an incident |
| POST | `/incidents/{id}/notes` | Add analyst note to an incident |
| GET | `/incidents/{id}/report` | Export incident report (JSON or CSV) |
| GET | `/hosts/{id}` | Host baseline vs current |
| GET | `/metrics/summary` | System-wide metrics (JSON) |
| GET | `/metrics` | Prometheus metrics (text format) |
| POST | `/auth/token` | JWT authentication (rate-limited) |
| POST | `/admin/train` | Force-train the model now |
| POST | `/admin/simulate` | Inject synthetic attack scenario (6 scenarios) |
| GET | `/health` | API health + telemetry status |
| WS | `/ws/events` | Real-time alert/incident WebSocket stream |

## Attack Simulation Scenarios

| Scenario | Description |
|----------|-------------|
| `brute_force_portscan` | Failed logins + port scanning + suspicious processes |
| `data_exfiltration` | High outbound bytes + archive tools + external connections |
| `lateral_movement` | Internal host scanning + privileged tools + credential access |
| `ransomware_staging` | Shadow copy deletion + file encryption + C2 callback |
| `c2_beaconing` | Periodic outbound connections + DNS queries + low-and-slow traffic |
| `privilege_escalation` | Credential dumping + LSASS access + token impersonation |

## Feature Vector (17 dimensions)

| Feature | Description |
|---------|-------------|
| `failed_login_count` | Failed authentication attempts |
| `successful_login_count` | Successful authentication events |
| `unique_dest_ips` | Unique outbound destination IPs |
| `unique_dest_ports` | Unique outbound destination ports |
| `outbound_conn_count` | Total outbound connections |
| `bytes_sent` / `bytes_received` | Network byte counters |
| `avg_process_cpu` | Average CPU across processes |
| `new_process_count` | Newly spawned processes |
| `inbound_outbound_ratio` | Bytes received / sent ratio |
| `unusual_hour_flag` | Activity outside 06:00-22:00 |
| `privileged_process_count` | net.exe, sc.exe, reg.exe, whoami, etc. |
| `parent_child_anomaly_score` | Suspicious parent-child process chains |
| `dns_query_count` | DNS queries (C2 beaconing indicator) |
| `unique_parent_processes` | Living-off-the-land breadth |
| `memory_usage_spike` | Process injection indicator |
| `sensitive_file_access_count` | SAM/LSASS/credential store access |

## Correlation Rules (10 rules)

| Rule | Triggers |
|------|----------|
| `high_anomaly_score` | Anomaly score > 0.3 |
| `repeated_anomaly_15min` | 2+ anomalies in 15-minute window |
| `unusual_port_spread` | > 10 unique destination ports |
| `login_plus_process_anomaly` | Failed logins + high process count |
| `consecutive_low_confidence_escalation` | 3+ consecutive anomalies |
| `powershell_encoded_command` | PowerShell + elevated process count |
| `credential_access_indicator` | Sensitive file access detected |
| `lateral_movement_indicator` | Many dest IPs + privileged tools |
| `c2_beaconing` | High DNS + outbound connections |
| `off_hours_escalation` | Off-hours + anomaly score > 0.3 |

## Dashboard Pages

- **Overview** — KPI cards, anomaly trend chart, live WebSocket feed, recent alerts table
- **Incidents** — incident list with severity/MITRE badges, kill-chain phase, LLM-generated narrative, suggested actions, analyst notes
- **ATT&CK Matrix** — interactive heatmap of MITRE tactics x techniques with detection counts
- **Network** — outbound connection charts, traffic volume, top connected processes
- **Telemetry Explorer** — raw event and feature window tables with column filters

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Configuration (environment variables)

See `.env.example` for a complete list with descriptions. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `IDS_JWT_SECRET` | *(must set)* | JWT signing secret (startup warns if default) |
| `IDS_ADMIN_PASSWORD` | *(must set)* | Auth password (startup warns if default) |
| `IDS_HOST_ID` | hostname | Host identifier |
| `IDS_DB_PATH` | `data/ids.db` | SQLite database path |
| `IDS_WINDOW_SECONDS` | `30` | Feature window duration |
| `IDS_MODEL_PATH` | `data/isolation_forest.joblib` | Model artifact path |
| `IDS_MIN_TRAINING_SAMPLES` | `20` | Windows before model trains |
| `IDS_CONTAMINATION` | `0.05` | Isolation Forest contamination |
| `IDS_CORS_ORIGINS` | `http://localhost:3000` | Comma-separated CORS allowlist |
| `IDS_AUTH_RATE_LIMIT` | `10/minute` | Login endpoint rate limit |
| `IDS_RETRAIN_HOURS` | `24` | Hours between automatic retrains |
| `IDS_OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `IDS_OLLAMA_MODEL` | `llama3` | LLM model name |
| `IDS_ABUSEIPDB_KEY` | *(empty = disabled)* | AbuseIPDB API key |
| `IDS_RAW_EVENT_RETENTION_DAYS` | `7` | Auto-prune raw events after N days |
| `IDS_FEATURE_WINDOW_RETENTION_DAYS` | `30` | Auto-prune feature windows after N days |

## Security Hardening

- JWT secrets and admin passwords validated at startup (critical-level warnings for insecure defaults)
- CORS restricted to explicit origin allowlist (no wildcard)
- Rate limiting on `/auth/token` (configurable per-IP limit)
- Model persistence uses `joblib` + HMAC integrity verification (prevents tampered model injection)
- Structured JSON logging with request-ID correlation
- Automatic data retention policies to bound storage growth

## Stack

- **Python 3.11+** — core language
- **FastAPI** — typed backend API with WebSocket support
- **Next.js 14** — React/TypeScript dashboard (App Router)
- **Tailwind CSS** — utility-first styling
- **scikit-learn** — Isolation Forest anomaly detection
- **SHAP** — TreeExplainer for ML feature attribution
- **Ollama** — local LLM for analyst narrative generation
- **SQLite + Alembic** — event storage + schema migrations
- **psutil** — host and network telemetry
- **Prometheus** — metrics exposition
- **slowapi** — rate limiting middleware
- **python-json-logger** — structured JSON logging
- **joblib** — secure model serialization
- **Docker Compose** — containerized deployment
- **GitHub Actions** — CI pipeline (lint + test + build)
