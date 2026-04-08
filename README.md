# Behavior-Based Intrusion Detection & Alert Intelligence Platform

A Windows-first, single-host behavior-based IDS that collects live telemetry,
engineers windowed features (17-dimensional), detects anomalies with Isolation
Forest + SHAP explainability, maps detections to MITRE ATT&CK (20+
techniques), enriches with threat intelligence (local + AbuseIPDB + auto-updated
feeds), generates analyst narratives via Ollama LLM, and exposes everything
through a hardened FastAPI API (REST + WebSocket) and a professional Next.js
dashboard with collapsible sidebar navigation, AI-powered threat briefings,
dark/light theme, and real-time streaming.

## Architecture

```
Telemetry Collector  -->  SQLite (Alembic migrations, retention policy)
        |
  Feature Pipeline (17 features incl. privileged processes, parent-child, DNS)
        |
  Isolation Forest + SHAP Explainer  -->  Alerts + Analyst Verdict Feedback
        |
  Threat Intel Enricher (local + AbuseIPDB + auto-updated feeds, hot-reload)
        |
  MITRE ATT&CK Mapper (20+ techniques, kill-chain tracking)
        |
  Correlation Engine (10+ rules, YAML extensible)  -->  Incidents
        |
  Ollama LLM Explainer (fallback: templates)  -->  AI Threat Briefings
        |
  FastAPI (REST + WebSocket + JWT + API Key + Rate Limiting + Prometheus)
        |
  Next.js 14 + TypeScript + Tailwind + React Query Dashboard
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
| POST | `/auth/token` | JWT authentication (rate-limited) |
| GET | `/health` | API health + telemetry status |
| GET | `/summary` | AI-powered threat briefing (LLM or template) |
| GET | `/events` | Raw telemetry events (paginated, filterable) |
| GET | `/features` | Feature windows (paginated, filterable) |
| GET | `/alerts` | Anomaly alerts (paginated, filterable by verdict) |
| PATCH | `/alerts/{id}/verdict` | Mark alert as true/false positive |
| GET | `/incidents` | Correlated incidents (paginated, filterable) |
| GET | `/incidents/{id}` | Single incident with MITRE + threat intel + kill chain |
| PATCH | `/incidents/{id}/status` | Update incident status (validated values) |
| GET | `/incidents/{id}/notes` | List analyst notes for an incident |
| POST | `/incidents/{id}/notes` | Add analyst note to an incident |
| GET | `/incidents/{id}/report` | Export incident report (JSON or CSV) |
| GET | `/incidents/{id}/timeline` | Incident timeline with correlated events |
| GET | `/hosts/{id}` | Host baseline vs current |
| GET | `/fleet/summary` | All hosts with alert/incident counts and risk scores |
| GET | `/metrics/summary` | System-wide metrics (JSON) |
| GET | `/metrics` | Prometheus metrics (text format) |
| GET | `/hunts` | List saved threat hunts |
| POST | `/hunts` | Create a saved hunt |
| POST | `/hunts/{id}/run` | Execute hunt against events and alerts |
| GET | `/audit` | Audit log (filterable by actor, action, date range) |
| GET | `/reports/weekly` | Weekly security report (JSON or HTML) |
| POST | `/reports/weekly/email` | Email the weekly report |
| POST | `/soar/action` | Execute SOAR action (IP validation, confirmation required) |
| GET | `/settings/notifications` | Notification channel status |
| POST | `/settings/notifications/test` | Test notification channels |
| POST | `/admin/train` | Force-train the model now |
| POST | `/admin/reload-rules` | Hot-reload correlation rules from YAML |
| POST | `/admin/simulate` | Inject synthetic attack scenario (6 scenarios) |
| WS | `/ws/events` | Real-time alert/incident stream (JWT authenticated) |

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

## Correlation Rules (10+ rules)

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

Additional rules can be added via `config/correlation_rules.yaml` and
hot-reloaded at runtime through `POST /admin/reload-rules`.

## Dashboard

The frontend features a collapsible sidebar with three navigation tiers
(Primary, Investigate, Operate), dark/light theme toggle, and responsive
layout with loading skeletons, empty states, and toast notifications.

### Pages

| Page | Description |
|------|-------------|
| **Overview** | AI threat briefing card, KPI metrics, anomaly score trend chart with gradient, live WebSocket event feed |
| **Alerts** | Filterable alert table with anomaly scores, severity badges, and pagination |
| **Incidents** | Incident list with severity/MITRE badges, status management, LLM narrative, suggested actions |
| **Telemetry** | Raw event and feature window explorer with column filters and pagination |
| **Hunt** | Server-side threat hunting — save, execute, and review hunt results against historical data |
| **Reports** | Weekly security report with severity pie chart, MITRE technique bar chart, JSON/HTML/email export |
| **Audit** | Activity log with actor/action filters, date range, CSV export, and pagination |
| **Fleet** | Per-host summary cards with alert counts, risk scores, and last-seen timestamps |
| **SOAR** | Guarded response actions with IP validation, dry-run preview, confirmation dialog, execution history |
| **Settings** | Authentication, notification channel status, correlation rule reload |

### Shared UI Components

The dashboard includes a reusable component library:
Button, Input, Select, Table, Dialog, Toast, Skeleton, EmptyState, StatusBadge, PageHeader.

## Teams-first Notifications

1. Create a Microsoft Teams Incoming Webhook in your channel.
2. Set `IDS_TEAMS_WEBHOOK_URL` in `.env`.
3. Start backend + frontend and authenticate in Settings.
4. Use `POST /settings/notifications/test` or trigger `/admin/simulate`.

Optional channels:
- `IDS_GENERIC_WEBHOOK_URL` for generic JSON webhooks
- SMTP (`IDS_SMTP_HOST`, `IDS_ALERT_EMAIL_TO`, etc.) for email alerts

## Running Tests

```bash
pip install pytest httpx
pytest tests/ -v
```

Test suites cover the correlation engine, API endpoints (with auth), WebSocket
authentication, SOAR input validation, hunt execution, and audit logging.

## Configuration (environment variables)

See `.env.example` for a complete list with descriptions. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `IDS_JWT_SECRET` | *(must set)* | JWT signing secret (startup warns if default) |
| `IDS_ADMIN_PASSWORD` | *(must set)* | Auth password (startup warns if default) |
| `IDS_ADMIN_USERNAME` | `admin` | Auth username |
| `IDS_API_KEY` | *(empty)* | Legacy API key auth (optional) |
| `IDS_HOST_ID` | hostname | Host identifier |
| `IDS_DB_PATH` | `data/ids.db` | SQLite database path |
| `IDS_WINDOW_SECONDS` | `30` | Feature window duration |
| `IDS_MODEL_PATH` | `data/isolation_forest.joblib` | Model artifact path |
| `IDS_MIN_TRAINING_SAMPLES` | `20` | Windows before model trains |
| `IDS_CONTAMINATION` | `0.05` | Isolation Forest contamination |
| `IDS_CORS_ORIGINS` | `http://localhost:3000,...` | Comma-separated CORS allowlist |
| `IDS_AUTH_RATE_LIMIT` | `10/minute` | Login endpoint rate limit |
| `IDS_TEAMS_WEBHOOK_URL` | *(empty = disabled)* | Teams Incoming Webhook URL |
| `IDS_GENERIC_WEBHOOK_URL` | *(empty = disabled)* | Generic incident webhook URL |
| `IDS_NOTIFY_ON_SEVERITY_INCREASE` | `false` | Notify when open incident severity changes |
| `IDS_RETRAIN_HOURS` | `24` | Hours between automatic retrains |
| `IDS_CORRELATION_RULES_PATH` | `config/correlation_rules.yaml` | YAML rules extension path |
| `IDS_SOAR_ENABLED` | `false` | Enable SOAR action endpoints |
| `IDS_OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `IDS_OLLAMA_MODEL` | `llama3` | LLM model name |
| `IDS_ABUSEIPDB_KEY` | *(empty = disabled)* | AbuseIPDB API key |
| `IDS_RAW_EVENT_RETENTION_DAYS` | `7` | Auto-prune raw events after N days |
| `IDS_FEATURE_WINDOW_RETENTION_DAYS` | `30` | Auto-prune feature windows after N days |
| `IDS_JWT_EXPIRE_MINUTES` | `60` | JWT token lifetime |

### Frontend environment variables

Set in `frontend/.env.local` (gitignored):

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_API_URL` | Backend API base URL (default: `http://localhost:8000`) |
| `NEXT_PUBLIC_WS_URL` | WebSocket URL (default: `ws://localhost:8000/ws/events`) |
| `NEXT_PUBLIC_IDS_USERNAME` | Auto-login username for development |
| `NEXT_PUBLIC_IDS_PASSWORD` | Auto-login password for development |

## Security Hardening

- **Default-deny authentication** — all API routes require JWT or API key (except `/health`, `/docs`, `/auth`, `/metrics`)
- **WebSocket authentication** — JWT token required via query parameter
- **CORS with auth-aware error responses** — CORS headers included on 401/403 rejections to prevent browser masking
- **Input validation** — SOAR targets validated as IPs; incident status changes restricted to allowed values; live SOAR actions require explicit confirmation
- **JWT secrets and admin passwords validated at startup** (critical-level warnings for insecure defaults)
- **CORS restricted to explicit origin allowlist** (no wildcard)
- **Rate limiting on `/auth/token`** (configurable per-IP limit)
- **Model integrity** — `joblib` + HMAC verification prevents tampered model injection
- **Threat intel hot-reload** — blocklist file changes detected and reloaded without restart
- **Structured JSON logging** with request-ID correlation
- **Automatic data retention** policies to bound storage growth
- **Audit logging** — authentication, status changes, hunt execution, rule reloads, and report exports are logged

## Stack

- **Python 3.11+** — core language
- **FastAPI** — typed backend API with WebSocket support
- **Next.js 14** — React/TypeScript dashboard (App Router)
- **Tailwind CSS** — utility-first styling with dark/light theme
- **@tanstack/react-query** — server-state management and caching
- **Recharts** — data visualization (trend charts, pie charts, bar charts)
- **Lucide React** — icon library
- **scikit-learn** — Isolation Forest anomaly detection
- **SHAP** — TreeExplainer for ML feature attribution
- **Ollama** — local LLM for analyst narrative generation and threat briefings
- **SQLite + Alembic** — event storage + schema migrations
- **psutil** — host and network telemetry
- **Prometheus** — metrics exposition (alerts, incidents, model state)
- **slowapi** — rate limiting middleware
- **python-jose** — JWT encoding/decoding
- **python-json-logger** — structured JSON logging
- **joblib** — secure model serialization
- **Docker Compose** — containerized deployment
- **GitHub Actions** — CI pipeline (lint + test + build)

## Backup and Restore (Windows)

Use `scripts/backup-ids.ps1` to snapshot:
- SQLite DB (`IDS_DB_PATH`)
- Model file (`IDS_MODEL_PATH`)
- `.env`

Restore by stopping the API and copying these files back into place.
