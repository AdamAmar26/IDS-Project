import logging
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.api.routes import alerts, events, features, hosts, incidents, metrics
from app.api.routes.prometheus import router as prom_router
from app.api.routes.ws import manager as ws_manager
from app.api.routes.ws import router as ws_router
from app.config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    API_KEY,
    AUTH_RATE_LIMIT,
    CORS_ORIGINS,
    JWT_ALGORITHM,
    JWT_EXPIRE_MINUTES,
    JWT_SECRET,
    MIN_TRAINING_SAMPLES,
    validate_security_defaults,
)
from app.db.session import init_db
from app.services.orchestrator import get_orchestrator

try:
    from pythonjsonlogger import jsonlogger

    handler = logging.StreamHandler()
    handler.setFormatter(
        jsonlogger.JsonFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            rename_fields={"asctime": "timestamp", "levelname": "level"},
        )
    )
    logging.root.handlers = [handler]
    logging.root.setLevel(logging.INFO)
except ImportError:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

validate_security_defaults()

limiter = Limiter(key_func=get_remote_address)

orchestrator = get_orchestrator()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    orchestrator.register_broadcast(ws_manager.enqueue)
    await ws_manager.start_broadcaster()
    orchestrator.start()
    yield
    orchestrator.stop()


app = FastAPI(
    title="IDS - Behavior-Based Intrusion Detection",
    version="3.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "X-API-Key", "Content-Type"],
)


# ---- Request-ID middleware for structured log correlation ----


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ---- Authentication middleware (supports both legacy API key and JWT) ----

EXEMPT_PREFIXES = ("/health", "/docs", "/openapi.json", "/redoc", "/auth", "/ws")


@app.middleware("http")
async def check_auth(request: Request, call_next):
    if any(request.url.path.startswith(p) for p in EXEMPT_PREFIXES):
        return await call_next(request)

    bearer = request.headers.get("Authorization", "")
    if bearer.startswith("Bearer "):
        token = bearer[7:]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return await call_next(request)
        except JWTError:
            return JSONResponse(status_code=401, content={"detail": "Invalid JWT token"})

    if API_KEY:
        key = request.headers.get("X-API-Key", "")
        if key == API_KEY:
            return await call_next(request)
        return JSONResponse(status_code=403, content={"detail": "Invalid or missing API key"})

    return await call_next(request)


# ---- JWT token endpoint ----


class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@app.post("/auth/token", response_model=TokenResponse, tags=["Auth"])
@limiter.limit(AUTH_RATE_LIMIT)
def login(request: Request, body: TokenRequest):
    if body.username != ADMIN_USERNAME or body.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    expire = datetime.now(UTC) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": body.username, "exp": expire}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return TokenResponse(access_token=token, expires_in=JWT_EXPIRE_MINUTES * 60)


# ---- Routers ----

app.include_router(events.router, prefix="/events", tags=["Events"])
app.include_router(features.router, prefix="/features", tags=["Features"])
app.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
app.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
app.include_router(hosts.router, prefix="/hosts", tags=["Hosts"])
app.include_router(metrics.router, prefix="/metrics/summary", tags=["Metrics"])
app.include_router(ws_router, tags=["WebSocket"])
app.include_router(prom_router, tags=["Prometheus"])


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_trained": orchestrator.detector.is_trained,
        "training_samples": len(orchestrator.detector.training_data),
        "min_training_samples": MIN_TRAINING_SAMPLES,
        "security_log_available": orchestrator.collector.security_log_available,
    }


@app.post("/admin/train")
def force_train():
    samples = len(orchestrator.detector.training_data)
    if samples < 2:
        return JSONResponse(
            status_code=400,
            content={"detail": f"Need at least 2 samples, have {samples}"},
        )
    ok = orchestrator.force_train()
    return {
        "trained": ok,
        "samples": len(orchestrator.detector.training_data),
    }


@app.post("/admin/simulate", tags=["Admin"])
def simulate_attack(scenario: str = "brute_force_portscan"):
    """Inject synthetic attack events for live demo purposes.

    Supported scenarios: brute_force_portscan, data_exfiltration,
    lateral_movement, ransomware_staging, c2_beaconing, privilege_escalation
    """
    import random

    from app.config import HOST_ID
    from app.db.models import RawEvent
    from app.db.session import SessionLocal

    now = datetime.now(UTC)
    events: list[dict] = []

    if scenario == "brute_force_portscan":
        for i in range(8):
            events.append({
                "host_id": HOST_ID,
                "type": "login_failure",
                "timestamp": (now - timedelta(seconds=random.randint(0, 25))).isoformat(),
                "user": f"admin{i}",
                "source_ip": f"185.220.101.{random.randint(1, 5)}",
            })
        events.append({
            "host_id": HOST_ID,
            "type": "login_success",
            "timestamp": now.isoformat(),
            "user": "admin",
            "source_ip": "185.220.101.1",
        })
        for port in random.sample(range(20, 10000), 25):
            events.append({
                "host_id": HOST_ID,
                "type": "connection",
                "timestamp": now.isoformat(),
                "remote_ip": f"45.148.10.{random.randint(1, 3)}",
                "remote_port": port,
                "process_name": "svchost.exe",
            })
        for _ in range(6):
            events.append({
                "host_id": HOST_ID,
                "type": "new_process",
                "timestamp": now.isoformat(),
                "name": random.choice(["cmd.exe", "powershell.exe", "wmic.exe", "net.exe"]),
                "pid": random.randint(5000, 9999),
                "cpu_percent": random.uniform(15.0, 85.0),
            })

    elif scenario == "data_exfiltration":
        for _ in range(3):
            events.append({
                "host_id": HOST_ID,
                "type": "connection",
                "timestamp": now.isoformat(),
                "remote_ip": f"93.174.95.{random.randint(100, 110)}",
                "remote_port": random.choice([443, 8443, 4444]),
                "process_name": "chrome.exe",
            })
        events.append({
            "host_id": HOST_ID,
            "type": "net_io",
            "timestamp": now.isoformat(),
            "bytes_sent": random.randint(50_000_000, 200_000_000),
            "bytes_received": random.randint(1000, 5000),
        })
        for _ in range(4):
            events.append({
                "host_id": HOST_ID,
                "type": "new_process",
                "timestamp": now.isoformat(),
                "name": random.choice(["7z.exe", "rar.exe", "curl.exe"]),
                "pid": random.randint(5000, 9999),
                "cpu_percent": random.uniform(20.0, 60.0),
            })

    elif scenario == "lateral_movement":
        target_hosts = [f"10.0.{random.randint(1, 5)}.{random.randint(10, 250)}" for _ in range(8)]
        for ip in target_hosts:
            events.append({
                "host_id": HOST_ID,
                "type": "connection",
                "timestamp": now.isoformat(),
                "remote_ip": ip,
                "remote_port": random.choice([445, 3389, 5985, 22]),
                "process_name": random.choice(["svchost.exe", "lsass.exe"]),
            })
        for _ in range(3):
            events.append({
                "host_id": HOST_ID,
                "type": "new_process",
                "timestamp": now.isoformat(),
                "name": random.choice(["net.exe", "wmic.exe", "psexec.exe"]),
                "parent_name": "cmd.exe",
                "pid": random.randint(5000, 9999),
                "cpu_percent": random.uniform(5.0, 30.0),
            })
        events.append({
            "host_id": HOST_ID,
            "type": "login_success",
            "timestamp": now.isoformat(),
            "user": "admin",
            "source_ip": target_hosts[0],
        })
        events.append({
            "host_id": HOST_ID,
            "type": "file_access",
            "timestamp": now.isoformat(),
            "path": r"C:\Windows\System32\config\SAM",
            "process_name": "lsass.exe",
        })

    elif scenario == "ransomware_staging":
        for _ in range(5):
            events.append({
                "host_id": HOST_ID,
                "type": "new_process",
                "timestamp": now.isoformat(),
                "name": random.choice(["vssadmin.exe", "wbadmin.exe", "bcdedit.exe"]),
                "parent_name": "cmd.exe",
                "pid": random.randint(5000, 9999),
                "cpu_percent": random.uniform(30.0, 90.0),
                "memory_percent": random.uniform(40.0, 85.0),
            })
        events.append({
            "host_id": HOST_ID,
            "type": "new_process",
            "timestamp": now.isoformat(),
            "name": "powershell.exe",
            "parent_name": "explorer.exe",
            "pid": random.randint(5000, 9999),
            "cpu_percent": random.uniform(50.0, 95.0),
            "memory_percent": random.uniform(60.0, 95.0),
        })
        for ext in ["docx", "xlsx", "pdf", "jpg", "sql"]:
            events.append({
                "host_id": HOST_ID,
                "type": "file_access",
                "timestamp": now.isoformat(),
                "path": f"C:\\Users\\admin\\Documents\\report.{ext}.encrypted",
                "process_name": "svchost.exe",
            })
        events.append({
            "host_id": HOST_ID,
            "type": "connection",
            "timestamp": now.isoformat(),
            "remote_ip": f"185.141.{random.randint(60, 63)}.{random.randint(1, 254)}",
            "remote_port": 443,
            "process_name": "svchost.exe",
        })

    elif scenario == "c2_beaconing":
        c2_ip = f"198.51.100.{random.randint(1, 254)}"
        for i in range(20):
            events.append({
                "host_id": HOST_ID,
                "type": "connection",
                "timestamp": (now - timedelta(seconds=i * 30)).isoformat(),
                "remote_ip": c2_ip,
                "remote_port": random.choice([443, 8080, 8443]),
                "process_name": "svchost.exe",
            })
        for i in range(30):
            xid = random.randint(1000, 9999)
            beacon = random.randint(1, 5)
            domain = f"x{xid}.beacon-{beacon}.example.com"
            events.append({
                "host_id": HOST_ID,
                "type": "dns_query",
                "timestamp": (now - timedelta(seconds=i * 10)).isoformat(),
                "domain": domain,
            })
        events.append({
            "host_id": HOST_ID,
            "type": "net_io",
            "timestamp": now.isoformat(),
            "bytes_sent": random.randint(500, 2000),
            "bytes_received": random.randint(100, 500),
        })
        events.append({
            "host_id": HOST_ID,
            "type": "new_process",
            "timestamp": now.isoformat(),
            "name": "rundll32.exe",
            "parent_name": "svchost.exe",
            "pid": random.randint(5000, 9999),
            "cpu_percent": random.uniform(1.0, 5.0),
        })

    elif scenario == "privilege_escalation":
        for _ in range(4):
            events.append({
                "host_id": HOST_ID,
                "type": "new_process",
                "timestamp": now.isoformat(),
                "name": random.choice(["whoami.exe", "net.exe", "sc.exe", "reg.exe"]),
                "parent_name": "powershell.exe",
                "pid": random.randint(5000, 9999),
                "cpu_percent": random.uniform(5.0, 40.0),
            })
        events.append({
            "host_id": HOST_ID,
            "type": "file_access",
            "timestamp": now.isoformat(),
            "path": r"C:\Windows\System32\config\SECURITY",
            "process_name": "mimikatz.exe",
        })
        events.append({
            "host_id": HOST_ID,
            "type": "file_access",
            "timestamp": now.isoformat(),
            "path": r"C:\Windows\System32\lsass.exe",
            "process_name": "procdump.exe",
        })
        events.append({
            "host_id": HOST_ID,
            "type": "new_process",
            "timestamp": now.isoformat(),
            "name": "powershell.exe",
            "parent_name": "wmiprvse.exe",
            "pid": random.randint(5000, 9999),
            "cpu_percent": random.uniform(30.0, 80.0),
            "memory_percent": random.uniform(50.0, 90.0),
        })
        events.append({
            "host_id": HOST_ID,
            "type": "login_success",
            "timestamp": now.isoformat(),
            "user": "SYSTEM",
            "source": "token_impersonation",
        })

    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario: {scenario}")

    db = SessionLocal()
    try:
        for ev in events:
            db.add(RawEvent(
                host_id=ev.get("host_id", HOST_ID),
                event_type=ev.get("type", "unknown"),
                timestamp=datetime.fromisoformat(ev["timestamp"]),
                data=ev,
            ))
        db.commit()
    finally:
        db.close()

    return {
        "scenario": scenario,
        "events_injected": len(events),
        "message": "Synthetic events injected. They will be picked up in the next detection cycle.",
    }
