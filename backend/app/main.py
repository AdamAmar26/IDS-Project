import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from jose import JWTError, jwt

from app.config import (
    API_KEY, MIN_TRAINING_SAMPLES,
    JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRE_MINUTES,
    ADMIN_USERNAME, ADMIN_PASSWORD,
)
from app.db.session import init_db
from app.services.orchestrator import get_orchestrator
from app.api.routes import events, features, alerts, incidents, hosts, metrics
from app.api.routes.ws import router as ws_router, manager as ws_manager
from app.api.routes.prometheus import router as prom_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

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
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
def login(body: TokenRequest):
    if body.username != ADMIN_USERNAME or body.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
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

    Supported scenarios: brute_force_portscan, data_exfiltration
    """
    import random
    from app.db.session import SessionLocal
    from app.db.models import RawEvent
    from app.config import HOST_ID

    now = datetime.now(timezone.utc)
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
        for i in range(6):
            events.append({
                "host_id": HOST_ID,
                "type": "new_process",
                "timestamp": now.isoformat(),
                "name": random.choice(["cmd.exe", "powershell.exe", "wmic.exe", "net.exe"]),
                "pid": random.randint(5000, 9999),
                "cpu_percent": random.uniform(15.0, 85.0),
            })
    elif scenario == "data_exfiltration":
        for i in range(3):
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
        for i in range(4):
            events.append({
                "host_id": HOST_ID,
                "type": "new_process",
                "timestamp": now.isoformat(),
                "name": random.choice(["7z.exe", "rar.exe", "curl.exe"]),
                "pid": random.randint(5000, 9999),
                "cpu_percent": random.uniform(20.0, 60.0),
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
