import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import API_KEY, MIN_TRAINING_SAMPLES
from app.db.session import init_db
from app.services.orchestrator import get_orchestrator
from app.api.routes import events, features, alerts, incidents, hosts, metrics

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

orchestrator = get_orchestrator()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    orchestrator.start()
    yield
    orchestrator.stop()


app = FastAPI(
    title="IDS - Behavior-Based Intrusion Detection",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def check_api_key(request: Request, call_next):
    if API_KEY:
        exempt = ("/health", "/docs", "/openapi.json", "/redoc")
        if not any(request.url.path.startswith(p) for p in exempt):
            key = request.headers.get("X-API-Key", "")
            if key != API_KEY:
                return JSONResponse(
                    status_code=403, content={"detail": "Invalid or missing API key"},
                )
    return await call_next(request)


app.include_router(events.router, prefix="/events", tags=["Events"])
app.include_router(features.router, prefix="/features", tags=["Features"])
app.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
app.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
app.include_router(hosts.router, prefix="/hosts", tags=["Hosts"])
app.include_router(metrics.router, prefix="/metrics", tags=["Metrics"])


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
