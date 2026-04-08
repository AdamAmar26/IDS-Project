"""AI-powered threat briefing endpoint."""

import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import OLLAMA_MODEL, OLLAMA_URL
from app.db.models import Alert, Incident, RawEvent
from app.db.session import get_db
from app.services.orchestrator import get_orchestrator

logger = logging.getLogger(__name__)

router = APIRouter()

_cache: dict[str, Any] = {"data": None, "expires": 0.0}
CACHE_TTL_SECONDS = 300


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class SummaryData(BaseModel):
    open_incidents: int = 0
    total_incidents_24h: int = 0
    alerts_24h: int = 0
    anomaly_alerts_24h: int = 0
    hosts_at_risk: int = 0
    severity_counts: SeverityCounts = SeverityCounts()
    top_rules: list[str] = []
    threat_intel_hits_24h: int = 0
    trend: str = "stable"
    model_health: str = "unknown"


class SummaryResponse(BaseModel):
    briefing: str
    data: SummaryData
    generated_at: str
    llm_available: bool = False


def _build_briefing_prompt(data: SummaryData) -> str:
    return f"""You are the AI analyst for a Security Operations Center. Generate a concise shift briefing (3-4 sentences max) for the incoming SOC team based on the following 24-hour metrics:

- Open incidents: {data.open_incidents}
- New incidents (24h): {data.total_incidents_24h}
- Total alerts (24h): {data.alerts_24h} ({data.anomaly_alerts_24h} anomalies)
- Hosts at risk: {data.hosts_at_risk}
- Severity breakdown: Critical={data.severity_counts.critical}, High={data.severity_counts.high}, Medium={data.severity_counts.medium}, Low={data.severity_counts.low}
- Top triggered rules: {', '.join(data.top_rules) if data.top_rules else 'None'}
- Threat intel hits: {data.threat_intel_hits_24h}
- Trend: {data.trend}
- Detection model: {data.model_health}

Write in a direct, professional tone. Mention the most critical items first. If there are no incidents, say the environment is calm but monitoring continues. Do NOT use markdown formatting."""


def _template_briefing(data: SummaryData) -> str:
    """Deterministic fallback when LLM is unavailable."""
    parts = []

    if data.severity_counts.critical > 0:
        parts.append(
            f"CRITICAL: {data.severity_counts.critical} critical-severity incident(s) require immediate attention."
        )
    elif data.severity_counts.high > 0:
        parts.append(
            f"There are {data.severity_counts.high} high-severity incident(s) that should be reviewed promptly."
        )

    if data.open_incidents > 0:
        parts.append(
            f"{data.open_incidents} incident(s) are currently open with {data.alerts_24h} alerts generated in the last 24 hours."
        )
    else:
        parts.append(
            "No open incidents. The environment is currently stable and under active monitoring."
        )

    if data.anomaly_alerts_24h > 0:
        parts.append(
            f"{data.anomaly_alerts_24h} anomaly detection(s) were flagged across {data.hosts_at_risk} host(s)."
        )

    if data.threat_intel_hits_24h > 0:
        parts.append(
            f"{data.threat_intel_hits_24h} threat intelligence match(es) detected — review correlated incidents."
        )

    if data.model_health == "training":
        parts.append(
            "The detection model is still in the training phase; baseline accuracy will improve as more data is collected."
        )

    return " ".join(parts) if parts else "System is initializing. Monitoring has begun and metrics will populate shortly."


def _gather_data(db: Session) -> SummaryData:
    now = datetime.now(UTC)
    t24h = now - timedelta(hours=24)
    t48h = now - timedelta(hours=48)

    open_incidents = db.query(Incident).filter(Incident.status == "open").count()

    incidents_24h = (
        db.query(Incident).filter(Incident.created_at >= t24h).all()
    )
    total_incidents_24h = len(incidents_24h)

    sev = SeverityCounts()
    rules_counter: dict[str, int] = {}
    ti_hits = 0
    hosts_set: set[str] = set()

    for inc in incidents_24h:
        s = (inc.severity or "low").lower()
        if s == "critical":
            sev.critical += 1
        elif s == "high":
            sev.high += 1
        elif s == "medium":
            sev.medium += 1
        else:
            sev.low += 1

        hosts_set.add(inc.host_id)

        if inc.threat_intel_hits:
            ti_hits += len(inc.threat_intel_hits)

    alerts_24h = db.query(Alert).filter(Alert.created_at >= t24h).count()
    anomaly_24h = (
        db.query(Alert)
        .filter(Alert.created_at >= t24h, Alert.is_anomaly.is_(True))
        .count()
    )

    # Trend: compare incident count in last 24h vs previous 24h
    prev_incidents = (
        db.query(Incident)
        .filter(Incident.created_at >= t48h, Incident.created_at < t24h)
        .count()
    )
    if total_incidents_24h > prev_incidents + 2:
        trend = "worsening"
    elif total_incidents_24h < prev_incidents - 2:
        trend = "improving"
    else:
        trend = "stable"

    orch = get_orchestrator()
    if orch.detector.is_trained:
        model_health = "active"
    elif len(orch.detector.training_data) > 0:
        model_health = "training"
    else:
        model_health = "initializing"

    return SummaryData(
        open_incidents=open_incidents,
        total_incidents_24h=total_incidents_24h,
        alerts_24h=alerts_24h,
        anomaly_alerts_24h=anomaly_24h,
        hosts_at_risk=len(hosts_set),
        severity_counts=sev,
        top_rules=list(rules_counter.keys())[:5],
        threat_intel_hits_24h=ti_hits,
        trend=trend,
        model_health=model_health,
    )


@router.get("", response_model=SummaryResponse)
def get_summary(db: Session = Depends(get_db)):
    now = time.time()

    if _cache["data"] and now < _cache["expires"]:
        return _cache["data"]

    data = _gather_data(db)
    llm_available = False
    briefing = ""

    try:
        prompt = _build_briefing_prompt(data)
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            briefing = resp.json().get("response", "").strip()
            if briefing:
                llm_available = True
    except Exception as exc:
        logger.info("LLM unavailable for summary, using template: %s", exc)

    if not briefing:
        briefing = _template_briefing(data)

    result = SummaryResponse(
        briefing=briefing,
        data=data,
        generated_at=datetime.now(UTC).isoformat(),
        llm_available=llm_available,
    )

    _cache["data"] = result
    _cache["expires"] = now + CACHE_TTL_SECONDS

    return result
