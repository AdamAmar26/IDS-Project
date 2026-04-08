from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import require_jwt
from app.db.models import Alert, RawEvent, SavedHunt
from app.db.session import get_db
from app.services.audit import log_audit_event

router = APIRouter()


class SavedHuntIn(BaseModel):
    name: str
    filters: dict[str, Any]


def _hunt_to_dict(r: SavedHunt) -> dict:
    return {
        "id": r.id,
        "name": r.name,
        "filters": r.filters,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


@router.get("")
def list_hunts(
    _: str = Depends(require_jwt),
    db: Session = Depends(get_db),
):
    rows = db.query(SavedHunt).order_by(SavedHunt.created_at.desc()).all()
    return [_hunt_to_dict(r) for r in rows]


@router.post("")
def create_hunt(
    body: SavedHuntIn,
    actor: str = Depends(require_jwt),
    db: Session = Depends(get_db),
):
    row = SavedHunt(name=body.name, filters=body.filters)
    db.add(row)
    db.commit()
    db.refresh(row)
    log_audit_event(actor, "hunt.create", f"hunts/{row.id}", {"name": body.name})
    return _hunt_to_dict(row)


@router.post("/{hunt_id}/run")
def run_hunt(
    hunt_id: int,
    limit: int = Query(200, le=1000),
    actor: str = Depends(require_jwt),
    db: Session = Depends(get_db),
):
    """Execute a saved hunt against raw events and alerts."""
    hunt = db.get(SavedHunt, hunt_id)
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")

    filters: dict[str, Any] = hunt.filters or {}

    eq = db.query(RawEvent)
    if filters.get("host_id"):
        eq = eq.filter(RawEvent.host_id == filters["host_id"])
    if filters.get("event_type"):
        eq = eq.filter(RawEvent.event_type == filters["event_type"])
    if filters.get("since"):
        eq = eq.filter(RawEvent.timestamp >= datetime.fromisoformat(filters["since"]))
    if filters.get("until"):
        eq = eq.filter(RawEvent.timestamp <= datetime.fromisoformat(filters["until"]))
    events = eq.order_by(RawEvent.timestamp.desc()).limit(limit).all()

    aq = db.query(Alert)
    if filters.get("host_id"):
        aq = aq.filter(Alert.host_id == filters["host_id"])
    if filters.get("is_anomaly") == "true":
        aq = aq.filter(Alert.is_anomaly.is_(True))
    if filters.get("since"):
        aq = aq.filter(Alert.created_at >= datetime.fromisoformat(filters["since"]))
    if filters.get("until"):
        aq = aq.filter(Alert.created_at <= datetime.fromisoformat(filters["until"]))
    alerts = aq.order_by(Alert.created_at.desc()).limit(limit).all()

    log_audit_event(
        actor,
        "hunt.run",
        f"hunts/{hunt_id}",
        {"results_events": len(events), "results_alerts": len(alerts)},
    )

    return {
        "total": len(events) + len(alerts),
        "events": [
            {
                "id": e.id,
                "host_id": e.host_id,
                "event_type": e.event_type,
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                "data": e.data,
            }
            for e in events
        ],
        "alerts": [
            {
                "id": a.id,
                "host_id": a.host_id,
                "anomaly_score": a.anomaly_score,
                "is_anomaly": a.is_anomaly,
                "top_features": a.top_features,
                "created_at": a.created_at.isoformat() if a.created_at else "",
            }
            for a in alerts
        ],
    }
