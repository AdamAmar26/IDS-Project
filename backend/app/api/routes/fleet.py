from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import require_jwt
from app.db.models import Alert, Incident, RawEvent
from app.db.session import get_db

router = APIRouter()


@router.get("/summary")
def fleet_summary(_: str = Depends(require_jwt), db: Session = Depends(get_db)):
    alert_rows = (
        db.query(Alert.host_id, func.count(Alert.id))
        .group_by(Alert.host_id)
        .all()
    )
    incident_rows = (
        db.query(Incident.host_id, func.count(Incident.id))
        .group_by(Incident.host_id)
        .all()
    )
    open_incident_rows = (
        db.query(Incident.host_id, func.count(Incident.id))
        .filter(Incident.status == "open")
        .group_by(Incident.host_id)
        .all()
    )
    last_event_rows = (
        db.query(RawEvent.host_id, func.max(RawEvent.timestamp))
        .group_by(RawEvent.host_id)
        .all()
    )
    max_risk_rows = (
        db.query(Incident.host_id, func.max(Incident.risk_score))
        .filter(Incident.status == "open")
        .group_by(Incident.host_id)
        .all()
    )

    alerts = {h: c for h, c in alert_rows}
    incidents = {h: c for h, c in incident_rows}
    open_incidents = {h: c for h, c in open_incident_rows}
    last_events = {h: ts.isoformat() if ts else None for h, ts in last_event_rows}
    max_risk = {h: r for h, r in max_risk_rows}

    hosts = sorted(set(alerts.keys()) | set(incidents.keys()) | set(last_events.keys()))
    return [
        {
            "host_id": host,
            "alert_count": alerts.get(host, 0),
            "incident_count": incidents.get(host, 0),
            "open_incidents": open_incidents.get(host, 0),
            "last_seen": last_events.get(host),
            "risk_score": max_risk.get(host, 0.0),
        }
        for host in hosts
    ]
