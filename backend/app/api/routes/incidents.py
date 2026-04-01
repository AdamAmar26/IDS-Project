from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import Incident
from app.api.schemas import IncidentOut

router = APIRouter()


def _to_out(inc: Incident) -> IncidentOut:
    return IncidentOut(
        id=inc.id,
        host_id=inc.host_id,
        risk_score=inc.risk_score,
        status=inc.status,
        severity=inc.severity,
        summary=inc.summary or "",
        explanation=inc.explanation or "",
        suggested_actions=inc.suggested_actions or "",
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        alert_ids=[a.id for a in inc.alerts],
    )


@router.get("", response_model=List[IncidentOut])
def list_incidents(
    host_id: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    q = db.query(Incident)
    if host_id:
        q = q.filter(Incident.host_id == host_id)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    if since:
        q = q.filter(Incident.created_at >= since)
    rows = q.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()
    return [_to_out(r) for r in rows]


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _to_out(inc)


@router.patch("/{incident_id}/status")
def update_status(incident_id: int, status: str, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc.status = status
    db.commit()
    return {"id": incident_id, "status": status}
