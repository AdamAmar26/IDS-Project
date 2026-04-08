import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.schemas import (
    IncidentNoteIn,
    IncidentNoteOut,
    IncidentOut,
)
from app.db.models import Incident, IncidentNote, RawEvent
from app.db.session import get_db
from app.services.audit import log_audit_event

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
        mitre_tactics=inc.mitre_tactics or [],
        mitre_techniques=inc.mitre_techniques or [],
        threat_intel_hits=inc.threat_intel_hits or [],
        kill_chain_phase=inc.kill_chain_phase,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        alert_ids=[a.id for a in inc.alerts],
    )


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    host_id: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    since: datetime | None = None,
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


VALID_STATUSES = {"open", "acknowledged", "investigating", "resolved", "closed"}


@router.patch("/{incident_id}/status")
def update_status(incident_id: int, status: str, db: Session = Depends(get_db)):
    if status not in VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status. Must be one of: {', '.join(sorted(VALID_STATUSES))}",
        )
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc.status = status
    db.commit()
    log_audit_event(
        "admin",
        "incident.status.update",
        f"incidents/{incident_id}",
        {"status": status},
    )
    return {"id": incident_id, "status": status}


# ---- Analyst notes ----


@router.get("/{incident_id}/notes", response_model=list[IncidentNoteOut])
def list_notes(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc.notes


@router.post("/{incident_id}/notes", response_model=IncidentNoteOut, status_code=201)
def add_note(incident_id: int, body: IncidentNoteIn, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    note = IncidentNote(
        incident_id=incident_id,
        author=body.author,
        body=body.body,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    log_audit_event(body.author, "incident.note.add", f"incidents/{incident_id}", {})
    return note


# ---- Export / Reporting ----


@router.get("/{incident_id}/report")
def export_report(
    incident_id: int,
    fmt: str = Query("json", alias="format"),
    db: Session = Depends(get_db),
):
    """Export a full incident report including timeline, alerts, MITRE, and notes."""
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    alert_rows = [
        {
            "alert_id": a.id,
            "anomaly_score": a.anomaly_score,
            "is_anomaly": a.is_anomaly,
            "verdict": a.verdict,
            "created_at": a.created_at.isoformat() if a.created_at else "",
            "top_features": a.top_features,
        }
        for a in inc.alerts
    ]
    note_rows = [
        {
            "author": n.author,
            "body": n.body,
            "created_at": n.created_at.isoformat() if n.created_at else "",
        }
        for n in inc.notes
    ]

    report = {
        "incident_id": inc.id,
        "host_id": inc.host_id,
        "status": inc.status,
        "severity": inc.severity,
        "risk_score": inc.risk_score,
        "kill_chain_phase": inc.kill_chain_phase,
        "summary": inc.summary,
        "explanation": inc.explanation,
        "suggested_actions": inc.suggested_actions,
        "mitre_tactics": inc.mitre_tactics or [],
        "mitre_techniques": inc.mitre_techniques or [],
        "threat_intel_hits": inc.threat_intel_hits or [],
        "created_at": inc.created_at.isoformat() if inc.created_at else "",
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else "",
        "alerts": alert_rows,
        "notes": note_rows,
    }

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "alert_id", "anomaly_score", "is_anomaly", "verdict", "created_at",
        ])
        for a in alert_rows:
            writer.writerow([
                a["alert_id"], a["anomaly_score"], a["is_anomaly"],
                a["verdict"], a["created_at"],
            ])
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=incident_{incident_id}.csv"
            },
        )

    log_audit_event("admin", "incident.report.export", f"incidents/{incident_id}", {"format": fmt})
    return report


@router.get("/{incident_id}/timeline")
def incident_timeline(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    alert_items = [
        {
            "type": "alert",
            "time": a.created_at.isoformat() if a.created_at else "",
            "id": a.id,
            "title": f"Alert #{a.id}",
            "detail": f"score={a.anomaly_score:.3f} anomaly={a.is_anomaly}",
        }
        for a in inc.alerts
    ]
    note_items = [
        {
            "type": "note",
            "time": n.created_at.isoformat() if n.created_at else "",
            "id": n.id,
            "title": f"Note by {n.author}",
            "detail": n.body,
        }
        for n in inc.notes
    ]
    raw_items = (
        db.query(RawEvent)
        .filter(RawEvent.host_id == inc.host_id)
        .order_by(RawEvent.timestamp.desc())
        .limit(50)
        .all()
    )
    event_items = [
        {
            "type": "event",
            "time": r.timestamp.isoformat() if r.timestamp else "",
            "id": r.id,
            "title": r.event_type,
            "detail": (r.data if isinstance(r.data, str) else str(r.data))[:200],
        }
        for r in raw_items
    ]
    items = sorted(alert_items + note_items + event_items, key=lambda i: i["time"], reverse=True)
    return {"incident_id": incident_id, "items": items}
