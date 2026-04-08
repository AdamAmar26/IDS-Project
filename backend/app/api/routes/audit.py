from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import require_jwt
from app.db.models import AuditEvent
from app.db.session import get_db

router = APIRouter()


@router.get("")
def list_audit_events(
    actor: str | None = None,
    action: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    _: str = Depends(require_jwt),
    db: Session = Depends(get_db),
):
    q = db.query(AuditEvent)
    if actor:
        q = q.filter(AuditEvent.actor == actor)
    if action:
        q = q.filter(AuditEvent.action.contains(action))
    if since:
        q = q.filter(AuditEvent.created_at >= since)
    if until:
        q = q.filter(AuditEvent.created_at <= until)

    total = q.count()
    rows = (
        q.order_by(AuditEvent.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "items": [
            {
                "id": r.id,
                "actor": r.actor,
                "action": r.action,
                "resource": r.resource,
                "metadata": r.event_metadata or {},
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }
