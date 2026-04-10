from __future__ import annotations

from typing import Any

from app.db.models import AuditEvent
from app.db.session import SessionLocal
from sqlalchemy.orm import Session


def log_audit_event(
    actor: str,
    action: str,
    resource: str,
    metadata: dict[str, Any] | None = None,
    db: Session | None = None,
) -> None:
    if db is not None:
        db.add(
            AuditEvent(
                actor=actor or "system",
                action=action,
                resource=resource,
                event_metadata=metadata or {},
            )
        )
        db.commit()
        return

    session = SessionLocal()
    try:
        session.add(
            AuditEvent(
                actor=actor or "system",
                action=action,
                resource=resource,
                event_metadata=metadata or {},
            )
        )
        session.commit()
    finally:
        session.close()
