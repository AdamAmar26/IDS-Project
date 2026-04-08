from __future__ import annotations

from typing import Any

from app.db.models import AuditEvent
from app.db.session import SessionLocal


def log_audit_event(
    actor: str,
    action: str,
    resource: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    db = SessionLocal()
    try:
        db.add(
            AuditEvent(
                actor=actor or "system",
                action=action,
                resource=resource,
                event_metadata=metadata or {},
            )
        )
        db.commit()
    finally:
        db.close()
