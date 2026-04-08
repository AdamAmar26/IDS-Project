from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import require_jwt
from app.db.models import Incident
from app.db.session import get_db
from app.services.audit import log_audit_event
from app.services.notifications import NotificationDispatcher

router = APIRouter()


@router.get("/weekly")
def weekly_report(
    since: datetime | None = None,
    format: str = Query("json"),
    _: str = Depends(require_jwt),
    db: Session = Depends(get_db),
):
    start = since or (datetime.now(UTC) - timedelta(days=7))
    rows = db.query(Incident).filter(Incident.created_at >= start).all()
    severity_counts: dict[str, int] = {}
    technique_counts: dict[str, int] = {}
    for inc in rows:
        sev: str = str(inc.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        techniques: list[dict[str, object]] = inc.mitre_techniques or []
        for t in techniques:
            tid = str(t.get("id", "unknown"))
            technique_counts[tid] = technique_counts.get(tid, 0) + 1

    closed_count = (
        db.query(func.count(Incident.id))
        .filter(Incident.created_at >= start, Incident.status == "resolved")
        .scalar()
    ) or 0

    payload = {
        "since": start.isoformat(),
        "generated_at": datetime.now(UTC).isoformat(),
        "incident_count": len(rows),
        "closed_count": closed_count,
        "severity_counts": severity_counts,
        "top_techniques": sorted(
            [{"technique": k, "count": v} for k, v in technique_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10],
    }
    if format == "html":
        html = [
            "<html><body><h1>IDS Weekly Security Summary</h1>",
            f"<p>Since: {payload['since']}</p>",
            f"<p>Generated: {payload['generated_at']}</p>",
            f"<p>Total incidents: {payload['incident_count']}</p>",
            f"<p>Resolved incidents: {payload['closed_count']}</p>",
            "<h2>Severity breakdown</h2><ul>",
        ]
        html += [f"<li>{s}: {c}</li>" for s, c in severity_counts.items()]
        html += ["</ul><h2>Top MITRE techniques</h2><ul>"]
        top: list[dict[str, object]] = payload["top_techniques"]  # type: ignore[assignment]
        html += [f"<li>{t['technique']}: {t['count']}</li>" for t in top]
        html += ["</ul></body></html>"]
        return HTMLResponse("".join(html))
    return payload


@router.post("/weekly/email")
def email_weekly_report(actor: str = Depends(require_jwt)):
    # Reuses existing notifier plumbing; this sends a lightweight report signal.
    NotificationDispatcher().send_test()
    log_audit_event(actor, "report.weekly.email", "reports.weekly", {})
    return {"sent": True}
