from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.schemas import AlertOut, VerdictRequest
from app.db.models import Alert
from app.db.session import get_db

router = APIRouter()


@router.get("", response_model=list[AlertOut])
def list_alerts(
    host_id: str | None = None,
    is_anomaly: bool | None = None,
    verdict: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    q = db.query(Alert)
    if host_id:
        q = q.filter(Alert.host_id == host_id)
    if is_anomaly is not None:
        q = q.filter(Alert.is_anomaly == is_anomaly)
    if verdict:
        q = q.filter(Alert.verdict == verdict)
    if since:
        q = q.filter(Alert.created_at >= since)
    if until:
        q = q.filter(Alert.created_at <= until)
    return q.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()


@router.patch("/{alert_id}/verdict", response_model=AlertOut)
def set_alert_verdict(
    alert_id: int,
    body: VerdictRequest,
    db: Session = Depends(get_db),
):
    """Mark an alert as true_positive or false_positive for feedback-driven retraining."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.verdict = body.verdict.value
    db.commit()
    db.refresh(alert)
    return alert
