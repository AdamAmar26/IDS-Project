from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import Alert
from app.api.schemas import AlertOut

router = APIRouter()


@router.get("", response_model=List[AlertOut])
def list_alerts(
    host_id: Optional[str] = None,
    is_anomaly: Optional[bool] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    q = db.query(Alert)
    if host_id:
        q = q.filter(Alert.host_id == host_id)
    if is_anomaly is not None:
        q = q.filter(Alert.is_anomaly == is_anomaly)
    if since:
        q = q.filter(Alert.created_at >= since)
    if until:
        q = q.filter(Alert.created_at <= until)
    return q.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
