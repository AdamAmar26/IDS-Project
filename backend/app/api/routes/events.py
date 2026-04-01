from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import RawEvent
from app.api.schemas import RawEventOut

router = APIRouter()


@router.get("", response_model=List[RawEventOut])
def list_events(
    host_id: Optional[str] = None,
    event_type: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    q = db.query(RawEvent)
    if host_id:
        q = q.filter(RawEvent.host_id == host_id)
    if event_type:
        q = q.filter(RawEvent.event_type == event_type)
    if since:
        q = q.filter(RawEvent.timestamp >= since)
    if until:
        q = q.filter(RawEvent.timestamp <= until)
    return q.order_by(RawEvent.timestamp.desc()).offset(offset).limit(limit).all()
