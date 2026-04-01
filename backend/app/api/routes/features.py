from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.schemas import FeatureWindowOut
from app.db.models import FeatureWindow
from app.db.session import get_db

router = APIRouter()


@router.get("", response_model=list[FeatureWindowOut])
def list_features(
    host_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    q = db.query(FeatureWindow)
    if host_id:
        q = q.filter(FeatureWindow.host_id == host_id)
    if since:
        q = q.filter(FeatureWindow.window_start >= since)
    if until:
        q = q.filter(FeatureWindow.window_end <= until)
    return q.order_by(FeatureWindow.window_end.desc()).offset(offset).limit(limit).all()
