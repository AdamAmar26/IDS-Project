from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import FeatureWindow
from app.api.schemas import FeatureWindowOut

router = APIRouter()


@router.get("", response_model=List[FeatureWindowOut])
def list_features(
    host_id: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
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
