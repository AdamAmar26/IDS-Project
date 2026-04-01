from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.schemas import MetricsOut
from app.config import MIN_TRAINING_SAMPLES
from app.db.models import Alert, FeatureWindow, Incident, RawEvent
from app.db.session import get_db
from app.services.orchestrator import get_orchestrator

router = APIRouter()


@router.get("", response_model=MetricsOut)
def get_metrics(db: Session = Depends(get_db)):
    total_events = db.query(RawEvent).count()
    total_windows = db.query(FeatureWindow).count()
    total_alerts = db.query(Alert).count()
    anomaly_alerts = db.query(Alert).filter(Alert.is_anomaly.is_(True)).count()
    total_incidents = db.query(Incident).count()
    active_incidents = db.query(Incident).filter(Incident.status == "open").count()

    orch = get_orchestrator()
    return MetricsOut(
        total_events=total_events,
        total_windows=total_windows,
        total_alerts=total_alerts,
        total_incidents=total_incidents,
        active_incidents=active_incidents,
        anomaly_rate=(anomaly_alerts / total_alerts) if total_alerts > 0 else 0.0,
        model_trained=orch.detector.is_trained,
        training_samples=len(orch.detector.training_data),
        min_training_samples=MIN_TRAINING_SAMPLES,
        security_log_available=orch.collector.security_log_available,
    )
