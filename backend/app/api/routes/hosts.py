from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.schemas import HostDetailOut
from app.db.models import Alert, FeatureWindow, HostBaseline, Incident
from app.db.session import get_db

router = APIRouter()


@router.get("/{host_id}", response_model=HostDetailOut)
def get_host(host_id: str, db: Session = Depends(get_db)):
    baseline_row = db.query(HostBaseline).filter_by(host_id=host_id).first()
    latest_window = (
        db.query(FeatureWindow)
        .filter_by(host_id=host_id)
        .order_by(FeatureWindow.window_end.desc())
        .first()
    )
    alert_count = db.query(Alert).filter_by(host_id=host_id).count()
    incident_count = db.query(Incident).filter_by(host_id=host_id).count()

    current_features = None
    if latest_window:
        current_features = {
            "failed_login_count": latest_window.failed_login_count,
            "successful_login_count": latest_window.successful_login_count,
            "unique_dest_ips": latest_window.unique_dest_ips,
            "unique_dest_ports": latest_window.unique_dest_ports,
            "outbound_conn_count": latest_window.outbound_conn_count,
            "bytes_sent": latest_window.bytes_sent,
            "bytes_received": latest_window.bytes_received,
            "avg_process_cpu": latest_window.avg_process_cpu,
            "new_process_count": latest_window.new_process_count,
            "inbound_outbound_ratio": latest_window.inbound_outbound_ratio,
            "unusual_hour_flag": latest_window.unusual_hour_flag,
        }

    return HostDetailOut(
        host_id=host_id,
        baseline=baseline_row.feature_means if baseline_row else None,
        current_features=current_features,
        alert_count=alert_count,
        incident_count=incident_count,
    )
