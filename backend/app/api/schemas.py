from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional, Dict, List, Any


class RawEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    host_id: str
    event_type: str
    timestamp: datetime
    data: Dict[str, Any]


class FeatureWindowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    host_id: str
    window_start: datetime
    window_end: datetime
    failed_login_count: int
    successful_login_count: int
    unique_dest_ips: int
    unique_dest_ports: int
    outbound_conn_count: int
    bytes_sent: float
    bytes_received: float
    avg_process_cpu: float
    new_process_count: int
    inbound_outbound_ratio: float
    unusual_hour_flag: bool
    context: Optional[Dict[str, Any]] = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    host_id: str
    feature_window_id: Optional[int] = None
    anomaly_score: float
    is_anomaly: bool
    top_features: Optional[Dict[str, float]] = None
    created_at: datetime


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    host_id: str
    risk_score: float
    status: str
    severity: str
    summary: str
    explanation: str
    suggested_actions: str
    mitre_tactics: List[Dict[str, Any]] = []
    mitre_techniques: List[Dict[str, Any]] = []
    threat_intel_hits: List[str] = []
    created_at: datetime
    updated_at: datetime
    alert_ids: List[int] = []


class HostDetailOut(BaseModel):
    host_id: str
    baseline: Optional[Dict[str, Any]] = None
    current_features: Optional[Dict[str, Any]] = None
    alert_count: int = 0
    incident_count: int = 0


class MetricsOut(BaseModel):
    total_events: int
    total_windows: int
    total_alerts: int
    total_incidents: int
    active_incidents: int
    anomaly_rate: float
    model_trained: bool
    training_samples: int
    min_training_samples: int
    security_log_available: bool
