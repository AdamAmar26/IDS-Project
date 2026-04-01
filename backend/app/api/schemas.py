from enum import Enum

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
    privileged_process_count: int = 0
    parent_child_anomaly_score: float = 0.0
    dns_query_count: int = 0
    unique_parent_processes: int = 0
    memory_usage_spike: float = 0.0
    sensitive_file_access_count: int = 0
    context: Optional[Dict[str, Any]] = None


class AlertVerdict(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"


class VerdictRequest(BaseModel):
    verdict: AlertVerdict


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    host_id: str
    feature_window_id: Optional[int] = None
    anomaly_score: float
    is_anomaly: bool
    top_features: Optional[Dict[str, float]] = None
    verdict: Optional[str] = None
    created_at: datetime


class IncidentNoteIn(BaseModel):
    author: str
    body: str


class IncidentNoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    incident_id: int
    author: str
    body: str
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
    kill_chain_phase: Optional[str] = None
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
