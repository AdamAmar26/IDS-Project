from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict


class RawEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    host_id: str
    event_type: str
    timestamp: datetime
    data: dict[str, Any]


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
    context: dict[str, Any] | None = None


class AlertVerdict(StrEnum):
    true_positive = "true_positive"
    false_positive = "false_positive"


class VerdictRequest(BaseModel):
    verdict: AlertVerdict


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    host_id: str
    feature_window_id: int | None = None
    anomaly_score: float
    is_anomaly: bool
    top_features: dict[str, float] | None = None
    verdict: str | None = None
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
    mitre_tactics: list[dict[str, Any]] = []
    mitre_techniques: list[dict[str, Any]] = []
    threat_intel_hits: list[str] = []
    kill_chain_phase: str | None = None
    created_at: datetime
    updated_at: datetime
    alert_ids: list[int] = []


class HostDetailOut(BaseModel):
    host_id: str
    baseline: dict[str, Any] | None = None
    current_features: dict[str, Any] | None = None
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
