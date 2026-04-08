from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


def _utcnow():
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", Integer, ForeignKey("incidents.id"), primary_key=True),
    Column("alert_id", Integer, ForeignKey("alerts.id"), primary_key=True),
)


class RawEvent(Base):
    __tablename__ = "raw_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    data = Column(JSON, nullable=False)


class FeatureWindow(Base):
    __tablename__ = "feature_windows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(String, nullable=False, index=True)
    window_start = Column(DateTime, nullable=False)
    window_end = Column(DateTime, nullable=False)
    failed_login_count = Column(Integer, default=0)
    successful_login_count = Column(Integer, default=0)
    unique_dest_ips = Column(Integer, default=0)
    unique_dest_ports = Column(Integer, default=0)
    outbound_conn_count = Column(Integer, default=0)
    bytes_sent = Column(Float, default=0.0)
    bytes_received = Column(Float, default=0.0)
    avg_process_cpu = Column(Float, default=0.0)
    new_process_count = Column(Integer, default=0)
    inbound_outbound_ratio = Column(Float, default=0.0)
    unusual_hour_flag = Column(Boolean, default=False)
    privileged_process_count = Column(Integer, default=0)
    parent_child_anomaly_score = Column(Float, default=0.0)
    dns_query_count = Column(Integer, default=0)
    unique_parent_processes = Column(Integer, default=0)
    memory_usage_spike = Column(Float, default=0.0)
    sensitive_file_access_count = Column(Integer, default=0)
    context = Column(JSON, default=dict)

    alerts = relationship("Alert", back_populates="feature_window")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(String, nullable=False, index=True)
    feature_window_id = Column(Integer, ForeignKey("feature_windows.id"))
    anomaly_score = Column(Float, nullable=False)
    is_anomaly = Column(Boolean, nullable=False)
    top_features = Column(JSON)
    verdict = Column(String, nullable=True)
    created_at = Column(DateTime, default=_utcnow)

    feature_window = relationship("FeatureWindow", back_populates="alerts")
    incidents = relationship(
        "Incident", secondary=incident_alerts, back_populates="alerts",
    )


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(String, nullable=False, index=True)
    risk_score = Column(Float, default=0.0)
    status = Column(String, default="open")
    severity = Column(String, default="low")
    summary = Column(Text, default="")
    explanation = Column(Text, default="")
    suggested_actions = Column(Text, default="")
    mitre_tactics = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    threat_intel_hits = Column(JSON, default=list)
    kill_chain_phase = Column(String, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    alerts = relationship(
        "Alert", secondary=incident_alerts, back_populates="incidents",
    )
    notes = relationship(
        "IncidentNote", back_populates="incident", order_by="IncidentNote.created_at",
    )


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    author = Column(String, nullable=False)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=_utcnow)

    incident = relationship("Incident", back_populates="notes")


class HostBaseline(Base):
    __tablename__ = "host_baselines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(String, nullable=False, unique=True)
    feature_means = Column(JSON)
    feature_stds = Column(JSON)
    sample_count = Column(Integer, default=0)
    updated_at = Column(DateTime, default=_utcnow)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    channel = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False, index=True)
    resource = Column(String, nullable=False, index=True)
    event_metadata = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=_utcnow, index=True)


class SavedHunt(Base):
    __tablename__ = "saved_hunts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    filters = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=_utcnow)
