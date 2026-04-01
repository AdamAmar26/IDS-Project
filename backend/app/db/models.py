from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text,
    ForeignKey, JSON, Table,
)
from sqlalchemy.orm import relationship, DeclarativeBase
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc)


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
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    alerts = relationship(
        "Alert", secondary=incident_alerts, back_populates="incidents",
    )


class HostBaseline(Base):
    __tablename__ = "host_baselines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(String, nullable=False, unique=True)
    feature_means = Column(JSON)
    feature_stds = Column(JSON)
    sample_count = Column(Integer, default=0)
    updated_at = Column(DateTime, default=_utcnow)
