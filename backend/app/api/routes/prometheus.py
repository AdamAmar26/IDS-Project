"""Prometheus metrics endpoint exposing IDS counters and histograms."""

from fastapi import APIRouter, Response
from prometheus_client import (
    Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST,
)

router = APIRouter()

alerts_total = Counter(
    "ids_alerts_total",
    "Total anomaly alerts generated",
    ["host_id", "is_anomaly"],
)
incidents_total = Counter(
    "ids_incidents_total",
    "Total incidents created",
    ["severity"],
)
anomaly_score_histogram = Histogram(
    "ids_anomaly_score",
    "Distribution of anomaly scores",
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0],
)
model_training_samples = Gauge(
    "ids_model_training_samples",
    "Number of samples used to train the current model",
)
model_trained = Gauge(
    "ids_model_trained",
    "Whether the anomaly detection model is trained (1) or not (0)",
)
active_incidents = Gauge(
    "ids_active_incidents",
    "Number of currently open incidents",
)


def record_alert(host_id: str, score: float, is_anomaly: bool):
    alerts_total.labels(host_id=host_id, is_anomaly=str(is_anomaly)).inc()
    anomaly_score_histogram.observe(score)


def record_incident(severity: str):
    incidents_total.labels(severity=severity).inc()


def update_model_gauges(trained: bool, samples: int, active: int):
    model_trained.set(1 if trained else 0)
    model_training_samples.set(samples)
    active_incidents.set(active)


@router.get("/metrics")
def prometheus_metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
