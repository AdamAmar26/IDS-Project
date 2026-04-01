from datetime import UTC, datetime, timedelta

from app.correlation.engine import CorrelationEngine


def test_low_risk_no_incident():
    engine = CorrelationEngine()
    result = engine.evaluate(
        {
            "anomaly_score": 0.1,
            "is_anomaly": True,
            "features": {},
            "created_at": datetime.now(UTC),
        },
        [],
    )
    assert result["risk_score"] < 3
    assert not result["should_create_incident"]
    assert result["severity"] == "low"


def test_high_anomaly_score():
    engine = CorrelationEngine()
    result = engine.evaluate(
        {
            "anomaly_score": 0.5,
            "is_anomaly": True,
            "features": {},
            "created_at": datetime.now(UTC),
        },
        [],
    )
    assert "high_anomaly_score" in result["triggered_rules"]
    assert result["risk_score"] >= 2


def test_login_plus_process():
    engine = CorrelationEngine()
    result = engine.evaluate(
        {
            "anomaly_score": 0.5,
            "is_anomaly": True,
            "features": {"failed_login_count": 3, "new_process_count": 5},
            "created_at": datetime.now(UTC),
        },
        [],
    )
    assert "login_plus_process_anomaly" in result["triggered_rules"]
    assert result["should_create_incident"]


def test_repeated_anomalies_escalate():
    engine = CorrelationEngine()
    now = datetime.now(UTC)
    recent = [
        {"is_anomaly": True, "created_at": now - timedelta(minutes=5)},
        {"is_anomaly": True, "created_at": now - timedelta(minutes=10)},
        {"is_anomaly": True, "created_at": now - timedelta(minutes=2)},
    ]
    result = engine.evaluate(
        {
            "anomaly_score": 0.4,
            "is_anomaly": True,
            "features": {},
            "created_at": now,
        },
        recent,
    )
    assert "repeated_anomaly_15min" in result["triggered_rules"]


def test_severity_thresholds():
    engine = CorrelationEngine()
    now = datetime.now(UTC)
    recent = [
        {"is_anomaly": True, "created_at": now - timedelta(minutes=i)}
        for i in range(5)
    ]
    result = engine.evaluate(
        {
            "anomaly_score": 0.5,
            "is_anomaly": True,
            "features": {
                "failed_login_count": 2,
                "new_process_count": 5,
                "unique_dest_ports": 15,
            },
            "created_at": now,
        },
        recent,
    )
    assert result["severity"] in ("high", "critical")
