from app.explanation.templates import AlertExplainer


def test_alert_explanation():
    explainer = AlertExplainer()
    result = explainer.explain_alert(
        host_id="TEST-HOST",
        anomaly_score=0.45,
        top_features={"outbound_conn_count": 3.2, "unique_dest_ports": 2.1},
        features={"outbound_conn_count": 40, "unique_dest_ports": 15},
        baseline={"outbound_conn_count": 5, "unique_dest_ports": 3},
    )
    assert "TEST-HOST" in result["summary"]
    assert "0.450" in result["summary"]
    assert "detail" in result


def test_incident_explanation():
    explainer = AlertExplainer()
    result = explainer.explain_incident(
        host_id="TEST-HOST",
        risk_score=7,
        severity="high",
        triggered_rules=["high_anomaly_score", "login_plus_process_anomaly"],
        alert_count=3,
        features={
            "outbound_conn_count": 40,
            "failed_login_count": 5,
            "new_process_count": 10,
            "unique_dest_ports": 15,
            "unique_dest_ips": 8,
            "bytes_sent": 50000,
        },
        baseline={
            "outbound_conn_count": 5,
            "failed_login_count": 0,
            "new_process_count": 2,
            "unique_dest_ports": 3,
            "unique_dest_ips": 2,
            "bytes_sent": 1000,
        },
    )
    assert "HIGH" in result["summary"]
    assert "explanation" in result
    assert "suggested_actions" in result
    assert "Investigate" in result["suggested_actions"]


def test_suggested_actions_covers_rules():
    explainer = AlertExplainer()
    result = explainer.explain_incident(
        host_id="H",
        risk_score=10,
        severity="critical",
        triggered_rules=[
            "high_anomaly_score",
            "repeated_anomaly_15min",
            "unusual_port_spread",
            "login_plus_process_anomaly",
            "consecutive_low_confidence_escalation",
        ],
        alert_count=5,
        features={},
        baseline={},
    )
    actions = result["suggested_actions"]
    assert "Investigate" in actions
    assert "outbound connections" in actions
    assert "login attempts" in actions
