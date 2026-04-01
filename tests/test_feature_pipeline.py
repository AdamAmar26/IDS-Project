from datetime import datetime
from app.features.pipeline import compute_features


def test_empty_events():
    now = datetime.utcnow()
    features = compute_features([], now, now)
    assert features["failed_login_count"] == 0
    assert features["outbound_conn_count"] == 0
    assert features["avg_process_cpu"] == 0.0


def test_login_counts():
    now = datetime.utcnow()
    events = [
        {"type": "login_failure"},
        {"type": "login_failure"},
        {"type": "login_success"},
    ]
    features = compute_features(events, now, now)
    assert features["failed_login_count"] == 2
    assert features["successful_login_count"] == 1


def test_connection_features():
    now = datetime.utcnow()
    events = [
        {"type": "connection", "remote_ip": "1.2.3.4", "remote_port": 80},
        {"type": "connection", "remote_ip": "1.2.3.4", "remote_port": 443},
        {"type": "connection", "remote_ip": "5.6.7.8", "remote_port": 80},
        {"type": "net_io", "bytes_sent": 1000, "bytes_received": 500},
    ]
    features = compute_features(events, now, now)
    assert features["outbound_conn_count"] == 3
    assert features["unique_dest_ips"] == 2
    assert features["unique_dest_ports"] == 2
    assert features["bytes_sent"] == 1000
    assert features["bytes_received"] == 500
    assert features["inbound_outbound_ratio"] == 0.5


def test_process_features():
    now = datetime.utcnow()
    events = [
        {"type": "new_process", "cpu_percent": 10.0},
        {"type": "new_process", "cpu_percent": 20.0},
        {"type": "system_stats", "cpu_percent": 30.0},
    ]
    features = compute_features(events, now, now)
    assert features["new_process_count"] == 2
    assert features["avg_process_cpu"] == 20.0


def test_unusual_hour_flag():
    early = datetime(2024, 1, 1, 3, 0, 0)
    normal = datetime(2024, 1, 1, 14, 0, 0)
    late = datetime(2024, 1, 1, 23, 0, 0)
    assert compute_features([], early, early)["unusual_hour_flag"] == 1
    assert compute_features([], normal, normal)["unusual_hour_flag"] == 0
    assert compute_features([], late, late)["unusual_hour_flag"] == 1
