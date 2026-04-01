from datetime import datetime, timezone
from typing import List, Dict, Any

SEVERITY_THRESHOLDS = [
    ("critical", 8),
    ("high", 5),
    ("medium", 3),
    ("low", 0),
]


def _same_host_recent_anomalies(
    alert: Dict, recent: List[Dict], window_sec: int = 900,
) -> int:
    count = 0
    alert_ts = alert.get("created_at") or datetime.now(timezone.utc)
    for a in recent:
        if not a.get("is_anomaly"):
            continue
        a_ts = a.get("created_at") or datetime.now(timezone.utc)
        if abs((alert_ts - a_ts).total_seconds()) <= window_sec:
            count += 1
    return count


class CorrelationEngine:
    """Transparent rules + scoring correlation layer."""

    def evaluate(
        self,
        alert_data: Dict[str, Any],
        recent_alerts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        risk = 0
        triggered: list[str] = []
        features = alert_data.get("features", {})

        if alert_data.get("anomaly_score", 0) > 0.3:
            risk += 2
            triggered.append("high_anomaly_score")

        if _same_host_recent_anomalies(alert_data, recent_alerts) >= 2:
            risk += 2
            triggered.append("repeated_anomaly_15min")

        if features.get("unique_dest_ports", 0) > 10:
            risk += 1
            triggered.append("unusual_port_spread")

        if (
            features.get("failed_login_count", 0) > 0
            and features.get("new_process_count", 0) > 3
        ):
            risk += 3
            triggered.append("login_plus_process_anomaly")

        consecutive = 0
        for a in sorted(
            recent_alerts, key=lambda x: x.get("created_at", datetime.min),
        ):
            consecutive = consecutive + 1 if a.get("is_anomaly") else 0
        if consecutive >= 3:
            risk += 2
            triggered.append("consecutive_low_confidence_escalation")

        severity = "low"
        for sev, threshold in SEVERITY_THRESHOLDS:
            if risk >= threshold:
                severity = sev
                break

        return {
            "risk_score": risk,
            "severity": severity,
            "triggered_rules": triggered,
            "should_create_incident": risk >= 3,
        }
