from datetime import datetime, timezone
from typing import List, Dict, Any

SEVERITY_THRESHOLDS = [
    ("critical", 8),
    ("high", 5),
    ("medium", 3),
    ("low", 0),
]

POWERSHELL_NAMES = frozenset({
    "powershell.exe", "pwsh.exe", "powershell_ise.exe",
})


def _to_utc(dt: Any) -> datetime:
    """Normalize naive/aware datetimes to timezone-aware UTC."""
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def _same_host_recent_anomalies(
    alert: Dict, recent: List[Dict], window_sec: int = 900,
) -> int:
    count = 0
    alert_ts = _to_utc(alert.get("created_at"))
    for a in recent:
        if not a.get("is_anomaly"):
            continue
        a_ts = _to_utc(a.get("created_at"))
        if abs((alert_ts - a_ts).total_seconds()) <= window_sec:
            count += 1
    return count


class CorrelationEngine:
    """Transparent rules + scoring correlation layer (10 rules)."""

    def evaluate(
        self,
        alert_data: Dict[str, Any],
        recent_alerts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        risk = 0
        triggered: list[str] = []
        features = alert_data.get("features", {})
        context = alert_data.get("context", {})

        # --- Original rules ---

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
            recent_alerts, key=lambda x: _to_utc(x.get("created_at")),
        ):
            consecutive = consecutive + 1 if a.get("is_anomaly") else 0
        if consecutive >= 3:
            risk += 2
            triggered.append("consecutive_low_confidence_escalation")

        # --- New rules ---

        new_procs = {p.lower() for p in (context.get("top_new_processes") or [])}
        if (
            features.get("new_process_count", 0) > 2
            and new_procs & POWERSHELL_NAMES
        ):
            risk += 2
            triggered.append("powershell_encoded_command")

        if features.get("sensitive_file_access_count", 0) > 0:
            risk += 3
            triggered.append("credential_access_indicator")

        if (
            features.get("unique_dest_ips", 0) > 5
            and features.get("privileged_process_count", 0) > 0
        ):
            risk += 2
            triggered.append("lateral_movement_indicator")

        if (
            features.get("dns_query_count", 0) > 20
            and features.get("outbound_conn_count", 0) > 5
        ):
            risk += 2
            triggered.append("c2_beaconing")

        if (
            features.get("unusual_hour_flag", 0)
            and alert_data.get("anomaly_score", 0) > 0.3
        ):
            risk += 1
            triggered.append("off_hours_escalation")

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
