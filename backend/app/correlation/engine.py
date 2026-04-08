from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from app.config import CORRELATION_RULES_PATH, FEATURE_NAMES

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
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    return datetime.now(UTC)


def _same_host_recent_anomalies(
    alert: dict, recent: list[dict], window_sec: int = 900,
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
    def __init__(self):
        self.dynamic_rules: list[dict[str, Any]] = []
        self.reload_rules()

    def reload_rules(self) -> int:
        path = Path(CORRELATION_RULES_PATH)
        if not path.exists():
            self.dynamic_rules = []
            return 0
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self.dynamic_rules = list(data.get("rules", []))
        return len(self.dynamic_rules)

    @staticmethod
    def _resolve_value(
        rule_value: Any,
        features: dict[str, Any],
        context: dict[str, Any],
        alert_data: dict[str, Any],
    ) -> Any:
        if isinstance(rule_value, str) and rule_value.startswith("feature:"):
            key = rule_value.split(":", 1)[1]
            if key in FEATURE_NAMES:
                return features.get(key)
        if isinstance(rule_value, str) and rule_value.startswith("context:"):
            key = rule_value.split(":", 1)[1]
            return context.get(key)
        if rule_value == "anomaly_score":
            return alert_data.get("anomaly_score", 0)
        return rule_value

    def _apply_dynamic_rules(
        self,
        alert_data: dict[str, Any],
        features: dict[str, Any],
        context: dict[str, Any],
        risk: int,
        triggered: list[str],
    ) -> int:
        for rule in self.dynamic_rules:
            op = rule.get("op", "gt")
            left = self._resolve_value(rule.get("left"), features, context, alert_data)
            right = self._resolve_value(rule.get("right"), features, context, alert_data)
            matched = False
            if op == "gt":
                matched = (left or 0) > (right or 0)
            elif op == "gte":
                matched = (left or 0) >= (right or 0)
            elif op == "eq":
                matched = left == right
            elif op == "contains":
                matched = isinstance(left, (list, set, tuple)) and right in left
            if matched:
                risk += int(rule.get("risk_delta", 1))
                triggered.append(str(rule.get("name", "dynamic_rule")))
        return risk

    def evaluate(
        self,
        alert_data: dict[str, Any],
        recent_alerts: list[dict[str, Any]],
    ) -> dict[str, Any]:
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

        risk = self._apply_dynamic_rules(alert_data, features, context, risk, triggered)

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
