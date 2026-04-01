from typing import Any


class AlertExplainer:
    """Deterministic template-based alert and incident explanation engine."""

    def explain_alert(
        self,
        host_id: str,
        anomaly_score: float,
        top_features: dict[str, float],
        features: dict[str, Any],
        baseline: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        parts: list[str] = []
        parts.append(
            f"Host {host_id} triggered an anomaly alert "
            f"(score {anomaly_score:.3f})."
        )

        if top_features:
            deviations = []
            for feat, z in sorted(top_features.items(), key=lambda x: x[1], reverse=True)[:3]:
                current = features.get(feat, 0)
                baseline_val = (baseline or {}).get(feat, "N/A")
                deviations.append(
                    f"  - {feat}: current={current}, baseline={baseline_val}, z-score={z:.2f}"
                )
            parts.append("Top deviating features:\n" + "\n".join(deviations))

        ctx = context or {}
        self._append_context_lines(parts, ctx)

        return {
            "summary": parts[0],
            "detail": "\n\n".join(parts),
        }

    def explain_incident(
        self,
        host_id: str,
        risk_score: float,
        severity: str,
        triggered_rules: list[str],
        alert_count: int,
        features: dict[str, Any],
        baseline: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        summary = (
            f"Host {host_id} reached {severity.upper()} severity "
            f"(risk score {risk_score}) based on {alert_count} correlated alert(s)."
        )
        detail_parts: list[str] = [summary]

        if triggered_rules:
            detail_parts.append(
                f"Triggered correlation rules: {', '.join(triggered_rules)}."
            )

        comparisons: list[str] = []
        for key in [
            "outbound_conn_count", "unique_dest_ports", "unique_dest_ips",
            "failed_login_count", "new_process_count", "bytes_sent",
        ]:
            current = features.get(key)
            base = (baseline or {}).get(key)
            if current is not None and base is not None:
                try:
                    if float(current) > float(base) * 1.5:
                        comparisons.append(f"  - {key}: {current} (baseline {base})")
                except (ValueError, TypeError):
                    pass

        if comparisons:
            detail_parts.append(
                "Notable deviations from baseline:\n" + "\n".join(comparisons)
            )

        ctx = context or {}
        self._append_context_lines(detail_parts, ctx)

        actions = self._suggest_actions(severity, triggered_rules, features)

        return {
            "summary": summary,
            "explanation": "\n\n".join(detail_parts),
            "suggested_actions": "\n".join(actions),
        }

    @staticmethod
    def _append_context_lines(parts: list[str], ctx: dict[str, Any]):
        top_procs = ctx.get("top_new_processes", [])
        if top_procs:
            parts.append(
                "New processes observed: " + ", ".join(top_procs[:5])
            )

        top_connected = ctx.get("top_connected_processes", {})
        if top_connected:
            conn_info = [
                f"{name} ({count} conns)"
                for name, count in list(top_connected.items())[:5]
            ]
            parts.append("Top connected processes: " + ", ".join(conn_info))

    def _suggest_actions(
        self, severity: str, rules: list[str], features: dict[str, Any],
    ) -> list[str]:
        actions: list[str] = []
        if "high_anomaly_score" in rules or severity in ("high", "critical"):
            actions.append("- Investigate the host immediately for signs of compromise.")
        if "login_plus_process_anomaly" in rules:
            actions.append(
                "- Review recent login attempts and new process activity "
                "for unauthorized access."
            )
        if "unusual_port_spread" in rules:
            actions.append(
                "- Check outbound connections for data exfiltration or C2 communication."
            )
        if "repeated_anomaly_15min" in rules:
            actions.append(
                "- Correlate with other hosts to determine if lateral movement is occurring."
            )
        if "consecutive_low_confidence_escalation" in rules:
            actions.append(
                "- Review the pattern of consecutive anomalies for slow-burn attack indicators."
            )
        if not actions:
            actions.append("- Continue monitoring; no immediate action required.")
        return actions
