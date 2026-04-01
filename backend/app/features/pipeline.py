from datetime import datetime
from typing import Dict, List, Any

from app.config import FEATURE_NAMES
from app.collectors.network import summarize_connections


def compute_features(
    events: List[Dict[str, Any]],
    window_start: datetime,
    window_end: datetime,
) -> Dict[str, Any]:
    """Turn a batch of raw events into a single feature vector for one window."""
    features: dict[str, Any] = {name: 0 for name in FEATURE_NAMES}
    cpu_values: list[float] = []

    for ev in events:
        etype = ev.get("type", "")
        if etype == "login_failure":
            features["failed_login_count"] += 1
        elif etype == "login_success":
            features["successful_login_count"] += 1
        elif etype == "new_process":
            features["new_process_count"] += 1
            cpu_values.append(ev.get("cpu_percent", 0.0))
        elif etype == "system_stats":
            cpu_values.append(ev.get("cpu_percent", 0.0))

    net = summarize_connections(events)
    features["unique_dest_ips"] = net["unique_dest_ips"]
    features["unique_dest_ports"] = net["unique_dest_ports"]
    features["outbound_conn_count"] = net["outbound_conn_count"]
    features["bytes_sent"] = net["bytes_sent"]
    features["bytes_received"] = net["bytes_received"]
    features["inbound_outbound_ratio"] = net["inbound_outbound_ratio"]

    features["avg_process_cpu"] = (
        (sum(cpu_values) / len(cpu_values)) if cpu_values else 0.0
    )

    hour = window_start.hour
    features["unusual_hour_flag"] = 1 if (hour < 6 or hour > 22) else 0

    return features


def compute_context(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract non-ML context from raw events for enriching explanations."""
    new_process_names: list[str] = []
    connected_procs: dict[str, int] = {}

    for ev in events:
        etype = ev.get("type", "")
        if etype == "new_process":
            name = ev.get("name", "")
            if name:
                new_process_names.append(name)
        elif etype == "connection":
            pname = ev.get("process_name", "")
            if pname:
                connected_procs[pname] = connected_procs.get(pname, 0) + 1

    top_connected = dict(
        sorted(connected_procs.items(), key=lambda x: x[1], reverse=True)[:10]
    )

    return {
        "top_new_processes": list(dict.fromkeys(new_process_names))[:20],
        "top_connected_processes": top_connected,
    }
