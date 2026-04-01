"""Network-level helpers consumed by the feature pipeline."""

from typing import Any


def summarize_connections(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive network features from raw connection and net_io events."""
    dest_ips: set[str] = set()
    dest_ports: set[int] = set()
    outbound_count = 0
    bytes_sent = 0.0
    bytes_received = 0.0

    for ev in events:
        etype = ev.get("type", "")
        if etype == "connection":
            outbound_count += 1
            if ev.get("remote_ip"):
                dest_ips.add(ev["remote_ip"])
            if ev.get("remote_port"):
                dest_ports.add(ev["remote_port"])
        elif etype == "net_io":
            bytes_sent += ev.get("bytes_sent", 0)
            bytes_received += ev.get("bytes_received", 0)

    return {
        "unique_dest_ips": len(dest_ips),
        "unique_dest_ports": len(dest_ports),
        "outbound_conn_count": outbound_count,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "inbound_outbound_ratio": (bytes_received / bytes_sent) if bytes_sent > 0 else 0.0,
    }
