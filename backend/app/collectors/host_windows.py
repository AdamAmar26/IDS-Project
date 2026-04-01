import logging
import socket
import subprocess
import json
from datetime import datetime, timezone
from typing import List, Dict, Any

import psutil

logger = logging.getLogger(__name__)


def _resolve_pid_name(pid: int | None) -> str:
    if pid is None or pid == 0:
        return ""
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ""


class WindowsHostCollector:
    """Collects host telemetry on Windows: processes, CPU/memory, logins, connections."""

    def __init__(self, host_id: str | None = None):
        self.host_id = host_id or socket.gethostname()

        # Pre-populate PIDs so the first real tick only sees truly new processes
        self._known_pids: set[int] = set()
        self._warm_up_pids()

        self._last_login_check = datetime.now(timezone.utc)
        self._known_users: set[str] = {u.name for u in psutil.users()}
        self.security_log_available = self._check_security_log()

        try:
            self._last_net_io = psutil.net_io_counters()
        except Exception:
            self._last_net_io = None

    def _warm_up_pids(self):
        for proc in psutil.process_iter(["pid"]):
            try:
                self._known_pids.add(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        logger.info("Pre-populated %d known PIDs", len(self._known_pids))

    def _check_security_log(self) -> bool:
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 'Get-WinEvent -LogName Security -MaxEvents 1 '
                 '-ErrorAction Stop | Out-Null; Write-Output "OK"'],
                capture_output=True, text=True, timeout=10,
            )
            ok = "OK" in result.stdout
            if not ok:
                logger.warning(
                    "Security event log NOT accessible — run as Administrator "
                    "for full login telemetry.  Falling back to psutil.users()."
                )
            else:
                logger.info("Security event log access confirmed")
            return ok
        except Exception as exc:
            logger.warning("Security log probe failed (%s); using fallback", exc)
            return False

    # ------------------------------------------------------------------
    # Process telemetry
    # ------------------------------------------------------------------

    def collect_processes(self) -> List[Dict[str, Any]]:
        events: list[dict[str, Any]] = []
        current_pids: set[int] = set()
        cpu_samples: list[float] = []

        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)
                cpu_samples.append(info.get("cpu_percent") or 0.0)
                if pid not in self._known_pids:
                    events.append({
                        "type": "new_process",
                        "pid": pid,
                        "name": info.get("name", ""),
                        "cpu_percent": info.get("cpu_percent") or 0.0,
                        "memory_percent": info.get("memory_percent") or 0.0,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self._known_pids = current_pids

        events.append({
            "type": "system_stats",
            "cpu_percent": psutil.cpu_percent(interval=0),
            "memory_percent": psutil.virtual_memory().percent,
            "process_count": len(current_pids),
            "avg_process_cpu": (sum(cpu_samples) / len(cpu_samples)) if cpu_samples else 0.0,
        })
        return events

    # ------------------------------------------------------------------
    # Network connection metadata + byte counters
    # ------------------------------------------------------------------

    def collect_connections(self) -> List[Dict[str, Any]]:
        events: list[dict[str, Any]] = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr:
                    events.append({
                        "type": "connection",
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote_ip": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "status": conn.status,
                        "pid": conn.pid,
                        "process_name": _resolve_pid_name(conn.pid),
                    })
        except (psutil.AccessDenied, OSError) as exc:
            logger.debug("Connection collection limited: %s", exc)

        try:
            current_io = psutil.net_io_counters()
            if self._last_net_io is not None:
                events.append({
                    "type": "net_io",
                    "bytes_sent": current_io.bytes_sent - self._last_net_io.bytes_sent,
                    "bytes_received": current_io.bytes_recv - self._last_net_io.bytes_recv,
                })
            self._last_net_io = current_io
        except Exception as exc:
            logger.debug("Net IO collection failed: %s", exc)

        return events

    # ------------------------------------------------------------------
    # Login / admin / UAC telemetry
    # ------------------------------------------------------------------

    def collect_logins(self) -> List[Dict[str, Any]]:
        events: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc)
        since = self._last_login_check
        self._last_login_check = now

        if self.security_log_available:
            events.extend(self._collect_logins_evtlog(since))
            events.extend(self._collect_uac_events(since))

        events.extend(self._collect_logins_psutil())
        return events

    def _collect_logins_evtlog(self, since: datetime) -> List[Dict[str, Any]]:
        events: list[dict[str, Any]] = []
        event_ids = {
            4624: "login_success",
            4625: "login_failure",
            4672: "admin_activity",
        }
        for eid, label in event_ids.items():
            try:
                ps_cmd = (
                    f'Get-WinEvent -FilterHashtable @{{LogName="Security";ID={eid};'
                    f'StartTime="{since.strftime("%Y-%m-%dT%H:%M:%S")}"}} '
                    f'-MaxEvents 50 -ErrorAction SilentlyContinue | '
                    f'Select-Object TimeCreated,Id | ConvertTo-Json -Compress'
                )
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    capture_output=True, text=True, timeout=10,
                )
                if result.stdout.strip():
                    data = json.loads(result.stdout)
                    if isinstance(data, dict):
                        data = [data]
                    for _ in data:
                        events.append({"type": label, "event_id": eid})
            except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as exc:
                logger.debug("Login event query for %s failed: %s", eid, exc)
        return events

    def _collect_uac_events(self, since: datetime) -> List[Dict[str, Any]]:
        """Detect elevated process creation (event 4688 with full-admin token)."""
        events: list[dict[str, Any]] = []
        try:
            ps_cmd = (
                f'Get-WinEvent -FilterHashtable @{{LogName="Security";ID=4688;'
                f'StartTime="{since.strftime("%Y-%m-%dT%H:%M:%S")}"}} '
                f'-MaxEvents 50 -ErrorAction SilentlyContinue | '
                f'Where-Object {{ $_.Message -match "Token Elevation Type.*%%1937" }} | '
                f'Select-Object TimeCreated | ConvertTo-Json -Compress'
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for _ in data:
                    events.append({"type": "elevated_process", "event_id": 4688})
        except Exception as exc:
            logger.debug("UAC event query failed: %s", exc)
        return events

    def _collect_logins_psutil(self) -> List[Dict[str, Any]]:
        """Lightweight fallback: detect new user sessions via psutil."""
        events: list[dict[str, Any]] = []
        current_users = {u.name for u in psutil.users()}
        for user in current_users - self._known_users:
            events.append({"type": "login_success", "user": user, "source": "psutil"})
        self._known_users = current_users
        return events

    # ------------------------------------------------------------------
    # Unified collection
    # ------------------------------------------------------------------

    def collect_all(self) -> List[Dict[str, Any]]:
        ts = datetime.now(timezone.utc).isoformat()
        all_events: list[dict[str, Any]] = []
        for event in self.collect_processes() + self.collect_connections() + self.collect_logins():
            event["timestamp"] = ts
            event["host_id"] = self.host_id
            all_events.append(event)
        return all_events
