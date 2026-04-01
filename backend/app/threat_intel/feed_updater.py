"""Automated blocklist updates from open threat intelligence feeds.

Runs as a background thread that refreshes the local blocklist daily by
downloading and merging IPs from Emerging Threats and Feodo Tracker.
"""

import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Set

import httpx

logger = logging.getLogger(__name__)

FEEDS = [
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
]

BLOCKLIST_PATH = Path(__file__).parent / "blocklist.txt"
UPDATE_INTERVAL_SECONDS = int(os.environ.get("IDS_FEED_UPDATE_INTERVAL", "86400"))

_LOCAL_HEADER = "# Local additions — lines below this marker are preserved across updates\n"


def _parse_blocklist(text: str) -> Set[str]:
    ips: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            if stripped[0].isdigit() or ":" in stripped:
                ip = stripped.split()[0]
                ips.add(ip)
    return ips


def _load_local_additions() -> Set[str]:
    """Extract IPs that were manually added to the blocklist (below the marker)."""
    if not BLOCKLIST_PATH.exists():
        return set()
    text = BLOCKLIST_PATH.read_text()
    if _LOCAL_HEADER.strip() in text:
        _, _, local_section = text.partition(_LOCAL_HEADER.strip())
        return _parse_blocklist(local_section)
    return set()


def _download_feed(url: str, timeout: float = 30.0) -> Set[str]:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            ips = _parse_blocklist(resp.text)
            logger.info("Downloaded %d IPs from %s", len(ips), url)
            return ips
    except Exception as exc:
        logger.warning("Failed to download feed %s: %s", url, exc)
        return set()


def update_blocklist() -> int:
    """Download feeds, merge with local additions, atomic-write the blocklist.

    Returns the total number of unique IPs in the updated list.
    """
    all_ips: set[str] = set()
    for url in FEEDS:
        all_ips |= _download_feed(url)

    local_additions = _load_local_additions()
    all_ips |= local_additions

    if not all_ips:
        logger.warning("No IPs obtained from any feed — keeping existing blocklist")
        return 0

    parent = BLOCKLIST_PATH.parent
    try:
        fd, tmp_path = tempfile.mkstemp(dir=parent, suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("# IDS Threat Intelligence Blocklist — auto-updated\n")
            f.write(f"# Total IPs: {len(all_ips)}\n")
            f.write("#\n")
            for ip in sorted(all_ips - local_additions):
                f.write(ip + "\n")
            if local_additions:
                f.write("\n")
                f.write(_LOCAL_HEADER)
                for ip in sorted(local_additions):
                    f.write(ip + "\n")

        os.replace(tmp_path, BLOCKLIST_PATH)
        logger.info("Blocklist updated: %d total IPs (%d local)", len(all_ips), len(local_additions))
        return len(all_ips)
    except Exception:
        logger.exception("Atomic blocklist swap failed")
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return 0


class FeedUpdateScheduler:
    """Runs `update_blocklist()` on a configurable interval in a daemon thread."""

    def __init__(self, interval_seconds: int = UPDATE_INTERVAL_SECONDS):
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Feed updater started (interval=%ds)", self._interval)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self):
        while not self._stop.is_set():
            try:
                update_blocklist()
            except Exception:
                logger.exception("Feed update cycle failed")
            self._stop.wait(self._interval)
