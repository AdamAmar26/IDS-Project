"""Threat intelligence enrichment via local blocklist and optional AbuseIPDB."""

import ipaddress
import logging
import os
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

ABUSEIPDB_KEY = os.environ.get("IDS_ABUSEIPDB_KEY", "")
BLOCKLIST_PATH = Path(__file__).parent / "blocklist.txt"

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True


class ThreatIntelEnricher:
    """Check IPs against a local blocklist and optionally AbuseIPDB."""

    def __init__(self):
        self._blocklist: set[str] = set()
        self._load_blocklist()

    def _load_blocklist(self):
        if BLOCKLIST_PATH.exists():
            try:
                for line in BLOCKLIST_PATH.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._blocklist.add(line)
                logger.info("Loaded %d IPs from local blocklist", len(self._blocklist))
            except Exception as exc:
                logger.warning("Could not load blocklist: %s", exc)

    def check_local(self, ips: list[str]) -> list[dict]:
        hits: list[dict] = []
        for ip in ips:
            if _is_private(ip):
                continue
            if ip in self._blocklist:
                hits.append({
                    "ip": ip,
                    "source": "local_blocklist",
                    "confidence": 90,
                    "detail": "IP found in local threat intelligence blocklist",
                })
        return hits

    async def check_abuseipdb(self, ips: list[str]) -> list[dict]:
        if not ABUSEIPDB_KEY:
            return []
        hits: list[dict] = []
        async with httpx.AsyncClient(timeout=5.0) as client:
            for ip in ips:
                if _is_private(ip):
                    continue
                try:
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": ip, "maxAgeInDays": "90"},
                        headers={
                            "Accept": "application/json",
                            "Key": ABUSEIPDB_KEY,
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        score = data.get("abuseConfidenceScore", 0)
                        if score >= 25:
                            hits.append({
                                "ip": ip,
                                "source": "abuseipdb",
                                "confidence": score,
                                "detail": (
                                    f"AbuseIPDB score {score}%, "
                                    f"{data.get('totalReports', 0)} reports"
                                ),
                            })
                except Exception as exc:
                    logger.warning("AbuseIPDB check failed for %s: %s", ip, exc)
        return hits

    async def enrich(self, ips: list[str]) -> list[dict]:
        """Run all enrichment sources and return merged hits."""
        hits = self.check_local(ips)
        abuseipdb_hits = await self.check_abuseipdb(ips)
        seen = {h["ip"] for h in hits}
        for h in abuseipdb_hits:
            if h["ip"] not in seen:
                hits.append(h)
                seen.add(h["ip"])
        return hits
