"""Maps IDS correlation rules to MITRE ATT&CK tactics and techniques.

Reference: https://attack.mitre.org/
"""


TECHNIQUE_DB: dict[str, dict] = {
    # --- Original techniques ---
    "T1078": {
        "name": "Valid Accounts",
        "tactics": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactics": ["TA0011"],
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactics": ["TA0007"],
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1110": {
        "name": "Brute Force",
        "tactics": ["TA0006"],
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactics": ["TA0002"],
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactics": ["TA0005"],
        "url": "https://attack.mitre.org/techniques/T1562/",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactics": ["TA0010"],
        "url": "https://attack.mitre.org/techniques/T1048/",
    },
    "T1021": {
        "name": "Remote Services",
        "tactics": ["TA0008"],
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    # --- New techniques ---
    "T1003": {
        "name": "OS Credential Dumping",
        "tactics": ["TA0006"],
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1055": {
        "name": "Process Injection",
        "tactics": ["TA0005", "TA0004"],
        "url": "https://attack.mitre.org/techniques/T1055/",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactics": ["TA0002", "TA0003", "TA0004"],
        "url": "https://attack.mitre.org/techniques/T1053/",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactics": ["TA0003", "TA0004"],
        "url": "https://attack.mitre.org/techniques/T1547/",
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactics": ["TA0005"],
        "url": "https://attack.mitre.org/techniques/T1070/",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactics": ["TA0002"],
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactics": ["TA0002"],
        "url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ["TA0011"],
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactics": ["TA0040"],
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactics": ["TA0040"],
        "url": "https://attack.mitre.org/techniques/T1490/",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactics": ["TA0011"],
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactics": ["TA0011"],
        "url": "https://attack.mitre.org/techniques/T1571/",
    },
}

TACTIC_DB: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

KILL_CHAIN_ORDER = [
    "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0007", "TA0008", "TA0009", "TA0010",
    "TA0011", "TA0040",
]

RULE_TO_TECHNIQUES: dict[str, list[str]] = {
    "high_anomaly_score": ["T1059", "T1078"],
    "repeated_anomaly_15min": ["T1021", "T1110"],
    "unusual_port_spread": ["T1046", "T1048", "T1071", "T1571"],
    "login_plus_process_anomaly": ["T1078", "T1110", "T1059"],
    "consecutive_low_confidence_escalation": ["T1562"],
    "powershell_encoded_command": ["T1059.001", "T1059"],
    "credential_access_indicator": ["T1003", "T1078"],
    "lateral_movement_indicator": ["T1021", "T1046", "T1105"],
    "c2_beaconing": ["T1071.001", "T1105", "T1571"],
    "off_hours_escalation": ["T1053", "T1547"],
}


class MitreMapper:
    """Resolve triggered correlation rules into ATT&CK techniques and tactics."""

    def map_rules(self, triggered_rules: list[str]) -> dict:
        techniques: dict[str, dict] = {}
        tactic_ids: set[str] = set()

        for rule in triggered_rules:
            for tech_id in RULE_TO_TECHNIQUES.get(rule, []):
                if tech_id not in techniques:
                    info = TECHNIQUE_DB.get(tech_id, {})
                    techniques[tech_id] = {
                        "id": tech_id,
                        "name": info.get("name", tech_id),
                        "url": info.get("url", ""),
                        "tactics": info.get("tactics", []),
                        "triggered_by": [],
                    }
                techniques[tech_id]["triggered_by"].append(rule)
                tactic_ids.update(TECHNIQUE_DB.get(tech_id, {}).get("tactics", []))

        tactics = [
            {"id": tid, "name": TACTIC_DB.get(tid, tid)}
            for tid in sorted(tactic_ids)
        ]

        kill_chain_phase = self._determine_kill_chain_phase(tactic_ids)

        return {
            "techniques": list(techniques.values()),
            "tactics": tactics,
            "kill_chain_phase": kill_chain_phase,
        }

    @staticmethod
    def _determine_kill_chain_phase(tactic_ids: set[str]) -> str:
        """Return the furthest-progressed kill-chain stage observed."""
        furthest = None
        for tid in KILL_CHAIN_ORDER:
            if tid in tactic_ids:
                furthest = tid
        if furthest:
            return f"{furthest} ({TACTIC_DB.get(furthest, furthest)})"
        return "unknown"
