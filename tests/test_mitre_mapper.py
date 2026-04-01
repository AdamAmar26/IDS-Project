from app.mitre.mapper import MitreMapper


def test_empty_rules():
    mapper = MitreMapper()
    result = mapper.map_rules([])
    assert result["techniques"] == []
    assert result["tactics"] == []


def test_login_plus_process_maps_to_techniques():
    mapper = MitreMapper()
    result = mapper.map_rules(["login_plus_process_anomaly"])
    tech_ids = {t["id"] for t in result["techniques"]}
    assert "T1078" in tech_ids
    assert "T1110" in tech_ids
    assert "T1059" in tech_ids


def test_unusual_port_spread_maps_to_exfiltration():
    mapper = MitreMapper()
    result = mapper.map_rules(["unusual_port_spread"])
    tactic_ids = {t["id"] for t in result["tactics"]}
    assert "TA0010" in tactic_ids or "TA0011" in tactic_ids


def test_all_rules_have_mappings():
    mapper = MitreMapper()
    all_rules = [
        "high_anomaly_score",
        "repeated_anomaly_15min",
        "unusual_port_spread",
        "login_plus_process_anomaly",
        "consecutive_low_confidence_escalation",
    ]
    result = mapper.map_rules(all_rules)
    assert len(result["techniques"]) > 0
    assert len(result["tactics"]) > 0


def test_technique_has_url():
    mapper = MitreMapper()
    result = mapper.map_rules(["high_anomaly_score"])
    for tech in result["techniques"]:
        assert tech["url"].startswith("https://attack.mitre.org/")


def test_triggered_by_tracked():
    mapper = MitreMapper()
    result = mapper.map_rules(["high_anomaly_score", "login_plus_process_anomaly"])
    for tech in result["techniques"]:
        assert len(tech["triggered_by"]) >= 1
        assert all(isinstance(r, str) for r in tech["triggered_by"])
