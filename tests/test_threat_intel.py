from app.threat_intel.enricher import ThreatIntelEnricher, _is_private


def test_private_ips():
    assert _is_private("192.168.1.1")
    assert _is_private("10.0.0.1")
    assert _is_private("127.0.0.1")
    assert _is_private("172.16.0.1")
    assert not _is_private("8.8.8.8")


def test_invalid_ip_treated_as_private():
    assert _is_private("not-an-ip")


def test_local_blocklist_hit():
    enricher = ThreatIntelEnricher()
    hits = enricher.check_local(["185.220.101.1"])
    if enricher._blocklist:
        assert len(hits) == 1
        assert hits[0]["ip"] == "185.220.101.1"
        assert hits[0]["source"] == "local_blocklist"


def test_local_blocklist_miss():
    enricher = ThreatIntelEnricher()
    hits = enricher.check_local(["8.8.8.8"])
    assert len(hits) == 0


def test_private_ips_skipped():
    enricher = ThreatIntelEnricher()
    hits = enricher.check_local(["192.168.1.1", "10.0.0.1"])
    assert len(hits) == 0


def test_empty_ip_list():
    enricher = ThreatIntelEnricher()
    hits = enricher.check_local([])
    assert hits == []
