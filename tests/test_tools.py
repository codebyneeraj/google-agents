import pytest
from src.tools.soc_tools import check_threat_intel, lookup_user_activity, isolate_host

def test_check_threat_intel_malicious():
    result = check_threat_intel("198.51.100.45")
    assert result["reputation"] == "MALICIOUS"
    assert result["threat_score"] > 80
    assert result["actor"] == "APT-29 (Cozy Bear)"

def test_check_threat_intel_benign():
    result = check_threat_intel("8.8.8.8")
    assert result["reputation"] == "BENIGN"
    assert result["threat_score"] == 0

def test_check_threat_intel_unknown():
    result = check_threat_intel("192.0.2.1")
    assert result["reputation"] == "UNKNOWN"

def test_lookup_user_activity_found():
    result = lookup_user_activity("john.doe@enterprise.corp")
    assert result["risk_level"] == "CRITICAL"
    assert len(result["recent_logins"]) > 0

def test_isolate_host():
    result = isolate_host("SRV-FINANCE-01", reason="Malware containment")
    assert result["status"] == "SUCCESS"
    assert result["action"] == "QUARANTINED"
