import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from src.observability.logger import log_audit_event

# Mock Threat Intelligence Database
THREAT_INTEL_DB = {
    "198.51.100.45": {
        "reputation": "MALICIOUS",
        "threat_score": 94,
        "category": "Command and Control (C2) / Brute Force",
        "actor": "APT-29 (Cozy Bear)",
        "country": "RU",
        "last_seen": "2026-08-14T22:15:00Z",
        "associated_cve": ["CVE-2024-21413"],
    },
    "203.0.113.195": {
        "reputation": "SUSPICIOUS",
        "threat_score": 68,
        "category": "Port Scanning / Tor Exit Node",
        "actor": "Unknown",
        "country": "NL",
        "last_seen": "2026-08-15T01:30:00Z",
        "associated_cve": [],
    },
    "8.8.8.8": {
        "reputation": "BENIGN",
        "threat_score": 0,
        "category": "Public DNS Resolver (Google)",
        "actor": "Google LLC",
        "country": "US",
        "last_seen": "2026-08-15T00:00:00Z",
        "associated_cve": [],
    },
    "evil-payload.exe": {
        "reputation": "MALICIOUS",
        "threat_score": 99,
        "category": "Ransomware Dropper (LockBit 4.0)",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "signatures_matched": 48,
    }
}

# Mock Active Directory / IAM Log Database
USER_ACTIVITY_DB = {
    "john.doe@enterprise.corp": {
        "user_id": "usr_99182",
        "role": "Financial Analyst",
        "mfa_enabled": True,
        "recent_logins": [
            {"ip": "198.51.100.45", "status": "FAILED", "location": "Moscow, RU", "time": "2026-08-15T04:12:00Z"},
            {"ip": "198.51.100.45", "status": "FAILED", "location": "Moscow, RU", "time": "2026-08-15T04:12:45Z"},
            {"ip": "198.51.100.45", "status": "SUCCESS", "location": "Moscow, RU", "time": "2026-08-15T04:14:10Z"},
        ],
        "risk_level": "CRITICAL",
    },
    "alice.smith@enterprise.corp": {
        "user_id": "usr_44021",
        "role": "DevOps Engineer",
        "mfa_enabled": True,
        "recent_logins": [
            {"ip": "10.0.4.12", "status": "SUCCESS", "location": "San Jose, US", "time": "2026-08-15T08:00:00Z"}
        ],
        "risk_level": "LOW",
    }
}

# Mock Endpoint Assets
HOST_INVENTORY = {
    "SRV-FINANCE-01": {"ip": "10.0.12.88", "status": "ONLINE", "os": "Windows Server 2022", "criticality": "HIGH"},
    "WKSTN-JDOE-04": {"ip": "10.0.12.92", "status": "ONLINE", "os": "Windows 11 Enterprise", "criticality": "MEDIUM"},
}

# Tool Execution Ledger
ACTIVE_TOOL_EXECUTIONS: List[Dict[str, Any]] = []

def get_and_clear_tool_executions() -> List[Dict[str, Any]]:
    global ACTIVE_TOOL_EXECUTIONS
    execs = list(ACTIVE_TOOL_EXECUTIONS)
    ACTIVE_TOOL_EXECUTIONS.clear()
    return execs

def check_threat_intel(indicator: str, trace_id: str = None) -> Dict[str, Any]:
    """Queries enterprise threat intelligence feeds for IP addresses, domain names, or file hashes."""
    clean_indicator = indicator.strip()
    result = THREAT_INTEL_DB.get(clean_indicator)
    if not result:
        result = {
            "indicator": clean_indicator,
            "reputation": "UNKNOWN",
            "threat_score": 15,
            "category": "Unindexed Indicator",
            "message": "Indicator not currently listed in threat intelligence blacklists."
        }
    else:
        result = {"indicator": clean_indicator, **result}

    ACTIVE_TOOL_EXECUTIONS.append({"tool": "check_threat_intel", "input": clean_indicator, "result": result})
    log_audit_event(
        event_type="TOOL_EXECUTION",
        action="CHECK_THREAT_INTEL",
        status="SUCCESS",
        trace_id=trace_id,
        details={"indicator": clean_indicator, "reputation": result.get("reputation")},
    )
    return result

def lookup_user_activity(user_identifier: str, trace_id: str = None) -> Dict[str, Any]:
    """Retrieves authentication logs, failed login anomalies, and MFA telemetry for a user."""
    clean_id = user_identifier.strip().lower()
    for email, profile in USER_ACTIVITY_DB.items():
        if clean_id in (email.lower(), profile["user_id"].lower()):
            data = {"email": email, **profile}
            ACTIVE_TOOL_EXECUTIONS.append({"tool": "lookup_user_activity", "input": clean_id, "result": data})
            log_audit_event(
                event_type="TOOL_EXECUTION",
                action="LOOKUP_USER_ACTIVITY",
                status="FOUND",
                trace_id=trace_id,
                details={"user": email, "risk_level": profile["risk_level"]},
            )
            return data

    res = {"user_identifier": user_identifier, "status": "NOT_FOUND", "risk_level": "UNKNOWN"}
    ACTIVE_TOOL_EXECUTIONS.append({"tool": "lookup_user_activity", "input": clean_id, "result": res})
    log_audit_event(
        event_type="TOOL_EXECUTION",
        action="LOOKUP_USER_ACTIVITY",
        status="NOT_FOUND",
        trace_id=trace_id,
        details={"user": user_identifier},
    )
    return res

def isolate_host(host_id: str, reason: str, trace_id: str = None) -> Dict[str, Any]:
    """Executes network quarantine isolation on a compromised enterprise host (EDR action)."""
    clean_host = host_id.strip().upper()
    if clean_host in HOST_INVENTORY:
        HOST_INVENTORY[clean_host]["status"] = "ISOLATED"
        res = {
            "host_id": clean_host,
            "action": "QUARANTINED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "status": "SUCCESS",
        }
    else:
        res = {
            "host_id": host_id,
            "action": "QUARANTINE_ATTEMPT",
            "status": "HOST_NOT_FOUND",
            "message": f"Host '{host_id}' not found in active inventory."
        }

    ACTIVE_TOOL_EXECUTIONS.append({"tool": "isolate_host", "input": clean_host, "result": res})
    log_audit_event(
        event_type="DEFENSIVE_ACTION",
        action="ISOLATE_HOST",
        status=res["status"],
        trace_id=trace_id,
        details={"host_id": host_id, "reason": reason},
    )
    return res

def get_soc_tool_declarations() -> List[Dict[str, Any]]:
    """Returns Gemini function calling declarations for SOC tools."""
    return [
        {
            "name": "check_threat_intel",
            "description": "Inspects reputation, threat scores, and APT associations for an IP address, domain, or file hash.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "indicator": {
                        "type": "STRING",
                        "description": "The IP address, domain name, or file hash to check."
                    }
                },
                "required": ["indicator"]
            }
        },
        {
            "name": "lookup_user_activity",
            "description": "Checks IAM login logs, failed attempts, and MFA security status for a user email or ID.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "user_identifier": {
                        "type": "STRING",
                        "description": "Corporate email address or User ID."
                    }
                },
                "required": ["user_identifier"]
            }
        },
        {
            "name": "isolate_host",
            "description": "Quarantines a compromised host machine from the network.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "host_id": {
                        "type": "STRING",
                        "description": "The hostname or server ID (e.g. WKSTN-JDOE-04)."
                    },
                    "reason": {
                        "type": "STRING",
                        "description": "Justification for the isolation action."
                    }
                },
                "required": ["host_id", "reason"]
            }
        }
    ]
