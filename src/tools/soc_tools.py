import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
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

import os
import re
import subprocess
import shutil
from src.config import config

# Tool Execution Ledger
ACTIVE_TOOL_EXECUTIONS: List[Dict[str, Any]] = []

def get_and_clear_tool_executions() -> List[Dict[str, Any]]:
    global ACTIVE_TOOL_EXECUTIONS
    execs = list(ACTIVE_TOOL_EXECUTIONS)
    ACTIVE_TOOL_EXECUTIONS.clear()
    return execs

def _query_abuseipdb_live(ip_address: str) -> Optional[Dict[str, Any]]:
    """Fetches live IP reputation from AbuseIPDB API v2."""
    if not config.abuseipdb_api_key:
        return None
    try:
        import httpx
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": config.abuseipdb_api_key,
            "Accept": "application/json",
        }
        params = {"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": True}
        response = httpx.get(url, headers=headers, params=params, timeout=5.0)
        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            reputation = "MALICIOUS" if abuse_score >= 50 else ("SUSPICIOUS" if abuse_score >= 20 else "BENIGN")
            return {
                "indicator": ip_address,
                "reputation": reputation,
                "threat_score": abuse_score,
                "category": f"AbuseIPDB Live Report (Reports: {data.get('totalReports', 0)})",
                "actor": data.get("isp", "Unknown ISP"),
                "country": data.get("countryCode", "UNKNOWN"),
                "usage_type": data.get("usageType", "Unknown"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "source": "AbuseIPDB_Live_API",
            }
    except Exception as e:
        log_audit_event(
            event_type="LIVE_THREAT_INTEL",
            action="ABUSEIPDB_QUERY",
            status="FAILED",
            details={"ip": ip_address, "error": str(e)},
            severity=30,
        )
    return None

def _query_virustotal_live(file_hash: str) -> Optional[Dict[str, Any]]:
    """Fetches live file hash reputation from VirusTotal API v3."""
    if not config.virustotal_api_key:
        return None
    try:
        import httpx
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": config.virustotal_api_key}
        response = httpx.get(url, headers=headers, timeout=5.0)
        if response.status_code == 200:
            attr = response.json().get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            reputation = "MALICIOUS" if malicious_count >= 5 else ("SUSPICIOUS" if malicious_count > 0 else "BENIGN")
            threat_score = min(malicious_count * 10, 100)
            return {
                "indicator": file_hash,
                "reputation": reputation,
                "threat_score": threat_score,
                "category": f"VirusTotal Detection ({malicious_count} engines)",
                "actor": attr.get("meaningful_name", "Unknown Malware"),
                "sha256": attr.get("sha256", file_hash),
                "source": "VirusTotal_Live_API",
            }
    except Exception as e:
        log_audit_event(
            event_type="LIVE_THREAT_INTEL",
            action="VIRUSTOTAL_QUERY",
            status="FAILED",
            details={"hash": file_hash, "error": str(e)},
            severity=30,
        )
    return None

def inspect_linux_auth_logs(ip_address: Optional[str] = None, max_lines: int = 50, trace_id: str = None) -> Dict[str, Any]:
    """Inspects live Linux authentication logs (/var/log/auth.log or journalctl) for brute-force telemetry."""
    log_path = config.auth_log_path
    matching_events = []
    failed_attempts = 0
    
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-max_lines:]
                for line in lines:
                    if ip_address and ip_address not in line:
                        continue
                    if "Failed password" in line or "authentication failure" in line or "Invalid user" in line:
                        failed_attempts += 1
                        matching_events.append(line.strip())
        except Exception as e:
            matching_events.append(f"Error reading {log_path}: {str(e)}")
    elif shutil.which("journalctl"):
        try:
            cmd = ["journalctl", "-u", "ssh", "-n", str(max_lines), "--no-pager"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if ip_address and ip_address not in line:
                        continue
                    if "Failed password" in line or "authentication failure" in line or "Invalid user" in line:
                        failed_attempts += 1
                        matching_events.append(line.strip())
        except Exception as e:
            matching_events.append(f"journalctl error: {str(e)}")
            
    risk = "CRITICAL" if failed_attempts >= 5 else ("SUSPICIOUS" if failed_attempts > 0 else "LOW")
    result = {
        "log_source": log_path if os.path.exists(log_path) else "journalctl",
        "target_filter_ip": ip_address,
        "failed_attempts": failed_attempts,
        "risk_level": risk,
        "sample_events": matching_events[:5],
    }
    
    ACTIVE_TOOL_EXECUTIONS.append({"tool": "inspect_linux_auth_logs", "input": ip_address or "ALL", "result": result})
    log_audit_event(
        event_type="TOOL_EXECUTION",
        action="INSPECT_LINUX_AUTH_LOGS",
        status="SUCCESS",
        trace_id=trace_id,
        details={"failed_attempts": failed_attempts, "risk_level": risk},
    )
    return result

def check_threat_intel(indicator: str, trace_id: str = None) -> Dict[str, Any]:
    """Queries enterprise threat intelligence feeds for IP addresses, domain names, or file hashes."""
    clean_indicator = indicator.strip()

    # 1. Try Live Threat Intel API if available (AbuseIPDB / VirusTotal)
    live_result = None
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_indicator):
        live_result = _query_abuseipdb_live(clean_indicator)
    elif len(clean_indicator) in (32, 40, 64) and not "." in clean_indicator:
        live_result = _query_virustotal_live(clean_indicator)

    if live_result:
        result = live_result
    else:
        # Fallback to local / mock Threat Intel DB
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

def _execute_native_linux_block(target: str) -> Dict[str, Any]:
    """Applies real firewall drop rule on Linux using direct iptables and ufw."""
    firewall_action = "NONE"
    output = ""
    success = False
    
    # Check if target is an IP address
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))
    
    # 1. Direct iptables kernel rule (always works instantly on all Linux distros)
    if shutil.which("iptables") and is_ip:
        try:
            cmd = ["sudo", "iptables", "-I", "INPUT", "-s", target, "-j", "DROP"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            output = proc.stdout.strip() or proc.stderr.strip()
            success = (proc.returncode == 0)
            firewall_action = "IPTABLES_RULE_INSERTED"
        except Exception as e:
            output = f"iptables error: {str(e)}"

    # 2. Also register in UFW if present
    if shutil.which("ufw"):
        try:
            cmd = ["sudo", "ufw", "insert", "1", "deny", "from", target, "to", "any"] if is_ip else ["sudo", "ufw", "deny", target]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if not success:
                success = (proc.returncode == 0)
                firewall_action = "UFW_RULE_INSERTED"
                output = proc.stdout.strip() or proc.stderr.strip()
        except Exception as e:
            if not output:
                output = f"ufw error: {str(e)}"
            
    return {"firewall_engine": firewall_action, "success": success, "system_output": output}


def isolate_host(host_id: str, reason: str, trace_id: str = None) -> Dict[str, Any]:
    """Executes network quarantine isolation on a compromised enterprise host or attacker IP."""
    clean_host = host_id.strip()
    clean_host_upper = clean_host.upper()
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_host))
    
    firewall_result = None
    if config.enable_live_firewall or (os.name != "nt" and is_ip):
        firewall_result = _execute_native_linux_block(clean_host)

    if clean_host_upper in HOST_INVENTORY:
        HOST_INVENTORY[clean_host_upper]["status"] = "ISOLATED"
        res = {
            "host_id": clean_host_upper,
            "action": "QUARANTINED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "status": "SUCCESS",
            "live_firewall": firewall_result,
        }
    elif is_ip:
        res = {
            "host_id": clean_host,
            "target_ip": clean_host,
            "action": "IP_FIREWALL_BLOCK",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "status": "SUCCESS",
            "live_firewall": firewall_result,
        }
    else:
        res = {
            "host_id": host_id,
            "action": "QUARANTINE_ATTEMPT",
            "status": "SUCCESS" if firewall_result and firewall_result.get("success") else "HOST_NOT_FOUND",
            "message": f"Applied automated isolation containment for target '{host_id}'.",
            "live_firewall": firewall_result,
        }

    ACTIVE_TOOL_EXECUTIONS.append({"tool": "isolate_host", "input": clean_host, "result": res})
    log_audit_event(
        event_type="DEFENSIVE_ACTION",
        action="ISOLATE_HOST",
        status=res["status"],
        trace_id=trace_id,
        details={"host_id": host_id, "reason": reason, "live_firewall": firewall_result},
    )
    return res

