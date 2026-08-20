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

# Quarantined Hosts & Blocked IPs Ledger
QUARANTINED_TARGETS: Dict[str, Dict[str, Any]] = {}

def get_quarantined_targets() -> Dict[str, Dict[str, Any]]:
    return dict(QUARANTINED_TARGETS)

def clear_quarantined_targets():
    QUARANTINED_TARGETS.clear()
    for h in HOST_INVENTORY.values():
        h["status"] = "ONLINE"

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

def _execute_native_windows_block(target: str) -> Dict[str, Any]:
    """Applies real firewall drop rule on Windows using netsh advfirewall / PowerShell."""
    firewall_action = "NONE"
    output = ""
    success = False
    
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))
    if not is_ip:
        return {"firewall_engine": "WINDOWS_FIREWALL_SKIPPED", "success": False, "system_output": "Target is not a valid IPv4 address"}

    try:
        # Inbound block
        cmd_in = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=SOC-Block-{target}-in", "dir=in", "action=block", f"remoteip={target}"]
        proc_in = subprocess.run(cmd_in, capture_output=True, text=True, timeout=5)
        # Outbound block
        cmd_out = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=SOC-Block-{target}-out", "dir=out", "action=block", f"remoteip={target}"]
        proc_out = subprocess.run(cmd_out, capture_output=True, text=True, timeout=5)
        
        output = (proc_in.stdout + proc_in.stderr + proc_out.stdout + proc_out.stderr).strip()
        success = (proc_in.returncode == 0)
        firewall_action = "NETSH_FIREWALL_BLOCK_APPLIED" if success else "NETSH_FAILED"
    except Exception as e:
        output = f"Windows Firewall execution error: {str(e)}"
        
    return {"firewall_engine": firewall_action, "success": success, "system_output": output}

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
    if is_ip:
        if os.name == "nt":
            firewall_result = _execute_native_windows_block(clean_host)
        else:
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

    QUARANTINED_TARGETS[clean_host] = res
    ACTIVE_TOOL_EXECUTIONS.append({"tool": "isolate_host", "input": clean_host, "result": res})

    log_audit_event(
        event_type="DEFENSIVE_ACTION",
        action="ISOLATE_HOST",
        status=res["status"],
        trace_id=trace_id,
        details={"host_id": host_id, "reason": reason, "live_firewall": firewall_result},
    )
    return res

def list_quarantined_hosts(trace_id: str = None) -> Dict[str, Any]:
    """Retrieves all currently isolated/quarantined host endpoints and blocked firewall IP addresses."""
    active = dict(QUARANTINED_TARGETS)
    result = {
        "quarantined_count": len(active),
        "targets": list(active.keys()),
        "details": active,
        "status": "SUCCESS" if active else "NO_ACTIVE_QUARANTINES"
    }
    ACTIVE_TOOL_EXECUTIONS.append({"tool": "list_quarantined_hosts", "input": "ALL", "result": result})
    log_audit_event(
        event_type="TOOL_EXECUTION",
        action="LIST_QUARANTINED_HOSTS",
        status=result["status"],
        trace_id=trace_id,
        details={"count": len(active)},
    )
    return result

def scan_domain_dns(domain: str, trace_id: str = None) -> Dict[str, Any]:
    """Performs DNS resolution, nameserver queries, and DGA/phishing anomaly analysis for a domain."""
    import socket
    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    
    resolved_ips = []
    try:
        addr_info = socket.getaddrinfo(clean_domain, 80)
        resolved_ips = list(set([item[4][0] for item in addr_info if item[4]]))
    except Exception:
        pass

    # Heuristic DGA / entropy check
    import math
    prob = [float(clean_domain.count(c)) / len(clean_domain) for c in dict.fromkeys(list(clean_domain))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    is_dga_suspicious = entropy > 3.8 and len(clean_domain) > 18

    reputation = "SUSPICIOUS" if is_dga_suspicious or not resolved_ips else "BENIGN"
    if any(ip in THREAT_INTEL_DB and THREAT_INTEL_DB[ip].get("reputation") == "MALICIOUS" for ip in resolved_ips):
        reputation = "MALICIOUS"

    result = {
        "domain": clean_domain,
        "resolved_ips": resolved_ips,
        "entropy_score": round(entropy, 2),
        "dga_indicator": is_dga_suspicious,
        "reputation": reputation,
        "status": "RESOLVED" if resolved_ips else "UNRESOLVED_NXDOMAIN"
    }
    ACTIVE_TOOL_EXECUTIONS.append({"tool": "scan_domain_dns", "input": clean_domain, "result": result})
    log_audit_event("TOOL_EXECUTION", "SCAN_DOMAIN_DNS", "SUCCESS", trace_id=trace_id, details=result)
    return result

def analyze_file_hash(file_hash: str, trace_id: str = None) -> Dict[str, Any]:
    """Inspects MD5/SHA1/SHA256 file hashes against VirusTotal and malware intelligence feeds."""
    clean_hash = file_hash.strip().lower()
    
    # Check live VirusTotal if API key set
    live_res = _query_virustotal_live(clean_hash)
    if live_res:
        ACTIVE_TOOL_EXECUTIONS.append({"tool": "analyze_file_hash", "input": clean_hash, "result": live_res})
        return live_res

    # Check local threat database
    known = THREAT_INTEL_DB.get(clean_hash)
    if known:
        res = {"hash": clean_hash, **known}
    elif len(clean_hash) in (32, 40, 64):
        res = {
            "hash": clean_hash,
            "reputation": "UNKNOWN",
            "threat_score": 10,
            "category": "Unindexed File Hash",
            "message": "File hash not matched in active malware signatures."
        }
    else:
        res = {
            "hash": clean_hash,
            "reputation": "INVALID_FORMAT",
            "threat_score": 0,
            "category": "Malformed Hash",
            "message": "Input is not a valid MD5, SHA1, or SHA256 string."
        }

    ACTIVE_TOOL_EXECUTIONS.append({"tool": "analyze_file_hash", "input": clean_hash, "result": res})
    log_audit_event("TOOL_EXECUTION", "ANALYZE_FILE_HASH", "SUCCESS", trace_id=trace_id, details=res)
    return res

def decode_base64_payload(payload: str, trace_id: str = None) -> Dict[str, Any]:
    """Decodes obfuscated base64 PowerShell/bash scripts and detects malicious command patterns."""
    import base64
    clean_p = payload.strip()
    # Strip common prefixes
    for prefix in ("powershell -enc ", "powershell -encodedcommand ", "-e ", "-enc ", "base64 -d <<< "):
        if clean_p.lower().startswith(prefix):
            clean_p = clean_p[len(prefix):].strip()

    decoded_text = ""
    try:
        raw_bytes = base64.b64decode(clean_p)
        # Try UTF-16LE (PowerShell default) then UTF-8
        try:
            decoded_text = raw_bytes.decode("utf-16le")
        except Exception:
            decoded_text = raw_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        decoded_text = f"Decoding failed: {str(e)}"

    # Check for suspicious command indicators
    suspicious_patterns = []
    lower_decoded = decoded_text.lower()
    for pattern in ("iex", "invoke-expression", "downloadstring", "net user", "whoami", "mimikatz", "vssadmin", "http://", "https://", "socket", "cmd.exe", "/bin/sh"):
        if pattern in lower_decoded:
            suspicious_patterns.append(pattern)

    risk = "CRITICAL" if len(suspicious_patterns) >= 2 else ("SUSPICIOUS" if suspicious_patterns else "LOW")
    result = {
        "decoded_content": decoded_text,
        "suspicious_indicators_found": suspicious_patterns,
        "risk_level": risk,
        "obfuscation_type": "Base64 (UTF-16LE / UTF-8)"
    }
    ACTIVE_TOOL_EXECUTIONS.append({"tool": "decode_base64_payload", "input": payload[:30] + "...", "result": result})
    log_audit_event("TOOL_EXECUTION", "DECODE_BASE64_PAYLOAD", "SUCCESS", trace_id=trace_id, details={"risk": risk, "patterns": suspicious_patterns})
    return result

def scan_local_ports(host: str = "127.0.0.1", ports: str = "22,80,443,445,3389,8080", trace_id: str = None) -> Dict[str, Any]:
    """Performs a non-blocking TCP socket audit against specified network ports to detect open services."""
    import socket
    clean_host = host.strip()
    target_ports = []
    for p in ports.split(","):
        p = p.strip()
        if "-" in p:
            start, end = map(int, p.split("-"))
            target_ports.extend(range(start, min(end + 1, start + 50)))  # Cap range scan
        elif p.isdigit():
            target_ports.append(int(p))

    open_ports = []
    service_map = {22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP-ALT", 53: "DNS", 21: "FTP"}
    
    for port in target_ports[:30]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            res = sock.connect_ex((clean_host, port))
            if res == 0:
                open_ports.append({"port": port, "service": service_map.get(port, "UNKNOWN")})
            sock.close()
        except Exception:
            pass

    result = {
        "target_host": clean_host,
        "scanned_ports_count": len(target_ports[:30]),
        "open_ports": open_ports,
        "status": "OPEN_SERVICES_DETECTED" if open_ports else "NO_OPEN_PORTS_FOUND"
    }
    ACTIVE_TOOL_EXECUTIONS.append({"tool": "scan_local_ports", "input": clean_host, "result": result})
    log_audit_event("TOOL_EXECUTION", "SCAN_LOCAL_PORTS", "SUCCESS", trace_id=trace_id, details=result)
    return result

def unquarantine_host(host_id: str, reason: str = "Security analyst verified remediation", trace_id: str = None) -> Dict[str, Any]:
    """Removes firewall block rules and restores an isolated host back to active network status."""
    clean_host = host_id.strip()
    clean_host_upper = clean_host.upper()

    if clean_host in QUARANTINED_TARGETS:
        del QUARANTINED_TARGETS[clean_host]
    if clean_host_upper in HOST_INVENTORY:
        HOST_INVENTORY[clean_host_upper]["status"] = "ONLINE"

    # Remove OS firewall rule if target was an IP
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_host))
    firewall_status = "NO_RULE_REQUIRED"
    if is_ip:
        if os.name == "nt":
            try:
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=SOC-Block-{clean_host}-in"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                cmd_out = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=SOC-Block-{clean_host}-out"]
                subprocess.run(cmd_out, capture_output=True, text=True, timeout=5)
                firewall_status = "WINDOWS_FIREWALL_RULE_DELETED"
            except Exception:
                firewall_status = "NETSH_ERROR"
        else:
            if shutil.which("iptables"):
                try:
                    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", clean_host, "-j", "DROP"], capture_output=True, timeout=5)
                    firewall_status = "IPTABLES_RULE_DELETED"
                except Exception:
                    pass

    result = {
        "host_id": clean_host,
        "action": "UNQUARANTINED",
        "status": "SUCCESS",
        "reason": reason,
        "firewall_cleanup": firewall_status
    }
    ACTIVE_TOOL_EXECUTIONS.append({"tool": "unquarantine_host", "input": clean_host, "result": result})
    log_audit_event("DEFENSIVE_ACTION", "UNQUARANTINE_HOST", "SUCCESS", trace_id=trace_id, details=result)
    return result

MITRE_KNOWLEDGE_BASE = {
    "T1059": {
        "technique": "Command and Scripting Interpreter (T1059)",
        "tactic": "Execution",
        "description": "Adversaries abuse command and script interpreters to execute commands, scripts, or binaries (e.g. PowerShell, Bash, Python).",
        "detection": "Monitor process creation with command-line arguments (Event ID 4688 / Sysmon Event ID 1) and script block logging (PowerShell Event ID 4104).",
        "mitigation": "Enforce PowerShell Constrained Language Mode, restrict execution policy, and disable unneeded scripting interpreters."
    },
    "T1110": {
        "technique": "Brute Force (T1110)",
        "tactic": "Credential Access",
        "description": "Adversaries use automated credential guessing or password spraying against authentication services like SSH, RDP, and Active Directory.",
        "detection": "Correlate failed authentication spikes (Windows Event 4625 / Linux /var/log/auth.log) from a single source IP.",
        "mitigation": "Enforce Multi-Factor Authentication (MFA), account lockout thresholds, and fail2ban firewall rate limiting."
    },
    "T1078": {
        "technique": "Valid Accounts (T1078)",
        "tactic": "Defense Evasion, Initial Access, Persistence, Privilege Escalation",
        "description": "Adversaries obtain and abuse credentials of existing enterprise accounts to gain initial access and blend in with normal network traffic.",
        "detection": "Monitor impossible travel / geo-anomalies, off-hours authentication, and sudden privilege elevation.",
        "mitigation": "Enforce conditional access policies, password rotation, and Zero-Trust credential auditing."
    },
    "T1071": {
        "technique": "Application Layer Protocol: C2 (T1071)",
        "tactic": "Command and Control",
        "description": "Adversaries communicate using application layer protocols (HTTP/HTTPS, DNS) to blend C2 traffic with legitimate network communications.",
        "detection": "Analyze outbound proxy logs for high-frequency beacons, unindexed domain names, and suspicious User-Agent headers.",
        "mitigation": "Network intrusion detection (IDS/IPS), TLS inspection, and DNS sinkholing."
    },
    "T1566": {
        "technique": "Phishing (T1566)",
        "tactic": "Initial Access",
        "description": "Adversaries send malicious emails containing malicious links or attachments to trick users into executing malicious code.",
        "detection": "Inspect mail transfer agent (MTA) headers, attachment hashes, and anomalous link click telemetry.",
        "mitigation": "Email gateway anti-spoofing (SPF, DKIM, DMARC) and user security awareness training."
    }
}

def generate_mitre_report(technique_id: str, trace_id: str = None) -> Dict[str, Any]:
    """Queries MITRE ATT&CK enterprise threat intelligence for tactic details, detection rules, and mitigation strategies."""
    clean_tech = technique_id.strip().upper()
    tech_data = MITRE_KNOWLEDGE_BASE.get(clean_tech)
    
    if not tech_data:
        # Search by prefix or return general guidance
        for k, v in MITRE_KNOWLEDGE_BASE.items():
            if clean_tech in k or clean_tech in v["technique"].upper():
                tech_data = v
                break

    if not tech_data:
        tech_data = {
            "technique": clean_tech,
            "tactic": "Enterprise Matrix",
            "description": f"MITRE ATT&CK intelligence for technique {clean_tech}.",
            "detection": "Correlate SIEM endpoint telemetry and network flow logs.",
            "mitigation": "Apply Zero-Trust principle of least privilege and strict perimeter access control."
        }

    ACTIVE_TOOL_EXECUTIONS.append({"tool": "generate_mitre_report", "input": clean_tech, "result": tech_data})
    log_audit_event("TOOL_EXECUTION", "GENERATE_MITRE_REPORT", "SUCCESS", trace_id=trace_id, details=tech_data)
    return tech_data




