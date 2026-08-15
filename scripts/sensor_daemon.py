#!/usr/bin/env python3
"""
SOC Sensor Daemon for Linux Virtual Machine
Tails /var/log/auth.log or journalctl in real-time, aggregates failed SSH attempts,
and triggers the SOC Agent Orchestrator Gateway when brute-force thresholds are exceeded.
"""

import os
import re
import time
import json
import socket
import argparse
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
import httpx

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8080/api/v1/agent/query")
THRESHOLD_ATTEMPTS = int(os.getenv("ATTACK_THRESHOLD", "5"))
WINDOW_SECONDS = int(os.getenv("ATTACK_WINDOW_SECONDS", "30"))
AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")

# Failed login regex patterns for OpenSSH
SSH_FAIL_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    re.compile(r"Invalid user (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    re.compile(r"authentication failure; .* rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?: .* user=(\S+))?"),
]

class LiveSecuritySensor:
    def __init__(self, gateway_url: str = GATEWAY_URL, threshold: int = THRESHOLD_ATTEMPTS):
        self.gateway_url = gateway_url
        self.threshold = threshold
        self.hostname = socket.gethostname()
        self.failure_tracker = defaultdict(list)
        self.alerted_ips = set()

    def process_log_line(self, line: str):
        for pattern in SSH_FAIL_PATTERNS:
            match = pattern.search(line)
            if match:
                groups = match.groups()
                if len(groups) == 2 and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", groups[0]):
                    attacker_ip, username = groups[0], groups[1] or "root"
                else:
                    username, attacker_ip = (groups[0] or "unknown"), groups[1]

                now = time.time()
                self.failure_tracker[attacker_ip].append(now)

                # Filter within time window
                recent = [t for t in self.failure_tracker[attacker_ip] if now - t <= WINDOW_SECONDS]
                self.failure_tracker[attacker_ip] = recent

                print(f"[{datetime.now().strftime('%H:%M:%S')}] [SSH_FAIL] IP: {attacker_ip} | User: {username} | Attempts in {WINDOW_SECONDS}s: {len(recent)}")

                if len(recent) >= self.threshold and attacker_ip not in self.alerted_ips:
                    self.alerted_ips.add(attacker_ip)
                    self.trigger_agent_alert(attacker_ip, username, len(recent))
                break

    def trigger_agent_alert(self, attacker_ip: str, target_user: str, attempt_count: int):
        alert_text = (
            f"SIEM Alert: Real-time SSH Brute-Force attack detected on host {self.hostname}. "
            f"Source IP: {attacker_ip} attempted {attempt_count} unauthorized logins targeting user {target_user}."
        )
        print(f"\n[ALERT] Threshold reached ({attempt_count} attempts)! Dispatching alert to SOC Agent Gateway: {self.gateway_url}...")
        
        payload = {
            "query": alert_text,
            "session_id": f"live_sensor_{int(time.time())}",
            "user_id": "linux_sensor_daemon"
        }
        
        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(self.gateway_url, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    print(f"[SUCCESS] SOC Agent Response (Status: {data.get('status')}):")
                    print(f"Summary: {data.get('summary')}")
                    print(f"Actions Taken: {len(data.get('actions_taken', []))}\n")
                else:
                    print(f"[WARN] Gateway returned error HTTP {res.status_code}: {res.text}\n")
        except Exception as e:
            print(f"[ERROR] Could not contact SOC Agent Gateway: {str(e)}\n")

    def run_file_tail(self, filepath: str):
        print(f"[*] Starting Security Sensor on {self.hostname}. Monitoring {filepath}...")
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                self.process_log_line(line)

    def run_journalctl_tail(self):
        print(f"[*] Starting Security Sensor on {self.hostname}. Monitoring journalctl -u ssh -f...")
        cmd = ["journalctl", "-u", "ssh", "-f", "-n", "0"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for line in iter(proc.stdout.readline, ""):
                if line:
                    self.process_log_line(line)
        finally:
            proc.kill()

def main():
    parser = argparse.ArgumentParser(description="Real-time SOC Sensor Daemon for Linux VM")
    parser.add_argument("--gateway", default=GATEWAY_URL, help="FastAPI Agent Gateway URL")
    parser.add_argument("--threshold", type=int, default=THRESHOLD_ATTEMPTS, help="Failed login threshold")
    parser.add_argument("--log-file", default=AUTH_LOG_PATH, help="Path to auth log file")
    args = parser.parse_args()

    sensor = LiveSecuritySensor(gateway_url=args.gateway, threshold=args.threshold)
    if os.path.exists(args.log_file):
        sensor.run_file_tail(args.log_file)
    else:
        sensor.run_journalctl_tail()

if __name__ == "__main__":
    main()
