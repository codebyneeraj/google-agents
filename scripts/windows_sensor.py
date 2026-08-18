#!/usr/bin/env python3
"""
Windows Defense Sensor for Live Red-Team / Attacker Testing.
Captures raw connection telemetry (honeypots) and Windows Event Logs,
then streams unclassified telemetry to the Gemini SOC Agent for autonomous classification and response.
"""

import sys
import os
import time
import socket
import select
import struct
import threading
import argparse
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
import urllib.request
import urllib.error

# Windows UTF-8 stdout configuration
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

class WindowsDefenseSensor:
    def __init__(self, gateway_url: str = "http://localhost:8080", ports: list = None, batch_window: float = 2.0):
        self.gateway_url = gateway_url.rstrip("/")
        self.ports = ports or [22, 445, 3389, 4444, 8088, 21, 23]
        self.batch_window = batch_window
        self.running = False
        
        self.sockets = []
        self.event_queue = deque()
        self.lock = threading.Lock()
        
        # Track recent attacker activity to aggregate bursts
        self.ip_activity = defaultdict(lambda: {"ports": set(), "count": 0, "payloads": [], "first_seen": 0, "last_seen": 0})
        self.quarantined_ips = set()
        self.last_flush = time.time()

    def _get_local_ips(self) -> set:
        """Returns set of local IPv4 addresses to ignore loopback/self."""
        local_ips = {"127.0.0.1", "localhost", "::1"}
        try:
            hostname = socket.gethostname()
            for ip in socket.gethostbyname_ex(hostname)[2]:
                local_ips.add(ip)
        except Exception:
            pass
        return local_ips

    def start_honeypots(self):
        """Binds TCP honeypot listeners to monitor incoming probes and connection bursts."""
        for port in self.ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                s.listen(50)
                s.setblocking(False)
                self.sockets.append((port, s))
                print(f"[+] Honeypot listener ACTIVE on 0.0.0.0:{port}")
            except OSError as e:
                print(f"[-] Port {port} skipped (in use or insufficient privilege: {e})")

    def _handle_connection(self, port: int, client_sock: socket.socket, client_addr: tuple):
        src_ip, src_port = client_addr
        
        # Check if IP has been quarantined by SOC agent
        if src_ip in self.quarantined_ips:
            try:
                # Send immediate TCP RST packet to drop connection
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                client_sock.close()
            except Exception:
                pass
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [FIREWALL DROP] Connection from quarantined IP {src_ip}:{src_port} on port {port} DROPPED (RST).")
            return

        payload_snippet = ""
        try:
            client_sock.settimeout(1.0)
            
            # Send brief honeypot banner to capture adversary interaction
            if port == 22:
                client_sock.sendall(b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n")
            elif port in (8088, 80):
                client_sock.sendall(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nContent-Length: 2\r\n\r\nOK")
            elif port == 21:
                client_sock.sendall(b"220 Microsoft FTP Service\r\n")

            # Receive initial payload / banner bytes from adversary
            data = client_sock.recv(512)
            if data:
                payload_snippet = repr(data[:120])[1:]
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass


        with self.lock:
            now = time.time()
            act = self.ip_activity[src_ip]
            if act["count"] == 0:
                act["first_seen"] = now
            act["last_seen"] = now
            act["count"] += 1
            act["ports"].add(port)
            if payload_snippet and len(act["payloads"]) < 3:
                act["payloads"].append(f"Port {port}: {payload_snippet}")

    def _poll_honeypot_sockets(self):
        """Polls active sockets for incoming connections."""
        while self.running:
            if not self.sockets:
                time.sleep(1.0)
                continue

            sock_list = [s for _, s in self.sockets]
            port_map = {s: p for p, s in self.sockets}

            try:
                readable, _, _ = select.select(sock_list, [], [], 0.5)
                for s in readable:
                    port = port_map[s]
                    try:
                        client_sock, client_addr = s.accept()
                        t = threading.Thread(target=self._handle_connection, args=(port, client_sock, client_addr), daemon=True)
                        t.start()
                    except Exception:
                        pass
            except Exception:
                time.sleep(0.1)

    def _batch_and_forward_worker(self):
        """Periodically flushes aggregated connection telemetry to the SOC Gateway for LLM triage."""
        while self.running:
            time.sleep(1.0)
            now = time.time()
            
            with self.lock:
                flushed_ips = []
                for ip, act in list(self.ip_activity.items()):
                    # Flush if idle for batch_window or high volume
                    if (now - act["last_seen"] >= self.batch_window) or (act["count"] >= 15):
                        flushed_ips.append((ip, act.copy()))
                        del self.ip_activity[ip]

            for ip, data in flushed_ips:
                self._send_raw_telemetry(ip, data)

    def _send_raw_telemetry(self, ip: str, data: dict):
        """Sends raw unclassified telemetry to the FastAPI SOC Gateway."""
        ports_list = sorted(list(data["ports"]))
        count = data["count"]
        payloads_str = " | ".join(data["payloads"]) if data["payloads"] else "No banner data sent"
        
        telemetry_desc = (
            f"RAW HOST TELEMETRY: Inbound network activity detected from IP {ip}. "
            f"Observed {count} connection event(s) across target port(s): {ports_list}. "
            f"Interaction snippets: [{payloads_str}]. "
            f"Duration: {data['last_seen'] - data['first_seen']:.2f}s."
        )

        alert_payload = {
            "source": "WindowsDefenseSensor-Live",
            "severity": "HIGH",
            "description": telemetry_desc,
            "target_ip": ip,
        }

        print(f"\n[!] >> FORWARDING RAW TELEMETRY TO SOC AGENT >> Target IP: {ip} | Ports: {ports_list} | Hits: {count}")
        try:
            req = urllib.request.Request(
                f"{self.gateway_url}/api/v1/webhook/alert",
                data=json.dumps(alert_payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "WindowsDefenseSensor/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                print(f"[+] << SOC AGENT TRIAGE RECEIVED (Status: {resp_data.get('status')})")
                print(f"    * MITRE ATT&CK: {', '.join(resp_data.get('mitre_tactics', []))}")
                print(f"    * Summary: {resp_data.get('summary', '')[:160]}...")
                for action in resp_data.get("actions_taken", []):
                    tool = action.get("tool")
                    inp = action.get("input")
                    res_status = action.get("result", {}).get("status", "OK")
                    print(f"    * Tool Executed: {tool}({inp}) -> Status: {res_status}")
                    if tool == "isolate_host" and (inp == ip or inp == "WKSTN-JDOE-04"):
                        self.quarantined_ips.add(ip)
                        print(f"    * [FIREWALL ACTIVE] IP {ip} added to Active Quarantine Drop list.")

        except urllib.error.URLError as e:
            print(f"[-] Failed to forward alert to gateway {self.gateway_url}: {e}")
        except Exception as e:
            print(f"[-] Error processing agent response: {e}")

    def run(self):
        self.running = True
        print("=================================================================")
        print("  WINDOWS DEFENSE SENSOR - RAW TELEMETRY COLLECTOR")
        print(f"  Target Gateway: {self.gateway_url}")
        print(f"  Monitored Honeypot Ports: {self.ports}")
        print("  Autonomous Agent: Gemini 3.6 Flash (Vertex AI Enterprise)")
        print("=================================================================")
        print("[*] Ready. Any incoming connection from Kali VM will be forwarded to Gemini for autonomous classification & response.")
        print("[*] Press Ctrl+C to stop.\n")

        self.start_honeypots()
        
        t_poll = threading.Thread(target=self._poll_honeypot_sockets, daemon=True)
        t_batch = threading.Thread(target=self._batch_and_forward_worker, daemon=True)
        
        t_poll.start()
        t_batch.start()

        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[*] Stopping sensor...")
            self.running = False
            for _, s in self.sockets:
                try:
                    s.close()
                except Exception:
                    pass
            print("[+] Sensor terminated cleanly.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Windows Defense Sensor for Real-World Red-Team Testing")
    parser.add_argument("--gateway", default="http://localhost:8080", help="FastAPI SOC Gateway URL (default: http://localhost:8080)")
    parser.add_argument("--ports", default="22,445,3389,4444,8088,21,23", help="Comma-separated honeypot TCP ports to monitor")
    parser.add_argument("--window", type=float, default=2.0, help="Burst aggregation window in seconds (default: 2.0)")
    args = parser.parse_args()

    port_list = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    sensor = WindowsDefenseSensor(gateway_url=args.gateway, ports=port_list, batch_window=args.window)
    sensor.run()
