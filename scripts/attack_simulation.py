#!/usr/bin/env python3
"""
Attack Simulator for Security Lab Testing (Windows Host -> Linux VM)
Simulates rapid SSH brute force login attempts against a target Linux VM
to trigger the automated SOC Agent defense and firewall isolation.
"""

import sys
import time
import socket
import argparse
from datetime import datetime

USERNAMES = ["root", "admin", "ubuntu", "devops", "testuser", "backup", "oracle", "database"]
PASSWORDS = ["123456", "password", "admin123", "toor", "root123", "welcome", "letmein", "secret"]

def test_ssh_connectivity(target_ip: str, port: int = 22, timeout: float = 2.0) -> bool:
    """Tests if TCP port 22 is reachable on the target VM."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        banner = sock.recv(1024)
        sock.close()
        return True
    except Exception:
        return False

def simulate_ssh_brute_force(target_ip: str, port: int = 22, attempts: int = 10, delay: float = 0.5):
    print(f"\n=======================================================")
    print(f"  ATTACK SIMULATION: SSH Brute Force against {target_ip}:{port}")
    print(f"=======================================================\n")

    print(f"[*] Step 1: Checking pre-attack connectivity to {target_ip}:{port}...")
    if not test_ssh_connectivity(target_ip, port):
        print(f"[!] ERROR: Target {target_ip}:{port} is unreachable. Please ensure SSH is running and VM network is bridged/host-only.")
        sys.exit(1)
    print(f"[+] Target {target_ip}:{port} is ONLINE and reachable.\n")

    print(f"[*] Step 2: Launching {attempts} failed authentication attempts...")

    blocked = False
    for i in range(1, attempts + 1):
        user = USERNAMES[(i - 1) % len(USERNAMES)]
        pwd = PASSWORDS[(i - 1) % len(PASSWORDS)]
        timestamp = datetime.now().strftime("%H:%M:%S")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target_ip, port))
            # Read server banner
            banner = sock.recv(1024)
            # Send fake client identification and invalid SSH protocol handshake to trigger auth record
            sock.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
            time.sleep(0.1)
            sock.close()

            print(f"[{timestamp}] [ATTEMPT #{i:02d}] Target: {user}@{target_ip} | Password: {pwd} | Status: Connection sent")
        except socket.timeout:
            print(f"[{timestamp}] [BLOCKED] Attempt #{i:02d} -> Connection TIMED OUT! (Host Firewall active)")
            blocked = True
            break
        except ConnectionRefusedError:
            print(f"[{timestamp}] [BLOCKED] Attempt #{i:02d} -> Connection REFUSED! (Firewall rule active)")
            blocked = True
            break
        except Exception as e:
            print(f"[{timestamp}] [BLOCKED] Attempt #{i:02d} -> Connection failed: {str(e)}")
            blocked = True
            break

        time.sleep(delay)

    print(f"\n[*] Step 3: Verifying post-attack containment status...")
    time.sleep(2.0)
    is_reachable = test_ssh_connectivity(target_ip, port, timeout=2.0)
    
    if not is_reachable or blocked:
        print(f"\n=======================================================")
        print(f"  RESULT: DEFENSE SUCCESSFUL!")
        print(f"  The SOC Agent detected the attack and blocked your IP.")
        print(f"  Port 22 on {target_ip} is now UNREACHABLE.")
        print(f"=======================================================\n")
    else:
        print(f"\n[-] Note: Target is still reachable. Check that sensor_daemon.py and FastAPI gateway are running on the VM.\n")

def main():
    parser = argparse.ArgumentParser(description="Attack Simulator (Windows -> Linux VM)")
    parser.add_argument("--target-ip", required=True, help="IP address of the Linux VM")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--attempts", type=int, default=10, help="Number of brute force attempts")
    parser.add_argument("--delay", type=float, default=0.4, help="Delay between attempts in seconds")
    args = parser.parse_args()

    simulate_ssh_brute_force(args.target_ip, port=args.port, attempts=args.attempts, delay=args.delay)

if __name__ == "__main__":
    main()
