# Secure SOC Analyst Orchestrator

**Autonomous Tier-2 Cyber Defense Agent for the Gemini Enterprise Agent Platform (GEAP)**

[![Model](https://img.shields.io/badge/Model-Gemini%203.6%20Flash-8E75B2?logo=google&logoColor=white)](https://ai.google.dev/)
[![Framework](https://img.shields.io/badge/Framework-Google%20GenAI%20SDK-34A853?logo=python&logoColor=white)](https://github.com/googleapis/python-genai)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Track:** Fortified Enterprise Fleet — Google All Things Agentic Hackathon
**Platform:** Gemini Enterprise Agent Platform (GEAP)
**Interface:** Interactive Agentic CLI (`soc`) and headless gateway API

---

## Overview

Enterprise Security Operations Centers face three persistent problems: alert volume that outpaces analyst capacity, investigation context that is lost between sessions and hosts, and the security risk of connecting an LLM directly to production defense tooling.

The Secure SOC Analyst Orchestrator addresses this with an autonomous agent that ingests SIEM/EDR alerts, runs threat intelligence and log correlation automatically, persists investigation context across sessions via Vertex AI Memory Bank, and enforces layered guardrails — including mandatory human confirmation before any destructive containment action.

---

## Architecture

![Architecture](docs/assets/SOC-Arch.png)

---

## Track Alignment — Fortified Enterprise Fleet

| Pillar | Requirement | Implementation |
|---|---|---|
| **Discovery & Lifecycle** | Agent registry for enterprise cataloging and fleet discovery | `/api/v1/agent/registry` and `/api/v1/agent/registry/fleet` serve `agent-card.json` with capability tags, versioning, and Zero-Trust IAM schemas. |
| **Core Execution & State** | Long-running background execution and persistent cross-session state | Asynchronous Cloud Run runtime with multi-turn `VertexAiSessionService` and persistent `VertexAiMemoryBankService`, correlating repeat threat actors across sessions. |
| **Security & Governance** | Zero-Trust access control, unified gateway, inline guardrails | Model Armor (`src/security/model_armor.py`) intercepts prompt injection pre-execution and redacts PII/tokens post-execution. Destructive containment (`isolate_host`, `unquarantine_host`) requires explicit operator confirmation. |
| **Telemetry & Observability** | OpenTelemetry-compliant structured audit logging | `src/observability/logger.py` emits structured JSON events with end-to-end `trace_id` correlation for SIEM compliance. |

---

## Tool Inventory

| # | Tool | Classification | Parameters | Description |
|---:|---|---|---|---|
| 1 | `check_threat_intel` | Read-only | `indicator: str` | Queries live threat feeds (AbuseIPDB, VirusTotal) for IP, domain, and hash reputation and actor attribution (e.g. APT-29). |
| 2 | `lookup_user_activity` | Read-only | `user_identifier: str` | Scans Active Directory / IAM logs for failed-login spikes, geo-anomalies, and signs of credential compromise. |
| 3 | `inspect_linux_auth_logs` | Read-only | `ip_address: str`, `max_lines: int` | Scans `/var/log/auth.log` or `journalctl` for SSH brute-force activity. |
| 4 | `scan_domain_dns` | Read-only | `domain: str` | Performs DNS resolution, nameserver telemetry, and entropy-based DGA anomaly analysis. |
| 5 | `analyze_file_hash` | Read-only | `file_hash: str` | Checks MD5/SHA1/SHA256 hashes against VirusTotal and malware intelligence feeds. |
| 6 | `decode_base64_payload` | Read-only | `payload: str` | Decodes obfuscated base64 PowerShell/bash payloads and flags malicious invocations (`IEX`, `DownloadString`, `mimikatz`). |
| 7 | `scan_local_ports` | Read-only | `host: str`, `ports: str` | Probes TCP sockets to detect open or rogue listening services. |
| 8 | `generate_mitre_report` | Read-only | `technique_id: str` | Returns MITRE ATT&CK technique detail — tactic description, detection event IDs, mitigations (e.g. `T1059`, `T1110`, `T1078`). |
| 9 | `list_quarantined_hosts` | Read-only | — | Lists all currently isolated hosts and active firewall drop rules. |
| 10 | `isolate_host` | **Gated — destructive** | `host_id: str`, `reason: str` | Quarantines a host via EDR or OS firewall rule (`netsh` / `iptables`). Requires operator confirmation in the CLI. |
| 11 | `unquarantine_host` | **Gated — destructive** | `host_id: str`, `reason: str` | Releases a host from quarantine and removes the corresponding firewall rule. |

---

## Agentic CLI (`soc`)

A full terminal frontend for analysts, in the style of Claude Code / GitHub Copilot CLI.

```bash
# Install in editable mode
pip install -e .

# Launch the interactive REPL (defaults to local engine)
soc

# Connect the CLI to the deployed Cloud Run service
soc chat --remote
```

### Subcommands

```bash
# Domain and DNS analysis with DGA entropy scoring
soc dns evil-c2-beacon.xyz

# Malware file hash inspection
soc hash evil-payload.exe

# Base64 payload deobfuscation
soc decode "powershell -enc SQBFAFgA"

# Manual emergency host quarantine (confirmation required)
soc isolate WKSTN-JDOE-04 --reason "Active ransomware beacon"

# Query persistent Vertex AI Memory Bank
soc memory 198.51.100.45

# Autonomous SIEM alert ingestion and triage
soc triage "SIEM Alert: Suspicious outbound beacon to 198.51.100.45"

# MITRE ATT&CK technique lookup
soc mitre T1059

# Run the automated red-team evaluation battery
soc redteam --url http://localhost:8080
```

---

## Getting Started

### 1. Set up the environment

```bash
python -m venv .venv

# Windows
.\.venv\Scripts\Activate.ps1

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Add `GEMINI_API_KEY`, `ABUSEIPDB_API_KEY`, and `VIRUSTOTAL_API_KEY` as needed.

### 3. Run the gateway locally

```bash
uvicorn src.gateway.server:app --reload --port 8080
```

- Swagger UI: `http://localhost:8080/docs`
- Agent registry: `http://localhost:8080/api/v1/agent/registry`
- Fleet catalog: `http://localhost:8080/api/v1/agent/registry/fleet`

### 4. Run the test suite

```bash
pytest -v
```

---

## Adversarial Red-Team Evaluation

A 10-scenario evaluation battery tests prompt-injection resilience, tool execution correctness, and memory persistence:

```bash
python scripts/advanced_soc_evaluation.py --url http://localhost:8080
```

---

## License

Built for the Google All Things Agentic Hackathon on the Gemini Enterprise Agent Platform (GEAP) and Google GenAI SDK.

Licensed under the Apache License, Version 2.0.
