# Secure SOC Analyst Orchestrator

**Hackathon:** All Things Agentic Hackathon by Google  
**Track:** The Fortified Enterprise Fleet  
**Platform:** Gemini Enterprise Agent Platform (GEAP)

---

## 🏗️ Architecture Workflow Diagram

```mermaid
flowchart TD
    A[SIEM / EDR Alert Webhook] --> B[FastAPI Agent Gateway]
    U[SOC Analyst Query] --> B
    B --> C{Model Armor Inbound}
    C -- "Injection Detected" --> D[Block & Emit Security Audit Log]
    C -- "Passed Validation" --> E[GEAP Memory Bank Recall]
    E --> F[Gemini 2.5 Autonomous Orchestrator]
    F --> G[SOC Tools: Threat Intel / IAM / EDR]
    G --> F
    F --> H[Memory Bank Callback: Auto-Store Context]
    F --> I{Model Armor Outbound}
    I --> J[PII & Token Redaction]
    J --> K[Incident Report & Cloud Logging Audit Trail]
```

---

## 🏆 Hackathon Rubric Mapping

### 1. Innovation & Operational Utility (40%)
- **Autonomous Triage & Remediation**: Beyond basic alert summaries, the agent orchestrates multi-source threat intelligence corroboration, correlates Active Directory IAM authentication anomalies, and executes automated EDR host quarantine on compromised endpoints.
- **Zero-Shot Context Continuity**: Powered by the managed `VertexAiMemoryBankService`, the agent recalls prior investigations across completely separate sessions without requiring analysts to re-provide indicators or logs.

### 2. Architectural Discipline & Tech Stack (30%)
- **Native GEAP Services**: Integrated with `VertexAiMemoryBankService`, `VertexAiSessionService`, and the Google GenAI SDK with automatic function calling.
- **Defense-in-Depth Model Armor**: Pre-execution heuristic guardrails intercept prompt injection and instruction overrides; post-execution NLP/regex sanitizers redact sensitive PII (emails, API keys, credentials).
- **Least-Privilege Zero-Trust Identity**: Configured with strict IAM roles (`roles/aiplatform.user`, `roles/datastore.user`, `roles/logging.logWriter`) and explicitly denied administrative permissions.

### 3. Demo & Production Readiness (30%)
- **A2A & Agent Registry Catalog**: Published `agent-card.json` schema compliant with GEAP Agent Registry specifications for enterprise fleet discovery.
- **Serverless Cloud Runtime**: Containerized with Docker and automated for deployment to Google Cloud Run via `cloudbuild.yaml`.
- **Structured Audit Observability**: Emits structured JSON logs compatible with Google Cloud Logging with unified `trace_id` correlation for full SOC compliance.

---

## 📋 GEAP Component Mapping

| GEAP / GCP Component | Implementation in This Project | Purpose |
| :--- | :--- | :--- |
| **Gemini / Gemma API** | `gemma-4-31b-it` / `gemini-2.5-flash` | Core reasoning engine for analyzing security alerts & synthesizing reports. |
| **Google ADK & GenAI SDK** | `google-genai` Python SDK | Official agent framework for managing tools, callbacks, and orchestration. |
| **Agent Registry** | `agent-card.json` & `/api/v1/agent/registry` | Central fleet catalog for capability discovery and IAM contract verification. |
| **Agent Runtime** | Google Cloud Run (`Dockerfile`, `cloudbuild.yaml`) | Serverless, scalable container execution runtime. |
| **Memory Bank** | `VertexAiMemoryBankService` | Retains cross-session investigation context (repeat IPs, user compromises). |
| **Model Armor** | `src/security/model_armor.py` | Inbound prompt injection defense & outbound PII/secret redaction. |
| **Observability** | `src/observability/logger.py` | Compliance-ready structured JSON logging and trace correlation. |

---

## 🚀 Quick Start

### 1. Set Up Virtual Environment
```bash
python -m venv .venv
# On Windows
.venv\Scripts\activate
# On Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 3. Run Automated Tests
```bash
pytest -v
```

### 4. Run Cloud Validation Suite
```bash
python validate_cloud.py
```

### 5. Run the Hackathon Pitch Demonstration
```bash
python demo.py
```

### 6. Launch the Interactive SOC Analyst CLI
```bash
python main.py
```

### 7. Launch the FastAPI Agent Gateway
```bash
uvicorn src.gateway.server:app --reload --port 8080
```
- API Docs: `http://localhost:8080/docs`
- Registry Discovery: `http://localhost:8080/api/v1/agent/registry`
- Fleet Listing: `http://localhost:8080/api/v1/agent/registry/fleet`
- Health Check: `http://localhost:8080/healthz`

---

## 🛡️ Live Linux VM Security Lab (Windows Attacker -> Linux Defender)

Test real intrusion detection and automated firewall containment using a Linux VM (Ubuntu / Debian / RHEL):

### Step 1: Install on Linux Virtual Machine
On your Linux VM, clone this repository and run the automated installer:
```bash
chmod +x install_vm.sh
./install_vm.sh
```

### Step 2: Start the Defender Services on Linux VM
```bash
# Terminal 1: Start Agent Gateway
source .venv/bin/activate
python main.py --gateway

# Terminal 2: Start the Live Auth Log Sensor Daemon
source .venv/bin/activate
sudo python scripts/sensor_daemon.py
```

### Step 3: Run the Attack Simulation from Windows Host
From your Windows host machine, launch simulated SSH brute force against the Linux VM:
```powershell
# Python
python scripts/attack_simulation.py --target-ip <LINUX_VM_IP>

# Or native PowerShell:
.\scripts\attack_simulation.ps1 -TargetIp <LINUX_VM_IP>
```
The sensor daemon detects the failed login attempts in `/var/log/auth.log`, alerts the SOC Agent, and the agent automatically executes `ufw`/`iptables` firewall rules to block your Windows IP.

---

## ☁️ Google Cloud Deployment


### 1. Deploy to Google Cloud Run (Agent Runtime)
```bash
gcloud builds submit --config cloudbuild.yaml
```

### 2. Register in GEAP Agent Registry
```bash
gcloud agent-registry services create soc-orchestrator-v1 \
  --project=YOUR_PROJECT_ID \
  --location=us-central1 \
  --display-name="Secure SOC Analyst Orchestrator" \
  --agent-spec-type=a2a-agent-card \
  --agent-spec-content=agent-card.json
```
