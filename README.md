# Secure SOC Analyst Orchestrator

**Hackathon:** All Things Agentic Hackathon by Google  
**Track:** The Fortified Enterprise Fleet  
**Platform:** Gemini Enterprise Agent Platform (GEAP)

---

## Architecture & GEAP Mapping

| GEAP / GCP Component | Implementation in This Project | Purpose |
| :--- | :--- | :--- |
| **Gemini API** | `gemini-2.0-flash` / `gemini-1.5-flash` | Core reasoning engine for analyzing security alerts & synthesizing reports. |
| **Google ADK & GenAI SDK** | `google-genai` Python SDK | Official agent framework for managing tools, callbacks, and orchestration. |
| **Agent Registry** | `/api/v1/agent/registry` | Central fleet catalog for capability discovery and IAM contract verification. |
| **Agent Runtime** | Google Cloud Run (`Dockerfile`) | Serverless, scalable container execution runtime. |
| **Memory Bank** | `VertexAiMemoryBankService` | Retains cross-session investigation context (repeat IPs, user compromises). |
| **Model Armor** | `src/security/model_armor.py` | Inbound prompt injection defense & outbound PII/secret redaction. |
| **Observability** | `src/observability/logger.py` | Compliance-ready structured JSON logging and trace correlation. |

---

## Key Features

1. **Autonomous SIEM Alert Triaging**: Correlates IPs against threat intelligence feeds, checks IAM authentication logs, and triggers EDR host quarantine when critical threats (e.g. APT-29) are detected.
2. **Model Armor Defense-in-Depth**:
   - **Inbound**: Detects and blocks instruction override, jailbreak, and prompt injection attempts.
   - **Outbound**: Automatically redacts emails, API keys, credentials, and sensitive tokens from reports.
3. **Cross-Session Memory Bank**: Remembers prior incidents and indicators without requiring the analyst to re-provide context across sessions.
4. **Least-Privilege IAM Posture**: Bounded to `roles/aiplatform.user`, `roles/datastore.user`, and `roles/logging.logWriter`.

---

## Quick Start

### 1. Set Up Virtual Environment
```bash
python -m venv .venv
# On Windows
.venv\Scripts\activate
# On Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure Environment (Optional)
Copy `.env.example` to `.env` and configure your `GEMINI_API_KEY`:
```bash
cp .env.example .env
```

### 3. Run Automated Tests
```bash
pytest -v
```

### 4. Run the Hackathon Pitch Demonstration
```bash
python demo.py
```

### 5. Launch the Interactive SOC Analyst CLI
```bash
python main.py
```

### 6. Launch the FastAPI Agent Gateway
```bash
uvicorn src.gateway.server:app --reload --port 8080
```
- API Docs: `http://localhost:8080/docs`
- Registry Discovery: `http://localhost:8080/api/v1/agent/registry`
- Health Check: `http://localhost:8080/healthz`

---

## Verification & Test Results
- 15 Unit tests across Model Armor, SOC Tools, Agent Orchestration, and API Gateway passed.
- Fully compatible with Google Cloud Run serverless deployment.
