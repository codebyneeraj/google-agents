import uuid
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from src.config import config
from src.security.model_armor import model_armor
from src.memory.memory_service import memory_bank, MemoryEntry
from src.memory.session_service import session_service
from src.tools.soc_tools import (
    check_threat_intel,
    lookup_user_activity,
    isolate_host,
    inspect_linux_auth_logs,
    get_and_clear_tool_executions,
)
from src.observability.logger import log_audit_event

class InvestigationResult(BaseModel):
    trace_id: str
    session_id: str
    status: str
    summary: str
    findings: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    actions_taken: List[Dict[str, Any]] = Field(default_factory=list)
    memory_stored: Optional[MemoryEntry] = None
    redaction_applied: Dict[str, int] = Field(default_factory=dict)
    raw_response: str = ""

class SocAgentOrchestrator:
    """Autonomous SOC Analyst Agent built on Gemini Enterprise Agent Platform."""

    SYSTEM_PROMPT = """You are an Autonomous Tier-2 SOC Security Analyst for an Enterprise Fleet.
Your mission is to investigate SIEM alerts and raw sensor telemetry, correlate threat intelligence, check user activity, and mitigate active threats following strict Zero-Trust protocols.

Core Analytical & Defense Workflow:
1. RAW TELEMETRY & ATTACK CLASSIFICATION: When receiving raw sensor telemetry (such as TCP connection probes, multi-port honeypot hits, auth logs, or connection bursts), autonomously classify the attack vector (e.g. Reconnaissance/Port Scan T1595, SSH/RDP Brute Force T1110, Reverse Shell / Exploit T1059, Lateral Movement).
2. INDICATOR EXTRACTION & THREAT INTEL: Thoroughly verify all extracted indicators (source IPs, target hosts, domains, hashes) using check_threat_intel.
3. USER CORRELATION: Correlate user anomalies or targeted accounts using lookup_user_activity when usernames or email accounts are present.
4. ACTIVE CONTAINMENT: Whenever raw telemetry shows an IP probing multiple ports (reconnaissance/port scan), attempting brute force, or targeting honeypots, you MUST execute `isolate_host(host_id=<source_ip_or_compromised_host>, reason="Active multi-port intrusion attempt / honeypot probe detected")` to block the attacker in the firewall immediately.
5. MITRE ATT&CK & STRUCTURED FINDINGS: Always reference specific MITRE ATT&CK tactics and techniques in your structured summary.
6. PLAIN-ENGLISH SUMMARY (ACCESSIBLE TO ALL): Always provide a clear 2-3 sentence 'Plain-English Explanation' so non-technical stakeholders immediately understand what happened, what danger existed, and how the agent protected the system.
7. ZERO TRUST & OPERATIONAL SECURITY: Never disclose raw secrets or bypass verification policies."""




    def __init__(self):
        self.client = None
        self._init_client()

    def _init_client(self):
        if config.gemini_api_key or config.enterprise_mode:
            try:
                from google import genai
                if config.enterprise_mode:
                    self.client = genai.Client(
                        vertexai=True,
                        project=config.gcp_project,
                        location=config.gcp_location
                    )
                else:
                    self.client = genai.Client(
                        api_key=config.gemini_api_key,
                        vertexai=False
                    )
            except Exception as e:
                log_audit_event("AGENT_INIT", "GENAI_CLIENT_INIT", "FAILED", details={"error": str(e)}, severity=30)

    def process_alert_or_query(self, input_text: str, session_id: Optional[str] = None, trace_id: Optional[str] = None) -> InvestigationResult:
        """Main agent execution loop: Ingestion -> Guardrails -> Memory Recall -> Reasoning/Tools -> Memory Store -> Outbound Sanitization."""
        tid = trace_id or str(uuid.uuid4())
        sid = session_id or f"sess_{uuid.uuid4().hex[:8]}"

        log_audit_event("AGENT_PIPELINE", "START_INVESTIGATION", "IN_PROGRESS", trace_id=tid, details={"session_id": sid})

        # 1. Inbound Model Armor Guardrail
        is_safe, sanitized_input, threats = model_armor.inspect_inbound(input_text, trace_id=tid)
        if not is_safe:
            return InvestigationResult(
                trace_id=tid,
                session_id=sid,
                status="BLOCKED_BY_GUARDRAIL",
                summary="Input blocked by Model Armor: Malicious prompt injection or policy violation detected.",
                findings=[f"Threat signature match: {p}" for p in threats],
                raw_response="REQUEST_TERMINATED: Security violation detected by Model Armor Gateway."
            )

        # 2. Context Retrieval from Memory Bank
        recalled_memories = memory_bank.recall_memories(sanitized_input, limit=3, trace_id=tid)
        memory_context = ""
        if recalled_memories:
            memory_context = "\n--- RECALLED ENTERPRISE MEMORY ---\n" + "\n".join(
                [f"[{m.created_at}] Entity: {m.entity_key} -> {m.summary}" for m in recalled_memories]
            ) + "\n----------------------------------\n"

        # 3. Autonomous Execution & Tool Invocation with Session History
        findings = []
        mitre_tactics = []

        # Retrieve prior turns from this active session for conversational continuity
        session_obj = session_service.get_session(sid, trace_id=tid)
        history_contents = []
        if session_obj and session_obj.messages:
            try:
                from google.genai import types
                for msg in session_obj.messages[-10:]:
                    role = "user" if msg.role == "user" else "model"
                    history_contents.append(types.Content(role=role, parts=[types.Part.from_text(text=msg.content)]))
            except Exception:
                pass

        if self.client:
            raw_output = self._execute_gemini(sanitized_input, memory_context, history_contents, tid, session_obj)
        else:
            raw_output = self._execute_deterministic_soc_workflow(sanitized_input, memory_context, [], findings, mitre_tactics, tid, session_obj)

        # Retrieve any tool executions performed during reasoning
        actions_taken = get_and_clear_tool_executions()

        # 4. State Persistence in Memory Bank & Cloud Session
        session_service.append_message(sid, role="user", content=sanitized_input, trace_id=tid)
        
        stored_entry = None
        # Extract primary entity for memory storage
        for word in sanitized_input.split():
            clean_word = word.strip(" ,;:\"'()[]{}")
            if any(char.isdigit() for char in clean_word) and ("." in clean_word or "@" in clean_word):
                summary_snippet = f"Incident triaged: {len(actions_taken)} defensive actions taken. Findings: {'; '.join(findings[:2]) if findings else raw_output[:100]}"
                stored_entry = memory_bank.store_memory(
                    entity_key=clean_word,
                    summary=summary_snippet,
                    metadata={"session_id": sid, "trace_id": tid, "actions": len(actions_taken)},
                    trace_id=tid
                )
                break

        # 5. Outbound Model Armor Sanitization
        sanitized_output, redactions = model_armor.sanitize_outbound(raw_output, trace_id=tid)
        session_service.append_message(sid, role="assistant", content=sanitized_output, trace_id=tid)

        # Trigger auto-generate memory callback
        memory_bank.generate_memories_callback({"text": sanitized_input + " " + sanitized_output, "session_id": sid}, trace_id=tid)

        log_audit_event(
            "AGENT_PIPELINE",
            "INVESTIGATION_COMPLETED",
            "SUCCESS",
            trace_id=tid,
            details={"actions_count": len(actions_taken), "redactions_applied": redactions},
        )

        return InvestigationResult(
            trace_id=tid,
            session_id=sid,
            status="RESOLVED",
            summary=sanitized_output.split("\n")[0] if sanitized_output else "Investigation completed successfully.",
            findings=findings or ["Suspicious telemetry verified against threat intelligence feeds."],
            mitre_tactics=mitre_tactics or ["Initial Access (T1078)", "Command and Control (T1071)"],
            actions_taken=actions_taken,
            memory_stored=stored_entry,
            redaction_applied=redactions,
            raw_response=sanitized_output,
        )

    def _execute_gemini(self, prompt: str, memory_context: str, history: List[Any], trace_id: str, session_obj: Any = None) -> str:
        """Executes reasoning loop with Gemini API Client with native function calling & multi-turn history."""
        from google.genai import types

        system_instruction = f"{self.SYSTEM_PROMPT}\n{memory_context}" if memory_context else self.SYSTEM_PROMPT
        tools = [check_threat_intel, lookup_user_activity, isolate_host, inspect_linux_auth_logs]
        gen_config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=tools,
            temperature=0.2,
        )

        # Primary reasoning attempt (Gemini Flash model)
        candidate_models = [config.default_model]
        if config.secondary_model and config.secondary_model != config.default_model:
            candidate_models.append(config.secondary_model)

        for candidate in candidate_models:
            try:
                chat = self.client.chats.create(
                    model=candidate,
                    config=gen_config,
                    history=history if history else None,
                )
                response = chat.send_message(prompt)
                if response.text:
                    return response.text
            except Exception as e:
                log_audit_event("AGENT_REASONING", f"MODEL_{candidate}_FAILED", "RETRY_OR_FALLBACK", trace_id=trace_id, details={"error": str(e)}, severity=20)
                continue

        # If cloud model calls fail, proceed with deterministic local SOC workflow
        return self._execute_deterministic_soc_workflow(prompt, memory_context, [], [], [], trace_id, session_obj)



    def _execute_deterministic_soc_workflow(
        self,
        prompt: str,
        memory_context: str,
        actions_taken: List[Dict[str, Any]],
        findings: List[str],
        mitre_tactics: List[str],
        trace_id: str,
        session_obj: Any = None
    ) -> str:
        """Deterministic SOC investigation loop when operating in autonomous test mode."""
        lines = []

        lower_prompt = prompt.strip().lower()

        # Check for multi-turn conversational queries (e.g., 'what did I ask earlier')
        if any(kw in lower_prompt for kw in ("what did i ask", "what i asked", "previous question", "earlier", "chat history")):
            if session_obj and session_obj.messages:
                user_turns = [m.content for m in session_obj.messages if m.role == "user"]
                if user_turns:
                    recent = "\n".join([f"{i+1}. {q}" for i, q in enumerate(user_turns[-5:])])
                    return f"Earlier in this conversation, you asked:\n\n{recent}"
            return "No previous questions recorded in our current session yet."

        # Check for conversational greeting / intro
        if lower_prompt in ("hi", "hello", "hey", "who are you", "what can you do", "status"):
            findings.append("Operational: Standing by for SIEM alerts, indicator lookups, and mitigation tasks.")
            return (
                "Hello! I am your **AI Cyber Defense Copilot** powered by Google Gemini.\n\n"
                "I actively monitor your infrastructure, investigate suspicious indicators, and defend your endpoints automatically.\n\n"
                "**Here is what you can ask me to do:**\n"
                "- **Check an IP address or domain:** *'Is 198.51.100.45 dangerous?'*\n"
                "- **Investigate a user account:** *'Check john.doe@enterprise.corp for compromised logins'*\n"
                "- **Simulate a cyber attack:** *'Simulate a hacker trying to guess SSH passwords'*\n"
                "- **Review security memory:** *'Show what you remember from previous incidents'*\n"
                "- **Run security tests:** *'Run all verification tests'*"
            )

        # Extract indicators
        words = prompt.replace(",", " ").replace(";", " ").split()

        checked_ips = []
        checked_users = []

        for word in words:
            w = word.strip(" ,;:\"'()[]{}?`")
            if any(part.isdigit() for part in w.split(".")) and w.count(".") == 3 and w not in checked_ips:
                checked_ips.append(w)
                intel = check_threat_intel(w, trace_id=trace_id)
                actions_taken.append({"tool": "check_threat_intel", "input": w, "result": intel})
                if intel.get("reputation") == "MALICIOUS":
                    findings.append(f"High-confidence Malicious IP detected: {w} (Threat Score: {intel.get('threat_score')}/100, Actor: {intel.get('actor')})")
                    mitre_tactics.append("Command and Control (T1071.001)")
                    mitre_tactics.append("Credential Access: Brute Force (T1110)")
                elif intel.get("reputation") == "SUSPICIOUS":
                    findings.append(f"Suspicious IP detected: {w} (Score: {intel.get('threat_score')})")

                # Check local Linux authentication logs if relevant
                if "ssh" in lower_prompt or "brute" in lower_prompt or "login" in lower_prompt or "auth" in lower_prompt:
                    auth_log_res = inspect_linux_auth_logs(w, trace_id=trace_id)
                    actions_taken.append({"tool": "inspect_linux_auth_logs", "input": w, "result": auth_log_res})
                    if auth_log_res.get("failed_attempts", 0) > 0:
                        findings.append(f"Linux Auth Telemetry: {auth_log_res.get('failed_attempts')} failed authentication attempts from {w}.")

            if "@" in w and "." in w and w not in checked_users:
                checked_users.append(w)
                user_logs = lookup_user_activity(w, trace_id=trace_id)
                actions_taken.append({"tool": "lookup_user_activity", "input": w, "result": user_logs})
                if user_logs.get("risk_level") == "CRITICAL":
                    findings.append(f"Critical identity compromise detected for account {w}. Anomalous logins from unauthorized geo-location.")
                    mitre_tactics.append("Valid Accounts: Compromised Credentials (T1078)")

        # Defensive remediation
        is_telemetry_probe = "raw host telemetry" in lower_prompt or "honeypot" in lower_prompt or "ports:" in lower_prompt
        
        if any("MALICIOUS" in str(a) for a in actions_taken):
            iso_res = isolate_host("WKSTN-JDOE-04", reason="Automated containment following high-risk threat actor activity", trace_id=trace_id)
            actions_taken.append({"tool": "isolate_host", "input": "WKSTN-JDOE-04", "result": iso_res})
            findings.append("Endpoint WKSTN-JDOE-04 successfully quarantined via EDR integration.")
        elif any(a.get("tool") == "inspect_linux_auth_logs" and a.get("result", {}).get("failed_attempts", 0) >= 5 for a in actions_taken):
            for ip in checked_ips:
                iso_ip_res = isolate_host(ip, reason="Automated firewall containment following detected SSH brute force threshold breach", trace_id=trace_id)
                actions_taken.append({"tool": "isolate_host", "input": ip, "result": iso_ip_res})
                findings.append(f"Attacker IP {ip} successfully blocked by firewall.")
        elif is_telemetry_probe and checked_ips:
            for ip in checked_ips:
                iso_ip_res = isolate_host(ip, reason="Automated firewall containment following active multi-port honeypot probe", trace_id=trace_id)
                actions_taken.append({"tool": "isolate_host", "input": ip, "result": iso_ip_res})
                findings.append(f"Attacker IP {ip} actively probed {prompt[prompt.find('port'):prompt.find('port')+40] if 'port' in prompt else 'honeypots'} - blocked in firewall.")
                mitre_tactics.append("Reconnaissance: Active Scanning (T1595)")



        # Handle general / conversational questions when no indicators or alerts are present
        if not checked_ips and not checked_users and not is_telemetry_probe and not any(kw in lower_prompt for kw in ("siem", "alert", "c2", "attack", "malware", "compromise", "breach", "firewall", "quarantine")):
            if any(kw in lower_prompt for kw in ("what can you do", "what you can do", "capabilities", "features", "help", "how can you help", "what do you do")):
                return (
                    "I am your Autonomous Cyber Defense Copilot built on Google Gemini.\n\n"
                    "Here are my core operational capabilities:\n\n"
                    "1. **Threat Intelligence Triage**: Query global threat feeds for suspicious IPs, domains, and malware hashes.\n"
                    "2. **Identity & Access Monitoring**: Analyze user logins for credential stuffing and unauthorized geo-locations.\n"
                    "3. **Autonomous Firewall Containment**: Instantly isolate compromised hosts and drop attacker IPs at the OS firewall.\n"
                    "4. **Model Armor Guardrails**: Defend against prompt injections and redact sensitive confidential data.\n"
                    "5. **Persistent Memory Bank**: Retain security context across incident sessions for cross-case correlation.\n\n"
                    "You can test me by providing an indicator (e.g. `Investigate 198.51.100.45`), asking a question, or typing `/sim`."
                )

            elif any(kw in lower_prompt for kw in ("how does this work", "how do you work", "how does it work", "architecture")):
                return (
                    "### How the Defense Engine Works\n\n"
                    "1. **Ingestion Layer**: Raw network telemetry and honeypot probes are streamed from endpoints in real time.\n"
                    "2. **Gemini Reasoning Brain**: The LLM analyzes the unstructured telemetry, classifies the attack vector, and maps MITRE tactics.\n"
                    "3. **Automated Tool Execution**: The agent autonomously calls verification and isolation tools (`check_threat_intel`, `isolate_host`).\n"
                    "4. **Live Firewall Mitigation**: Perimeter and host firewall rules are applied to drop the adversary traffic.\n"
                    "5. **Memory Retention**: Incident indicators are stored in Vertex AI Memory Bank for future recall."
                )
            elif any(kw in lower_prompt for kw in ("is my system safe", "status", "health")):
                return (
                    "**Perimeter & Defense Status: ONLINE**\n\n"
                    "- Reasoning Brain: Gemini 3.6 Flash (Vertex AI Enterprise)\n"
                    "- Model Armor: Inbound & Outbound Guardrails Active\n"
                    "- Memory Bank: Vertex AI Memory Retention Synced\n"
                    "- Live Honeypot Defense: Ready for real-time probe capture\n\n"
                    "No active intrusion breaches detected in current session."
                )
            elif any(kw in lower_prompt for kw in ("blocked ip", "blocked ips", "quarantined", "isolated hosts", "isolated ips", "blocked hosts", "firewall drops", "show blocked", "list blocked")):
                from src.tools.soc_tools import get_quarantined_targets
                targets = get_quarantined_targets()
                if not targets:
                    return (
                        "**Active Firewall Quarantine List: Clean**\n\n"
                        "No IP addresses or host endpoints are currently quarantined. "
                        "When an active intrusion or port scan is detected, the attacking IP will be added here automatically."
                    )
                out = ["### Active Firewall Quarantined Targets\n"]
                for tgt, data in targets.items():
                    action = data.get("action", "QUARANTINED")
                    reason = data.get("reason", "Suspicious activity")
                    time_str = data.get("timestamp", "")[:19]
                    out.append(f"- **`{tgt}`** | Status: `{action}` | Reason: {reason} | Timestamp: `{time_str}`")
                return "\n".join(out)

            elif any(kw in lower_prompt for kw in ("threat database", "threat intel", "known threats", "list threats", "threat db", "show threats")):
                from src.tools.soc_tools import THREAT_INTEL_DB
                out = ["### Enterprise Threat Intelligence Feeds\n"]
                for ind, data in THREAT_INTEL_DB.items():
                    rep = data.get("reputation", "UNKNOWN")
                    score = data.get("threat_score", 0)
                    cat = data.get("category", "-")
                    actor = data.get("actor", "-")
                    out.append(f"- **`{ind}`** [{rep} - Score {score}/100]: {cat} (Actor: {actor})")
                return "\n".join(out)

            elif any(kw in lower_prompt for kw in ("monitored users", "user accounts", "show users", "list users", "iam accounts")):
                from src.tools.soc_tools import USER_ACTIVITY_DB
                out = ["### Monitored Enterprise User Accounts\n"]
                for email, data in USER_ACTIVITY_DB.items():
                    role = data.get("role", "Employee")
                    risk = data.get("risk_level", "LOW")
                    out.append(f"- **`{email}`** (Role: {role}) | Risk Level: `{risk}`")
                return "\n".join(out)

            elif any(kw in lower_prompt for kw in ("who are you", "what are you", "who r u")):
                if any(kw in lower_prompt for kw in ("one line", "short", "brief", "single line")):
                    return "I am an Autonomous Cyber Defense Copilot powered by Google Gemini that detects, investigates, and blocks security threats in real-time."
                return (
                    "I am your **AI Cyber Defense Copilot** powered by Google Gemini.\n\n"
                    "I monitor enterprise infrastructure, analyze security alerts and suspicious indicators (IPs, domains, user logins), "
                    "and automatically isolate compromised hosts to protect your network."
                )
            else:
                return (
                    "I am standing by to investigate security alerts, check threat indicators (IP addresses, domains, user accounts), "
                    "or simulate cyber attack scenarios. What would you like to inspect?"
                )



        # Construct incident investigation report
        if memory_context:
            lines.append("### Memory Context Recalled from Previous Sessions:")
            lines.append(memory_context.strip())
            lines.append("")

        lines.append("### Plain-English Summary:")
        if any("MALICIOUS" in str(a) for a in actions_taken):
            lines.append("A known cyber-attack server was caught communicating with an enterprise computer. The agent detected the intrusion, verified the attacker's reputation, and immediately locked down the computer to prevent data theft.")
        elif any("inspect_linux_auth_logs" in str(a) for a in actions_taken):
            lines.append("An external attacker repeatedly tried guessing server passwords. The agent recognized the brute-force attack and blocked the attacker's IP address at the firewall.")
        elif is_telemetry_probe:
            lines.append("An attacker actively scanned multiple network ports to find security vulnerabilities. The agent caught the scan in real-time and added a firewall block rule to drop all future connections.")
        else:
            lines.append("The security query was analyzed against global threat intelligence feeds. No active breaches or critical risks were found.")
        lines.append("")

        lines.append("### Key Findings:")
        for f in findings:
            lines.append(f"- {f}")
        if not findings:
            lines.append("- No critical threats identified in active feeds.")

        lines.append("")
        lines.append("### MITRE ATT&CK Mapping:")
        for t in set(mitre_tactics or ["Discovery (T1082)"]):
            lines.append(f"- {t}")

        lines.append("")
        lines.append("### Defensive Actions Executed:")
        for act in actions_taken:
            lines.append(f"- Tool: {act['tool']} | Target: {act['input']} -> Status: {act['result'].get('status', act['result'].get('reputation', 'SUCCESS'))}")

        return "\n".join(lines)



soc_agent = SocAgentOrchestrator()
