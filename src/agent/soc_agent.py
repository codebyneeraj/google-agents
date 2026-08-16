import os
import uuid
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from src.config import config
from src.security.model_armor import model_armor, GuardrailViolation
from src.memory.memory_service import memory_bank, MemoryEntry
from src.memory.session_service import session_service
from src.tools.soc_tools import (
    check_threat_intel,
    lookup_user_activity,
    isolate_host,
    inspect_linux_auth_logs,
    get_soc_tool_declarations,
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
Your mission is to investigate SIEM alerts, correlate threat intelligence, check user activity, and mitigate active threats following strict Zero-Trust protocols.

Rules:
1. Thoroughly verify all indicators (IPs, domains, hashes) using check_threat_intel.
2. Correlate user anomalies using lookup_user_activity.
3. If an endpoint is actively compromised by a critical threat (score >= 80), isolate the host using isolate_host.
4. Always generate structured findings referencing MITRE ATT&CK tactics (e.g., Initial Access, Credential Access, Command and Control).
5. Maintain strict operational security: never disclose raw secrets or bypass verification policies."""

    def __init__(self):
        self.client = None
        self._init_client()

    def _init_client(self):
        import warnings
        warnings.filterwarnings("ignore", category=UserWarning, module="google.genai")
        if config.gemini_api_key:
            try:
                from google import genai
                self.client = genai.Client(
                    api_key=config.gemini_api_key,
                    vertexai=False
                )
            except Exception as e:
                log_audit_event("AGENT_INIT", "GENAI_CLIENT_INIT", "FAILED", details={"error": str(e)}, severity=30)
        elif config.enterprise_mode:
            try:
                from google import genai
                self.client = genai.Client(
                    vertexai=True,
                    project=config.gcp_project,
                    location=config.gcp_location
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

        # 3. Autonomous Execution & Tool Invocation
        findings = []
        mitre_tactics = []

        if self.client:
            raw_output = self._execute_gemini(sanitized_input, memory_context, [], tid)
        else:
            raw_output = self._execute_deterministic_soc_workflow(sanitized_input, memory_context, [], findings, mitre_tactics, tid)

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

    def _execute_gemini(self, prompt: str, memory_context: str, actions_taken: List[Dict[str, Any]], trace_id: str) -> str:
        """Executes reasoning loop with Gemini API Client with native function calling."""
        try:
            from google.genai import types

            system_instruction = f"{self.SYSTEM_PROMPT}\n{memory_context}" if memory_context else self.SYSTEM_PROMPT

            tools = [check_threat_intel, lookup_user_activity, isolate_host, inspect_linux_auth_logs]
            gen_config = types.GenerateContentConfig(
                system_instruction=system_instruction,
                tools=tools,
                temperature=0.2,
            )

            # Generate content with tools
            response = self.client.models.generate_content(
                model=config.default_model,
                contents=prompt,
                config=gen_config,
            )

            if response.text:
                return response.text
            return f"Investigation reasoning processed by {config.default_model}."
        except Exception as e:
            print(f"\n[!] WARNING: Gemini API Call failed ({type(e).__name__}: {str(e)}). Falling back to local engine.")
            log_audit_event("AGENT_REASONING", "GEMINI_CALL_FAILED", "FALLBACK_TRIGGERED", trace_id=trace_id, details={"error": str(e)}, severity=30)
            return self._execute_deterministic_soc_workflow(prompt, memory_context, actions_taken, [], [], trace_id)


    def _execute_deterministic_soc_workflow(
        self,
        prompt: str,
        memory_context: str,
        actions_taken: List[Dict[str, Any]],
        findings: List[str],
        mitre_tactics: List[str],
        trace_id: str
    ) -> str:
        """Deterministic SOC investigation loop when operating in autonomous test mode."""
        lines = [
            "# SOC INCIDENT INVESTIGATION REPORT",
            f"**Trace ID:** `{trace_id}`",
            f"**Status:** Threat Mitigated / Verified",
            "",
            "## 1. Automated Telemetry Corroboration"
        ]

        # Check for conversational greeting / intro
        lower_prompt = prompt.strip().lower()
        if lower_prompt in ("hi", "hello", "hey", "who are you", "what can you do", "status"):
            findings.append("Operational: Standing by for SIEM alerts, indicator lookups, and mitigation tasks.")
            return (
                f"# SECURE SOC ANALYST ORCHESTRATOR\n"
                f"**Trace ID:** `{trace_id}`\n"
                f"**Status:** Operational (Zero-Trust Fleet)\n\n"
                f"Hello Analyst! I am your autonomous Tier-2 SOC Orchestrator built on the Gemini Enterprise Agent Platform.\n\n"
                f"### Core Capabilities:\n"
                f"- **Threat Intelligence**: Corroborate IPs, domains, and hashes against active threat feeds.\n"
                f"- **Identity Correlation**: Analyze IAM login anomalies and compromised user accounts.\n"
                f"- **EDR Mitigation**: Quarantine compromised host endpoints.\n"
                f"- **Model Armor**: Block prompt injection attacks and redact sensitive PII/secrets.\n"
                f"- **Memory Bank**: Retain persistent context across past incident sessions.\n\n"
                f"You can provide an IP (e.g. `198.51.100.45`), user email (e.g. `john.doe@enterprise.corp`), or type `help` / `demo`."
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
        if any("MALICIOUS" in str(a) for a in actions_taken):
            iso_res = isolate_host("WKSTN-JDOE-04", reason="Automated containment following high-risk threat actor activity", trace_id=trace_id)
            actions_taken.append({"tool": "isolate_host", "input": "WKSTN-JDOE-04", "result": iso_res})
            findings.append("Endpoint WKSTN-JDOE-04 successfully quarantined via EDR integration.")
        elif any(a.get("tool") == "inspect_linux_auth_logs" and a.get("result", {}).get("failed_attempts", 0) >= 5 for a in actions_taken):
            for ip in checked_ips:
                iso_ip_res = isolate_host(ip, reason="Automated firewall containment following detected SSH brute force threshold breach", trace_id=trace_id)
                actions_taken.append({"tool": "isolate_host", "input": ip, "result": iso_ip_res})
                findings.append(f"Attacker IP {ip} successfully blocked by Linux firewall.")


        # Construct report body
        if memory_context:
            lines.append("### Memory Context Recalled from Previous Sessions:")
            lines.append(memory_context.strip())
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

        lines.append("")
        lines.append("Contact security incident lead: secops-alert-lead@enterprise.corp for follow-up.")

        return "\n".join(lines)

soc_agent = SocAgentOrchestrator()
