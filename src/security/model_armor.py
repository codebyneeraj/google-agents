import re
from typing import Dict, List, Tuple, Any
from src.observability.logger import log_audit_event

class GuardrailViolation(Exception):
    """Raised when an inbound or outbound guardrail check fails."""
    def __init__(self, message: str, violation_type: str, details: Dict[str, Any]):
        super().__init__(message)
        self.violation_type = violation_type
        self.details = details

class ModelArmor:
    """Enterprise security layer for Inbound Injection Prevention and Outbound PII Redaction."""

    # Inbound Injection & Jailbreak Heuristics
    INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above|existing|security)\s+(instructions|rules|policies|guidelines|system)",
        r"(?i)disregard\s+(all\s+)?(previous|prior|above|existing|security)\s+(instructions|rules|policies|guidelines)",
        r"(?i)system\s+(prompt|instruction)\s+override",
        r"(?i)output\s+(your\s+)?(system\s+prompt|initial\s+prompt|secret\s+instructions)",
        r"(?i)you\s+are\s+now\s+in\s+(developer\s+mode|god\s+mode|unrestricted)",
        r"(?i)dan\s+mode|jailbreak|unfiltered\s+mode",
        r"(?i)bypass\s+(safety|security|policy)\s+guidelines",
        r"(?i)drop\s+table\b|;\s*delete\s+from\b|union\s+select",
        r"(?i)<\s*script\b.*?>.*?<\s*/\s*script\s*>",
    ]

    # Outbound PII and Secret Redaction Patterns
    PII_PATTERNS = {
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "API_KEY": r"\b(?:ghp_[0-9a-zA-Z]{36}|sk-[a-zA-Z0-9]{32,}|sec_[a-zA-Z0-9]{24,})\b",
        "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "PASSWORD_HASH": r"\b(?:password|passwd|secret)\s*[:=]\s*['\"][^\s'\"]+['\"]\b",
    }

    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self._compiled_injection = [re.compile(p) for p in self.INJECTION_PATTERNS]
        self._compiled_pii = {k: re.compile(p, re.IGNORECASE) for k, p in self.PII_PATTERNS.items()}

    def evaluate_input_safety(self, prompt: str, trace_id: str = None) -> Dict[str, Any]:
        """Comprehensive inbound security evaluation returning risk score and matched heuristics."""
        threats_found = []
        threat_score = 0

        for pattern in self._compiled_injection:
            matches = pattern.findall(prompt)
            if matches:
                threats_found.append(pattern.pattern)
                threat_score += 45  # Each matched injection pattern increases severity score

        threat_score = min(threat_score, 100)
        is_safe = (threat_score < 40)

        if not is_safe:
            log_audit_event(
                event_type="MODEL_ARMOR_INBOUND",
                action="PROMPT_INJECTION_DETECTED",
                status="BLOCKED",
                trace_id=trace_id,
                details={"threat_score": threat_score, "threat_patterns": threats_found, "sample_input": prompt[:120]},
                severity=40,
            )
        else:
            log_audit_event(
                event_type="MODEL_ARMOR_INBOUND",
                action="INPUT_VALIDATION",
                status="PASSED",
                trace_id=trace_id,
                details={"threat_score": threat_score, "input_length": len(prompt)},
            )

        return {
            "is_safe": is_safe,
            "threat_score": threat_score,
            "threats": threats_found,
            "sanitized_prompt": prompt,
        }

    def inspect_inbound(self, prompt: str, trace_id: str = None) -> Tuple[bool, str, List[str]]:
        """Inspects inbound user or webhook input for prompt injection and malicious instructions.
        Returns: (is_safe, sanitized_prompt, detected_threats)
        """
        eval_res = self.evaluate_input_safety(prompt, trace_id=trace_id)
        return eval_res["is_safe"], eval_res["sanitized_prompt"], eval_res["threats"]

    def sanitize_outbound(self, text: str, trace_id: str = None) -> Tuple[str, Dict[str, int]]:
        """Sanitizes model outputs by redacting PII, tokens, and credentials.
        Returns: (redacted_text, redaction_counts)
        """
        redacted = text
        redaction_counts = {}

        for pii_type, pattern in self._compiled_pii.items():
            matches = pattern.findall(redacted)
            if matches:
                redaction_counts[pii_type] = len(matches)
                redacted = pattern.sub(f"[REDACTED_{pii_type}]", redacted)

        if redaction_counts:
            log_audit_event(
                event_type="MODEL_ARMOR_OUTBOUND",
                action="PII_REDACTION",
                status="SANITIZED",
                trace_id=trace_id,
                details={"redactions": redaction_counts},
            )
        else:
            log_audit_event(
                event_type="MODEL_ARMOR_OUTBOUND",
                action="OUTPUT_VALIDATION",
                status="PASSED",
                trace_id=trace_id,
            )

        return redacted, redaction_counts

# Global singleton
model_armor = ModelArmor()
