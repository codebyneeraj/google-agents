import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as structured JSON for GCP Cloud Logging compatibility."""
    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "component": getattr(record, "component", "soc_orchestrator"),
            "trace_id": getattr(record, "trace_id", None),
            "span_id": getattr(record, "span_id", None),
        }
        if hasattr(record, "audit_event"):
            log_entry["audit_event"] = record.audit_event
        if hasattr(record, "extra_data") and record.extra_data:
            log_entry["details"] = record.extra_data
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

def setup_logger(name: str = "soc_orchestrator", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:
        formatter = StructuredJsonFormatter()
        
        # Ensure logs directory exists
        log_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "soc_audit.log")
        
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Stream to stdout only when explicitly enabled (e.g. Cloud Run containers)
        if os.getenv("LOG_TO_STDOUT", "false").lower() == "true":
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(formatter)
            logger.addHandler(stream_handler)
            
    logger.propagate = False
    return logger

audit_logger = setup_logger("soc_audit")

def log_audit_event(
    event_type: str,
    action: str,
    status: str,
    trace_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    severity: int = logging.INFO,
):
    """Emit a compliance-ready structured audit event."""
    tid = trace_id or str(uuid.uuid4())
    audit_data = {
        "event_type": event_type,
        "action": action,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    extra = {
        "component": "soc_audit_trail",
        "trace_id": tid,
        "audit_event": audit_data,
        "extra_data": details or {},
    }
    audit_logger.log(severity, f"AUDIT [{event_type}]: {action} -> {status}", extra=extra)
    return tid
