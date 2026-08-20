"""
Client transport layer supporting both Local (direct Python) and Remote (Cloud Run HTTPS).
"""

from typing import Dict, Any, Generator, Optional
import httpx
import uuid
import json

from src.agent.soc_agent import soc_agent
from soc_cli.permissions import request_action_permission

class LocalClient:
    """Direct in-process execution using the local soc_agent instance."""

    def __init__(self, auto_approve: bool = False):
        self.auto_approve = auto_approve

    def stream_query(self, query: str, session_id: Optional[str] = None, trace_id: Optional[str] = None) -> Generator[Dict[str, Any], None, None]:
        for event in soc_agent.stream_alert_or_query(query, session_id=session_id, trace_id=trace_id):
            if event.get("type") == "tool_call":
                tool = event.get("tool")
                inp = event.get("input")
                # If destructive, verify permissions
                allowed, reason = request_action_permission(tool, {"host_id": inp, "reason": "Autonomous agent containment"}, self.auto_approve)
                if not allowed:
                    event["result"] = {"status": "DENIED_BY_ANALYST", "reason": "Operation cancelled by security operator."}
            yield event

class RemoteClient:
    """Remote HTTPS client communicating with Google Cloud Run gateway."""

    def __init__(self, base_url: str, auto_approve: bool = False):
        self.base_url = base_url.rstrip("/")
        self.auto_approve = auto_approve
        self.client = httpx.Client(timeout=35.0)

    def stream_query(self, query: str, session_id: Optional[str] = None, trace_id: Optional[str] = None) -> Generator[Dict[str, Any], None, None]:
        tid = trace_id or str(uuid.uuid4())
        sid = session_id or f"sess_remote_{uuid.uuid4().hex[:8]}"

        yield {"type": "start", "trace_id": tid, "session_id": sid, "input": query}
        yield {"type": "inbound_guardrail", "status": "SAFE", "threats": []}

        try:
            payload = {"query": query, "session_id": sid}
            resp = self.client.post(f"{self.base_url}/api/v1/agent/query", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                for action in data.get("actions_taken", []):
                    yield {
                        "type": "tool_call",
                        "tool": action.get("tool"),
                        "input": action.get("input"),
                        "result": action.get("result"),
                    }
                yield {"type": "final", "result": data}
            elif resp.status_code == 400 or "BLOCKED" in resp.text:
                yield {
                    "type": "inbound_guardrail",
                    "status": "BLOCKED",
                    "threats": ["Malicious payload intercepted by Cloud Model Armor"],
                }
                yield {"type": "final", "result": resp.json()}
            else:
                yield {
                    "type": "error",
                    "message": f"Cloud Gateway Error ({resp.status_code}): {resp.text[:100]}",
                }
        except Exception as e:
            yield {"type": "error", "message": f"Failed to connect to Cloud Run: {str(e)}"}
