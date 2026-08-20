"""
Event models for streaming agent investigations.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class AgentEvent(BaseModel):
    type: str
    trace_id: Optional[str] = None
    session_id: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)

class ToolCallEvent(BaseModel):
    tool: str
    input: Any
    result: Optional[Dict[str, Any]] = None

class MemoryItem(BaseModel):
    created_at: str
    entity_key: str
    summary: str

class StreamInvestigationResult(BaseModel):
    trace_id: str
    session_id: str
    status: str
    summary: str
    findings: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    actions_taken: List[Dict[str, Any]] = Field(default_factory=list)
    raw_response: str = ""
    redactions: Dict[str, int] = Field(default_factory=dict)
