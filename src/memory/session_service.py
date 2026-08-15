from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
import uuid

from src.config import config
from src.observability.logger import log_audit_event

class SessionMessage(BaseModel):
    role: str  # user, assistant, system
    content: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SessionState(BaseModel):
    session_id: str
    app_id: str = config.app_id
    user_id: str = config.default_user_id
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    messages: List[SessionMessage] = Field(default_factory=list)
    context_data: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True

class BaseSessionService:
    def create_session(self, user_id: Optional[str] = None, session_id: Optional[str] = None, trace_id: Optional[str] = None) -> SessionState:
        raise NotImplementedError

    def get_session(self, session_id: str, trace_id: Optional[str] = None) -> Optional[SessionState]:
        raise NotImplementedError

    def append_message(self, session_id: str, role: str, content: str, metadata: Optional[Dict[str, Any]] = None, trace_id: Optional[str] = None) -> SessionState:
        raise NotImplementedError

    def close_session(self, session_id: str, trace_id: Optional[str] = None) -> bool:
        raise NotImplementedError

class InMemorySessionService(BaseSessionService):
    """Fast local session store tracking multi-turn incident conversations."""
    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}

    def create_session(self, user_id: Optional[str] = None, session_id: Optional[str] = None, trace_id: Optional[str] = None) -> SessionState:
        sid = session_id or f"sess_{uuid.uuid4().hex[:8]}"
        uid = user_id or config.default_user_id
        session = SessionState(session_id=sid, user_id=uid)
        self._sessions[sid] = session
        log_audit_event("SESSION_SERVICE", "CREATE_SESSION", "SUCCESS", trace_id=trace_id, details={"session_id": sid, "user_id": uid})
        return session

    def get_session(self, session_id: str, trace_id: Optional[str] = None) -> Optional[SessionState]:
        session = self._sessions.get(session_id)
        if not session:
            # Auto-create if not found to ensure graceful continuity
            session = self.create_session(session_id=session_id, trace_id=trace_id)
        return session

    def append_message(self, session_id: str, role: str, content: str, metadata: Optional[Dict[str, Any]] = None, trace_id: Optional[str] = None) -> SessionState:
        session = self.get_session(session_id, trace_id=trace_id)
        msg = SessionMessage(role=role, content=content, metadata=metadata or {})
        session.messages.append(msg)
        session.updated_at = datetime.now(timezone.utc).isoformat()
        return session

    def close_session(self, session_id: str, trace_id: Optional[str] = None) -> bool:
        if session_id in self._sessions:
            self._sessions[session_id].is_active = False
            log_audit_event("SESSION_SERVICE", "CLOSE_SESSION", "SUCCESS", trace_id=trace_id, details={"session_id": session_id})
            return True
        return False

class VertexAiSessionService(BaseSessionService):
    """Google Cloud Vertex AI Session Service client with local fallback."""
    def __init__(self, project_id: Optional[str] = None, location: Optional[str] = None):
        self.project_id = project_id or config.gcp_project
        self.location = location or config.gcp_location
        self._local_fallback = InMemorySessionService()

    def create_session(self, user_id: Optional[str] = None, session_id: Optional[str] = None, trace_id: Optional[str] = None) -> SessionState:
        return self._local_fallback.create_session(user_id=user_id, session_id=session_id, trace_id=trace_id)

    def get_session(self, session_id: str, trace_id: Optional[str] = None) -> Optional[SessionState]:
        return self._local_fallback.get_session(session_id, trace_id=trace_id)

    def append_message(self, session_id: str, role: str, content: str, metadata: Optional[Dict[str, Any]] = None, trace_id: Optional[str] = None) -> SessionState:
        return self._local_fallback.append_message(session_id, role, content, metadata, trace_id)

    def close_session(self, session_id: str, trace_id: Optional[str] = None) -> bool:
        return self._local_fallback.close_session(session_id, trace_id)

# Global default session service
session_service = InMemorySessionService()
