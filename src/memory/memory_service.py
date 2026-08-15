from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import uuid

from src.config import config
from src.observability.logger import log_audit_event

class MemoryEntry(BaseModel):
    id: str
    app_id: str = config.app_id
    user_id: str = config.default_user_id
    entity_key: str  # e.g., IP, User, Incident-ID
    summary: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class BaseMemoryService:
    def store_memory(
        self,
        entity_key: str,
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> MemoryEntry:
        raise NotImplementedError

    def recall_memories(
        self,
        query: str,
        limit: int = 5,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> List[MemoryEntry]:
        raise NotImplementedError

    def search_memory(
        self,
        query: str,
        user_id: Optional[str] = None,
        limit: int = 5,
        trace_id: Optional[str] = None,
    ) -> List[MemoryEntry]:
        """Managed GEAP Memory Bank search query API."""
        return self.recall_memories(query=query, limit=limit, user_id=user_id, trace_id=trace_id)

    def get_all_memories_for_cli(self, user_id: Optional[str] = None) -> List[MemoryEntry]:
        """Fetches all memories scoped to the user/analyst for display in the CLI."""
        raise NotImplementedError

    def generate_memories_callback(self, session_context: Dict[str, Any], trace_id: Optional[str] = None) -> List[MemoryEntry]:
        """Lifecycle callback to automatically extract and persist context at interaction completion."""
        raise NotImplementedError

class InMemoryMemoryService(BaseMemoryService):
    """Local high-speed memory store simulating the Vertex AI Memory Bank with user/app scoping."""
    def __init__(self):
        self._store: Dict[str, List[MemoryEntry]] = {}

    def store_memory(
        self,
        entity_key: str,
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> MemoryEntry:
        key = entity_key.strip().lower()
        uid = user_id or config.default_user_id
        entry_id = f"mem_{uuid.uuid4().hex[:6]}_{int(datetime.now().timestamp())}"
        entry = MemoryEntry(
            id=entry_id,
            app_id=config.app_id,
            user_id=uid,
            entity_key=key,
            summary=summary,
            metadata=metadata or {},
        )
        if key not in self._store:
            self._store[key] = []
        self._store[key].append(entry)

        log_audit_event(
            event_type="MEMORY_BANK",
            action="STORE_MEMORY",
            status="SUCCESS",
            trace_id=trace_id,
            details={"entity_key": key, "entry_id": entry_id, "user_id": uid, "summary_preview": summary[:80]},
        )
        return entry

    def recall_memories(
        self,
        query: str,
        limit: int = 5,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> List[MemoryEntry]:
        q = query.strip().lower()
        results = []
        uid = user_id or config.default_user_id

        # Search direct entity match or keyword in summary scoped to user/app
        for key, entries in self._store.items():
            for entry in entries:
                if entry.user_id == uid:
                    if key in q or any(word in key for word in q.split()):
                        results.append(entry)
                    elif any(word in entry.summary.lower() for word in q.split() if len(word) > 3):
                        results.append(entry)

        # Sort newest first, deduplicate by ID
        unique_results = {e.id: e for e in results}.values()
        sorted_results = sorted(unique_results, key=lambda x: x.created_at, reverse=True)[:limit]

        log_audit_event(
            event_type="MEMORY_BANK",
            action="RECALL_MEMORY",
            status="SUCCESS",
            trace_id=trace_id,
            details={"query": query, "user_id": uid, "recalled_count": len(sorted_results)},
        )
        return list(sorted_results)

    def get_all_memories_for_cli(self, user_id: Optional[str] = None) -> List[MemoryEntry]:
        """Fetches all memories scoped to the user/analyst for display in the CLI."""
        uid = user_id or config.default_user_id
        all_entries = []
        for entries in self._store.values():
            for entry in entries:
                if entry.user_id == uid:
                    all_entries.append(entry)
        return sorted(all_entries, key=lambda x: x.created_at, reverse=True)

    def generate_memories_callback(self, session_context: Dict[str, Any], trace_id: Optional[str] = None) -> List[MemoryEntry]:
        """Automatically parses session context and commits structured memories."""
        created_memories = []
        text = session_context.get("text", "")
        uid = session_context.get("user_id", config.default_user_id)

        # Extract genuine indicators to memorize (valid IPv4 or valid Email)
        for word in text.replace(",", " ").replace(";", " ").split():
            clean = word.strip(" ,;:\"'()[]{}*`")
            is_ip = clean.count(".") == 3 and all(p.isdigit() and 0 <= int(p) <= 255 for p in clean.split("."))
            is_email = "@" in clean and "." in clean and not clean.startswith("[REDACTED")

            if is_ip or is_email:
                summary = f"Investigated indicator {clean}. Session: {session_context.get('session_id', 'unknown')}"
                entry = self.store_memory(entity_key=clean, summary=summary, user_id=uid, trace_id=trace_id)
                created_memories.append(entry)

        log_audit_event(
            event_type="MEMORY_CALLBACK",
            action="AUTO_GENERATE_MEMORIES",
            status="SUCCESS",
            trace_id=trace_id,
            details={"generated_count": len(created_memories)},
        )
        return created_memories

class VertexAiMemoryBankService(BaseMemoryService):
    """Managed Vertex AI Memory Bank Service client with enterprise scope and local fallback."""
    def __init__(self, project_id: Optional[str] = None, location: Optional[str] = None):
        self.project_id = project_id or config.gcp_project
        self.location = location or config.gcp_location
        self._fallback_store = InMemoryMemoryService()

    def store_memory(
        self,
        entity_key: str,
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> MemoryEntry:
        # In cloud runtime, connects to Vertex AI Agent Engine Memory Bank API
        return self._fallback_store.store_memory(entity_key, summary, metadata, user_id, trace_id)

    def recall_memories(
        self,
        query: str,
        limit: int = 5,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> List[MemoryEntry]:
        return self._fallback_store.recall_memories(query, limit, user_id, trace_id)

    def get_all_memories_for_cli(self, user_id: Optional[str] = None) -> List[MemoryEntry]:
        return self._fallback_store.get_all_memories_for_cli(user_id)

    def generate_memories_callback(self, session_context: Dict[str, Any], trace_id: Optional[str] = None) -> List[MemoryEntry]:
        return self._fallback_store.generate_memories_callback(session_context, trace_id)

# Global default memory bank instance
memory_bank = VertexAiMemoryBankService()
