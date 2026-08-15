import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from src.config import config
from src.observability.logger import log_audit_event

class AgentPermissionContract(BaseModel):
    required_roles: List[str] = Field(default_factory=lambda: [
        "roles/aiplatform.user",
        "roles/datastore.user",
        "roles/logging.logWriter",
    ])
    denied_roles: List[str] = Field(default_factory=lambda: [
        "roles/owner",
        "roles/editor",
        "roles/iam.serviceAccountAdmin",
    ])
    zero_trust_enforced: bool = True

class AgentManifest(BaseModel):
    agent_id: str = config.app_id
    agent_name: str = "secure-soc-analyst"
    display_name: str = config.app_name
    version: str = config.app_version
    track: str = "The Fortified Enterprise Fleet"
    description: str = (
        "Autonomous Tier-1/Tier-2 SOC security agent built on Gemini Enterprise Agent Platform. "
        "Operates under strict Zero-Trust least-privilege identity, persistent Memory Bank recall, "
        "and Model Armor defensive guardrails."
    )
    model: str = config.default_model
    runtime: str = "Google Cloud Run"
    project_id: str = config.gcp_project
    location: str = config.gcp_location
    permissions: AgentPermissionContract = Field(default_factory=AgentPermissionContract)
    iam_permissions: List[str] = Field(default_factory=lambda: [
        "roles/aiplatform.user",
        "roles/datastore.user",
        "roles/logging.logWriter",
    ])
    capabilities: List[str] = Field(default_factory=lambda: [
        "SIEM Alert Ingestion (Webhooks)",
        "Threat Intelligence Corroboration (IP/Domain/Hash)",
        "Active Directory & IAM Telemetry Correlation",
        "EDR Endpoint Host Quarantine",
        "Inbound Model Armor Prompt Injection Filtering",
        "Outbound PII / Secret Redaction",
        "Vertex AI Cross-Session Memory Bank Retention"
    ])
    endpoints: Dict[str, str] = Field(default_factory=lambda: {
        "webhook_alert": "/api/v1/webhook/alert",
        "analyst_query": "/api/v1/agent/query",
        "registry": "/api/v1/agent/registry",
        "health": "/healthz",
    })
    registered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AgentRegistryService:
    """Enterprise Agent Registry Client for discovering and publishing GEAP fleet agents."""

    def __init__(self, project_id: Optional[str] = None, location: Optional[str] = None):
        self.project_id = project_id or config.gcp_project
        self.location = location or config.gcp_location
        self._fleet_catalog: Dict[str, AgentManifest] = {}
        # Pre-register our SOC agent
        self.register_agent(AgentManifest())

    def register_agent(self, manifest: AgentManifest, trace_id: Optional[str] = None) -> Dict[str, Any]:
        """Registers or updates an agent in the enterprise catalog."""
        self._fleet_catalog[manifest.agent_id] = manifest
        log_audit_event(
            event_type="AGENT_REGISTRY",
            action="REGISTER_AGENT",
            status="SUCCESS",
            trace_id=trace_id,
            details={"agent_id": manifest.agent_id, "version": manifest.version, "project": self.project_id},
        )
        return {
            "status": "REGISTERED",
            "agent_id": manifest.agent_id,
            "version": manifest.version,
            "catalog_size": len(self._fleet_catalog),
            "manifest": manifest.model_dump(),
        }

    def get_agent_spec(self, agent_id: str, trace_id: Optional[str] = None) -> Optional[AgentManifest]:
        """Retrieves an agent specification by identifier."""
        spec = self._fleet_catalog.get(agent_id)
        if spec:
            log_audit_event(
                event_type="AGENT_REGISTRY",
                action="GET_AGENT_SPEC",
                status="FOUND",
                trace_id=trace_id,
                details={"agent_id": agent_id},
            )
        return spec

    def list_fleet_agents(self, trace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists all active discoverable agents in the enterprise fleet."""
        agents = [
            {
                "agent_id": m.agent_id,
                "display_name": m.display_name,
                "version": m.version,
                "track": m.track,
                "runtime": m.runtime,
                "capabilities_count": len(m.capabilities),
            }
            for m in self._fleet_catalog.values()
        ]
        log_audit_event(
            event_type="AGENT_REGISTRY",
            action="LIST_FLEET",
            status="SUCCESS",
            trace_id=trace_id,
            details={"count": len(agents)},
        )
        return agents

    def export_gcloud_registration_payload(self) -> str:
        """Generates formatted JSON payload for gcloud CLI registration."""
        soc_agent_spec = self.get_agent_spec(config.app_id)
        return json.dumps(soc_agent_spec.model_dump() if soc_agent_spec else {}, indent=2)

agent_registry = AgentRegistryService()
