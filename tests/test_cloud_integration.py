import pytest
from src.config import config
from src.memory.memory_service import memory_bank, VertexAiMemoryBankService
from src.memory.session_service import session_service, VertexAiSessionService
from src.registry.agent_registry import agent_registry, AgentManifest

def test_scoped_memory_bank():
    service = VertexAiMemoryBankService()
    entry = service.store_memory(
        entity_key="203.0.113.195",
        summary="Port scanning from Tor exit node targeting SSH services.",
        user_id="analyst_test_01"
    )
    assert entry.entity_key == "203.0.113.195"
    assert entry.user_id == "analyst_test_01"
    assert entry.app_id == config.app_id

    recalled = service.recall_memories("203.0.113.195", user_id="analyst_test_01")
    assert len(recalled) > 0
    assert recalled[0].entity_key == "203.0.113.195"

def test_memory_lifecycle_callback():
    service = VertexAiMemoryBankService()
    session_data = {
        "text": "Incident resolved for compromised host communicating with 198.51.100.45",
        "user_id": "analyst_test_02"
    }
    created = service.generate_memories_callback(session_data)
    assert len(created) > 0
    assert any(m.entity_key == "198.51.100.45" for m in created)

def test_cloud_session_service():
    service = VertexAiSessionService()
    session = service.create_session(user_id="analyst_03", session_id="test_cloud_sess_01")
    assert session.session_id == "test_cloud_sess_01"
    assert session.user_id == "analyst_03"

    service.append_message("test_cloud_sess_01", role="user", content="Check status of WKSTN-JDOE-04")
    service.append_message("test_cloud_sess_01", role="assistant", content="Host is currently quarantined.")

    retrieved = service.get_session("test_cloud_sess_01")
    assert len(retrieved.messages) == 2
    assert retrieved.messages[0].content == "Check status of WKSTN-JDOE-04"
    assert retrieved.messages[1].content == "Host is currently quarantined."

def test_agent_registry_service():
    # Verify pre-registered SOC agent
    spec = agent_registry.get_agent_spec(config.app_id)
    assert spec is not None
    assert spec.agent_id == config.app_id
    assert "roles/aiplatform.user" in spec.permissions.required_roles
    assert spec.permissions.zero_trust_enforced is True

    # Verify fleet catalog listing
    fleet = agent_registry.list_fleet_agents()
    assert len(fleet) >= 1
    assert any(a["agent_id"] == config.app_id for a in fleet)

    # Verify gcloud JSON export
    payload_json = agent_registry.export_gcloud_registration_payload()
    assert config.app_id in payload_json
    assert "The Fortified Enterprise Fleet" in payload_json
