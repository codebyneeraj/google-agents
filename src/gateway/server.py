import time
from collections import defaultdict
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import uuid

from src.config import config
from src.agent.soc_agent import soc_agent, InvestigationResult
from src.memory.session_service import session_service
from src.registry.agent_registry import agent_registry
from src.observability.logger import log_audit_event

app = FastAPI(
    title=config.app_name,
    version=config.app_version,
    description="Enterprise Agent Gateway for Autonomous SOC Incident Triaging and Threat Response (GEAP Fleet)",
)

# Sliding Window Rate Limiter (Enterprise Security Requirement)
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_REQUESTS_PER_WINDOW = 120
request_records = defaultdict(list)

@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    
    # Filter timestamps within window
    timestamps = [t for t in request_records[client_ip] if now - t < RATE_LIMIT_WINDOW_SECONDS]
    timestamps.append(now)
    request_records[client_ip] = timestamps
    
    if len(timestamps) > MAX_REQUESTS_PER_WINDOW:
        log_audit_event(
            event_type="GATEWAY_RATE_LIMIT",
            action="REQUEST_THROTTLED",
            status="RATE_LIMIT_EXCEEDED",
            details={"client_ip": client_ip, "request_count": len(timestamps)},
            severity=30
        )
        return JSONResponse(
            status_code=429,
            content={"detail": "Enterprise Gateway: Rate limit exceeded. Please retry shortly."}
        )
        
    return await call_next(request)

class AlertPayload(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"alert_{uuid.uuid4().hex[:6]}")
    source: str = "SIEM-CrowdStrike"
    severity: str = "HIGH"
    description: str
    target_ip: Optional[str] = None
    affected_user: Optional[str] = None

class AnalystQuery(BaseModel):
    query: str
    session_id: Optional[str] = None
    user_id: Optional[str] = None

@app.get("/healthz")
async def health_check():
    return {
        "status": "HEALTHY",
        "service": config.app_name,
        "app_id": config.app_id,
        "version": config.app_version,
        "environment": config.environment,
        "enterprise_mode": config.enterprise_mode,
        "gcp_project": config.gcp_project,
        "gcp_location": config.gcp_location,
    }

@app.get("/api/v1/agent/registry")
async def get_agent_registry():
    """Agent Registry discovery endpoint complying with GEAP specifications."""
    spec = agent_registry.get_agent_spec(config.app_id)
    if not spec:
        raise HTTPException(status_code=404, detail="Agent not registered in catalog")
    return spec.model_dump()

@app.get("/api/v1/agent/registry/fleet")
async def list_fleet():
    """Lists all discovered agents registered in the enterprise fleet."""
    return {"agents": agent_registry.list_fleet_agents()}

@app.get("/api/v1/sessions/{session_id}")
async def get_session_details(session_id: str):
    """Retrieves conversation thread and audit state for a cloud session."""
    session = session_service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return session.model_dump()

@app.post("/api/v1/webhook/alert", response_model=InvestigationResult)
async def handle_siem_alert(payload: AlertPayload):
    """Webhook entry point for incoming security alerts."""
    trace_id = str(uuid.uuid4())
    log_audit_event("GATEWAY", "ALERT_RECEIVED", "ACCEPTED", trace_id=trace_id, details=payload.model_dump())

    query_text = f"SIEM Alert {payload.alert_id} ({payload.severity}): {payload.description}"
    if payload.target_ip:
        query_text += f" IP: {payload.target_ip}"
    if payload.affected_user:
        query_text += f" User: {payload.affected_user}"

    result = soc_agent.process_alert_or_query(query_text, session_id=payload.alert_id, trace_id=trace_id)
    return result

@app.post("/api/v1/agent/query", response_model=InvestigationResult)
async def handle_analyst_query(payload: AnalystQuery):
    """Interactive endpoint for SOC analysts with session continuity."""
    trace_id = str(uuid.uuid4())
    log_audit_event("GATEWAY", "ANALYST_QUERY_RECEIVED", "ACCEPTED", trace_id=trace_id, details={"query": payload.query})

    result = soc_agent.process_alert_or_query(payload.query, session_id=payload.session_id, trace_id=trace_id)
    print(f"\n>>> [INVESTIGATION RESOLVED] Trace ID: {trace_id[:8]} | Actions: {len(result.actions_taken)} | Status: {result.status}")
    for act in result.actions_taken:
        print(f"    * {act.get('tool')}: {act.get('input')} -> {act.get('result', {}).get('status', 'SUCCESS')}")
    return result

