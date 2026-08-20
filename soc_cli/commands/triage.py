"""
Subcommand: soc triage <alert_file_or_json>
Ingests a SIEM/EDR alert JSON or string and executes autonomous investigation.
"""

import json
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from src.agent.soc_agent import soc_agent
from soc_cli.rendering import render_tool_chip, render_final_report, render_guardrail_block

console = Console()

def run_triage(alert_input: str, auto_approve: bool = False):
    alert_text = alert_input
    # Check if input is a filepath
    if os.path.exists(alert_input):
        try:
            with open(alert_input, "r", encoding="utf-8") as f:
                content = f.read()
                try:
                    data = json.loads(content)
                    alert_text = f"SIEM Alert {data.get('alert_id', 'raw')} ({data.get('severity', 'HIGH')}): {data.get('description', '')}"
                    if data.get("target_ip"):
                        alert_text += f" IP: {data['target_ip']}"
                    if data.get("affected_user"):
                        alert_text += f" User: {data['affected_user']}"
                except json.JSONDecodeError:
                    alert_text = content
        except Exception as e:
            console.print(f"[bold #fc8181]Error reading alert file:[/] {e}")
            return

    console.print(f"\n[bold #63b3ed]Triaging SIEM Alert:[/] [dim]{alert_text}[/]\n")

    for event in soc_agent.stream_alert_or_query(alert_text):
        etype = event.get("type")
        if etype == "inbound_guardrail" and event.get("status") == "BLOCKED":
            render_guardrail_block("Alert blocked by Model Armor", event.get("threats", []))
        elif etype == "tool_call":
            render_tool_chip(event.get("tool"), event.get("input"), event.get("result", {}).get("status", "SUCCESS"), event.get("result"))
        elif etype == "final":
            res = event.get("result")
            raw = res.raw_response if hasattr(res, "raw_response") else res.get("raw_response", "")
            tid = res.trace_id if hasattr(res, "trace_id") else res.get("trace_id")
            render_final_report(raw, trace_id=tid)
