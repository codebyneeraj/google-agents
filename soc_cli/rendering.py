"""
Rich terminal UI rendering components for soc-cli.
Styled after Claude Code / GitHub Copilot CLI with clean live progress and chips.
"""

from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown
from rich.live import Live
from rich.spinner import Spinner

console = Console()

def render_banner(mode: str = "local", model: str = "gemini-3.6-flash", session_id: Optional[str] = None):
    title = Text()
    title.append("⚡ SOC ANALYST AGENTIC CLI", style="bold #00ff9d")
    title.append(f"  [{mode.upper()} MODE]\n", style="bold #63b3ed")
    title.append(f"Model: {model} | Platform: Gemini Enterprise Agent Platform (GEAP)\n", style="dim #cbd5e0")
    if session_id:
        title.append(f"Active Session: {session_id} | Type /help for commands\n", style="dim #a0aec0")
    console.print(Panel(title, border_style="#4a5568", title="[bold #e2e8f0]Enterprise Threat Defense[/]"))

def render_tool_chip(tool_name: str, target: Any, status: str, details: Optional[Dict[str, Any]] = None):
    """Renders a single-line tool execution chip."""
    color = "#9ae6b4" if "MALICIOUS" in str(status) or "SUCCESS" in str(status) or "FOUND" in str(status) else "#e2e8f0"
    if "DENIED" in str(status) or "BLOCKED" in str(status) or "FAILED" in str(status):
        color = "#fc8181"

    text = Text()
    text.append("  [✓] ", style="bold #00ff9d")
    text.append(f"{tool_name}", style="bold #63b3ed")
    text.append(f"({target})", style="bold #faf089")
    text.append(f" → {status}", style=f"bold {color}")
    
    if details and "threat_score" in details:
        text.append(f" (Score: {details['threat_score']}/100)", style="bold #fc8181" if details['threat_score'] > 50 else "dim")
    if details and "actor" in details and details["actor"] != "Unknown":
        text.append(f" [Actor: {details['actor']}]", style="dim #cbd5e0")

    console.print(text)

def render_memory_chip(memories: List[Dict[str, Any]]):
    """Renders recalled cross-session memory indicators."""
    if not memories:
        return
    text = Text()
    text.append("  [🧠 Memory Recalled] ", style="bold #81e6d9")
    indicators = [f"{m.get('entity_key')} ({m.get('summary', '')[:40]}...)" for m in memories]
    text.append(", ".join(indicators), style="dim #cbd5e0")
    console.print(text)

import re

def render_guardrail_block(summary: str, findings: List[str], trace_id: Optional[str] = None):
    """Renders an inbound Model Armor block panel."""
    content = f"[bold #fc8181]{summary}[/]\n\n"
    for f in findings:
        content += f"[#fbd38d]* {f}[/]\n"

    console.print(Panel(
        content.strip(),
        border_style="#e53e3e",
        title="[bold #feb2b2]Model Armor Inbound Interceptor: BLOCKED[/]"
    ))

def render_final_report(response_text: str, trace_id: Optional[str] = None, elapsed: Optional[float] = None):
    """Renders the synthesized Markdown incident report without noisy trace IDs."""
    title = f"[bold #9ae6b4]SOC Incident Report[/]"
    if elapsed is not None:
        title += f" [dim]({elapsed:.2f}s)[/]"

    # Filter out any internal trace id lines from model or server outputs
    cleaned_text = re.sub(r"(?i)\*?\*?trace\s*id:?\*?\*?\s*[`\"']?[a-f0-9\-]+[`\"']?\n?", "", response_text)
    cleaned_text = cleaned_text.strip()

    # If markdown text contains headers, format with Rich Markdown
    if "###" in cleaned_text or "##" in cleaned_text:
        md = Markdown(cleaned_text)
        console.print(Panel(md, border_style="#38a169", title=title))
    else:
        console.print(Panel(cleaned_text, border_style="#38a169", title=title))
