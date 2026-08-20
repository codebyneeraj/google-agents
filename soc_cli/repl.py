"""
Interactive Agentic REPL powered by prompt_toolkit and Rich.
Styled after Claude Code / GitHub Copilot CLI.
"""

import sys
import time
import os
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from soc_cli.rendering import (
    render_banner,
    render_tool_chip,
    render_memory_chip,
    render_guardrail_block,
    render_final_report,
)
from soc_cli.client import LocalClient, RemoteClient
from soc_cli.commands.memory import run_memory_lookup
from soc_cli.commands.isolate import run_isolate
from soc_cli.commands.triage import run_triage
from soc_cli.commands.audit import run_audit
from soc_cli.commands.dns import run_dns_lookup
from soc_cli.commands.hash_cmd import run_hash_lookup
from soc_cli.commands.decode import run_decode
from soc_cli.commands.scan import run_port_scan
from soc_cli.commands.unquarantine import run_unquarantine
from soc_cli.commands.mitre import run_mitre

console = Console()

SLASH_COMMANDS = [
    "/triage",
    "/memory",
    "/isolate",
    "/unquarantine",
    "/dns",
    "/hash",
    "/decode",
    "/scan",
    "/mitre",
    "/audit",
    "/resume",
    "/mode",
    "/clear",
    "/help",
    "/exit",
    "/quit",
]

pt_completer = WordCompleter(SLASH_COMMANDS, ignore_case=True, match_middle=False)

pt_style = Style.from_dict({
    "prompt": "ansicyan bold",
})

def print_help():
    help_text = Text()
    help_text.append("⚡ SOC Agentic CLI — Available Commands\n\n", style="bold #00ff9d")
    help_text.append("Natural Language Input:\n", style="bold #63b3ed")
    help_text.append("  Just type your goal, query, or incident description.\n", style="dim")
    help_text.append("  Example: 'Investigate IP 198.51.100.45 communicating on port 443'\n\n", style="dim #faf089")
    help_text.append("Slash Commands:\n", style="bold #63b3ed")
    help_text.append("  /triage <alert_json_or_file>  - Ingest raw SIEM alert\n", style="#e2e8f0")
    help_text.append("  /dns <domain>                 - DNS resolution & DGA entropy check\n", style="#e2e8f0")
    help_text.append("  /hash <file_hash>             - Query VirusTotal & malware signatures\n", style="#e2e8f0")
    help_text.append("  /decode <base64_payload>      - Decode PowerShell/bash scripts\n", style="#e2e8f0")
    help_text.append("  /scan [host] [ports]          - Network socket port scan\n", style="#e2e8f0")
    help_text.append("  /isolate <host_id_or_ip>      - Emergency manual host/IP quarantine\n", style="#e2e8f0")
    help_text.append("  /unquarantine <host_id_or_ip> - Release host from network quarantine\n", style="#e2e8f0")
    help_text.append("  /mitre <technique_id>         - Query MITRE ATT&CK matrix intelligence\n", style="#e2e8f0")
    help_text.append("  /memory <indicator>           - Query Vertex AI Memory Bank for past records\n", style="#e2e8f0")
    help_text.append("  /audit <trace_id>             - Inspect audit trail and session state\n", style="#e2e8f0")
    help_text.append("  /resume <session_id>          - Resume prior investigation session\n", style="#e2e8f0")
    help_text.append("  /mode [local|remote]          - Switch between local direct and Cloud Run\n", style="#e2e8f0")
    help_text.append("  /clear                        - Clear terminal screen\n", style="#e2e8f0")
    help_text.append("  /help                         - Show this help menu\n", style="#e2e8f0")
    help_text.append("  /exit or /quit                - Exit REPL\n", style="#e2e8f0")
    console.print(Panel(help_text, border_style="#4a5568", title="[bold #e2e8f0]Command Reference[/]"))

def run_repl(
    mode: str = "local",
    remote_url: str = "http://localhost:8080",
    auto_approve: bool = False,
    resume_id: Optional[str] = None,
):
    session_id = resume_id or f"sess_{int(time.time())}"
    current_mode = mode.lower()

    if current_mode == "remote":
        client = RemoteClient(base_url=remote_url, auto_approve=auto_approve)
    else:
        client = LocalClient(auto_approve=auto_approve)

    render_banner(mode=current_mode, session_id=session_id)

    prompt_session = PromptSession(completer=pt_completer, style=pt_style)

    while True:
        try:
            user_input = prompt_session.prompt(f"\n[soc:{current_mode}] > ").strip()
            if not user_input:
                continue

            # Handle Slash Commands
            if user_input.startswith("/"):
                parts = user_input.split(maxsplit=1)
                cmd = parts[0].lower()
                arg = parts[1].strip() if len(parts) > 1 else ""

                if cmd in ("/exit", "/quit"):
                    console.print("[dim]Exiting SOC CLI. Stay secure.[/]")
                    break
                elif cmd == "/clear":
                    os.system("cls" if os.name == "nt" else "clear")
                    render_banner(mode=current_mode, session_id=session_id)
                    continue
                elif cmd == "/help":
                    print_help()
                    continue
                elif cmd == "/memory":
                    if not arg:
                        console.print("[dim #fc8181]Usage: /memory <indicator_ip_or_email>[/]")
                    else:
                        run_memory_lookup(arg)
                    continue
                elif cmd == "/isolate":
                    if not arg:
                        console.print("[dim #fc8181]Usage: /isolate <host_id_or_ip>[/]")
                    else:
                        run_isolate(arg, auto_approve=auto_approve)
                    continue
                elif cmd == "/unquarantine":
                    if not arg:
                        console.print("[dim #fc8181]Usage: /unquarantine <host_id_or_ip>[/]")
                    else:
                        run_unquarantine(arg, auto_approve=auto_approve)
                    continue
                elif cmd == "/dns":
                    if not arg:
                        console.print("[dim #fc8181]Usage: /dns <domain_name>[/]")
                    else:
                        run_dns_lookup(arg)
                    continue
                elif cmd == "/hash":
                    if not arg:
                        console.print("[dim #fc8181]Usage: /hash <file_hash_md5_sha256>[/]")
                    else:
                        run_hash_lookup(arg)
                    continue
                elif cmd == "/decode":
                    if not arg:
                        console.print("[dim #fc8181]Usage: /decode <base64_encoded_payload>[/]")
                    else:
                        run_decode(arg)
                    continue
                elif cmd == "/scan":
                    parts_scan = arg.split(maxsplit=1) if arg else []
                    host = parts_scan[0] if parts_scan else "127.0.0.1"
                    ports = parts_scan[1] if len(parts_scan) > 1 else "22,80,443,445,3389,8080"
                    run_port_scan(host=host, ports=ports)
                    continue
                elif cmd == "/mitre":
                    if not arg:
                        console.print("[dim #fc8181]Usage: /mitre <technique_id_e.g._T1059>[/]")
                    else:
                        run_mitre(arg)
                    continue
                elif cmd == "/triage":
                    if not arg:
                        console.print("[dim #fc8181]Usage: /triage <alert_json_or_file>[/]")
                    else:
                        run_triage(arg, auto_approve=auto_approve)
                    continue
                elif cmd == "/audit":
                    if not arg:
                        console.print("[dim #fc8181]Usage: /audit <trace_id>[/]")
                    else:
                        run_audit(arg)
                    continue
                elif cmd == "/resume":
                    if not arg:
                        console.print("[dim #fc8181]Usage: /resume <session_or_trace_id>[/]")
                    else:
                        session_id = arg
                        console.print(f"[bold #00ff9d]Switched to session:[/] {session_id}")
                    continue
                elif cmd == "/mode":
                    if arg in ("local", "remote"):
                        current_mode = arg
                        if current_mode == "remote":
                            client = RemoteClient(base_url=remote_url, auto_approve=auto_approve)
                        else:
                            client = LocalClient(auto_approve=auto_approve)
                        console.print(f"[bold #63b3ed]Transport mode switched to:[/] {current_mode.upper()}")
                    else:
                        console.print(f"[dim]Current transport mode: {current_mode}. Use `/mode local` or `/mode remote`[/]")
                    continue
                else:
                    console.print(f"[dim #fc8181]Unknown slash command '{cmd}'. Type /help for options.[/]")
                    continue

            # Natural Language Agent Reasoning Loop
            console.print("[dim]Analyzing with Gemini & executing tools...[/]")
            start_time = time.time()
            final_report_text = ""
            active_trace_id = None

            for event in client.stream_query(user_input, session_id=session_id):
                etype = event.get("type")

                if etype == "start":
                    active_trace_id = event.get("trace_id")

                elif etype == "inbound_guardrail" and event.get("status") == "BLOCKED":
                    render_guardrail_block("Input Blocked by Model Armor", event.get("threats", []), trace_id=active_trace_id)

                elif etype == "memory_recall":
                    render_memory_chip(event.get("memories", []))

                elif etype == "tool_call":
                    tool = event.get("tool")
                    target = event.get("input")
                    res = event.get("result", {})
                    status = res.get("status", res.get("reputation", "SUCCESS"))
                    render_tool_chip(tool, target, status, details=res)

                elif etype == "final":
                    res = event.get("result")
                    if hasattr(res, "raw_response"):
                        final_report_text = res.raw_response
                        active_trace_id = res.trace_id
                    elif isinstance(res, dict):
                        final_report_text = res.get("raw_response", "")
                        active_trace_id = res.get("trace_id", active_trace_id)

                elif etype == "error":
                    console.print(f"[bold #fc8181]Error:[/] {event.get('message')}")

            elapsed = time.time() - start_time
            if final_report_text:
                render_final_report(final_report_text, trace_id=active_trace_id, elapsed=elapsed)

        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session terminated.[/]")
            break
        except Exception as e:
            console.print(f"[bold #fc8181]Unexpected error:[/] {e}")
