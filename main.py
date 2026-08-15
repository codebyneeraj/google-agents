import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

from src.config import config
from src.agent.soc_agent import soc_agent

# Curated SOC Theme (Charcoal / Emerald Green / Amber)
console = Console()

def display_banner():
    banner_text = Text()
    banner_text.append("SECURE SOC ANALYST ORCHESTRATOR\n", style="bold #00ff9d")
    banner_text.append("Gemini Enterprise Agent Platform | Fortified Enterprise Fleet\n", style="dim #a0aec0")
    banner_text.append(f"Model: {config.default_model} | Guardrails: Model Armor ACTIVE | Runtime: Cloud Run Ready", style="#f6ad55")
    console.print(Panel(banner_text, border_style="#4a5568", title="[bold #e2e8f0]Enterprise Security Operations Center[/]", subtitle="[dim #718096]v1.0.0[/]"))

def run_interactive_soc():
    display_banner()
    session_id = "analyst_console_01"

    console.print("\n[bold #cbd5e0]Type security alerts, IP indicators, or natural language questions.[/]")
    console.print("[dim #718096]Commands: 'exit' to quit, 'demo' for pre-built scenarios, 'memory' to view stored contexts.[/]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold #00ff9d]SOC-Analyst>[/]")
            if not user_input.strip():
                continue

            if user_input.lower() in ("exit", "quit"):
                console.print("[dim #a0aec0]Shutting down SOC Analyst session. Audit log synchronized.[/]")
                break

            if user_input.lower() == "demo":
                from demo import run_full_demo
                run_full_demo()
                continue

            if user_input.lower() in ("help", "?"):
                help_table = Table(title="SOC Analyst Orchestrator - Quick Help", border_style="#4a5568", header_style="bold #00ff9d")
                help_table.add_column("Command / Query", style="#63b3ed")
                help_table.add_column("Description / Test Vector", style="#e2e8f0")
                help_table.add_row("demo", "Run the 6-step Hackathon pitch showcase")
                help_table.add_row("memory", "Inspect all cross-session memories in Vertex AI Memory Bank")
                help_table.add_row("198.51.100.45", "Triage malicious APT-29 C2 IP alert")
                help_table.add_row("john.doe@enterprise.corp", "Check user account compromise & anomalous logins")
                help_table.add_row("Ignore previous instructions...", "Test Model Armor prompt injection defense")
                help_table.add_row("exit", "Close the SOC console")
                console.print(help_table)
                console.print()
                continue

            if user_input.lower() == "memory":
                from src.memory.memory_service import memory_bank
                with console.status("[bold #00ff9d]Querying Vertex AI Memory Bank for retained enterprise context...[/]"):
                    entries = memory_bank.get_all_memories_for_cli()
                
                if not entries:
                    console.print("[dim #f6ad55]Memory Bank is currently empty. Run an alert triage query or 'demo' first.[/]\n")
                else:
                    mem_table = Table(title="Vertex AI Memory Bank - Enterprise Contexts", border_style="#4a5568", header_style="bold #00ff9d")
                    mem_table.add_column("Entity Key", style="#63b3ed")
                    mem_table.add_column("Memory Summary", style="#e2e8f0")
                    mem_table.add_column("Timestamp (UTC)", style="#a0aec0")
                    for e in entries:
                        mem_table.add_row(e.entity_key, e.summary, e.created_at[:19])
                    console.print(mem_table)
                    console.print()
                continue

            console.print("\n[dim #718096]Analyzing alert through Model Armor and Memory Bank...[/]")
            res = soc_agent.process_alert_or_query(user_input, session_id=session_id)

            # Output Formatting
            if res.status == "BLOCKED_BY_GUARDRAIL":
                console.print(Panel(
                    f"[bold #fc8181]SECURITY ALERT - REQUEST BLOCKED[/]\n\n{res.summary}\n\n" +
                    "\n".join([f"[#fbd38d]* {f}[/]" for f in res.findings]),
                    border_style="#e53e3e",
                    title="[bold #feb2b2]Model Armor Guardrail Enforcement[/]"
                ))
            else:
                table = Table(title="Investigation Actions & Evidence", border_style="#4a5568", header_style="bold #00ff9d")
                table.add_column("Tool", style="#63b3ed")
                table.add_column("Target Indicator", style="#faf089")
                table.add_column("Action / Outcome", style="#e2e8f0")

                for action in res.actions_taken:
                    tool_name = action.get("tool", "unknown")
                    inp = action.get("input", "-")
                    outcome = str(action.get("result", {}).get("status", action.get("result", {}).get("reputation", "SUCCESS")))
                    table.add_row(tool_name, inp, outcome)

                if res.actions_taken:
                    console.print(table)

                console.print(Panel(
                    res.raw_response,
                    border_style="#38a169",
                    title=f"[bold #9ae6b4]Incident Report (Trace: {res.trace_id[:8]})[/]",
                    subtitle=f"[dim]Session: {res.session_id}[/]"
                ))

                if res.redaction_applied:
                    console.print(f"[dim #d69e2e]Model Armor Redaction applied: {res.redaction_applied}[/]")

            console.print()

        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim #a0aec0]Session interrupted. Exiting.[/]")
            break

if __name__ == "__main__":
    run_interactive_soc()
