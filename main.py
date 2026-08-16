import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich.markdown import Markdown

from src.config import config
from src.agent.soc_agent import soc_agent

# Curated Aesthetic Dark Theme (Slate / Mint Emerald / Warm Amber)
console = Console()

def display_banner():
    banner_text = Text()
    banner_text.append("SECURE SOC ANALYST ORCHESTRATOR\n", style="bold #00b894")
    banner_text.append("Gemini Enterprise Agent Platform | Fortified Enterprise Fleet\n", style="dim #b2bec3")
    
    engine_status = f"Reasoning Brain: ONLINE ({config.default_model})" if soc_agent.client else "Reasoning Brain: LOCAL ENGINE (Active)"
    engine_color = "#00b894" if soc_agent.client else "#fdcb6e"
    banner_text.append(f"{engine_status}\n", style=engine_color)
    banner_text.append("Guardrails: Model Armor ACTIVE | Memory: Vertex AI Memory Bank ACTIVE", style="#fdcb6e")
    console.print(Panel(banner_text, border_style="#4a5568", title="[bold #dfe6e9]Enterprise Security Operations Center[/]", subtitle="[dim #636e72]v1.0.0[/]"))


def run_interactive_soc():
    display_banner()
    session_id = "analyst_console_01"

    console.print("\n[bold #dfe6e9]Type security alerts, IP indicators, or natural language questions.[/]")
    console.print("[dim #636e72]Commands: 'exit' to quit, 'demo' for pre-built scenarios, 'memory' to view stored contexts.[/]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold #00b894]SOC-Analyst>[/]")
            if not user_input.strip():
                continue

            if user_input.lower() in ("exit", "quit"):
                console.print("[dim #b2bec3]Shutting down SOC Analyst session. Audit log synchronized.[/]")
                break

            if user_input.lower() == "demo":
                from demo import run_full_demo
                run_full_demo()
                continue

            if user_input.lower() in ("help", "?"):
                help_table = Table(title="SOC Analyst Orchestrator - Quick Help", border_style="#4a5568", header_style="bold #00b894")
                help_table.add_column("Command / Query", style="#00cec9")
                help_table.add_column("Description / Test Vector", style="#dfe6e9")
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
                with console.status("[bold #00b894]Querying Vertex AI Memory Bank for retained enterprise context...[/]"):
                    entries = memory_bank.get_all_memories_for_cli()
                
                if not entries:
                    console.print("[dim #fdcb6e]Memory Bank is currently empty. Run an alert triage query or 'demo' first.[/]\n")
                else:
                    mem_table = Table(title="Vertex AI Memory Bank - Enterprise Contexts", border_style="#4a5568", header_style="bold #00b894")
                    mem_table.add_column("Entity Key", style="#00cec9")
                    mem_table.add_column("Memory Summary", style="#dfe6e9")
                    mem_table.add_column("Timestamp (UTC)", style="#b2bec3")
                    for e in entries:
                        mem_table.add_row(e.entity_key, e.summary, e.created_at[:19])
                    console.print(mem_table)
                    console.print()
                continue

            console.print("\n[dim #636e72]Analyzing query through Model Armor and Memory Bank...[/]")
            res = soc_agent.process_alert_or_query(user_input, session_id=session_id)

            # Output Formatting
            if res.status == "BLOCKED_BY_GUARDRAIL":
                console.print(Panel(
                    f"[bold #e17055]SECURITY ALERT - REQUEST BLOCKED[/]\n\n{res.summary}\n\n" +
                    "\n".join([f"[#fab1a0]* {f}[/]" for f in res.findings]),
                    border_style="#e17055",
                    title="[bold #fab1a0]Model Armor Interceptor[/]"
                ))
            elif res.actions_taken:
                # Active Incident Investigation with Tool Executions
                table = Table(title="Investigation Actions & Evidence", border_style="#4a5568", header_style="bold #00b894")
                table.add_column("Tool", style="#00cec9")
                table.add_column("Target Indicator", style="#fdcb6e")
                table.add_column("Action / Outcome", style="#dfe6e9")

                for action in res.actions_taken:
                    tool_name = action.get("tool", "unknown")
                    inp = action.get("input", "-")
                    outcome = str(action.get("result", {}).get("status", action.get("result", {}).get("reputation", "SUCCESS")))
                    table.add_row(tool_name, inp, outcome)

                console.print(table)
                console.print()

                # Render formatted Markdown report inside an Investigation Panel
                md_content = Markdown(res.raw_response, code_theme="monokai")
                console.print(Panel(
                    md_content,
                    border_style="#00b894",
                    title="[bold #00b894]Security Investigation[/]",
                    subtitle=f"[dim #636e72]Trace: {res.trace_id[:8]}[/]"
                ))

                if res.redaction_applied:
                    console.print(f"[dim #fdcb6e]Model Armor Redaction applied: {res.redaction_applied}[/]")
            else:
                # Standard Conversational Output / Question Response (Clean Markdown rendering, No aggressive box)
                console.print()
                md_content = Markdown(res.raw_response, code_theme="monokai")
                console.print(md_content)

            console.print()

        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim #b2bec3]Session interrupted. Exiting.[/]")
            break

if __name__ == "__main__":
    if "--gateway" in sys.argv:
        import uvicorn
        port = int(config.port) if hasattr(config, "port") else 8080
        console.print(f"[bold #00b894]Starting Enterprise SOC Agent Gateway on 0.0.0.0:{port}...[/]")
        uvicorn.run("src.gateway.server:app", host="0.0.0.0", port=port, reload=False)
    else:
        run_interactive_soc()
