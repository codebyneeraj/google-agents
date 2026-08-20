import sys
import os
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from src.config import config
from src.agent.soc_agent import soc_agent

console = Console()

def run_interactive_session():
    console.print(Panel(
        "[bold #00ff9d]⚡ SOC ANALYST COPILOT - LIVE INTERACTIVE SESSION[/]\n"
        f"[dim]Model: {config.default_model} | Runtime: {'Gemini Enterprise (Vertex AI)' if config.enterprise_mode and not config.gemini_api_key else 'Google GenAI SDK (Live AI)'}[/]\n"
        "[dim]Type your query, enter an IP/domain to investigate, paste a SIEM alert, or type 'exit' to quit.[/]",
        border_style="#4a5568",
        title="[bold #e2e8f0]Enterprise Defense Fleet[/]"
    ))

    session_id = f"sess_live_{int(time.time())}"
    
    while True:
        try:
            user_input = Prompt.ask("\n[bold #63b3ed]SOC Analyst[/]").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "q"):
                console.print("[dim]Ending interactive SOC session. Goodbye.[/]")
                break

            console.print("[dim]Analyzing with Gemini & executing defensive tools...[/]")
            start_t = time.time()
            res = soc_agent.process_alert_or_query(user_input, session_id=session_id)
            elapsed = time.time() - start_t

            # Display any actions taken
            if res.actions_taken:
                tbl = Table(title="Autonomous Actions Executed", border_style="#4a5568", header_style="bold #00ff9d")
                tbl.add_column("Tool", style="#63b3ed")
                tbl.add_column("Target Indicator", style="#faf089")
                tbl.add_column("Status / Result", style="#9ae6b4")
                for act in res.actions_taken:
                    status = act.get("result", {}).get("status", act.get("result", {}).get("reputation", "SUCCESS"))
                    tbl.add_row(act.get("tool", ""), str(act.get("input", "")), str(status))
                console.print(tbl)

            # Display the Agent Response
            if res.status == "BLOCKED_BY_GUARDRAIL":
                console.print(Panel(
                    f"[bold #fc8181]{res.summary}[/]\n\n" + "\n".join([f"[#fbd38d]* {f}[/]" for f in res.findings]),
                    border_style="#e53e3e",
                    title="[bold #feb2b2]Model Armor Guardrail Interceptor[/]"
                ))
            else:
                console.print(Panel(
                    res.raw_response,
                    border_style="#38a169",
                    title=f"[bold #9ae6b4]SOC Agent Response ({elapsed:.2f}s | Trace: {res.trace_id[:8]})[/]"
                ))

        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session terminated.[/]")
            break
        except Exception as err:
            console.print(f"[bold #fc8181]Error:[/] {err}")

if __name__ == "__main__":
    run_interactive_session()
