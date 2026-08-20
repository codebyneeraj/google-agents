"""
Subcommand: soc audit <trace_id>
Queries structured audit trail events for a given trace_id.
"""

from rich.console import Console
from rich.table import Table
from src.memory.session_service import session_service

console = Console()

def run_audit(trace_id: str):
    console.print(f"\n[bold #f6ad55]Auditing Investigation Trace:[/] [bold #63b3ed]{trace_id}[/]\n")
    
    # Check session service for messages/sessions matching trace or session_id
    session = session_service.get_session(trace_id)
    if not session:
        # Check sessions list
        for sid in session_service.list_active_sessions():
            s = session_service.get_session(sid)
            if s and s.session_id == trace_id:
                session = s
                break

    if not session:
        console.print(f"[dim]No local session telemetry found for trace/session '{trace_id}'.[/]\n")
        console.print(f"[dim #a0aec0]Check Google Cloud Logging using query: `jsonPayload.trace_id=\"{trace_id}\"`[/]\n")
        return

    table = Table(title=f"Session State ({session.session_id})", border_style="#4a5568", header_style="bold #00ff9d")
    table.add_column("Timestamp", style="#63b3ed", width=22)
    table.add_column("Role", style="#faf089", width=12)
    table.add_column("Message Preview", style="#e2e8f0")

    for msg in session.messages:
        table.add_row(msg.timestamp[:19], msg.role.upper(), msg.content[:80] + ("..." if len(msg.content) > 80 else ""))

    console.print(table)
    console.print()
