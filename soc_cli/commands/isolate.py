"""
Subcommand: soc isolate <host_id_or_ip>
Directly triggers manual emergency host or IP firewall quarantine.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.tools.soc_tools import isolate_host
from soc_cli.permissions import request_action_permission

console = Console()

def run_isolate(target: str, reason: str = "Manual security operator quarantine", auto_approve: bool = False):
    allowed, note = request_action_permission("isolate_host", {"host_id": target, "reason": reason}, auto_approve)
    if not allowed:
        console.print("[dim #fc8181]Host isolation aborted by operator.[/]\n")
        return

    console.print(f"[dim]Applying Zero-Trust perimeter containment on {target}...[/]")
    result = isolate_host(host_id=target, reason=reason)

    tbl = Table(title="Host Quarantine Execution Result", border_style="#4a5568", header_style="bold #00ff9d")
    tbl.add_column("Property", style="#63b3ed")
    tbl.add_column("Value", style="#e2e8f0")

    tbl.add_row("Target Asset / IP", str(result.get("host_id", target)))
    tbl.add_row("Action Taken", str(result.get("action", "QUARANTINED")))
    tbl.add_row("Execution Status", f"[bold #9ae6b4]{result.get('status', 'SUCCESS')}[/]")
    tbl.add_row("Justification", str(result.get("reason", reason)))
    if result.get("live_firewall"):
        tbl.add_row("Firewall Engine", str(result["live_firewall"].get("firewall_engine", "NONE")))

    console.print(tbl)
    console.print()
