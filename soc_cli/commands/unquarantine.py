"""
Subcommand: soc unquarantine <host_id_or_ip>
Removes firewall block rules and restores an isolated host back to the active network.
"""

from rich.console import Console
from rich.table import Table
from src.tools.soc_tools import unquarantine_host
from soc_cli.permissions import request_action_permission

console = Console()

def run_unquarantine(target: str, reason: str = "Security analyst verified remediation", auto_approve: bool = False):
    allowed, _ = request_action_permission("isolate_host", {"host_id": target, "reason": reason}, auto_approve)
    if not allowed:
        console.print("[dim #fc8181]Unquarantine action aborted by operator.[/]\n")
        return

    console.print(f"[dim]Releasing {target} from network containment...[/]")
    res = unquarantine_host(host_id=target, reason=reason)

    tbl = Table(title="Host Unquarantine Result", border_style="#4a5568", header_style="bold #00ff9d")
    tbl.add_column("Property", style="#63b3ed")
    tbl.add_column("Value", style="#e2e8f0")

    tbl.add_row("Target Asset / IP", str(res.get("host_id", target)))
    tbl.add_row("Action Taken", str(res.get("action", "UNQUARANTINED")))
    tbl.add_row("Status", f"[bold #9ae6b4]{res.get('status', 'SUCCESS')}[/]")
    tbl.add_row("Firewall Cleanup", str(res.get("firewall_cleanup", "NO_RULE_REQUIRED")))

    console.print(tbl)
    console.print()
