"""
Tool permissions and confirmation layer.
Gates destructive tools (e.g. isolate_host) behind explicit analyst approval.
"""

from typing import Dict, Any, Tuple
from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel

console = Console()

SAFE_TOOLS = {"check_threat_intel", "lookup_user_activity", "inspect_linux_auth_logs"}
DESTRUCTIVE_TOOLS = {"isolate_host"}

def is_destructive_action(tool_name: str) -> bool:
    return tool_name in DESTRUCTIVE_TOOLS

def request_action_permission(tool_name: str, args: Dict[str, Any], auto_approve: bool = False) -> Tuple[bool, str]:
    """
    Checks if an action requires analyst confirmation.
    Returns (allowed: bool, reason: str).
    """
    if not is_destructive_action(tool_name):
        return True, "AUTO_ALLOWED_SAFE_TOOL"

    if auto_approve:
        return True, "AUTO_APPROVED_BY_FLAG"

    # Present confirmation prompt
    target = args.get("host_id") or args.get("input") or "UNKNOWN_TARGET"
    reason = args.get("reason", "Automated threat response")

    console.print(Panel(
        f"[bold #feb2b2]⚠️ DESTRUCTIVE ACTION CONFIRMATION REQUIRED[/]\n\n"
        f"[bold #e2e8f0]Tool:[/] [bold #fc8181]{tool_name}[/]\n"
        f"[bold #e2e8f0]Target Asset / IP:[/] [bold #faf089]{target}[/]\n"
        f"[bold #e2e8f0]Justification:[/] [dim]{reason}[/]\n\n"
        "[dim #fc8181]This will isolate the host from the network or insert a firewall drop rule.[/]",
        border_style="#e53e3e",
        title="[bold #feb2b2]Security Perimeter Gate[/]"
    ))

    try:
        approved = Confirm.ask(f"[bold #feb2b2]Approve execution of {tool_name} on {target}?[/]", default=False)
        if approved:
            return True, "ANALYST_APPROVED"
        else:
            return False, "ANALYST_DENIED"
    except (KeyboardInterrupt, EOFError):
        return False, "CANCELLED"
