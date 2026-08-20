"""
Subcommand: soc mitre <technique_id>
Queries MITRE ATT&CK enterprise threat matrix intelligence for tactics, detections, and mitigations.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from src.tools.soc_tools import generate_mitre_report

console = Console()

def run_mitre(technique_id: str):
    console.print(f"\n[bold #63b3ed]Querying MITRE ATT&CK Matrix for:[/] [bold #faf089]{technique_id}[/]\n")
    res = generate_mitre_report(technique_id)

    tbl = Table(title="MITRE ATT&CK Technique Intel", border_style="#4a5568", header_style="bold #00ff9d")
    tbl.add_column("Property", style="#63b3ed", width=22)
    tbl.add_column("Value", style="#e2e8f0")

    tbl.add_row("Technique", str(res.get("technique", technique_id)))
    tbl.add_row("Tactic", str(res.get("tactic", "Enterprise Matrix")))
    tbl.add_row("Description", str(res.get("description", "")))
    tbl.add_row("Detection Strategy", str(res.get("detection", "")))
    tbl.add_row("Mitigation Guidance", str(res.get("mitigation", "")))

    console.print(tbl)
    console.print()
