"""
Subcommand: soc dns <domain>
Performs DNS resolution, nameserver telemetry, and DGA anomaly analysis.
"""

from rich.console import Console
from rich.table import Table
from src.tools.soc_tools import scan_domain_dns

console = Console()

def run_dns_lookup(domain: str):
    console.print(f"\n[bold #63b3ed]Scanning Domain & DNS Telemetry:[/] [bold #faf089]{domain}[/]\n")
    res = scan_domain_dns(domain)

    tbl = Table(title="Domain DNS & Threat Analysis", border_style="#4a5568", header_style="bold #00ff9d")
    tbl.add_column("Property", style="#63b3ed", width=22)
    tbl.add_column("Value", style="#e2e8f0")

    tbl.add_row("Domain Name", res.get("domain", domain))
    tbl.add_row("Resolved IPv4/IPv6", ", ".join(res.get("resolved_ips", [])) or "[dim]NXDOMAIN / Unresolved[/]")
    tbl.add_row("Entropy Score", str(res.get("entropy_score", 0.0)))
    tbl.add_row("DGA Heuristic Indicator", "[bold #fc8181]HIGH_ENTROPY_DGA[/]" if res.get("dga_indicator") else "[#9ae6b4]NORMAL[/]")
    
    rep = res.get("reputation", "BENIGN")
    rep_color = "#fc8181" if rep == "MALICIOUS" else ("#f6ad55" if rep == "SUSPICIOUS" else "#9ae6b4")
    tbl.add_row("Reputation", f"[bold {rep_color}]{rep}[/]")
    tbl.add_row("Resolution Status", res.get("status", "RESOLVED"))

    console.print(tbl)
    console.print()
