"""
Subcommand: soc scan <target_host> [--ports ...]
Performs network socket scan against specified host to identify listening ports and rogue services.
"""

from rich.console import Console
from rich.table import Table
from src.tools.soc_tools import scan_local_ports

console = Console()

def run_port_scan(host: str = "127.0.0.1", ports: str = "22,80,443,445,3389,8080"):
    console.print(f"\n[bold #63b3ed]Scanning Network Ports on Target:[/] [bold #faf089]{host}[/]\n")
    res = scan_local_ports(host=host, ports=ports)

    open_ports = res.get("open_ports", [])
    tbl = Table(title=f"Network Socket Scan Results ({res.get('scanned_ports_count')} ports checked)", border_style="#4a5568", header_style="bold #00ff9d")
    tbl.add_column("Port", style="#63b3ed", width=12)
    tbl.add_column("Standard Service", style="#faf089", width=20)
    tbl.add_column("State", style="#9ae6b4")

    if open_ports:
        for p in open_ports:
            tbl.add_row(str(p["port"]), str(p["service"]), "[bold #9ae6b4]OPEN / LISTENING[/]")
    else:
        tbl.add_row("—", "—", "[dim]No open listening ports detected in scanned range[/]")

    console.print(tbl)
    console.print()
