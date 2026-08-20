"""
Subcommand: soc hash <file_hash>
Inspects MD5/SHA1/SHA256 hashes against VirusTotal and malware intelligence.
"""

from rich.console import Console
from rich.table import Table
from src.tools.soc_tools import analyze_file_hash

console = Console()

def run_hash_lookup(file_hash: str):
    console.print(f"\n[bold #63b3ed]Inspecting Malware File Hash:[/] [bold #faf089]{file_hash}[/]\n")
    res = analyze_file_hash(file_hash)

    tbl = Table(title="File Hash Threat Analysis", border_style="#4a5568", header_style="bold #00ff9d")
    tbl.add_column("Property", style="#63b3ed", width=22)
    tbl.add_column("Value", style="#e2e8f0")

    tbl.add_row("Hash Indicator", res.get("hash", file_hash))
    rep = res.get("reputation", "UNKNOWN")
    rep_color = "#fc8181" if rep == "MALICIOUS" else ("#f6ad55" if rep == "SUSPICIOUS" else "#9ae6b4")
    tbl.add_row("Reputation", f"[bold {rep_color}]{rep}[/]")
    tbl.add_row("Threat Score", f"{res.get('threat_score', 0)}/100")
    tbl.add_row("Category / Family", str(res.get("category", "Unindexed")))
    if res.get("actor"):
        tbl.add_row("Threat Actor / Malware", str(res["actor"]))
    if res.get("source"):
        tbl.add_row("Intelligence Source", str(res["source"]))

    console.print(tbl)
    console.print()
