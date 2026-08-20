"""
Subcommand: soc decode <encoded_payload>
Decodes obfuscated base64 PowerShell/bash scripts and highlights suspicious command patterns.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from src.tools.soc_tools import decode_base64_payload

console = Console()

def run_decode(payload: str):
    console.print(f"\n[bold #63b3ed]Decoding Obfuscated Payload...[/]\n")
    res = decode_base64_payload(payload)

    tbl = Table(title="Payload Obfuscation Analysis", border_style="#4a5568", header_style="bold #00ff9d")
    tbl.add_column("Property", style="#63b3ed", width=24)
    tbl.add_column("Value", style="#e2e8f0")

    risk = res.get("risk_level", "LOW")
    risk_color = "#fc8181" if risk == "CRITICAL" else ("#f6ad55" if risk == "SUSPICIOUS" else "#9ae6b4")
    tbl.add_row("Risk Level", f"[bold {risk_color}]{risk}[/]")
    tbl.add_row("Encoding Detected", res.get("obfuscation_type", "Base64"))
    
    indicators = res.get("suspicious_indicators_found", [])
    tbl.add_row("Suspicious Commands", ", ".join(indicators) if indicators else "[#9ae6b4]None detected[/]")

    console.print(tbl)
    console.print(Panel(
        res.get("decoded_content", ""),
        border_style="#319795",
        title="[bold #81e6d9]Decoded Script / Command Output[/]"
    ))
    console.print()
