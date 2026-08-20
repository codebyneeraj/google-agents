"""
Subcommand: soc redteam
Executes the comprehensive red-team adversarial battery.
"""

import subprocess
import sys
from pathlib import Path
from rich.console import Console

console = Console()

def run_redteam(url: str = "http://localhost:8080"):
    script_path = Path(__file__).resolve().parent.parent.parent / "scripts" / "advanced_soc_evaluation.py"
    if not script_path.exists():
        console.print(f"[bold #fc8181]Red-team evaluation script not found at {script_path}[/]")
        return

    console.print(f"\n[bold #feb2b2]Launching Automated SOC Red-Team Evaluation Battery...[/]\n")
    cmd = [sys.executable, str(script_path), "--url", url]
    try:
        subprocess.run(cmd, check=False)
    except Exception as e:
        console.print(f"[bold #fc8181]Red-team execution error:[/] {e}")
