"""
Subcommand: soc memory <indicator>
Inspects cross-session Vertex AI Memory Bank entries for an indicator.
"""

from rich.console import Console
from rich.table import Table
from src.memory.memory_service import memory_bank

console = Console()

def run_memory_lookup(indicator: str):
    console.print(f"\n[bold #81e6d9]Querying Vertex AI Memory Bank for:[/] [bold #faf089]{indicator}[/]\n")
    memories = memory_bank.recall_memories(indicator, limit=5)

    if not memories:
        console.print(f"[dim]No past investigation memories found for indicator '{indicator}'.[/]\n")
        return

    table = Table(title=f"Enterprise Memory Bank Records ({len(memories)} entries)", border_style="#4a5568", header_style="bold #00ff9d")
    table.add_column("Timestamp", style="#63b3ed", width=22)
    table.add_column("Entity Key", style="#faf089", width=20)
    table.add_column("Stored Investigation Summary", style="#e2e8f0")

    for m in memories:
        table.add_row(m.created_at[:19], m.entity_key, m.summary)

    console.print(table)
    console.print()
