"""
Main Typer entry point for soc-cli.
"""

import typer
from typing import Optional
from pathlib import Path

from soc_cli.config import load_cli_config, save_cli_config, get_config_path
from soc_cli.repl import run_repl
from soc_cli.commands.triage import run_triage
from soc_cli.commands.memory import run_memory_lookup
from soc_cli.commands.isolate import run_isolate
from soc_cli.commands.unquarantine import run_unquarantine
from soc_cli.commands.dns import run_dns_lookup
from soc_cli.commands.hash_cmd import run_hash_lookup
from soc_cli.commands.decode import run_decode
from soc_cli.commands.scan import run_port_scan
from soc_cli.commands.mitre import run_mitre
from soc_cli.commands.audit import run_audit
from soc_cli.commands.redteam import run_redteam

app = typer.Typer(
    name="soc",
    help="Agentic SOC Analyst CLI — Powered by Gemini Enterprise Agent Platform (GEAP)",
    no_args_is_help=False,
    invoke_without_command=True,
)

@app.callback()
def main_callback(
    ctx: typer.Context,
    local: bool = typer.Option(False, "--local", "-l", help="Use local in-process execution engine"),
    remote: bool = typer.Option(False, "--remote", "-r", help="Use Google Cloud Run remote gateway"),
    auto_approve: bool = typer.Option(False, "--auto-approve", "-y", help="Auto-approve destructive tool actions"),
    resume: Optional[str] = typer.Option(None, "--resume", help="Resume prior investigation by trace/session ID"),
):
    """
    If no subcommand is passed, defaults to launching the interactive REPL (`soc chat`).
    """
    if ctx.invoked_subcommand is None:
        cfg = load_cli_config()
        mode = "remote" if remote else ("local" if local else cfg.get("core", {}).get("mode", "local"))
        remote_url = cfg.get("core", {}).get("remote_url", "http://localhost:8080")
        approve = auto_approve or cfg.get("security", {}).get("auto_approve", False)
        run_repl(mode=mode, remote_url=remote_url, auto_approve=approve, resume_id=resume)

@app.command("chat")
def chat_cmd(
    local: bool = typer.Option(False, "--local", "-l", help="Force local direct execution"),
    remote: bool = typer.Option(False, "--remote", "-r", help="Force remote Cloud Run execution"),
    auto_approve: bool = typer.Option(False, "--auto-approve", "-y", help="Auto-approve destructive tool actions"),
    resume: Optional[str] = typer.Option(None, "--resume", help="Resume prior investigation by trace/session ID"),
):
    """Launch the interactive Agentic SOC REPL session."""
    cfg = load_cli_config()
    mode = "remote" if remote else ("local" if local else cfg.get("core", {}).get("mode", "local"))
    remote_url = cfg.get("core", {}).get("remote_url", "http://localhost:8080")
    approve = auto_approve or cfg.get("security", {}).get("auto_approve", False)
    run_repl(mode=mode, remote_url=remote_url, auto_approve=approve, resume_id=resume)

@app.command("triage")
def triage_cmd(
    alert: str = typer.Argument(..., help="Path to alert JSON file or raw alert text string"),
    auto_approve: bool = typer.Option(False, "--auto-approve", "-y", help="Auto-approve destructive actions"),
):
    """Ingest and autonomously triage a SIEM/EDR alert."""
    run_triage(alert, auto_approve=auto_approve)

@app.command("memory")
def memory_cmd(
    indicator: str = typer.Argument(..., help="IP address, domain, or user email to inspect in Memory Bank"),
):
    """Query past cross-session investigations from Vertex AI Memory Bank."""
    run_memory_lookup(indicator)

@app.command("isolate")
def isolate_cmd(
    target: str = typer.Argument(..., help="Host ID or IP address to isolate"),
    reason: str = typer.Option("Manual security operator quarantine", "--reason", help="Quarantine justification"),
    auto_approve: bool = typer.Option(False, "--auto-approve", "-y", help="Skip confirmation prompt"),
):
    """Trigger manual emergency EDR host or firewall quarantine."""
    run_isolate(target, reason=reason, auto_approve=auto_approve)

@app.command("unquarantine")
def unquarantine_cmd(
    target: str = typer.Argument(..., help="Host ID or IP address to release from quarantine"),
    reason: str = typer.Option("Security analyst verified remediation", "--reason", help="Release justification"),
    auto_approve: bool = typer.Option(False, "--auto-approve", "-y", help="Skip confirmation prompt"),
):
    """Release a host or IP from firewall network isolation."""
    run_unquarantine(target, reason=reason, auto_approve=auto_approve)

@app.command("dns")
def dns_cmd(
    domain: str = typer.Argument(..., help="Domain name to scan and analyze (e.g. evil-c2.xyz)"),
):
    """Perform live DNS resolution, nameserver telemetry, and DGA anomaly analysis."""
    run_dns_lookup(domain)

@app.command("hash")
def hash_cmd(
    file_hash: str = typer.Argument(..., help="MD5, SHA1, or SHA256 file hash to inspect"),
):
    """Inspect file hashes against VirusTotal and malware intelligence signatures."""
    run_hash_lookup(file_hash)

@app.command("decode")
def decode_cmd(
    payload: str = typer.Argument(..., help="Base64 or obfuscated script payload to analyze"),
):
    """Decode obfuscated PowerShell/bash payloads and highlight malicious commands."""
    run_decode(payload)

@app.command("scan")
def scan_cmd(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Target host or IP to probe"),
    ports: str = typer.Option("22,80,443,445,3389,8080", "--ports", "-p", help="Comma-separated ports or range (e.g. 20-100)"),
):
    """Perform network socket port scan to discover open services and backdoors."""
    run_port_scan(host=host, ports=ports)

@app.command("mitre")
def mitre_cmd(
    technique: str = typer.Argument(..., help="MITRE ATT&CK Technique ID (e.g. T1059, T1110, T1078)"),
):
    """Query MITRE ATT&CK matrix intelligence for tactics, detections, and mitigations."""
    run_mitre(technique)

@app.command("audit")
def audit_cmd(
    trace_id: str = typer.Argument(..., help="Cryptographic trace_id or session_id to audit"),
):
    """Inspect structured audit log events for an investigation trace."""
    run_audit(trace_id)

@app.command("redteam")
def redteam_cmd(
    url: str = typer.Option("http://localhost:8080", "--url", help="Target gateway endpoint to evaluate"),
):
    """Run the automated adversarial red-team evaluation battery."""
    run_redteam(url=url)

@app.command("config")
def config_cmd(
    show: bool = typer.Option(True, "--show", help="Display current CLI configuration"),
    set_mode: Optional[str] = typer.Option(None, "--set-mode", help="Set default transport mode (local/remote)"),
):
    """View or update ~/.config/soc-cli/config.toml settings."""
    cfg = load_cli_config()
    if set_mode:
        if set_mode in ("local", "remote"):
            cfg["core"]["mode"] = set_mode
            save_cli_config(cfg)
            typer.echo(f"Updated default mode to: {set_mode}")
        else:
            typer.echo("Invalid mode. Choose 'local' or 'remote'.")
    
    if show:
        typer.echo(f"Config File: {get_config_path()}")
        import json
        typer.echo(json.dumps(cfg, indent=2))

if __name__ == "__main__":
    app()
