"""
Configuration management for soc-cli.
Loads and saves settings to ~/.config/soc-cli/config.toml
"""

import os
from pathlib import Path
from typing import Dict, Any, List
import tomlkit

DEFAULT_CONFIG = {
    "core": {
        "mode": "local",  # 'local' or 'remote'
        "remote_url": "http://localhost:8080",
        "default_model": "gemini-3.6-flash",
    },
    "security": {
        "auto_approve": False,
        "safe_tools": ["check_threat_intel", "lookup_user_activity", "inspect_linux_auth_logs"],
        "gated_tools": ["isolate_host"],
    },
    "ui": {
        "theme": "terminal",
        "show_trace_ids": False,
        "show_mitre_chips": True,
    }
}

def get_config_path() -> Path:
    config_dir = Path.home() / ".config" / "soc-cli"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "config.toml"

def load_cli_config() -> Dict[str, Any]:
    config_file = get_config_path()
    if not config_file.exists():
        save_cli_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG

    try:
        with open(config_file, "r", encoding="utf-8") as f:
            data = tomlkit.parse(f.read())
            # Merge with defaults
            config = dict(DEFAULT_CONFIG)
            for k, v in data.items():
                if k in config and isinstance(config[k], dict):
                    config[k].update(dict(v))
                else:
                    config[k] = v
            return config
    except Exception:
        return DEFAULT_CONFIG

def save_cli_config(config_dict: Dict[str, Any]):
    config_file = get_config_path()
    doc = tomlkit.document()
    for section, values in config_dict.items():
        table = tomlkit.table()
        for k, v in values.items():
            table.add(k, v)
        doc.add(section, table)

    with open(config_file, "w", encoding="utf-8") as f:
        f.write(tomlkit.dumps(doc))
