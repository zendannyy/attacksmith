"""Generate raw Linux audit events from ATT&CKSmith scenarios."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from models import RawLogRecord


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_scenarios(path: Path) -> list[dict[str, Any]]:
    """Load scenario definitions from YAML."""
    with path.open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream) or {}
    scenarios = document.get("scenarios", [])
    if not isinstance(scenarios, list):
        raise ValueError(f"'scenarios' must be a list in {path}")
    return scenarios


def generate_linux_audit_event(scenario: dict[str, Any]) -> RawLogRecord:
    """Create one decoded auditd EXECVE-style record."""
    if scenario.get("log_source") != "linux_audit":
        raise ValueError(
            f"Unsupported log source for scenario '{scenario.get('id')}': "
            f"{scenario.get('log_source')}"
        )

    required = ("id", "command_line", "exe")
    missing = [key for key in required if not scenario.get(key)]
    if missing:
        raise ValueError(
            f"Scenario is missing required field(s): {', '.join(missing)}"
        )

    payload = {
        "timestamp": _utc_now(),
        "hostname": scenario.get("host", "localhost"),
        "type": "EXECVE",
        "exe": scenario["exe"],
        "comm": Path(scenario["exe"]).name,
        "proctitle": scenario["command_line"],
        "user": scenario.get("user", ""),
        "uid": scenario.get("user_id"),
        "auid": scenario.get("audit_user_id"),
        "tty": scenario.get("terminal", ""),
        "parent_comm": scenario.get("parent_comm", ""),
        "syscall": "execve",
    }
    return RawLogRecord(
        source="linux_audit",
        payload=payload,
        scenario_id=scenario["id"],
        technique_id=scenario.get("technique_id"),
    )


def generate(path: Path, scenario_id: str) -> list[RawLogRecord]:
    """Generate all records for one named scenario."""
    matches = [
        scenario
        for scenario in load_scenarios(path)
        if scenario.get("id") == scenario_id
    ]
    if not matches:
        raise ValueError(f"Unknown scenario '{scenario_id}'")
    if len(matches) > 1:
        raise ValueError(f"Duplicate scenario id '{scenario_id}'")

    scenario = matches[0]
    count = int(scenario.get("count", 1))
    if count < 1:
        raise ValueError("Scenario count must be at least 1")
    return [generate_linux_audit_event(scenario) for _ in range(count)]
