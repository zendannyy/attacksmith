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


def resolve_scenarios(
    path: Path, selector: str
) -> list[dict[str, Any]]:
    """Resolve a user selector to one or more scenarios.

    Accepts either:
    - scenario ``id`` (exact match; preferred when present)
    - ``technique_id`` (case-insensitive; may return multiple scenarios)
    """
    scenarios = load_scenarios(path)
    if not selector or not selector.strip():
        raise ValueError("Scenario selector cannot be empty")

    selector = selector.strip()
    by_id = [scenario for scenario in scenarios if scenario.get("id") == selector]
    if by_id:
        if len(by_id) > 1:
            raise ValueError(f"Duplicate scenario id '{selector}'")
        return by_id

    selector_key = selector.casefold()
    by_technique = [
        scenario
        for scenario in scenarios
        if str(scenario.get("technique_id") or "").casefold() == selector_key
    ]
    if by_technique:
        return by_technique

    available_ids = sorted(
        scenario["id"] for scenario in scenarios if scenario.get("id")
    )
    available_techniques = sorted(
        {
            str(scenario["technique_id"])
            for scenario in scenarios
            if scenario.get("technique_id")
        }
    )
    raise ValueError(
        f"Unknown scenario selector '{selector}'. "
        f"Known ids: {', '.join(available_ids) or '(none)'}. "
        f"Known technique_ids: {', '.join(available_techniques) or '(none)'}."
    )


def resolve_scenario_selectors(
    path: Path, selectors: list[str]
) -> list[dict[str, Any]]:
    """Resolve one or more selectors and de-duplicate by scenario id."""
    selected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for selector in selectors:
        for scenario in resolve_scenarios(path, selector):
            scenario_id = scenario["id"]
            if scenario_id in seen_ids:
                continue
            seen_ids.add(scenario_id)
            selected.append(scenario)
    return selected


def generate_records(scenarios: list[dict[str, Any]]) -> list[RawLogRecord]:
    """Generate raw records for already-resolved scenario definitions."""
    records: list[RawLogRecord] = []
    for scenario in scenarios:
        count = int(scenario.get("count", 1))
        if count < 1:
            raise ValueError(
                f"Scenario count must be at least 1 for '{scenario.get('id')}'"
            )
        records.extend(generate_linux_audit_event(scenario) for _ in range(count))
    return records


def generate(path: Path, selector: str) -> list[RawLogRecord]:
    """Generate records for a scenario id or technique_id selector."""
    return generate_records(resolve_scenarios(path, selector))
