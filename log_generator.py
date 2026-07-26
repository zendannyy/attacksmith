"""Generate raw Linux audit events from scenarios or Sigma rules."""

from __future__ import annotations

from datetime import datetime, timezone
from faker import Faker
from faker import Faker
from pathlib import Path
from typing import Any
import yaml
from faker import Faker

from alerting import SigmaRule
from models import RawLogRecord

fake = Faker()


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


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _first(value: Any, default: str = "") -> str:
    items = _as_list(value)
    return str(items[0]) if items else default


def technique_from_tags(tags: list[str]) -> str | None:
    """Map Sigma ``attack.t1053.003`` tags to ``T1053.003``."""
    for tag in tags:
        text = str(tag)
        if not text.casefold().startswith("attack.t"):
            continue
        token = text.split(".", 1)[1]  # t1053.003
        if len(token) > 1 and token[0].lower() == "t" and token[1].isdigit():
            return token.upper()
    return None


def _selection_maps(rule: SigmaRule) -> list[dict[str, Any]]:
    detection = rule.detection
    condition = detection.get("condition", "selection")
    selections = {
        name: value
        for name, value in detection.items()
        if name != "condition" and isinstance(value, dict)
    }
    if condition == "selection":
        selection = selections.get("selection")
        return [selection] if selection else []
    if condition == "all of selection_*":
        return [
            selection
            for name, selection in selections.items()
            if name.startswith("selection_")
        ]
    raise ValueError(
        f"Cannot synthesize logs for unsupported condition "
        f"'{condition}' in rule '{rule.id}'"
    )


def synthesize_scenario_from_rule(rule: SigmaRule) -> dict[str, Any]:
    """Build a linux_audit scenario that should satisfy ``rule``.

    Inverts the supported Sigma subset (exact / contains / startswith on
    process fields) into exe, command_line, parent, and tty values.
    """
    process_name = "bash"
    executable: str | None = None
    command_parts: list[str] = []
    parent_comm = "bash"
    terminal = "pts0"

    for selection in _selection_maps(rule):
        for expression, expected in selection.items():
            field, separator, operator = expression.partition("|")
            operator = operator if separator else None

            if field == "process.name":
                process_name = _first(expected, process_name)
            elif field == "process.executable":
                executable = _first(expected)
                process_name = Path(executable).name or process_name
            elif field == "process.parent.name":
                parent_comm = _first(expected, parent_comm)
            elif field == "process.tty":
                token = _first(expected, "pts")
                terminal = token if operator != "startswith" else f"{token}0"
            elif field == "process.command_line":
                values = [str(item) for item in _as_list(expected)]
                if operator == "contains":
                    # Include every OR token so the cmdline is distinctive and
                    # still satisfies ``any(token in cmdline)``.
                    command_parts.extend(values)
                elif operator == "startswith":
                    command_parts.insert(0, values[0])
                else:
                    # Exact match: use the whole expected cmdline.
                    command_parts = [values[0]]
                    break

    if executable is None:
        executable = f"/usr/bin/{process_name}"

    joined = " ".join(command_parts)
    if not command_parts:
        command_line = process_name
    elif process_name.casefold() not in joined.casefold():
        command_line = f"{process_name} {joined}"
    else:
        command_line = joined

    return {
        "id": f"synth_{rule.id}",
        "name": f"Synthesized for {rule.id}",
        "description": f"Auto-generated positive telemetry for rule {rule.id}",
        "technique_id": technique_from_tags(rule.tags),
        "platform": "linux",
        "log_source": "linux_audit",
        "count": 1,
        "host": "synth-host-01",
        "user": fake.user_name(),
        "user_id": 1000,
        "audit_user_id": 1000,
        "terminal": terminal,
        "exe": executable,
        "parent_comm": parent_comm,
        "command_line": command_line,
        "source_rule_id": rule.id,
        "expect": {
            "id": f"detect_{rule.id}",
            "rules": [rule.id],
            "min_alerts": 1,
            "description": f"Synthesized log should fire {rule.id}",
        },
    }


def synthesize_scenarios_from_rules(
    rules: list[SigmaRule],
) -> list[dict[str, Any]]:
    """Synthesize one positive scenario per Sigma rule."""
    return [synthesize_scenario_from_rule(rule) for rule in rules]


def resolve_rules(
    rules: list[SigmaRule], selector: str
) -> list[SigmaRule]:
    """Resolve a selector to rules by id or ATT&CK technique tag."""
    if not selector or not selector.strip():
        raise ValueError("Rule selector cannot be empty")
    selector = selector.strip()
    by_id = [rule for rule in rules if rule.id == selector]
    if by_id:
        return by_id

    technique = selector.upper()
    if not technique.startswith("T"):
        technique = f"T{technique}"
    matched = [
        rule for rule in rules if technique_from_tags(rule.tags) == technique
    ]
    if matched:
        return matched

    known = ", ".join(sorted(rule.id for rule in rules)) or "(none)"
    raise ValueError(
        f"Unknown rule selector '{selector}'. Known rule ids: {known}."
    )


def resolve_rule_selectors(
    rules: list[SigmaRule], selectors: list[str]
) -> list[SigmaRule]:
    """Resolve one or more rule selectors and de-duplicate by rule id."""
    selected: list[SigmaRule] = []
    seen: set[str] = set()
    for selector in selectors:
        for rule in resolve_rules(rules, selector):
            if rule.id in seen:
                continue
            seen.add(rule.id)
            selected.append(rule)
    return selected


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


def generate_from_rules(rules: list[SigmaRule]) -> list[RawLogRecord]:
    """Generate positive raw logs synthesized from Sigma rules."""
    return generate_records(synthesize_scenarios_from_rules(rules))


def generate(path: Path, selector: str) -> list[RawLogRecord]:
    """Generate records for a scenario id or technique_id selector."""
    return generate_records(resolve_scenarios(path, selector))
