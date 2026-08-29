"""Generate raw events from scenarios or Sigma rules (Linux + Windows)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from faker import Faker

from alerting import SigmaRule
from models import RawLogRecord

fake = Faker()

SUPPORTED_SYNTH_PRODUCTS = frozenset({"linux", "windows"})


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_scenarios(path: Path) -> list[dict[str, Any]]:
    """Load scenario definitions from one YAML file."""
    with path.open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream) or {}
    scenarios = document.get("scenarios", [])
    if not isinstance(scenarios, list):
        raise ValueError(f"'scenarios' must be a list in {path}")
    return scenarios


def load_scenario_files(paths: list[Path]) -> list[dict[str, Any]]:
    """Load and merge scenarios from multiple YAML files."""
    scenarios: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        for scenario in load_scenarios(path):
            sid = scenario.get("id")
            if not sid:
                raise ValueError(f"Scenario missing id in {path}")
            if sid in seen:
                raise ValueError(f"Duplicate scenario id '{sid}' in {path}")
            seen.add(sid)
            scenarios.append(scenario)
    return scenarios


def default_scenario_paths(root: Path) -> list[Path]:
    """Return standard scenario files under ``scenarios/``.
    chooses which ones, linux or windows"""
    return [
        root / "scenarios" / "linux.yaml",
        root / "scenarios" / "windows.yaml",
    ]


def generate_linux_audit_event(scenario: dict[str, Any]) -> RawLogRecord:
    """Create one decoded auditd EXECVE-style record."""
    # this was convoluted, not as clean as new approach
    #   if scenario.get("log_source") != "linux_audit":
    #     raise ValueError(
    #         f"Unsupported log source for scenario '{scenario.get('id')}': "
    #         f"{scenario.get('log_source')}"
    #     )
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


def generate_sysmon_event(scenario: dict[str, Any]) -> RawLogRecord:
    """Create one Sysmon Event ID 1 (process creation) record."""
    required = ("id", "command_line")
    missing = [key for key in required if not scenario.get(key)]
    if missing:
        raise ValueError(
            f"Scenario is missing required field(s): {', '.join(missing)}"
        )

    process_name = scenario.get("process_name", "cmd.exe")
    image = scenario.get(
        "image_path",
        f"C:\\Windows\\System32\\{process_name}",
    )
    parent_image = scenario.get(
        "parent_image",
        "C:\\Windows\\System32\\cmd.exe",
    )
    payload = {
        "EventID": 1,
        "UtcTime": _utc_now(),
        "Computer": scenario.get("host", "WORKSTATION-01"),
        "User": scenario.get("user", fake.user_name()),
        "Image": image,
        "ProcessGuid": "{" + str(uuid.uuid4()).upper() + "}",
        "ProcessId": 4000 + (hash(scenario["id"]) % 1000),
        "CommandLine": scenario["command_line"],
        "ParentImage": parent_image,
        "ParentProcessId": 2100,
        "LogName": "Microsoft-Windows-Sysmon/Operational",
    }
    return RawLogRecord(
        source="sysmon",
        payload=payload,
        scenario_id=scenario["id"],
        technique_id=scenario.get("technique_id"),
    )


EVENT_BUILDERS = {
    "linux_audit": generate_linux_audit_event,
    "sysmon": generate_sysmon_event,
}


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
        token = text.split(".", 1)[1]
        if len(token) > 1 and token[0].lower() == "t" and token[1].isdigit():
            return token.upper()
    return None


def rule_product(rule: SigmaRule) -> str:
    """Return the Sigma logsource product (lowercased), defaulting to linux."""
    product = str(rule.logsource.get("product") or "linux").casefold()
    return product


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


def _extract_process_constraints(
    rule: SigmaRule,
) -> tuple[str, str | None, list[str], str]:
    """Return process_name, executable, command_parts, parent_name."""
    process_name = "cmd.exe"
    executable: str | None = None
    command_parts: list[str] = []
    parent_name = "cmd.exe"

    for selection in _selection_maps(rule):
        for expression, expected in selection.items():
            field, separator, operator = expression.partition("|")
            operator = operator if separator else None

            if field == "process.name":
                process_name = _first(expected, process_name)
            elif field == "process.executable":
                executable = _first(expected)
                process_name = (
                    Path(executable.replace("\\", "/")).name or process_name
                )
            elif field == "process.parent.name":
                parent_name = _first(expected, parent_name)
            elif field == "process.command_line":
                values = [str(item) for item in _as_list(expected)]
                if operator == "contains":
                    command_parts.extend(values)
                elif operator == "startswith":
                    command_parts.insert(0, values[0])
                else:
                    command_parts = [values[0]]
                    break

    return process_name, executable, command_parts, parent_name


def _command_line_from_parts(
    process_name: str, command_parts: list[str]
) -> str:
    joined = " ".join(command_parts)
    if not command_parts:
        return process_name
    if process_name.casefold() not in joined.casefold():
        return f"{process_name} {joined}"
    return joined


def synthesize_linux_scenario_from_rule(rule: SigmaRule) -> dict[str, Any]:
    """Build a linux_audit scenario that should satisfy ``rule``."""
    process_name, executable, command_parts, parent_name = (
        _extract_process_constraints(rule)
    )
    # Defaults differ for Linux.
    if process_name == "cmd.exe":
        process_name = "bash"
    if parent_name == "cmd.exe":
        parent_name = "bash"
    if executable is None:
        executable = f"/usr/bin/{process_name}"

    terminal = "pts0"
    for selection in _selection_maps(rule):
        for expression, expected in selection.items():
            field, separator, operator = expression.partition("|")
            if field != "process.tty":
                continue
            token = _first(expected, "pts")
            terminal = token if operator != "startswith" else f"{token}0"

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
        "parent_comm": parent_name,
        "command_line": _command_line_from_parts(process_name, command_parts),
        "source_rule_id": rule.id,
        "expect": {
            "id": f"detect_{rule.id}",
            "rules": [rule.id],
            "min_alerts": 1,
            "description": f"Synthesized log should fire {rule.id}",
        },
    }


def synthesize_windows_scenario_from_rule(rule: SigmaRule) -> dict[str, Any]:
    """Build a Sysmon process-creation scenario that should satisfy ``rule``."""
    process_name, executable, command_parts, parent_name = (
        _extract_process_constraints(rule)
    )
    if not process_name.lower().endswith(".exe"):
        # Sysmon Image basenames are usually *.exe
        if process_name in {"powershell", "pwsh", "cmd", "notepad"}:
            process_name = f"{process_name}.exe"
    if executable is None:
        executable = f"C:\\Windows\\System32\\{process_name}"
    if not parent_name.lower().endswith(".exe"):
        parent_name = f"{parent_name}.exe"

    return {
        "id": f"synth_{rule.id}",
        "name": f"Synthesized for {rule.id}",
        "description": f"Auto-generated positive telemetry for rule {rule.id}",
        "technique_id": technique_from_tags(rule.tags),
        "platform": "windows",
        "log_source": "sysmon",
        "count": 1,
        "host": "WORKSTATION-01",
        "user": f"CORP\\{fake.user_name()}",
        "process_name": process_name,
        "image_path": executable,
        "parent_image": f"C:\\Windows\\System32\\{parent_name}",
        "command_line": _command_line_from_parts(process_name, command_parts),
        "source_rule_id": rule.id,
        "expect": {
            "id": f"detect_{rule.id}",
            "rules": [rule.id],
            "min_alerts": 1,
            "description": f"Synthesized log should fire {rule.id}",
        },
    }


def synthesize_scenario_from_rule(rule: SigmaRule) -> dict[str, Any]:
    """Build a platform-appropriate scenario that should satisfy ``rule``."""
    product = rule_product(rule)
    if product == "windows":
        return synthesize_windows_scenario_from_rule(rule)
    if product == "linux":
        return synthesize_linux_scenario_from_rule(rule)
    raise ValueError(
        f"Cannot synthesize logs for rule '{rule.id}' "
        f"(unsupported logsource.product={product!r}; "
        f"supported: {', '.join(sorted(SUPPORTED_SYNTH_PRODUCTS))})"
    )


def synthesize_scenarios_from_rules(
    rules: list[SigmaRule],
    *,
    skip_unsupported: bool = False,
) -> list[dict[str, Any]]:
    """Synthesize one positive scenario per supported Sigma rule."""
    scenarios: list[dict[str, Any]] = []
    for rule in rules:
        if skip_unsupported and rule_product(rule) not in SUPPORTED_SYNTH_PRODUCTS:
            continue
        scenarios.append(synthesize_scenario_from_rule(rule))
    return scenarios


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
    paths: Path | list[Path], selector: str
) -> list[dict[str, Any]]:
    """Resolve a selector to scenarios by id or technique_id."""
    if isinstance(paths, Path):
        paths = [paths]
    scenarios = load_scenario_files(list(paths))
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
    paths: Path | list[Path], selectors: list[str]
) -> list[dict[str, Any]]:
    """Resolve one or more selectors and de-duplicate by scenario id."""
    selected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for selector in selectors:
        for scenario in resolve_scenarios(paths, selector):
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
        log_source = scenario.get("log_source")
        builder = EVENT_BUILDERS.get(log_source)
        if builder is None:
            raise ValueError(
                f"Unsupported log source for scenario '{scenario.get('id')}': "
                f"{log_source}"
            )
        count = int(scenario.get("count", 1))
        if count < 1:
            raise ValueError(
                f"Scenario count must be at least 1 for '{scenario.get('id')}'"
            )
        records.extend(builder(scenario) for _ in range(count))
    return records


def generate_from_rules(rules: list[SigmaRule]) -> list[RawLogRecord]:
    """Generate positive raw logs synthesized from Sigma rules."""
    return generate_records(
        synthesize_scenarios_from_rules(rules, skip_unsupported=False)
    )


def generate(path: Path, selector: str) -> list[RawLogRecord]:
    """Generate records for a scenario id or technique_id selector."""
    return generate_records(resolve_scenarios(path, selector))
