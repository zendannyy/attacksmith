"""Evaluate the small Sigma subset needed by the viability scenario."""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from models import Alert, NormalizedEvent


def _expected_values(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _value_matches(actual: Any, expected: Any, operator: str | None) -> bool:
    if actual is None:
        return False

    actual_text = str(actual).casefold()
    expected_values = _expected_values(expected)
    if operator == "contains":
        return any(str(value).casefold() in actual_text for value in expected_values)
    if operator == "startswith":
        return any(actual_text.startswith(str(value).casefold()) for value in expected_values)
    return any(actual_text == str(value).casefold() for value in expected_values)


def _match_selection(
    event: NormalizedEvent, selection: dict[str, Any]) -> dict[str, Any] | None:
    matched: dict[str, Any] = {}
    for expression, expected in selection.items():
        field_name, separator, operator = expression.partition("|")
        actual = event.get(field_name)
        if not _value_matches(actual, expected, operator if separator else None):
            return None
        matched[field_name] = actual
    return matched


@dataclass
class SigmaRule:
    """Parsed fields from the supported subset of one Sigma rule."""
    id: str
    title: str
    level: str
    logsource: dict[str, Any]
    detection: dict[str, Any]
    tags: list[str]

    @classmethod
    def from_path(cls, path: Path) -> SigmaRule:
        with path.open(encoding="utf-8") as stream:
            document = yaml.safe_load(stream) or {}
        if not document.get("id"):
            raise ValueError(f"Sigma rule has no id: {path}")
        return cls(
            id=document["id"],
            title=document.get("title", document["id"]),
            level=document.get("level", "medium"),
            logsource=document.get("logsource", {}),
            detection=document.get("detection", {}),
            tags=document.get("tags", []),
        )

    def matches(self, event: NormalizedEvent) -> dict[str, Any] | None:
        for key, expected in self.logsource.items():
            if not _value_matches(event.get(f"logsource.{key}"), expected, None):
                return None

        selections = {
            name: value
            for name, value in self.detection.items()
            if name != "condition" and isinstance(value, dict)
        }
        condition = self.detection.get("condition", "selection")
        if condition == "selection":
            return _match_selection(event, selections.get("selection", {}))
        if condition == "all of selection_*":
            selected = {
                name: selection
                for name, selection in selections.items()
                if name.startswith("selection_")
            }
            if not selected:
                return None
            combined: dict[str, Any] = {}
            for selection in selected.values():
                result = _match_selection(event, selection)
                if result is None:
                    return None
                combined.update(result)
            return combined
        raise ValueError(f"Unsupported Sigma condition '{condition}'")


def load_rules(rules_dir: Path) -> list[SigmaRule]:
    """Load YAML Sigma rules recursively."""
    paths = sorted([*rules_dir.rglob("*.yml"), *rules_dir.rglob("*.yaml")])
    if not paths:
        raise ValueError(f"No Sigma rules found under {rules_dir}")
    return [SigmaRule.from_path(path) for path in paths]


def evaluate(
    events: list[NormalizedEvent], rules: list[SigmaRule]
) -> list[Alert]:
    """Return an alert for each matching event and rule pair."""
    alerts: list[Alert] = []
    for event in events:
        for rule in rules:
            matched_fields = rule.matches(event)
            if matched_fields is not None:
                alerts.append(
                    Alert(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        severity=rule.level,
                        event_id=event.id,
                        technique_id=event.technique_id,
                        matched_fields=matched_fields,
                        tags=rule.tags,
                    )
                )
    return alerts
