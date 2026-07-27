"""Evaluate alerts against collection-test expectations."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml

from models import Alert, NormalizedEvent, TestCase, TestResult


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def tests_from_scenarios(scenarios: list[dict[str, Any]]) -> list[TestCase]:
    """Build collection tests from each scenario's ``expect`` block."""
    tests: list[TestCase] = []
    for scenario in scenarios:
        expect = scenario.get("expect")
        if not isinstance(expect, dict):
            continue
        test = TestCase(
            id=str(expect.get("id") or f"detect_{scenario['id']}"),
            scenario_id=scenario["id"],
            description=str(
                expect.get("description")
                or scenario.get("description")
                or scenario.get("name")
                or ""
            ),
            technique_id=scenario.get("technique_id"),
            expected_rules=list(expect.get("rules") or expect.get("expected_rules") or []),
            min_alerts=int(expect.get("min_alerts", 1)),
            max_alerts=_optional_int(expect.get("max_alerts")),
            must_not_match=list(expect.get("must_not_match") or []),
        )
        _validate_test_case(test)
        tests.append(test)
    return tests


def load_tests(path: Path) -> list[TestCase]:
    """Load collection tests from YAML (legacy registry)."""
    with path.open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream) or {}
    items = document.get("tests", [])
    if not isinstance(items, list):
        raise ValueError(f"'tests' must be a list in {path}")

    tests: list[TestCase] = []
    for item in items:
        test = TestCase(
            id=item["id"],
            scenario_id=item["scenario_id"],
            description=item.get("description", ""),
            technique_id=item.get("technique_id"),
            expected_rules=item.get("expected_rules", []),
            min_alerts=int(item.get("min_alerts", 1)),
            max_alerts=_optional_int(item.get("max_alerts")),
            must_not_match=item.get("must_not_match", []),
        )
        _validate_test_case(test)
        tests.append(test)
    return tests


def _validate_test_case(test: TestCase) -> None:
    if test.min_alerts < 0:
        raise ValueError(f"min_alerts cannot be negative for test '{test.id}'")
    if test.max_alerts is None:
        return
    if test.max_alerts < 0:
        raise ValueError(f"max_alerts cannot be negative for test '{test.id}'")
    if test.min_alerts > test.max_alerts:
        raise ValueError(f"min_alerts ({test.min_alerts}) cannot exceed max_alerts "
            f"({test.max_alerts}) for test '{test.id}'"
        )


def evaluate(
    alerts: list[Alert],
    events: list[NormalizedEvent],
    tests: list[TestCase],
) -> list[TestResult]:
    """Produce one pass/fail result for each collection test."""
    results: list[TestResult] = []

    for test in tests:
        scenario_events = [
            event for event in events if event.scenario_id == test.scenario_id
        ]
        event_ids = {event.id for event in scenario_events}
        scenario_alerts = [
            alert for alert in alerts if alert.event_id in event_ids
        ]
        alert_count = len(scenario_alerts)
        matched_rules = sorted({alert.rule_id for alert in scenario_alerts})
        missing_rules = [
            rule for rule in test.expected_rules if rule not in matched_rules
        ]
        forbidden_matches = [
            rule for rule in test.must_not_match if rule in matched_rules
        ]
        observed_techniques = {
            event.technique_id for event in scenario_events if event.technique_id
        }
        within_max_alerts = (
            test.max_alerts is None or alert_count <= test.max_alerts
        )
        technique_matches = (
            test.technique_id is None or test.technique_id in observed_techniques
        )
        passed = (
            alert_count >= test.min_alerts
            and within_max_alerts
            and not missing_rules
            and not forbidden_matches
            and technique_matches
        )
        results.append(
            TestResult(
                test_id=test.id,
                passed=passed,
                alerts=scenario_alerts,
                matched_rules=matched_rules,
                missing_rules=missing_rules,
                forbidden_matches=forbidden_matches,
                message=_result_message(
                    passed=passed,
                    alert_count=alert_count,
                    test=test,
                    missing_rules=missing_rules,
                    forbidden_matches=forbidden_matches,
                    observed_techniques=observed_techniques,
                    within_max_alerts=within_max_alerts,
                ),
            )
        )
    return results


def _result_message(
    *,
    passed: bool,
    alert_count: int,
    test: TestCase,
    missing_rules: list[str],
    forbidden_matches: list[str],
    observed_techniques: set[str],
    within_max_alerts: bool,
) -> str:
    if passed:
        return "PASS"
    if forbidden_matches:
        return f"Forbidden rule(s) matched: {', '.join(forbidden_matches)}"
    if missing_rules:
        return f"Missing expected rule(s): {', '.join(missing_rules)}"
    if not within_max_alerts:
        return f"Expected at most {test.max_alerts} alert(s), got {alert_count}"
    if test.technique_id and test.technique_id not in observed_techniques:
        observed = ", ".join(sorted(observed_techniques)) or "none"
        return f"Expected technique {test.technique_id}; observed {observed}"
    return f"Expected at least {test.min_alerts} alert(s), got {alert_count}"
