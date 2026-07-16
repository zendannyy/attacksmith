"""Evaluate alerts against collection-test expectations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from models import Alert, NormalizedEvent, TestCase, TestResult


def load_tests(path: Path) -> list[TestCase]:
    """Load collection tests from YAML."""
    with path.open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream) or {}
    items = document.get("tests", [])
    if not isinstance(items, list):
        raise ValueError(f"'tests' must be a list in {path}")

    tests = [
        TestCase(
            id=item["id"],
            scenario_id=item["scenario_id"],
            description=item.get("description", ""),
            technique_id=item.get("technique_id"),
            expected_rules=item.get("expected_rules", []),
            min_alerts=int(item.get("min_alerts", 1)),
            must_not_match=item.get("must_not_match", []),
        )
        for item in items
    ]
    if any(test.min_alerts < 0 for test in tests):
        raise ValueError("min_alerts cannot be negative")
    return tests


def evaluate(
    alerts: list[Alert],
    events: list[NormalizedEvent],
    tests: list[TestCase],
) -> list[TestResult]:
    """Produce one pass/fail result for each collection test."""
    event_by_id = {event.id: event for event in events}
    results: list[TestResult] = []

    for test in tests:
        scenario_events = [
            event for event in events if event.scenario_id == test.scenario_id
        ]
        scenario_alerts = [
            alert
            for alert in alerts
            if event_by_id.get(alert.event_id) in scenario_events
        ]
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
        technique_matches = (
            test.technique_id is None or test.technique_id in observed_techniques
        )

        passed = (
            len(scenario_alerts) >= test.min_alerts
            and not missing_rules
            and not forbidden_matches
            and technique_matches
        )
        message = _result_message(
            passed=passed,
            alert_count=len(scenario_alerts),
            test=test,
            missing_rules=missing_rules,
            forbidden_matches=forbidden_matches,
            observed_techniques=observed_techniques,
        )
        results.append(
            TestResult(
                test_id=test.id,
                passed=passed,
                alerts=scenario_alerts,
                matched_rules=matched_rules,
                missing_rules=missing_rules,
                forbidden_matches=forbidden_matches,
                message=message,
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
) -> str:
    if passed:
        return "PASS"
    if forbidden_matches:
        return f"Forbidden rule(s) matched: {', '.join(forbidden_matches)}"
    if missing_rules:
        return f"Missing expected rule(s): {', '.join(missing_rules)}"
    if test.technique_id and test.technique_id not in observed_techniques:
        observed = ", ".join(sorted(observed_techniques)) or "none"
        return f"Expected technique {test.technique_id}; observed {observed}"
    return f"Expected at least {test.min_alerts} alert(s), got {alert_count}"


def summary(results: list[TestResult]) -> dict[str, Any]:
    """Summarize collection-test outcomes."""
    passed = sum(result.passed for result in results)
    return {
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "all_passed": passed == len(results),
    }
