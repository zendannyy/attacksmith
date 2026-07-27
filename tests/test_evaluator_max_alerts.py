"""Unit tests for collection-test evaluation, including max_alerts."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from evaluator import evaluate
from evaluator import load_tests as load_collection_tests
from models import Alert, NormalizedEvent, TestCase


def _event(event_id: str, scenario_id: str) -> NormalizedEvent:
    return NormalizedEvent(
        id=event_id,
        timestamp="2026-01-01T00:00:00+00:00",
        log_source="linux_audit",
        event_kind="process_creation",
        scenario_id=scenario_id,
        technique_id=None,
    )


def _alert(rule_id: str, event_id: str) -> Alert:
    return Alert(
        rule_id=rule_id,
        rule_title=rule_id,
        severity="high",
        event_id=event_id,
    )


class MaxAlertsEvaluatorTest(unittest.TestCase):
    def test_max_alerts_zero_passes_with_no_alerts(self) -> None:
        test = TestCase(
            id="ignore_benign",
            scenario_id="benign_crontab_listing",
            min_alerts=0,
            max_alerts=0,
            must_not_match=["linux_cron_persistence_interactive_shell"],
        )
        event = _event("e1", "benign_crontab_listing")

        results = evaluate([], [event], [test])

        self.assertTrue(results[0].passed)
        self.assertEqual(results[0].message, "PASS")

    def test_max_alerts_zero_fails_when_any_alert_fires(self) -> None:
        test = TestCase(
            id="ignore_benign",
            scenario_id="benign_crontab_listing",
            min_alerts=0,
            max_alerts=0,
        )
        event = _event("e1", "benign_crontab_listing")
        alert = _alert("some_unrelated_rule", "e1")

        results = evaluate([alert], [event], [test])

        self.assertFalse(results[0].passed)
        self.assertIn("at most 0", results[0].message)

    def test_omitted_max_alerts_allows_multiple_alerts(self) -> None:
        test = TestCase(
            id="detect_cron",
            scenario_id="cron_persistence_interactive_shell",
            expected_rules=["linux_cron_persistence_interactive_shell"],
            min_alerts=1,
            max_alerts=None,
        )
        events = [
            _event("e1", "cron_persistence_interactive_shell"),
            _event("e2", "cron_persistence_interactive_shell"),
        ]
        alerts = [
            _alert("linux_cron_persistence_interactive_shell", "e1"),
            _alert("linux_cron_persistence_interactive_shell", "e2"),
        ]

        results = evaluate(alerts, events, [test])

        self.assertTrue(results[0].passed)

    def test_load_tests_reads_max_alerts(self) -> None:
        content = """
tests:
  - id: benign_linux_cron_listing
    scenario_id: benign_crontab_listing
    expected_rules: []
    min_alerts: 0
    max_alerts: 0
    must_not_match:
      - linux_cron_persistence_interactive_shell
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collection_tests.yaml"
            path.write_text(content, encoding="utf-8")
            tests = load_collection_tests(path)

        self.assertEqual(len(tests), 1)
        self.assertEqual(tests[0].max_alerts, 0)
        self.assertEqual(tests[0].min_alerts, 0)

    def test_load_tests_rejects_min_greater_than_max(self) -> None:
        content = """
tests:
  - id: bad_bounds
    scenario_id: some_scenario
    min_alerts: 2
    max_alerts: 1
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collection_tests.yaml"
            path.write_text(content, encoding="utf-8")
            with self.assertRaises(ValueError) as context:
                load_collection_tests(path)
        self.assertIn("cannot exceed max_alerts", str(context.exception))


if __name__ == "__main__":
    unittest.main()
