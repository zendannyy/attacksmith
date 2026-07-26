"""Tests for synthesizing positive logs from Sigma rules."""

from __future__ import annotations

import unittest
from pathlib import Path

from alerting import load_rules
from ingestor import ingest
from log_generator import (
    generate_from_rules,
    synthesize_scenario_from_rule,
    technique_from_tags,
)
from normalizer import normalize
from run_collection_tests import run_pipeline_from_rules


ROOT = Path(__file__).resolve().parent.parent


class RuleSynthesisTest(unittest.TestCase):
    def test_technique_from_tags(self) -> None:
        self.assertEqual(
            technique_from_tags(["attack.persistence", "attack.t1053.003"]),
            "T1053.003",
        )

    def test_synthesize_scenario_includes_expect_for_rule(self) -> None:
        rules = load_rules(ROOT / "sigma" / "rules")
        cron = next(
            rule
            for rule in rules
            if rule.id == "linux_cron_persistence_interactive_shell"
        )
        scenario = synthesize_scenario_from_rule(cron)
        self.assertEqual(scenario["source_rule_id"], cron.id)
        self.assertEqual(scenario["expect"]["rules"], [cron.id])
        # test for "linux_cron_persistence_interactive_shell"
        self.assertIn("/etc/cron.d/", scenario["command_line"])

    def test_synthesized_log_matches_its_rule(self) -> None:
        rules = load_rules(ROOT / "sigma" / "rules")
        for rule in rules:
            with self.subTest(rule=rule.id):
                records = generate_from_rules([rule])
                events = normalize(ingest(records))
                matched = rule.matches(events[0])
                self.assertIsNotNone(
                    matched,
                    f"synthesized event did not match rule {rule.id}: "
                    f"{events[0].fields}",
                )

    def test_pipeline_from_rules_all_pass(self) -> None:
        report = run_pipeline_from_rules(ROOT)
        self.assertEqual(report.tests_failed, 0)
        self.assertEqual(report.tests_passed, report.generated)
        self.assertGreaterEqual(report.tests_passed, 1)


if __name__ == "__main__":
    unittest.main()
