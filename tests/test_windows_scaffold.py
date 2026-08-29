"""Windows Sysmon scaffolding tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from alerting import load_rules
from ingestor import ingest
from log_generator import (
    generate_from_rules,
    generate_sysmon_event,
    synthesize_scenario_from_rule,
)
from normalizer import normalize
from run_collection_tests import run_pipeline, run_pipeline_from_rules


ROOT = Path(__file__).resolve().parent.parent


class WindowsScaffoldTest(unittest.TestCase):
    def test_sysmon_normalize_maps_canonical_fields(self) -> None:
        scenario = {
            "id": "demo",
            "technique_id": "T1059.001",
            "command_line": "powershell.exe -EncodedCommand AAA=",
            "process_name": "powershell.exe",
            "image_path": (
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            ),
            "parent_image": r"C:\Windows\System32\cmd.exe",
            "host": "WORKSTATION-05",
            "user": r"CORP\jsmith",
        }
        events = normalize(ingest([generate_sysmon_event(scenario)]))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.log_source, "sysmon")
        self.assertEqual(event.get("logsource.product"), "windows")
        self.assertEqual(event.get("process.name"), "powershell.exe")
        self.assertEqual(event.get("process.parent.name"), "cmd.exe")
        self.assertIn("-EncodedCommand", event.get("process.command_line"))

    def test_windows_rule_synthesizes_and_matches(self) -> None:
        rules = load_rules(ROOT / "sigma" / "rules")
        rule = next(
            item for item in rules if item.id == "win_sysmon_powershell_encoded"
        )
        scenario = synthesize_scenario_from_rule(rule)
        self.assertEqual(scenario["log_source"], "sysmon")
        self.assertEqual(scenario["platform"], "windows")

        events = normalize(ingest(generate_from_rules([rule])))
        self.assertIsNotNone(rule.matches(events[0]))

    def test_windows_hand_scenario_passes(self) -> None:
        report = run_pipeline(ROOT, "powershell_encoded_command")
        self.assertEqual(report.tests_failed, 0)
        self.assertEqual(report.tests_passed, 1)

    def test_rule_pipeline_includes_windows(self) -> None:
        report = run_pipeline_from_rules(
            ROOT, ["win_sysmon_powershell_encoded"]
        )
        self.assertEqual(report.tests_failed, 0)
        self.assertGreaterEqual(report.tests_passed, 1)


if __name__ == "__main__":
    unittest.main()
