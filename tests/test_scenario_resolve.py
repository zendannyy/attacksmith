"""Tests for scenario id / technique_id selector resolution."""

from __future__ import annotations

import unittest
from pathlib import Path

from log_generator import (
    default_scenario_paths,
    resolve_scenario_selectors,
    resolve_scenarios,
)


ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios" / "linux.yaml"
ALL_SCENARIOS = default_scenario_paths(ROOT)


class ScenarioResolveTest(unittest.TestCase):
    def test_resolve_by_scenario_id(self) -> None:
        selected = resolve_scenarios(SCENARIOS, "ssh_remote_forward")
        self.assertEqual([item["id"] for item in selected], ["ssh_remote_forward"])

    def test_resolve_windows_scenario_across_files(self) -> None:
        selected = resolve_scenarios(ALL_SCENARIOS, "powershell_encoded_command")
        self.assertEqual(
            [item["id"] for item in selected],
            ["powershell_encoded_command"],
        )
        self.assertEqual(selected[0]["log_source"], "sysmon")

    def test_resolve_by_technique_id(self) -> None:
        selected = resolve_scenarios(SCENARIOS, "T1572")
        ids = sorted(item["id"] for item in selected)
        self.assertIn("ssh_remote_forward", ids)
        self.assertIn("ssh_remote_tunneling", ids)
        self.assertIn("ssh_dynamic_socks_forward", ids)

    def test_resolve_technique_id_is_case_insensitive(self) -> None:
        selected = resolve_scenarios(SCENARIOS, "t1572")
        self.assertGreaterEqual(len(selected), 2)

    def test_unknown_selector_lists_known_values(self) -> None:
        with self.assertRaises(ValueError) as context:
            resolve_scenarios(ALL_SCENARIOS, "not-a-real-selector")
        message = str(context.exception)
        self.assertIn("Known ids:", message)
        self.assertIn("Known technique_ids:", message)
        self.assertIn("ssh_remote_forward", message)
        self.assertIn("powershell_encoded_command", message)
        self.assertIn("T1572", message)
        self.assertIn("T1059.001", message)

    def test_multiple_selectors_are_deduplicated(self) -> None:
        selected = resolve_scenario_selectors(
            SCENARIOS,
            ["T1572", "ssh_remote_forward"],
        )
        ids = [item["id"] for item in selected]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("ssh_remote_forward", ids)


if __name__ == "__main__":
    unittest.main()
