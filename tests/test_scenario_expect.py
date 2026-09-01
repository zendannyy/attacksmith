"""Tests for scenario expect → TestCase conversion."""

from __future__ import annotations

import unittest
from pathlib import Path
from evaluator import tests_from_scenarios
from log_generator import default_scenario_paths, load_scenario_files, load_scenarios


ROOT = Path(__file__).resolve().parent.parent


class ScenarioExpectTest(unittest.TestCase):
    def test_all_linux_scenarios_have_expect_blocks(self) -> None:
        scenarios = load_scenarios(ROOT / "scenarios" / "linux.yaml")
        tests = tests_from_scenarios(scenarios)
        self.assertEqual(len(tests), len(scenarios))
        self.assertTrue(all(test.scenario_id for test in tests))

    def test_authored_persistence_and_c2_cases_still_present(self) -> None:
        scenarios = load_scenarios(ROOT / "scenarios" / "linux.yaml")
        ids = {scenario["id"] for scenario in scenarios}
        expected = {
            "systemd_timer_persistence",
            "bashrc_persistence",
            "powershell_encoded_command",
            "ssh_dynamic_socks_forward",
            "ssh_proxycommand_tunnel",
            "benign_notepad_start",
        }
        self.assertTrue(expected.issubset(ids))


if __name__ == "__main__":
    unittest.main()
