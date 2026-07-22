"""End-to-end viability test for the first ATT&CKSmith scenario."""

from __future__ import annotations

import unittest
from pathlib import Path

from run_collection_tests import run_pipeline


class CronPersistencePipelineTest(unittest.TestCase):
    def test_interactive_shell_cron_scenario_passes(self) -> None:
        root = Path(__file__).resolve().parent.parent

        # report = run_pipeline(root, DEFAULT_SCENARIO)
        report = run_pipeline(root, "cron_persistence_interactive_shell")

        self.assertEqual(report.generated, 1)
        self.assertEqual(report.ingested, 1)
        self.assertEqual(report.normalized, 1)
        self.assertEqual(len(report.alerts), 1)
        self.assertEqual(
            report.alerts[0].rule_id,
            "linux_cron_persistence_interactive_shell",
        )
        self.assertEqual(len(report.test_results), 1)
        self.assertTrue(report.test_results[0].passed)
        self.assertEqual(report.test_results[0].message, "PASS")


if __name__ == "__main__":
    unittest.main()
