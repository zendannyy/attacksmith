"""Run the ATT&CKSmith viability scenario end to end."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from alerting import evaluate as evaluate_rules
from alerting import load_rules
from evaluator import evaluate as evaluate_tests
from evaluator import load_tests
from ingestor import ingest
from log_generator import generate_records, resolve_scenario_selectors
from models import PipelineReport
from normalizer import normalize

DEFAULT_SCENARIO = "cron_persistence_interactive_shell"


def run_pipeline(root: Path, selectors: str | list[str]) -> PipelineReport:
    """Execute one or more scenarios from generation through test evaluation.

    Each selector may be a scenario ``id`` or a ``technique_id``.
    """
    if isinstance(selectors, str):
        selectors = [selectors]

    scenarios_path = root / "scenarios" / "linux.yaml"
    selected = resolve_scenario_selectors(scenarios_path, selectors)
    scenario_ids = {scenario["id"] for scenario in selected}

    raw_records = generate_records(selected)
    ingested_records = ingest(raw_records)
    normalized_events = normalize(ingested_records)
    alerts = evaluate_rules(
        normalized_events,
        load_rules(root / "sigma" / "rules"),
    )
    tests = [
        test
        for test in load_tests(root / "tests" / "collection_tests.yaml")
        if test.scenario_id in scenario_ids
    ]
    if not tests:
        joined = ", ".join(sorted(scenario_ids))
        raise ValueError(f"No collection test found for scenario(s): {joined}")
    test_results = evaluate_tests(alerts, normalized_events, tests)
    return PipelineReport(
        generated=len(raw_records),
        ingested=len(ingested_records),
        normalized=len(normalized_events),
        alerts=alerts,
        test_results=test_results,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run an ATT&CKSmith collection-test scenario. "
            "Selectors accept scenario id or technique_id."
        )
    )
    parser.add_argument(
        "--scenario",
        action="append", dest="scenarios", metavar="SELECTOR",
        help=(
            "Scenario id or technique_id to run; repeatable. "
            "Example: --scenario ssh_remote_forward or --scenario T1572"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true", help="Print full report as JSON",
    )
    args = parser.parse_args()

    report = run_pipeline(
        Path(__file__).resolve().parent,
        args.scenarios or [DEFAULT_SCENARIO],
    )
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.tests_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
