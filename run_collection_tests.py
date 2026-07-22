"""Run ATT&CKSmith collection tests end to end."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from alerting import evaluate as evaluate_rules
from alerting import load_rules
from evaluator import evaluate as evaluate_tests
from evaluator import load_tests
from ingestor import ingest
from log_generator import (
    generate_records,
    load_scenarios,
    resolve_scenario_selectors,
)
from models import PipelineReport
from normalizer import normalize



def run_pipeline(root: Path, selectors: str | list[str]) -> PipelineReport:
    """Execute one or more scenarios from generation through test evaluation.
    If ``selectors`` is omitted, every scenario is run.
    Each selector may be a scenario ``id`` or a ``technique_id``.
    """
    scenarios_path = root / "scenarios" / "linux.yaml"
    if selectors is None:
        selected = load_scenarios(scenarios_path)
    else:
        if isinstance(selectors, str):
            selectors = [selectors]
        selected = resolve_scenario_selectors(scenarios_path, selectors)

    if not selected:
        raise ValueError("No scenarios selected")

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
            "Run ATT&CKSmith collection tests. "
            "Omit --scenario to run all scenarios."
        )
    )
    parser.add_argument(
        "--scenario",
        action="append",
        dest="scenarios",
        metavar="SELECTOR",
        help=(
            "Scenario id or technique_id to run; repeatable. "
            "If omitted, all scenarios are run. "
            "Example: --scenario ssh_remote_forward or --scenario T1572"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full report as JSON",
    )
    args = parser.parse_args()

    report = run_pipeline(Path(__file__).resolve().parent, args.scenarios)
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.tests_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
