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
from log_generator import generate
from models import PipelineReport
from normalizer import normalize

DEFAULT_SCENARIO = "cron_persistence_interactive_shell"


def run_pipeline(root: Path, scenario_id: str = DEFAULT_SCENARIO) -> PipelineReport:
    """Execute one scenario from generation through test evaluation."""
    raw_records = generate(root / "scenarios" / "linux.yaml", scenario_id)
    ingested_records = ingest(raw_records)
    normalized_events = normalize(ingested_records)
    alerts = evaluate_rules(
        normalized_events,
        load_rules(root / "sigma" / "rules"),
    )
    tests = [
        test
        for test in load_tests(root / "tests" / "collection_tests.yaml")
        if test.scenario_id == scenario_id
    ]
    if not tests:
        raise ValueError(f"No collection test found for scenario '{scenario_id}'")
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
        description="Run an ATT&CKSmith collection-test scenario."
    )
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO)
    args = parser.parse_args()

    report = run_pipeline(Path(__file__).resolve().parent, args.scenario)
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.tests_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
