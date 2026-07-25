"""Run ATT&CKSmith collection tests end to end."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from alerting import evaluate as evaluate_rules
from alerting import load_rules
from evaluator import evaluate as evaluate_tests
from evaluator import load_tests, tests_from_scenarios
from ingestor import ingest
from log_generator import (
    generate_records,
    load_scenarios,
    resolve_rule_selectors,
    resolve_scenario_selectors,
    synthesize_scenarios_from_rules,
)
from models import PipelineReport, TestCase
from normalizer import normalize


def _tests_for_scenarios(
    root: Path,
    selected: list[dict],
) -> list[TestCase]:
    """Prefer scenario ``expect`` blocks; fall back to collection_tests.yaml."""
    from_expect = tests_from_scenarios(selected)
    covered = {test.scenario_id for test in from_expect}
    legacy = [
        test
        for test in load_tests(root / "tests" / "collection_tests.yaml")
        if test.scenario_id in {scenario["id"] for scenario in selected}
        and test.scenario_id not in covered
    ]
    return from_expect + legacy


def _run_selected_scenarios(
    root: Path,
    selected: list[dict],
    *,
    rules_for_eval: list | None = None,
) -> PipelineReport:
    if not selected:
        raise ValueError("No scenarios selected")

    scenario_ids = {scenario["id"] for scenario in selected}
    raw_records = generate_records(selected)
    ingested_records = ingest(raw_records)
    normalized_events = normalize(ingested_records)
    rules = rules_for_eval if rules_for_eval is not None else load_rules(
        root / "sigma" / "rules"
    )
    alerts = evaluate_rules(normalized_events, rules)
    tests = _tests_for_scenarios(root, selected)
    if not tests:
        joined = ", ".join(sorted(scenario_ids))
        raise ValueError(
            f"No expect block or collection test for scenario(s): {joined}"
        )
    test_results = evaluate_tests(alerts, normalized_events, tests)
    return PipelineReport(
        generated=len(raw_records),
        ingested=len(ingested_records),
        normalized=len(normalized_events),
        alerts=alerts,
        test_results=test_results,
    )


def run_pipeline_from_rules(
    root: Path,
    rule_selectors: list[str] | None = None,
) -> PipelineReport:
    """Synthesize logs from Sigma rules and grade that each rule fires."""
    all_rules = load_rules(root / "sigma" / "rules")
    if rule_selectors:
        selected_rules = resolve_rule_selectors(all_rules, rule_selectors)
    else:
        selected_rules = all_rules

    selected = synthesize_scenarios_from_rules(selected_rules)
    # Evaluate only the selected rules so authoring stays rule-local.
    return _run_selected_scenarios(
        root,
        selected,
        rules_for_eval=selected_rules,
    )


def run_pipeline(
    root: Path,
    selectors: str | list[str] | None = None,
) -> PipelineReport:
    """Execute hand-authored scenarios from generation through evaluation."""
    scenarios_path = root / "scenarios" / "linux.yaml"
    if selectors is None:
        selected = load_scenarios(scenarios_path)
    else:
        if isinstance(selectors, str):
            selectors = [selectors]
        selected = resolve_scenario_selectors(scenarios_path, selectors)
    return _run_selected_scenarios(root, selected)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run ATT&CKSmith tests. Default: synthesize logs from every Sigma "
            "rule and grade that each rule fires (rule-only authoring)."
        )
    )
    parser.add_argument(
        "--rule",
        action="append",
        dest="rules",
        metavar="SELECTOR",
        help=(
            "Rule id or technique (e.g. linux_audit_socat_reverse_shell or "
            "T1090). Default is all rules."
        ),
    )
    parser.add_argument(
        "--scenario",
        action="append",
        dest="scenarios",
        metavar="SELECTOR",
        help=(
            "Optional hand-authored scenario id or technique_id. "
            "When set, runs scenario mode instead of rule synthesis."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full report as JSON",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    if args.scenarios:
        report = run_pipeline(root, args.scenarios)
    else:
        report = run_pipeline_from_rules(root, args.rules)

    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.tests_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
