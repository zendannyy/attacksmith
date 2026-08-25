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
    default_scenario_paths,
    generate_records,
    load_scenario_files,
    resolve_rule_selectors,
    resolve_scenario_selectors,
    rule_product,
    synthesize_scenarios_from_rules,
    SUPPORTED_SYNTH_PRODUCTS,
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
    legacy_path = root / "tests" / "collection_tests.yaml"
    if not legacy_path.exists():
        return from_expect
    legacy = [
        test
        for test in load_tests(legacy_path)
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
        # Default suite: only platforms we can synthesize today.
        selected_rules = [
            rule
            for rule in all_rules
            if rule_product(rule) in SUPPORTED_SYNTH_PRODUCTS
        ]

    selected = synthesize_scenarios_from_rules(selected_rules)
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
    scenario_paths = default_scenario_paths(root)
    if selectors is None:
        selected = load_scenario_files(scenario_paths)
    else:
        if isinstance(selectors, str):
            selectors = [selectors]
        selected = resolve_scenario_selectors(scenario_paths, selectors)
    return _run_selected_scenarios(root, selected)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run ATT&CKSmith tests. Default: synthesize logs from Linux/Windows "
            "Sigma rules and grade that each rule fires."
        )
    )
    parser.add_argument(
        "--rule",
        action="append",
        dest="rules",
        metavar="SELECTOR",
        help=(
            "Rule id or technique (e.g. win_sysmon_powershell_encoded or "
            "T1059.001). Default is all synthesizable rules."
        ),
    )
    parser.add_argument(
        "--scenario",
        action="append",
        dest="scenarios",
        metavar="SELECTOR",
        help=(
            "Optional hand-authored scenario id or technique_id "
            "(searches linux.yaml and windows.yaml)."
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
