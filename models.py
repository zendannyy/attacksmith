"""Shared data contracts for the ATT&CKSmith detection-test pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RawLogRecord:
    """A generated or collected event before ingestion."""
    source: str
    payload: dict[str, Any]
    scenario_id: str | None = None
    technique_id: str | None = None


@dataclass
class IngestedRecord:
    """A raw event with identity and ingestion metadata."""
    id: str
    source: str
    payload: dict[str, Any]
    ingested_at: str
    scenario_id: str | None = None
    technique_id: str | None = None


@dataclass
class NormalizedEvent:
    """A source-independent event consumed by detection rules."""
    id: str
    timestamp: str
    log_source: str
    event_kind: str
    fields: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    scenario_id: str | None = None
    technique_id: str | None = None

    def get(self, key: str, default: Any = None) -> Any:
        """Return a canonical field value, such as ``process.tty``."""
        return self.fields.get(key, default)


@dataclass
class Alert:
    """A detection rule match associated with one normalized event."""
    rule_id: str
    rule_title: str
    severity: str
    event_id: str
    technique_id: str | None = None
    matched_fields: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)


@dataclass
class TestCase:
    """Expected and forbidden detections for one scenario."""

    id: str
    scenario_id: str
    description: str = ""
    technique_id: str | None = None
    expected_rules: list[str] = field(default_factory=list)
    min_alerts: int = 1
    max_alerts: int | None = None
    must_not_match: list[str] = field(default_factory=list)


@dataclass
class TestResult:
    """Outcome of evaluating one collection test."""
    test_id: str
    passed: bool
    alerts: list[Alert] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    missing_rules: list[str] = field(default_factory=list)
    forbidden_matches: list[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable result for reporting."""
        result = asdict(self)
        result["alert_count"] = len(self.alerts)
        return result


@dataclass
class PipelineReport:
    """Counts and test outcomes from one complete pipeline run."""
    generated: int = 0
    ingested: int = 0
    normalized: int = 0
    alerts: list[Alert] = field(default_factory=list)
    test_results: list[TestResult] = field(default_factory=list)

    @property
    def tests_passed(self) -> int:
        return sum(result.passed for result in self.test_results)

    @property
    def tests_failed(self) -> int:
        return len(self.test_results) - self.tests_passed

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable pipeline summary."""
        return {
            "generated": self.generated,
            "ingested": self.ingested,
            "normalized": self.normalized,
            "alert_count": len(self.alerts),
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "test_results": [result.to_dict() for result in self.test_results],
        }
