"""Normalize collected Linux audit records into canonical events."""

from __future__ import annotations

from pathlib import Path

from models import IngestedRecord, NormalizedEvent


def normalize_linux_audit(record: IngestedRecord) -> NormalizedEvent:
    """Map a decoded auditd process event into ATT&CKSmith fields."""
    payload = record.payload
    executable = str(payload.get("exe", ""))
    return NormalizedEvent(
        id=record.id,
        timestamp=str(payload.get("timestamp", record.ingested_at)),
        log_source=record.source,
        event_kind="process_creation",
        scenario_id=record.scenario_id,
        technique_id=record.technique_id,
        fields={
            "host.name": payload.get("hostname", ""),
            "user.name": payload.get("user", ""),
            "user.id": payload.get("uid"),
            "user.audit.id": payload.get("auid"),
            "process.name": Path(executable).name,
            "process.executable": executable,
            "process.command_line": payload.get("proctitle", ""),
            "process.parent.name": payload.get("parent_comm", ""),
            "process.tty": payload.get("tty", ""),
            "event.type": payload.get("type", ""),
            "logsource.product": "linux",
            "logsource.service": "auditd",
            "logsource.category": "process_creation",
        },
        tags=["linux", "auditd", "process_creation"],
    )


def normalize(records: list[IngestedRecord]) -> list[NormalizedEvent]:
    """Normalize supported records and reject unknown sources."""
    events: list[NormalizedEvent] = []
    for record in records:
        if record.source != "linux_audit":
            raise ValueError(f"Unsupported log source '{record.source}'")
        events.append(normalize_linux_audit(record))
    return events
