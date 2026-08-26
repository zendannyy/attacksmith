"""Normalize collected log records into canonical ATT&CKSmith events."""

from __future__ import annotations

from pathlib import Path

from models import IngestedRecord, NormalizedEvent


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def normalize_linux_audit(record: IngestedRecord) -> NormalizedEvent:
    """Map a decoded auditd process event into ATT&CK fields."""
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


def normalize_sysmon(record: IngestedRecord) -> NormalizedEvent:
    """Map a Sysmon process-creation event into ATT&CK fields."""
    payload = record.payload
    image = str(payload.get("Image", ""))
    parent = str(payload.get("ParentImage", ""))
    return NormalizedEvent(
        id=record.id,
        timestamp=str(payload.get("UtcTime", record.ingested_at)),
        log_source=record.source,
        event_kind="process_creation",
        scenario_id=record.scenario_id,
        technique_id=record.technique_id,
        fields={
            "host.name": payload.get("Computer", ""),
            "user.name": payload.get("User", ""),
            "process.name": _basename(image),
            "process.executable": image,
            "process.command_line": payload.get("CommandLine", ""),
            "process.parent.name": _basename(parent),
            "process.parent.executable": parent,
            "event.code": str(payload.get("EventID", "")),
            "logsource.product": "windows",
            "logsource.service": "sysmon",
            "logsource.category": "process_creation",
        },
        tags=["windows", "sysmon", "process_creation"],
    )


HOOKS = {
    "linux_audit": normalize_linux_audit,
    "sysmon": normalize_sysmon,
}


def normalize(records: list[IngestedRecord]) -> list[NormalizedEvent]:
    """Normalize supported records and reject unknown sources."""
    events: list[NormalizedEvent] = []
    for record in records:
        hook = HOOKS.get(record.source)
        if hook is None:
            raise ValueError(f"Unsupported log source '{record.source}'")
        events.append(hook(record))
    return events
