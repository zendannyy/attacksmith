"""Attach ingestion metadata to raw ATT&CKSmith records."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from models import IngestedRecord, RawLogRecord


def ingest(records: list[RawLogRecord]) -> list[IngestedRecord]:
    """Assign raw log stable-in-run event identities and ingestion timestamps."""
    ingested_at = datetime.now(timezone.utc).isoformat()
    return [
        IngestedRecord(
            id=str(uuid.uuid4()),
            source=record.source,
            payload=record.payload,
            ingested_at=ingested_at,
            scenario_id=record.scenario_id,
            technique_id=record.technique_id,
        )
        for record in records
    ]
