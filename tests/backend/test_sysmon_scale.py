from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db import Base
from app.services.sysmon_ingestion import NormalizedSysmonEvent, persist_events


def test_persist_and_deduplicate_100000_synthetic_events() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    start = datetime(2026, 11, 20, tzinfo=timezone.utc)
    events = [
        NormalizedSysmonEvent(
            event_id=1,
            timestamp=start + timedelta(seconds=index),
            hostname="SYNTHETIC-ENDPOINT",
            endpoint_id="SYNTHETIC-ENDPOINT",
            user_name=None,
            process_guid=f"{{{index:032x}}}",
            process_id=str(index),
            parent_process_guid=None,
            parent_process_id=None,
            image="benign.exe",
            command_line=None,
            hashes={},
            destination_ip=None,
            destination_hostname=None,
            destination_port=None,
            protocol=None,
            target_filename=None,
            registry_key=None,
            registry_value_name=None,
            registry_value_data=None,
            raw_evidence="synthetic-benign-event",
            provenance={"source": "synthetic"},
            fingerprint=f"{index:064x}",
        )
        for index in range(100_000)
    ]
    try:
        with Session(engine) as db:
            stored, duplicates = persist_events(db, events)
            assert len(stored) == 100_000
            assert duplicates == 0
            stored_again, duplicate_count = persist_events(db, events)
            assert len(stored_again) == 100_000
            assert duplicate_count == 100_000
    finally:
        engine.dispose()
