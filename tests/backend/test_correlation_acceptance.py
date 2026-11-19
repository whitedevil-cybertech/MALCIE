from __future__ import annotations

from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    Artifact,
    ArtifactAnalysis,
    EndpointEvent,
    Incident,
    ThreatIntelResult,
)
from app.services.correlation_engine import (
    CORRELATION_ALGORITHM_VERSION,
    SCORING_ALGORITHM_VERSION,
    build_evidence_linkages,
    compute_correlation_confidence,
    compute_incident_risk,
    normalize_email_timestamp,
    normalize_pe_timestamp,
    run_incident_correlation,
)


def _setup_incident_with_hash(
    client: TestClient, title: str = "Acceptance Test Incident"
) -> int:
    resp = client.post(
        "/api/v1/incidents",
        json={"title": title, "description": "Testing correlation acceptance criteria"},
    )
    assert resp.status_code == 200
    return resp.json()["id"]


def test_duplicate_evidence_resistance(client: TestClient) -> None:
    """Duplicate evidence must NOT artificially increase confidence or risk scores."""
    from app.db import get_db

    incident_id = _setup_incident_with_hash(client, "Deduplication Test Incident")

    # Ingest a mock incident into DB with 1 artifact and 1 endpoint event
    # Then ingest 5 duplicate endpoint events with the same hash
    with client:
        # Access session
        db_override = client.app.dependency_overrides[get_db]()
        db: Session = next(db_override)
        try:
            incident = db.get(Incident, incident_id)
            assert incident is not None

            # Add an artifact
            art = Artifact(
                incident_id=incident_id,
                email_id=1,
                filename="mimikatz_stub.exe",
                size=4096,
                sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                storage_path="artifacts/mimikatz_stub.exe",
            )
            art.analysis = ArtifactAnalysis(
                artifact_id=1,
                incident_id=incident_id,
                status="completed",
                is_pe=True,
                file_type="pe32",
                pe_headers={"machine": "x86"},
                sections=[],
                imports=[],
                extracted_strings=[],
                yara_matches=[{"rule": "Credential_Dumping_Signatures", "tags": ["credential"]}],
            )
            incident.artifacts.append(art)

            # Add 1 endpoint event matching the artifact hash
            event1 = EndpointEvent(
                incident_id=incident_id,
                event_id=1,
                timestamp=datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc),
                hostname="WORKSTATION-01",
                endpoint_id="agent-01",
                image="C:\\mimikatz_stub.exe",
                hashes={"sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"},
                raw_evidence="raw-1",
                provenance={"source": "sysmon"},
                fingerprint="fp-event-1",
            )
            incident.endpoint_events.append(event1)

            # Add 1 threat intel result
            ti1 = ThreatIntelResult(
                incident_id=incident_id,
                ioc_type="sha256",
                ioc_value=art.sha256,
                normalized_value=art.sha256,
                query_status="SUCCESS",
                malicious_votes=10,
                provider="VirusTotal",
            )
            incident.threat_intel_results.append(ti1)

            db.commit()

            # Baseline score with 1 event and 1 TI
            risk_single = compute_incident_risk(incident)
            conf_single = compute_correlation_confidence(incident, build_evidence_linkages(incident))

            # Add 4 duplicate endpoint events for the exact same hash/host/image execution
            for i in range(2, 6):
                dup_event = EndpointEvent(
                    incident_id=incident_id,
                    event_id=1,
                    timestamp=datetime(2026, 9, 10, 10, 0, i, tzinfo=timezone.utc),
                    hostname="WORKSTATION-01",
                    endpoint_id="agent-01",
                    image="C:\\mimikatz_stub.exe",
                    hashes={"sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"},
                    raw_evidence=f"raw-{i}",
                    provenance={"source": "sysmon"},
                    fingerprint=f"fp-event-{i}",
                )
                incident.endpoint_events.append(dup_event)

            # Add 2 duplicate TI queries for the same hash
            ti_dup = ThreatIntelResult(
                incident_id=incident_id,
                ioc_type="sha256",
                ioc_value=art.sha256,
                normalized_value=art.sha256,
                query_status="SUCCESS",
                malicious_votes=10,
                provider="VirusTotal",
            )
            incident.threat_intel_results.append(ti_dup)

            db.commit()

            # Recalculate score with duplicate events
            risk_dup = compute_incident_risk(incident)
            conf_dup = compute_correlation_confidence(incident, build_evidence_linkages(incident))

            # Risk and confidence scores MUST be identical despite repeated duplicate events
            assert risk_single.score == risk_dup.score, (
                f"Duplicate evidence inflated risk score from {risk_single.score} to {risk_dup.score}"
            )
            assert conf_single.score == conf_dup.score, (
                f"Duplicate evidence inflated confidence score from {conf_single.score} to {conf_dup.score}"
            )
        finally:
            db.close()


def test_missing_unavailable_failed_stale_representation(client: TestClient) -> None:
    """Missing, unavailable, failed, and stale evidence must be explicitly represented."""
    from app.db import get_db

    incident_id = _setup_incident_with_hash(client, "Missing Evidence Incident")
    db_override = client.app.dependency_overrides[get_db]()
    db: Session = next(db_override)
    try:
        incident = db.get(Incident, incident_id)
        assert incident is not None

        # Add artifact with failed analysis
        art = Artifact(
            incident_id=incident_id,
            email_id=1,
            filename="corrupt_payload.bin",
            size=100,
            sha256="1122334455667788990011223344556677889900112233445566778899001122",
            storage_path="artifacts/corrupt_payload.bin",
        )
        art.analysis = ArtifactAnalysis(
            artifact_id=1,
            incident_id=incident_id,
            status="failed",
            error_message="PE Format Error: truncated header",
            is_pe=False,
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=[],
        )
        incident.artifacts.append(art)

        linkages = build_evidence_linkages(incident)
        confidence = compute_correlation_confidence(incident, linkages)

        # Verify explicit representation
        assert "Email evidence absent" in confidence.missing_evidence
        assert "Endpoint Sysmon telemetry not available for this incident" in confidence.missing_evidence
        assert "Threat intelligence not queried" in confidence.missing_evidence
        assert any("Static PE analysis failed" in f for f in confidence.failed_evidence)
    finally:
        db.close()


def test_every_relationship_references_source_evidence(client: TestClient) -> None:
    """Every relationship must reference identifiable source evidence."""
    from app.db import get_db

    incident_id = _setup_incident_with_hash(client, "Relationship Provenance Incident")
    db_override = client.app.dependency_overrides[get_db]()
    db: Session = next(db_override)
    try:
        incident = db.get(Incident, incident_id)
        assert incident is not None

        art = Artifact(
            incident_id=incident_id,
            email_id=1,
            filename="test.exe",
            size=2048,
            sha256="cafebabe00112233445566778899aabbccddeeff00112233445566778899aabb",
            storage_path="artifacts/test.exe",
        )
        art.analysis = ArtifactAnalysis(
            artifact_id=1,
            incident_id=incident_id,
            status="completed",
            is_pe=True,
            file_type="pe32",
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=[],
            yara_matches=[{"rule": "Suspicious_Downloader_Artifact", "tags": ["downloader"]}],
        )
        incident.artifacts.append(art)
        db.commit()

        linkages = build_evidence_linkages(incident)
        assert len(linkages) > 0
        for lnk in linkages:
            assert lnk.evidence_ref is not None, f"Linkage {lnk.relation} has empty evidence_ref"
            assert len(lnk.evidence_ref) > 0
            assert lnk.source_id is not None
            assert lnk.target_id is not None
            assert lnk.source_type is not None
            assert lnk.target_type is not None
    finally:
        db.close()


def test_process_lineage_links_parent_child_with_endpoint_provenance() -> None:
    parent = EndpointEvent(
        id=11, incident_id=993, event_id=1,
        timestamp=datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc),
        hostname="HOST-A", endpoint_id="agent-a", process_guid="{parent}",
        process_id="100", image="services.exe", hashes={}, raw_evidence="synthetic-parent",
        provenance={"source": "synthetic"}, fingerprint="d" * 64,
    )
    child = EndpointEvent(
        id=12, incident_id=993, event_id=1,
        timestamp=datetime(2026, 11, 20, 10, 1, tzinfo=timezone.utc),
        hostname="HOST-A", endpoint_id="agent-a", process_guid="{child}",
        process_id="200", parent_process_guid="{parent}", parent_process_id="100",
        image="benign.exe", hashes={}, raw_evidence="synthetic-child",
        provenance={"source": "synthetic"}, fingerprint="e" * 64,
    )
    incident = Incident(
        id=993, title="Process lineage", emails=[], artifacts=[], iocs=[],
        endpoint_events=[parent, child], threat_intel_results=[],
    )
    lineage = [
        item for item in build_evidence_linkages(incident)
        if item.relation == "PROCESS_PARENT_CHILD"
    ]
    assert len(lineage) == 1
    assert lineage[0].source_id == 11
    assert lineage[0].target_id == 12
    assert lineage[0].metadata["endpoint_id"] == "agent-a"


def test_timestamp_provenance_and_clock_skew_handling() -> None:
    """Preserve original timestamps, sources, timezones, and detect clock skew."""
    now = datetime.now(timezone.utc)

    # 1. Normal email timestamp with timezone preservation
    normal_email_date = "Tue, 15 Sep 2026 14:30:00 +0530"
    prov1 = normalize_email_timestamp(normal_email_date, now)
    assert prov1.original_timestamp == normal_email_date
    assert prov1.source == "email_header_date"
    assert prov1.normalization_method == "rfc2822_parsedate"
    assert prov1.is_uncertain is False
    assert prov1.clock_skew_flag is None

    # 2. Future email timestamp (Clock skew)
    future_email_date = "Tue, 15 Sep 2038 14:30:00 +0000"
    prov2 = normalize_email_timestamp(future_email_date, now)
    assert prov2.is_uncertain is True
    assert prov2.clock_skew_flag is not None
    assert "Future timestamp" in prov2.clock_skew_flag

    # 3. Missing email timestamp (Fallback preservation)
    prov3 = normalize_email_timestamp(None, now)
    assert prov3.is_uncertain is True
    assert prov3.original_timestamp is None
    assert prov3.normalization_method == "fallback"
    assert prov3.fallback_reason is not None

    # 4. Realistic PE timestamp
    valid_pe_stamp = 1600000000  # Sept 2020
    pe_prov1 = normalize_pe_timestamp(valid_pe_stamp, now)
    assert pe_prov1.is_uncertain is False
    assert pe_prov1.original_timestamp == valid_pe_stamp
    assert pe_prov1.normalization_method == "posix_epoch_to_utc"

    # 5. Stomped / Bogus PE timestamp (Year 1970 or 2099)
    bogus_pe_stamp = 0
    pe_prov2 = normalize_pe_timestamp(bogus_pe_stamp, now)
    assert pe_prov2.is_uncertain is True
    assert pe_prov2.normalization_method == "fallback_due_to_anachronistic_pe_header"
    assert pe_prov2.clock_skew_flag is not None


def test_unavailable_stale_and_conflicting_intelligence_is_explicit() -> None:
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=991,
        title="Evidence state test",
        emails=[],
        artifacts=[],
        iocs=[],
        endpoint_events=[],
        threat_intel_results=[
            ThreatIntelResult(
                incident_id=991, ioc_type="domain", ioc_value="example.test",
                normalized_value="example.test",
                query_status="SUCCESS", malicious_votes=5, provider="source-a",
                queried_at=now - timedelta(days=60),
            ),
            ThreatIntelResult(
                incident_id=991, ioc_type="domain", ioc_value="example.test",
                normalized_value="example.test",
                query_status="SUCCESS", malicious_votes=0, provider="source-b", queried_at=now,
            ),
            ThreatIntelResult(
                incident_id=991, ioc_type="sha256", ioc_value="a" * 64,
                normalized_value="a" * 64,
                query_status="UNAVAILABLE", malicious_votes=0, provider="source-c",
                queried_at=now,
            ),
        ],
    )

    confidence = compute_correlation_confidence(incident, [])
    assert any("is stale" in item for item in confidence.stale_evidence)
    assert any("conflict" in item for item in confidence.conflicting_evidence)
    assert any("UNAVAILABLE" in item for item in confidence.failed_evidence)
    incident.threat_intel_results = [incident.threat_intel_results[2]]
    unavailable_only = compute_correlation_confidence(incident, [])
    assert "Threat intelligence not queried" in unavailable_only.missing_evidence

    digest = "b" * 64
    stale_artifact = Artifact(
        id=7, incident_id=992, email_id=1, filename="benign.exe", size=1,
        sha256=digest, storage_path="synthetic-only",
    )
    stale_endpoint = EndpointEvent(
        id=8, incident_id=992, event_id=1, timestamp=now - timedelta(days=60),
        hostname="SYNTHETIC", endpoint_id="SYNTHETIC", image="benign.exe",
        hashes={"sha256": digest}, raw_evidence="synthetic", fingerprint="c" * 64,
    )
    stale_incident = Incident(
        id=992, title="Stale telemetry", emails=[], artifacts=[stale_artifact], iocs=[],
        endpoint_events=[stale_endpoint], threat_intel_results=[],
    )
    assert compute_incident_risk(stale_incident).score == 0


def test_reproducibility_and_versioning(client: TestClient) -> None:
    """Identical inputs and algorithm versions must produce reproducible results."""
    from app.db import get_db

    incident_id = _setup_incident_with_hash(client, "Reproducibility Incident")
    db_override = client.app.dependency_overrides[get_db]()
    db: Session = next(db_override)
    try:
        corr1 = run_incident_correlation(db, incident_id)
        corr2 = run_incident_correlation(db, incident_id)

        assert corr1.algorithm_version == CORRELATION_ALGORITHM_VERSION
        assert corr1.scoring_version == SCORING_ALGORITHM_VERSION
        assert corr1.confidence.score == corr2.confidence.score
        assert corr1.risk.score == corr2.risk.score
        assert [lnk.model_dump() for lnk in corr1.linkages] == [
            lnk.model_dump() for lnk in corr2.linkages
        ]
    finally:
        db.close()


def test_evidence_change_triggers_recalculation(client: TestClient) -> None:
    """Changes in evidence must trigger appropriate recalculation."""
    from app.db import get_db

    incident_id = _setup_incident_with_hash(client, "Recalculation Incident")
    db_override = client.app.dependency_overrides[get_db]()
    db: Session = next(db_override)
    try:
        incident = db.get(Incident, incident_id)
        assert incident is not None

        # 1. Initial state: Empty
        corr1 = run_incident_correlation(db, incident_id)
        initial_risk = corr1.risk.score
        initial_conf = corr1.confidence.score

        # 2. Add an artifact with high-severity YARA match
        art = Artifact(
            incident_id=incident_id,
            email_id=1,
            filename="ransomware.exe",
            size=1024,
            sha256="deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb",
            storage_path="artifacts/ransomware.exe",
        )
        art.analysis = ArtifactAnalysis(
            artifact_id=1,
            incident_id=incident_id,
            status="completed",
            is_pe=True,
            file_type="pe32",
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=[],
            yara_matches=[{"rule": "Ransomware_Behavior_Indicators", "tags": ["ransomware"]}],
        )
        incident.artifacts.append(art)
        db.commit()

        # 3. Recalculate
        corr2 = run_incident_correlation(db, incident_id)
        assert corr2.risk.score > initial_risk
        assert corr2.confidence.score > initial_conf
        assert any("Ransomware_Behavior_Indicators" in r for r in corr2.risk.reasons)
    finally:
        db.close()
