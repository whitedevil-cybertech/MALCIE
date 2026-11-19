from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.services.sysmon_ingestion import normalize_event


def _incident(client: TestClient) -> int:
    response = client.post("/api/v1/incidents", json={"title": "Sysmon test"})
    assert response.status_code == 200
    return response.json()["id"]


def _event(event_id: int = 1) -> dict[str, object]:
    return {
        "EventID": event_id,
        "UtcTime": "2026-11-09T07:00:00Z",
        "Computer": "WIN-TEST-01",
        "EventData": {
            "User": "CORP\\analyst",
            "Image": r"C:\Users\analyst\payload.exe",
            "CommandLine": r"C:\Users\analyst\payload.exe -silent",
            "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
            "ProcessId": "4120",
            "Hashes": "SHA256=" + "a" * 64,
        },
    }


def test_future_sysmon_timestamp_preserves_source_and_marks_clock_skew() -> None:
    event = _event()
    event["UtcTime"] = "2038-09-15T14:30:00Z"
    normalized = normalize_event(event)
    assert normalized.provenance["source_timestamp"] == "2038-09-15T14:30:00Z"
    assert normalized.provenance["timestamp_normalization"] == "sysmon_iso8601_to_utc"
    assert normalized.provenance["timestamp_uncertain"] is True
    assert normalized.provenance["clock_skew_flag"]


def test_json_sysmon_ingestion_is_normalized_and_idempotent(client: TestClient) -> None:
    incident_id = _incident(client)
    payload = json.dumps(
        [
            _event(),
            _event(3)
            | {
                "EventData": {
                    "DestinationIp": "203.0.113.10",
                    "DestinationPort": "443",
                    "Protocol": "tcp",
                }
            },
        ]
    )

    first = client.post(
        f"/api/v1/telemetry/upload?incident_id={incident_id}",
        content=payload,
        headers={"content-type": "application/json"},
    )
    assert first.status_code == 200
    assert first.json()["ingested_count"] == 2
    assert first.json()["events"][0]["timestamp"].startswith("2026-11-09T07:00:00")
    assert first.json()["events"][0]["hostname"] == "WIN-TEST-01"
    assert first.json()["events"][0]["hashes"]["sha256"] == "a" * 64

    second = client.post(
        f"/api/v1/telemetry/upload?incident_id={incident_id}",
        content=payload,
        headers={"content-type": "application/json"},
    )
    assert second.status_code == 200
    assert second.json()["duplicate_count"] == 2
    listed = client.get(f"/api/v1/incidents/{incident_id}/telemetry")
    assert listed.status_code == 200
    assert len(listed.json()) == 2


def test_xml_sysmon_event_preserves_raw_evidence_and_optional_hashes(
    client: TestClient,
) -> None:
    incident_id = _incident(client)
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>11</EventID><TimeCreated SystemTime="2026-11-09T07:01:00Z"/>
      <Computer>WIN-XML-01</Computer></System>
      <EventData><Data Name="TargetFilename">C:\\Temp\\created.txt</Data></EventData>
    </Event>"""
    response = client.post(
        f"/api/v1/telemetry/upload?incident_id={incident_id}",
        content=xml,
        headers={"content-type": "application/xml"},
    )
    assert response.status_code == 200
    event = response.json()["events"][0]
    assert event["event_id"] == 11
    assert event["hashes"] == {}
    assert "TargetFilename" in event["raw_evidence"]
    assert event["endpoint_id"] == "WIN-XML-01"


def test_endpoint_events_are_added_to_timeline_and_404_is_explicit(
    client: TestClient,
) -> None:
    incident_id = _incident(client)
    response = client.post(
        f"/api/v1/telemetry/upload?incident_id={incident_id}",
        json=_event(),
    )
    assert response.status_code == 200
    correlation = client.post(f"/api/v1/incidents/{incident_id}/correlate")
    assert correlation.status_code == 200
    timeline = client.get(f"/api/v1/incidents/{incident_id}/timeline").json()
    assert any(item["event_type"] == "PROCESS_CREATED" for item in timeline)
    assert client.get("/api/v1/incidents/999999/telemetry").status_code == 404
