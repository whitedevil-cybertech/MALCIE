from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.models import Artifact
from app.services.graph_client import GraphClient
from app.services.pe_static_analysis import analyze_artifact
from app.services.sysmon_ingestion import normalize_event


def test_sysmon_rejects_invalid_timestamp() -> None:
    with pytest.raises(ValueError, match="timestamp"):
        normalize_event(
            {
                "EventID": 1,
                "UtcTime": "not-a-timestamp",
                "Computer": "host-a",
                "EventData": {},
            }
        )


def test_sysmon_rejects_entity_declarations(client) -> None:
    incident = client.post("/api/v1/incidents", json={"title": "XML security"}).json()["id"]
    xml = """<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <Event><System><EventID>1</EventID><TimeCreated SystemTime="2026-11-09T08:00:00Z"/>
    <Computer>host-a</Computer></System><EventData><Data Name="Image">&xxe;</Data>
    </EventData></Event>"""
    response = client.post(
        f"/api/v1/telemetry/upload?incident_id={incident}",
        content=xml,
        headers={"content-type": "application/xml"},
    )
    assert response.status_code == 400
    assert "entities" in response.json()["detail"]


def test_sysmon_rejects_oversized_payload(client, monkeypatch) -> None:
    incident = client.post("/api/v1/incidents", json={"title": "size"}).json()["id"]
    monkeypatch.setattr(settings, "max_telemetry_size_bytes", 10)
    response = client.post(
        f"/api/v1/telemetry/upload?incident_id={incident}",
        content=json.dumps({"EventID": 1}),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert "size limit" in response.json()["detail"]


def test_production_api_requires_configured_key(client, monkeypatch) -> None:
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "api_key", "test-api-key")
    unauthenticated = client.get("/api/v1/health")
    authenticated = client.get("/api/v1/health", headers={"X-API-Key": "test-api-key"})
    assert unauthenticated.status_code == 401
    assert authenticated.status_code == 200


def test_production_graph_webhook_handshake_remains_reachable(client, monkeypatch) -> None:
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "api_key", "test-api-key")
    response = client.post(
        "/api/v1/emails/graph/webhook?validationToken=challenge",
    )
    assert response.status_code == 200
    assert response.text == "challenge"


def test_graph_oauth_state_is_signed_and_redirect_bound(monkeypatch) -> None:
    monkeypatch.setattr(settings, "graph_client_secret", "state-signing-secret")
    monkeypatch.setattr(settings, "graph_redirect_uris", "https://app.example/callback")
    graph = GraphClient()
    _, state = graph.build_auth_url("https://app.example/callback")
    with pytest.raises(HTTPException, match="Invalid OAuth state"):
        graph._verify_state(f"{state}tampered")
    with pytest.raises(HTTPException, match="Unapproved OAuth redirect URI"):
        graph.build_auth_url("https://attacker.example/callback")


def test_production_graph_webhook_requires_client_state(client, monkeypatch) -> None:
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "api_key", "test-api-key")
    monkeypatch.setattr(settings, "graph_webhook_client_state", "")
    response = client.post(
        "/api/v1/emails/graph/webhook",
        json={"value": []},
    )
    assert response.status_code == 503


def test_graph_webhook_rejects_malformed_notifications(client, monkeypatch) -> None:
    monkeypatch.setattr(settings, "graph_webhook_client_state", "test-webhook-secret")
    response = client.post(
        "/api/v1/emails/graph/webhook",
        json={
            "value": [
                {
                    "clientState": "test-webhook-secret",
                    "changeType": "created",
                    "resourceData": {"id": "message-1"},
                }
            ]
        },
    )
    assert response.status_code == 202
    assert response.json()["processed_notifications"] == 0


def test_artifact_analysis_rejects_modified_evidence(tmp_path: Path, monkeypatch) -> None:
    content = b"original evidence"
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"modified evidence")
    monkeypatch.setattr(settings, "artifact_storage_path", str(tmp_path))
    artifact = Artifact(
        id=1,
        incident_id=1,
        email_id=1,
        filename="artifact.bin",
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        storage_path=str(path),
    )
    result = analyze_artifact(artifact)
    assert result.status == "failed"
    assert "hash does not match" in (result.error_message or "")


def test_concurrent_duplicate_telemetry_is_stored_once(client) -> None:
    incident = client.post("/api/v1/incidents", json={"title": "concurrency"}).json()["id"]
    event = {
        "EventID": 1,
        "UtcTime": "2026-11-09T08:00:00Z",
        "Computer": "host-a",
        "EventData": {"Image": r"C:\payload.exe", "ProcessId": "7"},
    }

    def submit() -> int:
        response = client.post(
            f"/api/v1/telemetry/upload?incident_id={incident}",
            json=event,
        )
        return response.status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(lambda _: submit(), range(2)))

    assert statuses == [200, 200]
    telemetry = client.get(f"/api/v1/incidents/{incident}/telemetry")
    assert telemetry.status_code == 200
    assert len(telemetry.json()) == 1
