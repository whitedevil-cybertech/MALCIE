from __future__ import annotations

from dataclasses import dataclass

from fastapi.testclient import TestClient

from app.services.graph_client import GraphMessagePayload

SAMPLE_EML = b"""From: attacker@example.com
To: analyst@example.com
Cc: second@example.org
Subject: Invoice Review
Date: Tue, 1 Sep 2026 10:00:00 +0000
Message-ID: <sample-message@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=BOUNDARY

--BOUNDARY
Content-Type: text/plain; charset=utf-8

Please review https://evil.example/path and backup.example.net immediately.

--BOUNDARY
Content-Type: text/plain; name=payload.txt
Content-Disposition: attachment; filename=payload.txt
Content-Transfer-Encoding: base64

c2FtcGxlLWF0dGFjaG1lbnQ=

--BOUNDARY--
"""


@dataclass
class FakeGraphClient:
    content: bytes

    def build_auth_url(self, redirect_uri: str) -> tuple[str, str]:
        return f"https://auth.local?redirect_uri={redirect_uri}", "state-token"

    def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, str | int]:
        return {
            "access_token": "token123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh123",
        }

    def get_message_eml(self, access_token: str, message_id: str) -> GraphMessagePayload:
        assert access_token == "graph-token"
        return GraphMessagePayload(message_id=message_id, eml_content=self.content)


def _create_incident(client: TestClient) -> int:
    response = client.post(
        "/api/v1/incidents",
        json={"title": "Suspicious Email", "description": "Testing Phase 2A"},
    )
    assert response.status_code == 200
    return response.json()["id"]


def test_eml_upload_parses_and_persists_evidence(client: TestClient) -> None:
    incident_id = _create_incident(client)

    response = client.post(
        "/api/v1/emails/upload-eml",
        files={"eml_file": ("sample.eml", SAMPLE_EML, "message/rfc822")},
        data={"incident_id": str(incident_id)},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["incident_id"] == incident_id
    assert body["source"] == "manual_eml"
    assert body["sender"] == "attacker@example.com"
    assert "analyst@example.com" in body["recipients"]
    assert body["subject"] == "Invoice Review"
    assert "https://evil.example/path" in body["urls"]
    assert "evil.example" in body["domains"]
    assert body["artifacts"]
    artifact = body["artifacts"][0]
    assert artifact["filename"] == "payload.txt"
    assert artifact["size"] > 0
    assert len(artifact["sha256"]) == 64


def test_eml_upload_rejects_non_eml_file(client: TestClient) -> None:
    incident_id = _create_incident(client)

    response = client.post(
        "/api/v1/emails/upload-eml",
        files={"eml_file": ("sample.txt", b"not eml", "text/plain")},
        data={"incident_id": str(incident_id)},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Only .eml files are accepted"


def test_graph_endpoints_and_ingest_workflow(client: TestClient) -> None:
    from app.api.emails import get_graph_client

    app = client.app
    app.dependency_overrides[get_graph_client] = lambda: FakeGraphClient(content=SAMPLE_EML)

    incident_id = _create_incident(client)

    auth_response = client.get(
        "/api/v1/emails/graph/auth-url",
        params={"redirect_uri": "https://localhost/callback"},
    )
    assert auth_response.status_code == 200
    assert auth_response.json()["state"] == "state-token"

    token_response = client.post(
        "/api/v1/emails/graph/oauth/token",
        json={"code": "abc", "redirect_uri": "https://localhost/callback"},
    )
    assert token_response.status_code == 200
    assert token_response.json()["access_token"] == "token123"

    ingest_response = client.post(
        "/api/v1/emails/graph/messages/msg-001/ingest",
        json={"incident_id": incident_id, "access_token": "graph-token"},
    )

    assert ingest_response.status_code == 201
    ingest_body = ingest_response.json()
    assert ingest_body["source"] == "microsoft_graph"
    assert ingest_body["graph_message_id"] == "msg-001"
    assert ingest_body["artifacts"]

    email_id = ingest_body["id"]
    lookup = client.get(f"/api/v1/emails/{email_id}")
    assert lookup.status_code == 200
    assert lookup.json()["incident_id"] == incident_id
