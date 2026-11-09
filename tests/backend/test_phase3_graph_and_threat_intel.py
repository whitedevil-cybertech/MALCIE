from __future__ import annotations

import base64
from typing import Any

from fastapi.testclient import TestClient
import httpx

from app.api.emails import get_graph_client
from app.api.threat_intel import get_virustotal_client
from app.core.config import settings
from app.services.graph_client import GraphClient, GraphMessagePayload
from app.services.virustotal_client import (
    VirusTotalClient,
    compute_url_id,
)

SAMPLE_EML_PHISHING = b"""From: phisher@badactor.org
To: victim@example.com
Subject: Urgent Security Notice
Date: Mon, 7 Sep 2026 12:00:00 +0000
Message-ID: <threat-msg-001@badactor.org>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=BOUNDARY123

--BOUNDARY123
Content-Type: text/plain; charset=utf-8

Please verify your credentials at http://phishing.badactor.org/login immediately.

--BOUNDARY123
Content-Type: application/octet-stream; name=invoice.exe
Content-Disposition: attachment; filename=invoice.exe
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAA=

--BOUNDARY123--
"""


def _create_test_incident(client: TestClient) -> int:
    response = client.post(
        "/api/v1/incidents",
        json={"title": "Phase 3 Threat Investigation", "description": "Graph & VT integration"},
    )
    assert response.status_code == 200
    return response.json()["id"]


# ==============================================================================
# 1. MICROSOFT GRAPH POLLING & WEBHOOK TESTS
# ==============================================================================


class FakeGraphService(GraphClient):
    def __init__(self) -> None:
        super().__init__(http_client=httpx.Client())
        self.listed_messages = [
            {
                "id": "msg-phish-101",
                "subject": "Urgent Security Notice",
                "sender": "phisher@badactor.org",
                "received_at": "2026-09-07T12:00:00Z",
                "has_attachments": True,
                "is_read": False,
            }
        ]

    def list_messages(
        self,
        access_token: str,
        folder_id: str = "inbox",
        top: int = 10,
        search: str | None = None,
        filter_query: str | None = None,
    ) -> list[dict[str, Any]]:
        assert access_token == "valid-graph-token"
        return self.listed_messages

    def get_message_eml(self, access_token: str, message_id: str) -> GraphMessagePayload:
        assert access_token == "valid-graph-token"
        assert message_id == "msg-phish-101"
        return GraphMessagePayload(message_id=message_id, eml_content=SAMPLE_EML_PHISHING)

    def create_subscription(
        self,
        access_token: str,
        notification_url: str,
        resource: str = "/me/messages",
        change_type: str = "created",
        client_state: str | None = None,
        expiration_minutes: int = 4230,
    ) -> dict[str, Any]:
        assert access_token == "valid-graph-token"
        return {
            "id": "sub-uuid-999",
            "resource": resource,
            "changeType": change_type,
            "notificationUrl": notification_url,
            "expirationDateTime": "2026-09-10T12:00:00Z",
            "clientState": client_state,
        }

    def delete_subscription(self, access_token: str, subscription_id: str) -> bool:
        assert access_token == "valid-graph-token"
        return subscription_id == "sub-uuid-999"


def test_graph_poll_and_auto_ingest(client: TestClient) -> None:
    app = client.app
    fake_graph = FakeGraphService()
    app.dependency_overrides[get_graph_client] = lambda: fake_graph

    incident_id = _create_test_incident(client)

    # 1. List messages endpoint
    list_resp = client.get(
        "/api/v1/emails/graph/messages",
        params={"access_token": "valid-graph-token", "folder_id": "inbox", "top": 5},
    )
    assert list_resp.status_code == 200
    messages = list_resp.json()
    assert len(messages) == 1
    assert messages[0]["id"] == "msg-phish-101"
    assert messages[0]["has_attachments"] is True

    # 2. Poll without auto_ingest
    poll_resp = client.post(
        "/api/v1/emails/graph/poll",
        json={"access_token": "valid-graph-token", "auto_ingest": False},
    )
    assert poll_resp.status_code == 200
    poll_data = poll_resp.json()
    assert poll_data["ingested_count"] == 0
    assert len(poll_data["messages"]) == 1

    # 3. Poll with auto_ingest missing incident_id -> 400
    bad_poll = client.post(
        "/api/v1/emails/graph/poll",
        json={"access_token": "valid-graph-token", "auto_ingest": True},
    )
    assert bad_poll.status_code == 400

    # 4. Poll with auto_ingest and incident_id -> ingests email & parses attachments
    ingest_poll = client.post(
        "/api/v1/emails/graph/poll",
        json={
            "access_token": "valid-graph-token",
            "incident_id": incident_id,
            "auto_ingest": True,
        },
    )
    assert ingest_poll.status_code == 200
    ingest_data = ingest_poll.json()
    assert ingest_data["ingested_count"] == 1
    assert len(ingest_data["ingested_emails"]) == 1

    email_obj = ingest_data["ingested_emails"][0]
    assert email_obj["source"] == "microsoft_graph_poll"
    assert email_obj["graph_message_id"] == "msg-phish-101"
    assert email_obj["sender"] == "phisher@badactor.org"
    assert "victim@example.com" in email_obj["recipients"]
    assert "http://phishing.badactor.org/login" in email_obj["urls"]
    assert "phishing.badactor.org" in email_obj["domains"]
    assert len(email_obj["artifacts"]) == 1
    assert email_obj["artifacts"][0]["filename"] == "invoice.exe"


def test_graph_webhook_validation_and_notifications(client: TestClient) -> None:
    # 1. Webhook validation handshake
    token_str = "SecretValidationTokenXYZ123"
    handshake_resp = client.post(
        f"/api/v1/emails/graph/webhook?validationToken={token_str}",
    )
    assert handshake_resp.status_code == 200
    assert handshake_resp.text == token_str
    assert "text/plain" in handshake_resp.headers["content-type"]

    # 2. Webhook notification payload with matching clientState
    original_state = settings.graph_webhook_client_state
    settings.graph_webhook_client_state = "test-webhook-secret"

    try:
        payload = {
            "value": [
                {
                    "subscriptionId": "sub-uuid-999",
                    "changeType": "created",
                    "clientState": "test-webhook-secret",
                    "resource": "Users/victim@example.com/Messages/msg-phish-101",
                    "resourceData": {"id": "msg-phish-101", "@odata.type": "#Microsoft.Graph.Message"},
                },
                {
                    "subscriptionId": "sub-uuid-999",
                    "changeType": "created",
                    "clientState": "invalid-secret",
                    "resource": "Users/victim@example.com/Messages/msg-ignored",
                    "resourceData": {"id": "msg-ignored"},
                },
            ]
        }
        resp = client.post("/api/v1/emails/graph/webhook", json=payload)
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"
        # Only 1 valid notification processed because the second had mismatched clientState
        assert data["processed_notifications"] == 1
    finally:
        settings.graph_webhook_client_state = original_state


def test_graph_subscription_lifecycle(client: TestClient) -> None:
    app = client.app
    app.dependency_overrides[get_graph_client] = FakeGraphService

    # Create subscription
    create_resp = client.post(
        "/api/v1/emails/graph/subscriptions",
        json={
            "access_token": "valid-graph-token",
            "notification_url": "https://malcie.example.com/api/v1/emails/graph/webhook",
            "resource": "/me/messages",
            "client_state": "my-client-state",
        },
    )
    assert create_resp.status_code == 200
    sub_data = create_resp.json()
    assert sub_data["subscription_id"] == "sub-uuid-999"
    assert sub_data["notification_url"] == "https://malcie.example.com/api/v1/emails/graph/webhook"

    # Delete subscription
    del_resp = client.delete(
        "/api/v1/emails/graph/subscriptions/sub-uuid-999",
        params={"access_token": "valid-graph-token"},
    )
    assert del_resp.status_code == 204


def test_graph_client_exponential_backoff_and_timeout() -> None:
    retry_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal retry_count
        retry_count += 1
        if retry_count < 3:
            return httpx.Response(429, headers={"Retry-After": "0.01"})
        return httpx.Response(200, json={"value": [{"id": "retry-success"}]})

    transport = httpx.MockTransport(mock_handler)
    mock_http_client = httpx.Client(transport=transport)
    graph_client = GraphClient(http_client=mock_http_client, max_retries=3)

    messages = graph_client.list_messages(access_token="test-token")
    assert len(messages) == 1
    assert messages[0]["id"] == "retry-success"
    assert retry_count == 3


# ==============================================================================
# 2. VIRUSTOTAL ENRICHMENT & THREAT INTEL TESTS
# ==============================================================================


def test_compute_url_id() -> None:
    url = "https://example.com/login"
    computed = compute_url_id(url)
    # Base64 urlsafe without padding '='
    expected = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert computed == expected
    assert "=" not in computed


def test_virustotal_client_hashes_urls_domains_enrichment() -> None:
    sha256_val = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    url_val = "http://phishing.badactor.org/login"
    domain_val = "phishing.badactor.org"

    def mock_vt_handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("x-apikey") == "test-api-key"
        path = request.url.path

        if f"/files/{sha256_val}" in path:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": sha256_val,
                        "type": "file",
                        "attributes": {
                            "reputation": -50,
                            "last_analysis_stats": {
                                "malicious": 45,
                                "suspicious": 3,
                                "harmless": 0,
                                "undetected": 12,
                            },
                            "last_analysis_results": {
                                "VendorA": {
                                    "category": "malicious",
                                    "result": "Trojan.Generic",
                                    "method": "blacklist",
                                }
                            },
                        },
                    }
                },
            )
        elif "/urls/" in path:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "url-id",
                        "type": "url",
                        "attributes": {
                            "reputation": -20,
                            "last_analysis_stats": {
                                "malicious": 15,
                                "suspicious": 1,
                                "harmless": 2,
                                "undetected": 50,
                            },
                            "last_analysis_results": {
                                "VendorB": {
                                    "category": "malicious",
                                    "result": "Phishing.Site",
                                    "method": "blacklist",
                                }
                            },
                        },
                    }
                },
            )
        elif f"/domains/{domain_val}" in path:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": domain_val,
                        "type": "domain",
                        "attributes": {
                            "reputation": -10,
                            "last_analysis_stats": {
                                "malicious": 8,
                                "suspicious": 0,
                                "harmless": 10,
                                "undetected": 60,
                            },
                            "last_analysis_results": {},
                        },
                    }
                },
            )
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    transport = httpx.MockTransport(mock_vt_handler)
    http_client = httpx.Client(transport=transport)
    vt_client = VirusTotalClient(api_key="test-api-key", http_client=http_client)

    # 1. Hash lookup (SHA-256)
    hash_res = vt_client.lookup_ioc("sha256", sha256_val)
    assert hash_res.query_status == "SUCCESS"
    assert hash_res.malicious_votes == 45
    assert hash_res.reputation_score == -50
    assert hash_res.total_engines == 60
    assert "VendorA" in hash_res.detection_details

    # 2. URL lookup
    url_res = vt_client.lookup_ioc("url", url_val)
    assert url_res.query_status == "SUCCESS"
    assert url_res.malicious_votes == 15
    assert url_res.suspicious_votes == 1
    assert "VendorB" in url_res.detection_details

    # 3. Domain lookup
    dom_res = vt_client.lookup_ioc("domain", domain_val)
    assert dom_res.query_status == "SUCCESS"
    assert dom_res.malicious_votes == 8

    # 4. In-memory caching: repeat lookup does not hit transport
    hash_res_cached = vt_client.lookup_ioc("sha256", sha256_val)
    assert hash_res_cached is hash_res


def test_virustotal_not_found_and_rate_limit_backoff() -> None:
    rate_limit_attempts = 0

    def mock_vt_handler(request: httpx.Request) -> httpx.Response:
        nonlocal rate_limit_attempts
        path = request.url.path
        if "unknown-hash" in path:
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        if "rate-limit-hash" in path:
            rate_limit_attempts += 1
            return httpx.Response(429, headers={"Retry-After": "0.01"})
        return httpx.Response(500, json={"error": {"message": "Server Error"}})

    transport = httpx.MockTransport(mock_vt_handler)
    http_client = httpx.Client(transport=transport)
    vt_client = VirusTotalClient(
        api_key="test-api-key",
        http_client=http_client,
        max_retries=2,
    )

    # 1. 404 Not Found returns gracefully with NOT_FOUND status
    not_found = vt_client.lookup_ioc("sha256", "unknown-hash")
    assert not_found.query_status == "NOT_FOUND"
    assert not_found.malicious_votes == 0

    # 2. 429 Rate limited with retries exhausted returns RATE_LIMITED
    rate_limited = vt_client.lookup_ioc("sha256", "rate-limit-hash")
    assert rate_limited.query_status == "RATE_LIMITED"
    assert rate_limit_attempts == 3  # Initial + 2 retries


def test_virustotal_unconfigured_api_key_handles_gracefully() -> None:
    vt_client = VirusTotalClient(api_key="")
    res = vt_client.lookup_ioc("sha256", "abcd1234abcd1234")
    assert res.query_status == "UNCONFIGURED"
    assert res.malicious_votes == 0
    assert "not configured" in res.detection_details.get("message", "")


# ==============================================================================
# 3. END-TO-END REPUTATION PERSISTENCE & API ENRICHMENT TESTS
# ==============================================================================


class FakeVirusTotalService(VirusTotalClient):
    def __init__(self) -> None:
        super().__init__(api_key="mock-key", http_client=httpx.Client())

    def lookup_ioc(self, ioc_type: str, value: str) -> Any:
        from app.services.virustotal_client import VTLookupResult

        normalized_type = ioc_type.lower()
        if normalized_type == "sha256":
            return VTLookupResult(
                ioc_type="sha256",
                ioc_value=value,
                normalized_value=value.lower(),
                query_status="SUCCESS",
                reputation_score=-80,
                malicious_votes=52,
                suspicious_votes=2,
                harmless_votes=0,
                undetected_votes=10,
                total_engines=64,
                detection_details={"VendorMalware": {"category": "malicious", "result": "Worm.Generic"}},
            )
        elif normalized_type == "url":
            return VTLookupResult(
                ioc_type="url",
                ioc_value=value,
                normalized_value=value,
                query_status="SUCCESS",
                reputation_score=-30,
                malicious_votes=18,
                suspicious_votes=1,
                harmless_votes=2,
                undetected_votes=45,
                total_engines=66,
                detection_details={"VendorPhish": {"category": "malicious", "result": "Phishing.Portal"}},
            )
        elif normalized_type == "domain":
            return VTLookupResult(
                ioc_type="domain",
                ioc_value=value,
                normalized_value=value.lower(),
                query_status="SUCCESS",
                reputation_score=-15,
                malicious_votes=12,
                suspicious_votes=0,
                harmless_votes=5,
                undetected_votes=50,
                total_engines=67,
            )
        return VTLookupResult(
            ioc_type=normalized_type,
            ioc_value=value,
            normalized_value=value,
            query_status="NOT_FOUND",
        )


def test_incident_and_artifact_enrichment_persistence_workflow(client: TestClient) -> None:
    app = client.app
    app.dependency_overrides[get_virustotal_client] = FakeVirusTotalService

    incident_id = _create_test_incident(client)

    # Ingest suspicious email to generate artifacts and IOCs
    upload_resp = client.post(
        "/api/v1/emails/upload-eml",
        files={"eml_file": ("phishing.eml", SAMPLE_EML_PHISHING, "message/rfc822")},
        data={"incident_id": str(incident_id)},
    )
    assert upload_resp.status_code == 201
    email_data = upload_resp.json()
    assert email_data["artifacts"]
    artifact_id = email_data["artifacts"][0]["id"]

    # Run static analysis to produce IOCs for the artifact
    analysis_resp = client.post(f"/api/v1/artifacts/{artifact_id}/analyze-static")
    assert analysis_resp.status_code == 200
    assert len(analysis_resp.json()["iocs"]) > 0

    # 1. Trigger incident-wide threat intelligence enrichment
    enrich_resp = client.post(
        f"/api/v1/incidents/{incident_id}/enrich",
        json={"ioc_types": ["sha256", "url", "domain"]},
    )
    assert enrich_resp.status_code == 200
    enrich_results = enrich_resp.json()
    assert len(enrich_results) >= 1

    # Check that threat intel results are persisted
    sha256_result = next((r for r in enrich_results if r["ioc_type"] == "sha256"), None)
    assert sha256_result is not None
    assert sha256_result["query_status"] == "SUCCESS"
    assert sha256_result["malicious_votes"] == 52
    assert sha256_result["reputation_score"] == -80
    assert sha256_result["incident_id"] == incident_id
    assert "VendorMalware" in sha256_result["detection_details"]

    # 2. Query incident threat intelligence endpoint
    get_intel = client.get(f"/api/v1/incidents/{incident_id}/threat-intel")
    assert get_intel.status_code == 200
    intel_records = get_intel.json()
    assert len(intel_records) == len(enrich_results)

    # 3. Artifact-specific enrichment
    art_enrich = client.post(f"/api/v1/artifacts/{artifact_id}/enrich")
    assert art_enrich.status_code == 200
    art_results = art_enrich.json()
    assert len(art_results) >= 1

    get_art_intel = client.get(f"/api/v1/artifacts/{artifact_id}/threat-intel")
    assert get_art_intel.status_code == 200
    assert len(get_art_intel.json()) == len(art_results)

    # 4. Ad-hoc threat intel lookup endpoint
    adhoc = client.post(
        "/api/v1/threat-intel/lookup",
        json={"ioc_type": "url", "value": "http://phishing.badactor.org/login"},
    )
    assert adhoc.status_code == 200
    adhoc_data = adhoc.json()
    assert adhoc_data["query_status"] == "SUCCESS"
    assert adhoc_data["malicious_votes"] == 18
    assert adhoc_data["reputation_score"] == -30
