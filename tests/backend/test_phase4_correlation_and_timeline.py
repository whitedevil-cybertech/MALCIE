from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient

from app.api.threat_intel import get_virustotal_client
from app.services.virustotal_client import VirusTotalClient, VTLookupResult

# Sample EML with phishing body and an embedded DOS/PE executable stub
SAMPLE_PHISHING_EMAIL = b"""From: badactor@phishing-c2.net
To: target-analyst@corp.local
Subject: Critical Payment Request
Date: Wed, 09 Sep 2026 09:15:00 +0000
Message-ID: <msg-phish-404@phishing-c2.net>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=BOUNDARY_CORR

--BOUNDARY_CORR
Content-Type: text/plain; charset=utf-8

Please check the transaction log at http://phishing-c2.net/login.

--BOUNDARY_CORR
Content-Type: application/octet-stream; name=payload.exe
Content-Disposition: attachment; filename=payload.exe
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAA=

--BOUNDARY_CORR--
"""


class MockVTService(VirusTotalClient):
    def __init__(self) -> None:
        super().__init__(api_key="mock-key")

    def lookup_ioc(self, ioc_type: str, value: str) -> VTLookupResult:
        norm_type = ioc_type.lower()
        if norm_type in {"sha256", "md5", "sha1"}:
            return VTLookupResult(
                ioc_type=norm_type,
                ioc_value=value,
                normalized_value=value.lower(),
                query_status="SUCCESS",
                reputation_score=-75,
                malicious_votes=42,
                suspicious_votes=3,
                harmless_votes=0,
                undetected_votes=20,
                total_engines=65,
                detection_details={
                    "EngineX": {"category": "malicious", "result": "Trojan.Dropper"}
                },
            )
        elif norm_type in {"url", "domain"}:
            return VTLookupResult(
                ioc_type=norm_type,
                ioc_value=value,
                normalized_value=value.lower(),
                query_status="SUCCESS",
                reputation_score=-40,
                malicious_votes=15,
                suspicious_votes=1,
                harmless_votes=1,
                undetected_votes=50,
                total_engines=67,
                detection_details={"EngineY": {"category": "malicious", "result": "Malicious.URL"}},
            )
        return VTLookupResult(
            ioc_type=norm_type,
            ioc_value=value,
            normalized_value=value,
            query_status="NOT_FOUND",
        )


def _create_incident(client: TestClient, title: str = "Correlation Investigation") -> int:
    resp = client.post(
        "/api/v1/incidents",
        json={"title": title, "description": "Testing Phase 4 Correlation & Linkage"},
    )
    assert resp.status_code == 200
    return resp.json()["id"]


def test_empty_incident_correlation(client: TestClient) -> None:
    incident_id = _create_incident(client, title="Empty Incident")

    # Run correlation on incident with no evidence
    corr_resp = client.post(f"/api/v1/incidents/{incident_id}/correlate")
    assert corr_resp.status_code == 200
    data = corr_resp.json()

    assert data["incident_id"] == incident_id
    assert data["confidence"]["score"] == 0.0
    assert data["confidence"]["level"] == "LOW"
    assert data["risk"]["score"] == 0
    assert data["risk"]["level"] == "NONE"
    assert len(data["linkages"]) == 0

    # Timeline on empty incident contains only the CORRELATION_ASSESSED event
    tl_resp = client.get(f"/api/v1/incidents/{incident_id}/timeline")
    assert tl_resp.status_code == 200
    events = tl_resp.json()
    assert len(events) == 1
    assert events[0]["event_type"] == "CORRELATION_ASSESSED"


def test_separation_of_confidence_and_malware_risk(client: TestClient) -> None:
    """Verifies that high correlation completeness does not artificially inflate malware risk.

    A clean file or non-malicious evidence should yield HIGH confidence but LOW/NONE risk.
    """
    incident_id = _create_incident(client, title="Clean Evidence Incident")

    # Create benign text attachment in an EML
    clean_eml = b"""From: hr@legit.corp
To: employee@legit.corp
Subject: Policy Update
Date: Thu, 10 Sep 2026 08:00:00 +0000
Message-ID: <msg-clean-1@legit.corp>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=CLEAN_BOUND

--CLEAN_BOUND
Content-Type: text/plain; charset=utf-8

Please read the attached employee handbook.

--CLEAN_BOUND
Content-Type: text/plain; name=handbook.txt
Content-Disposition: attachment; filename=handbook.txt

Company policy content here.
--CLEAN_BOUND--
"""
    upload_resp = client.post(
        "/api/v1/emails/upload-eml",
        files={"eml_file": ("clean.eml", clean_eml, "message/rfc822")},
        data={"incident_id": str(incident_id)},
    )
    assert upload_resp.status_code == 201

    corr_resp = client.post(f"/api/v1/incidents/{incident_id}/correlate")
    assert corr_resp.status_code == 200
    data = corr_resp.json()

    # Evidence exists (email + attachment + hash), so confidence is established
    assert data["confidence"]["score"] >= 35.0
    # But no malware characteristics exist, so risk remains 0 (NONE)
    assert data["risk"]["score"] == 0
    assert data["risk"]["level"] == "NONE"
    assert "No suspicious indicators" in data["risk"]["reasons"][0]


def test_full_pipeline_evidence_correlation_linkages(client: TestClient) -> None:
    app = client.app
    app.dependency_overrides[get_virustotal_client] = MockVTService

    incident_id = _create_incident(client, title="Full Phishing Investigation")

    # 1. Ingest phishing email with payload attachment
    upload_resp = client.post(
        "/api/v1/emails/upload-eml",
        files={"eml_file": ("phishing.eml", SAMPLE_PHISHING_EMAIL, "message/rfc822")},
        data={"incident_id": str(incident_id)},
    )
    assert upload_resp.status_code == 201
    email_data = upload_resp.json()
    artifact_id = email_data["artifacts"][0]["id"]

    # 2. Run static PE analysis
    analysis_resp = client.post(f"/api/v1/artifacts/{artifact_id}/analyze-static")
    assert analysis_resp.status_code == 200

    # 3. Enrich IOCs via Threat Intelligence
    enrich_resp = client.post(f"/api/v1/incidents/{incident_id}/enrich")
    assert enrich_resp.status_code == 200

    # 4. Execute Correlation Engine
    corr_resp = client.post(f"/api/v1/incidents/{incident_id}/correlate")
    assert corr_resp.status_code == 200
    corr = corr_resp.json()

    # Verify Confidence Assessment
    assert corr["confidence"]["score"] >= 70.0
    assert corr["confidence"]["level"] == "HIGH"
    assert len(corr["confidence"]["reasons"]) >= 4

    # Verify Risk Assessment
    assert corr["risk"]["score"] >= 50
    assert corr["risk"]["level"] in {"HIGH", "CRITICAL"}
    assert any("VirusTotal flagged" in r for r in corr["risk"]["reasons"])
    assert any("Phishing indicator" in r for r in corr["risk"]["reasons"])

    # Verify Linkages
    linkages = corr["linkages"]
    relations = {lnk["relation"] for lnk in linkages}
    assert "CONTAINS_ATTACHMENT" in relations
    assert "COMPUTED_HASH" in relations
    assert "STATIC_ANALYSIS" in relations
    assert "EXTRACTED_IOC" in relations
    assert "THREAT_INTEL_VERDICT" in relations
    assert "CORROBORATED_MALICIOUS_HASH" in relations

    # 5. Verify Timeline Generation
    tl_resp = client.get(f"/api/v1/incidents/{incident_id}/timeline")
    assert tl_resp.status_code == 200
    timeline = tl_resp.json()
    assert len(timeline) >= 5

    event_types = [ev["event_type"] for ev in timeline]
    assert "EMAIL_RECEIVED" in event_types
    assert "ATTACHMENT_EXTRACTED" in event_types
    assert "STATIC_ANALYSIS_COMPLETED" in event_types
    assert "IOC_EXTRACTED" in event_types
    assert "THREAT_INTEL_QUERIED" in event_types
    assert "CORRELATION_ASSESSED" in event_types

    # Verify Strict Chronological Ordering
    for i in range(len(timeline) - 1):
        t1 = datetime.fromisoformat(timeline[i]["timestamp"])
        t2 = datetime.fromisoformat(timeline[i + 1]["timestamp"])
        assert t1 <= t2, (
            f"Timeline event {timeline[i]['event_type']} ({t1}) not before "
            f"{timeline[i + 1]['event_type']} ({t2})"
        )


def test_correlation_idempotence_and_retrieval(client: TestClient) -> None:
    incident_id = _create_incident(client, title="Idempotence Test")

    # Ingest email
    client.post(
        "/api/v1/emails/upload-eml",
        files={"eml_file": ("phish.eml", SAMPLE_PHISHING_EMAIL, "message/rfc822")},
        data={"incident_id": str(incident_id)},
    )

    # First correlation
    run1 = client.post(f"/api/v1/incidents/{incident_id}/correlate")
    assert run1.status_code == 200
    data1 = run1.json()

    # Second correlation (updates existing record without duplication)
    run2 = client.post(f"/api/v1/incidents/{incident_id}/correlate")
    assert run2.status_code == 200
    data2 = run2.json()

    assert data1["confidence"]["score"] == data2["confidence"]["score"]
    assert data1["risk"]["score"] == data2["risk"]["score"]
    assert len(data1["linkages"]) == len(data2["linkages"])

    # GET /correlations returns matching result
    get_corr = client.get(f"/api/v1/incidents/{incident_id}/correlations")
    assert get_corr.status_code == 200
    get_data = get_corr.json()
    assert get_data["confidence"]["score"] == data1["confidence"]["score"]
    assert get_data["risk"]["score"] == data1["risk"]["score"]


def test_correlate_and_timeline_404_on_missing_incident(client: TestClient) -> None:
    resp1 = client.post("/api/v1/incidents/99999/correlate")
    assert resp1.status_code == 404
    assert resp1.json()["detail"] == "Incident not found"

    resp2 = client.get("/api/v1/incidents/99999/timeline")
    assert resp2.status_code == 404
    assert resp2.json()["detail"] == "Incident not found"

    resp3 = client.get("/api/v1/incidents/99999/correlations")
    assert resp3.status_code == 404
    assert resp3.json()["detail"] == "Incident not found"
