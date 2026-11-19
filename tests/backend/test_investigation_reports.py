from __future__ import annotations

from fastapi.testclient import TestClient


def test_reports_are_persisted_versioned_and_export_json_and_pdf(client: TestClient) -> None:
    incident = client.post("/api/v1/incidents", json={"title": "Report fixture"})
    assert incident.status_code == 200
    incident_id = incident.json()["id"]

    first = client.post(
        f"/api/v1/incidents/{incident_id}/reports",
        json={"title": "First report", "summary": "Analyst reviewed evidence."},
    )
    assert first.status_code == 201
    first_body = first.json()
    assert first_body["version"] == 1

    detail = client.get(
        f"/api/v1/incidents/{incident_id}/reports/{first_body['report_id']}"
    )
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["evidence_hash"]
    assert detail_body["report_data"]["report_id"] == detail_body["report_id"]
    assert detail_body["evidence_snapshot"]["observed_evidence"]
    assert detail_body["evidence_snapshot"]["correlation"]["risk"]
    assert detail_body["evidence_snapshot"]["analyst_conclusions"]["summary"] == (
        "Analyst reviewed evidence."
    )

    second = client.post(
        f"/api/v1/incidents/{incident_id}/reports",
        json={"disposition": "confirmed"},
    )
    assert second.status_code == 201
    assert second.json()["version"] == 2
    assert second.json()["report_id"] != first_body["report_id"]

    listing = client.get(f"/api/v1/incidents/{incident_id}/reports")
    assert [item["version"] for item in listing.json()] == [2, 1]

    pdf = client.get(
        f"/api/v1/incidents/{incident_id}/reports/{first_body['report_id']}/pdf"
    )
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-1.4")
    assert pdf.content.endswith(b"%%EOF")


def test_reports_are_scoped_to_the_requested_incident(client: TestClient) -> None:
    one = client.post("/api/v1/incidents", json={"title": "One"}).json()["id"]
    two = client.post("/api/v1/incidents", json={"title": "Two"}).json()["id"]
    report = client.post(f"/api/v1/incidents/{one}/reports", json={}).json()
    assert client.get(f"/api/v1/incidents/{two}/reports/{report['report_id']}").status_code == 404

