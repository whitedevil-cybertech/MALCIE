from __future__ import annotations

import struct
from email.message import EmailMessage

from fastapi.testclient import TestClient

from app.models import Artifact
from app.services.pe_static_analysis import analyze_artifact


def _build_eml_with_attachment(filename: str, attachment: bytes) -> bytes:
    message = EmailMessage()
    message["From"] = "attacker@example.com"
    message["To"] = "analyst@example.com"
    message["Subject"] = "Attachment"
    message.set_content("Please review attached file")
    message.add_attachment(
        attachment,
        maintype="application",
        subtype="octet-stream",
        filename=filename,
    )
    return message.as_bytes()


def _build_minimal_pe() -> bytes:
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x010F)

    optional_header = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,
        0,
        0,
        0x200,
        0x200,
        0,
        0x1000,
        0x1000,
        0x2000,
        0x400000,
        0x1000,
        0x200,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        0x2000,
        0x200,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    data_directories = b"\x00" * (16 * 8)

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x100,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )

    headers = bytes(dos_header) + (b"\x00" * (0x80 - len(dos_header)))
    headers += pe_signature + coff_header + optional_header + data_directories + section_header
    headers = headers.ljust(0x200, b"\x00")

    section_data = (b"\x90" * 32) + b"ThisIsVisibleStringInPE" + (b"\x00" * (0x200 - 55))
    return headers + section_data


def _create_incident(client: TestClient) -> int:
    response = client.post(
        "/api/v1/incidents",
        json={"title": "Static Analysis", "description": "Phase 2B-Part A"},
    )
    assert response.status_code == 200
    return response.json()["id"]


def _upload_artifact(client: TestClient, incident_id: int, name: str, content: bytes) -> int:
    eml = _build_eml_with_attachment(name, content)
    response = client.post(
        "/api/v1/emails/upload-eml",
        files={"eml_file": ("sample.eml", eml, "message/rfc822")},
        data={"incident_id": str(incident_id)},
    )
    assert response.status_code == 201
    artifacts = response.json()["artifacts"]
    assert artifacts
    return artifacts[0]["id"]


def test_static_analysis_valid_pe_persists_headers_sections_entropy_strings(
    client: TestClient,
) -> None:
    incident_id = _create_incident(client)
    artifact_id = _upload_artifact(client, incident_id, "sample.exe", _build_minimal_pe())

    analyze_response = client.post(f"/api/v1/artifacts/{artifact_id}/analyze-static")
    assert analyze_response.status_code == 200
    body = analyze_response.json()

    assert body["status"] == "completed"
    assert body["is_pe"] is True
    assert body["file_type"] in {"pe32", "pe32+"}
    assert body["pe_headers"]["number_of_sections"] >= 1
    assert body["sections"]
    assert isinstance(body["sections"][0]["entropy"], float)
    assert "name" in body["sections"][0]
    assert isinstance(body["imports"], list)
    assert any("ThisIsVisibleStringInPE" in value for value in body["extracted_strings"])

    persisted = client.get(f"/api/v1/artifacts/{artifact_id}/analysis-static")
    assert persisted.status_code == 200
    assert persisted.json()["id"] == body["id"]


def test_static_analysis_non_pe_file_returns_unsupported(client: TestClient) -> None:
    incident_id = _create_incident(client)
    artifact_id = _upload_artifact(client, incident_id, "document.txt", b"hello world string")

    response = client.post(f"/api/v1/artifacts/{artifact_id}/analyze-static")
    assert response.status_code == 200
    body = response.json()

    assert body["status"] == "unsupported"
    assert body["is_pe"] is False
    assert body["error_message"] is not None


def test_static_analysis_malformed_pe_file_returns_failed(client: TestClient) -> None:
    incident_id = _create_incident(client)
    malformed = b"MZ" + b"\x00" * 14
    artifact_id = _upload_artifact(client, incident_id, "broken.exe", malformed)

    response = client.post(f"/api/v1/artifacts/{artifact_id}/analyze-static")
    assert response.status_code == 200
    body = response.json()

    assert body["status"] == "failed"
    assert body["is_pe"] is True
    assert "Malformed PE file" in (body["error_message"] or "")


def test_static_analysis_missing_artifact_returns_404(client: TestClient) -> None:
    response = client.post("/api/v1/artifacts/999999/analyze-static")
    assert response.status_code == 404
    assert response.json()["detail"] == "Artifact not found"


def test_static_analysis_missing_artifact_file_is_handled() -> None:
    artifact = Artifact(
        id=1,
        incident_id=1,
        email_id=1,
        filename="missing.exe",
        content_type="application/octet-stream",
        size=1,
        sha256="0" * 64,
        storage_path="/tmp/non-existent-file.exe",
    )
    analysis = analyze_artifact(artifact)
    assert analysis.status == "failed"
    assert "does not exist" in (analysis.error_message or "")
