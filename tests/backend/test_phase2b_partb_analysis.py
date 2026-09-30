from __future__ import annotations

import struct
from email.message import EmailMessage
from pathlib import Path

from fastapi.testclient import TestClient

from app.services.ioc_extraction import (
    deduplicate_iocs,
    extract_artifact_hashes,
    extract_artifact_iocs,
    extract_iocs_from_text,
)
from app.services.yara_scanner import (
    compile_rule_source,
    compile_yara_rules,
    scan_content_with_yara,
)


def _build_eml_with_attachment(filename: str, attachment: bytes) -> bytes:
    message = EmailMessage()
    message["From"] = "threat-source@example.com"
    message["To"] = "soc-analyst@example.com"
    message["Subject"] = "Urgent Analysis Sample"
    message.set_content("Automated triage request with attachment")
    message.add_attachment(
        attachment,
        maintype="application",
        subtype="octet-stream",
        filename=filename,
    )
    return message.as_bytes()


def _build_pe_with_payload(custom_strings: bytes) -> bytes:
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
        0x200,
        0x1000,
        0x300,
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

    payload = (b"\x90" * 16) + custom_strings
    payload = payload.ljust(0x300, b"\x00")
    return headers + payload


def _create_incident(client: TestClient) -> int:
    response = client.post(
        "/api/v1/incidents",
        json={"title": "Phase 2B-Part B Incident", "description": "Detection and IOC testing"},
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


# ==========================================
# 1. YARA Tests
# ==========================================


def test_yara_valid_rule_compilation() -> None:
    rules = compile_yara_rules()
    assert rules is not None


def test_yara_custom_rule_compilation() -> None:
    source = """
    rule CustomTestRule {
        meta:
            description = "Custom in-memory YARA rule test"
        strings:
            $match_token = "IN_MEMORY_TOKEN_XYZ"
        condition:
            $match_token
    }
    """
    rules = compile_rule_source(source)
    assert rules is not None
    matches = rules.match(data=b"Sample with IN_MEMORY_TOKEN_XYZ present")
    assert len(matches) == 1
    assert matches[0].rule == "CustomTestRule"


def test_yara_successful_match() -> None:
    data = b"Some payload with MALCIE_TEST_INDICATOR_SAMPLE embedded inside"
    matches = scan_content_with_yara(data)
    assert len(matches) >= 1
    matched_rules = [item["rule"] for item in matches]
    assert "Test_Indicator_Rule" in matched_rules

    test_finding = next(item for item in matches if item["rule"] == "Test_Indicator_Rule")
    assert test_finding["meta"].get("category") == "test"
    assert test_finding["meta"].get("severity") == "low"
    assert "test" in test_finding["tags"]
    assert test_finding["strings"]
    assert test_finding["strings"][0]["identifier"] == "$test_string"


def test_yara_non_match() -> None:
    clean_data = b"This is completely clean text without matching any known signature"
    matches = scan_content_with_yara(clean_data)
    assert matches == []


def test_yara_malformed_rule_handling(tmp_path: Path) -> None:
    broken_rule_file = tmp_path / "broken.yar"
    broken_rule_file.write_text("rule InvalidSyntax { strings: $a = broken condition: }")
    compiled = compile_yara_rules(tmp_path)
    assert compiled is None


# ==========================================
# 2. IOC Extraction & Normalization Tests
# ==========================================


def test_ioc_extraction_hashes() -> None:
    data = b"Deterministic payload for hash testing"
    hashes = extract_artifact_hashes(data)
    assert len(hashes) == 3
    ioc_types = {ioc.ioc_type for ioc in hashes}
    assert ioc_types == {"sha256", "md5", "sha1"}
    for ioc in hashes:
        assert ioc.normalized_value == ioc.value.lower()
        assert len(ioc.normalized_value) in {32, 40, 64}


def test_ioc_extraction_network_types_and_normalization() -> None:
    text = (
        "Contact C2 server at https://c2.evil.com:8443/api/v1/beacon, "
        "secondary IP 198.51.100.45 or IPv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 "
        "and domain malware-delivery.net. Also http://UPPERCASE.EXAMPLE.ORG/Path."
    )
    iocs = extract_iocs_from_text(text)
    types_found = {ioc.ioc_type for ioc in iocs}

    assert "url" in types_found
    assert "ipv4" in types_found
    assert "ipv6" in types_found
    assert "domain" in types_found

    url_iocs = [ioc for ioc in iocs if ioc.ioc_type == "url"]
    assert any("c2.evil.com" in item.normalized_value for item in url_iocs)
    assert any("uppercase.example.org" in item.normalized_value for item in url_iocs)

    ipv4_iocs = [ioc for ioc in iocs if ioc.ioc_type == "ipv4"]
    assert any(item.normalized_value == "198.51.100.45" for item in ipv4_iocs)

    ipv6_iocs = [ioc for ioc in iocs if ioc.ioc_type == "ipv6"]
    assert any("2001:db8:85a3::8a2e:370:7334" in item.normalized_value for item in ipv6_iocs)

    domain_iocs = [ioc for ioc in iocs if ioc.ioc_type == "domain"]
    domain_vals = {item.normalized_value for item in domain_iocs}
    assert "malware-delivery.net" in domain_vals


def test_ioc_extraction_file_paths() -> None:
    text = (
        "Drops binary into C:\\Windows\\System32\\svchost_fake.exe "
        "and staging at %TEMP%\\dropper.exe. "
        "On Linux target /usr/local/bin/malicious_daemon and /tmp/stage.sh"
    )
    iocs = extract_iocs_from_text(text)
    path_iocs = [ioc for ioc in iocs if ioc.ioc_type == "file_path"]
    normalized_paths = [ioc.normalized_value for ioc in path_iocs]

    assert any("C:\\Windows\\System32\\svchost_fake.exe" in p for p in normalized_paths)
    assert any("%TEMP%\\dropper.exe" in p for p in normalized_paths)
    assert any("/usr/local/bin/malicious_daemon" in p for p in normalized_paths)
    assert any("/tmp/stage.sh" in p for p in normalized_paths)


def test_ioc_deduplication() -> None:
    text = (
        "https://evil.example.com/payload "
        "https://evil.example.com/payload "
        "192.0.2.1 192.0.2.1 192.0.2.1"
    )
    # extract_iocs_from_text returns raw matches; deduplicate_iocs removes dupes.
    raw = extract_iocs_from_text(text)
    extracted = deduplicate_iocs(raw)
    url_count = sum(1 for ioc in extracted if ioc.ioc_type == "url")
    ip_count = sum(1 for ioc in extracted if ioc.ioc_type == "ipv4")
    assert url_count == 1
    assert ip_count == 1


def test_ioc_invalid_filter() -> None:
    text = "Invalid IP 999.888.777.666 and library kernel32.dll user32.dll not a domain"
    iocs = extract_iocs_from_text(text)
    assert not any(ioc.ioc_type == "ipv4" and ioc.value == "999.888.777.666" for ioc in iocs)
    domain_vals = [ioc.normalized_value for ioc in iocs if ioc.ioc_type == "domain"]
    assert "kernel32.dll" not in domain_vals
    assert "user32.dll" not in domain_vals


# ==========================================
# 3. Association, Persistence & Pipeline Tests
# ==========================================


def test_artifact_analysis_end_to_end_pipeline(client: TestClient) -> None:
    incident_id = _create_incident(client)

    payload_text = (
        b"MALCIE_TEST_INDICATOR_SAMPLE\x00"
        b"https://evil-c2.example.com/gate.php\x00"
        b"203.0.113.88\x00"
        b"C:\\ProgramData\\updater.exe\x00"
    )
    sample_pe = _build_pe_with_payload(payload_text)
    artifact_id = _upload_artifact(client, incident_id, "test_malware.exe", sample_pe)

    # 1. Trigger analysis via API
    analyze_resp = client.post(f"/api/v1/artifacts/{artifact_id}/analyze-static")
    assert analyze_resp.status_code == 200
    body = analyze_resp.json()

    assert body["status"] == "completed"
    assert body["is_pe"] is True
    assert body["file_type"] in {"pe32", "pe32+"}
    assert body["pe_headers"]
    assert body["sections"]
    assert body["md5"] is not None and len(body["md5"]) == 32
    assert body["sha1"] is not None and len(body["sha1"]) == 40

    # 2. Verify YARA findings
    assert isinstance(body["yara_matches"], list)
    yara_rules = [match["rule"] for match in body["yara_matches"]]
    assert "Test_Indicator_Rule" in yara_rules

    # 3. Verify IOC records in response
    assert isinstance(body["iocs"], list)
    ioc_types = {ioc["ioc_type"] for ioc in body["iocs"]}
    assert "sha256" in ioc_types
    assert "md5" in ioc_types
    assert "sha1" in ioc_types
    assert "url" in ioc_types
    assert "ipv4" in ioc_types
    assert "file_path" in ioc_types

    # 4. Verify persistence retrieval via GET /artifacts/{id}/analysis-static
    get_analysis = client.get(f"/api/v1/artifacts/{artifact_id}/analysis-static")
    assert get_analysis.status_code == 200
    get_body = get_analysis.json()
    assert get_body["id"] == body["id"]
    assert get_body["md5"] == body["md5"]
    assert len(get_body["yara_matches"]) == len(body["yara_matches"])
    assert len(get_body["iocs"]) == len(body["iocs"])

    # 5. Verify direct artifact IOC retrieval via GET /artifacts/{id}/iocs
    get_artifact_iocs = client.get(f"/api/v1/artifacts/{artifact_id}/iocs")
    assert get_artifact_iocs.status_code == 200
    artifact_iocs = get_artifact_iocs.json()
    assert len(artifact_iocs) == len(body["iocs"])
    for ioc in artifact_iocs:
        assert ioc["artifact_id"] == artifact_id
        assert ioc["incident_id"] == incident_id

    # 6. Verify incident-wide IOC retrieval via GET /incidents/{id}/iocs
    get_incident_iocs = client.get(f"/api/v1/incidents/{incident_id}/iocs")
    assert get_incident_iocs.status_code == 200
    inc_iocs = get_incident_iocs.json()
    assert len(inc_iocs) >= len(artifact_iocs)


def test_yara_match_is_evidence_not_binary_verdict() -> None:
    # The YARA rule matched string data must contain a recognisable IOC pattern
    # so that extract_iocs_from_text produces an IOC tagged with the rule source.
    # This confirms YARA hits are recorded as evidence, not as binary verdicts.
    ioc_url = "http://192.0.2.200/malcie_test_download"
    data = ioc_url.encode()
    extracted = extract_artifact_iocs(
        content=data,
        extracted_strings=[ioc_url],
        yara_matches=[
            {
                "rule": "Test_Indicator_Rule",
                "tags": ["test"],
                "meta": {"severity": "low", "category": "test"},
                "strings": [
                    {"identifier": "$test_url", "data": ioc_url},
                ],
            }
        ],
    )
    # Confirm indicators are extracted and tagged as evidence
    # without generating arbitrary malware verdicts
    assert any(ioc.source == "yara_match:Test_Indicator_Rule" for ioc in extracted)
