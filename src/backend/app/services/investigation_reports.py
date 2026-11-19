from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Incident, InvestigationReport
from app.services.correlation_engine import (
    CORRELATION_ALGORITHM_VERSION,
    SCORING_ALGORITHM_VERSION,
    run_incident_correlation,
)


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat() if value.tzinfo else value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def create_investigation_report(
    db: Session,
    incident: Incident,
    *,
    author_id: int | None,
    author_email: str,
    title: str,
    summary: str | None,
    disposition: str,
) -> InvestigationReport:
    correlation = run_incident_correlation(db, incident.id)
    snapshot = {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "status": incident.status,
            "created_at": incident.created_at,
        },
        "observed_evidence": {
            "emails": [
                {"id": e.id, "sender": e.sender, "subject": e.subject, "sent_at": e.sent_at,
                 "urls": e.urls, "domains": e.domains}
                for e in incident.emails
            ],
            "artifacts": [
                {"id": a.id, "filename": a.filename, "size": a.size, "sha256": a.sha256,
                 "analysis": ({"status": a.analysis.status, "is_pe": a.analysis.is_pe,
                               "file_type": a.analysis.file_type,
                               "pe_headers": a.analysis.pe_headers,
                               "sections": a.analysis.sections,
                               "imports": a.analysis.imports,
                               "strings": a.analysis.extracted_strings,
                               "yara_matches": a.analysis.yara_matches,
                               "iocs": a.analysis.iocs}
                              if a.analysis else None)}
                for a in incident.artifacts
            ],
            "iocs": [
                {"id": i.id, "type": i.ioc_type, "value": i.normalized_value,
                 "source": i.source, "created_at": i.created_at}
                for i in incident.iocs
            ],
            "threat_intelligence": [
                {"id": t.id, "ioc_type": t.ioc_type, "ioc_value": t.ioc_value,
                 "provider": t.provider, "query_status": t.query_status,
                 "malicious_votes": t.malicious_votes, "queried_at": t.queried_at}
                for t in incident.threat_intel_results
            ],
            "endpoint_events": [
                {"id": e.id, "event_id": e.event_id, "timestamp": e.timestamp,
                 "hostname": e.hostname, "endpoint_id": e.endpoint_id,
                 "process_guid": e.process_guid, "process_id": e.process_id,
                 "parent_process_guid": e.parent_process_guid,
                 "parent_process_id": e.parent_process_id, "image": e.image,
                 "command_line": e.command_line, "hashes": e.hashes,
                 "raw_evidence": e.raw_evidence, "provenance": e.provenance}
                for e in incident.endpoint_events
            ],
        },
        "automated_findings": {
            "static_analysis": [
                {
                    "artifact_id": artifact.id,
                    "status": artifact.analysis.status,
                    "suspicious_indicators": (artifact.analysis.pe_headers or {}).get(
                        "suspicious_indicators", []
                    ),
                    "yara_matches": artifact.analysis.yara_matches,
                    "iocs": artifact.analysis.iocs,
                }
                for artifact in incident.artifacts
                if artifact.analysis is not None
            ],
            "threat_intelligence": [
                {
                    "id": result.id,
                    "ioc_type": result.ioc_type,
                    "ioc_value": result.normalized_value,
                    "provider": result.provider,
                    "status": result.query_status,
                    "malicious_votes": result.malicious_votes,
                    "reputation_score": result.reputation_score,
                    "queried_at": result.queried_at,
                }
                for result in incident.threat_intel_results
            ],
        },
        "correlation": correlation.model_dump(mode="json"),
        "analyst_conclusions": {"summary": summary, "disposition": disposition},
        "provenance": {"generated_at": datetime.now(timezone.utc).isoformat(),
                       "author_id": author_id, "author_email": author_email},
    }
    snapshot = _json_value(snapshot)
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    evidence_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    version = (db.scalar(select(InvestigationReport.version)
                          .where(InvestigationReport.incident_id == incident.id)
                          .order_by(InvestigationReport.version.desc()).limit(1)) or 0) + 1
    report_id = str(uuid.uuid4())
    report = InvestigationReport(
        report_id=report_id, incident_id=incident.id, version=version,
        author_id=author_id, author_email=author_email, title=title, summary=summary,
        disposition=disposition, correlation_version=correlation.algorithm_version,
        scoring_version=correlation.scoring_version, evidence_hash=evidence_hash,
        evidence_snapshot=snapshot,
        report_data={
            "report_id": report_id,
            "format_version": "1.0",
            "evidence_hash": evidence_hash,
        },
    )
    db.add(report)
    db.flush()
    db.commit()
    db.refresh(report)
    return report


def render_report_pdf(report: InvestigationReport) -> bytes:
    """Render a compact text PDF using only the standard library."""
    lines = [
        report.title, f"Report ID: {report.report_id}", f"Incident: {report.incident_id}",
        f"Version: {report.version}", f"Generated: {report.created_at.isoformat()}",
        f"Disposition: {report.disposition}", f"Evidence SHA-256: {report.evidence_hash}",
        "", "Analyst summary:", report.summary or "No analyst summary provided.", "",
        "Evidence snapshot:", json.dumps(report.evidence_snapshot, sort_keys=True, indent=2),
    ]
    text_lines: list[str] = []
    for line in lines:
        text_lines.extend(line[i:i + 95] for i in range(0, max(len(line), 1), 95))
    def escape(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    pages = [text_lines[i:i + 65] for i in range(0, len(text_lines), 65)] or [[]]
    page_object_ids = [4 + 2 * index for index in range(len(pages))]
    kids = " ".join(f"{page_id} 0 R" for page_id in page_object_ids)
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    ]
    for index, page_lines in enumerate(pages):
        page_id = page_object_ids[index]
        stream_id = page_id + 1
        commands = ["BT", "/F1 8 Tf", "45 790 Td", "10 TL"]
        commands.extend(f"({escape(line)}) Tj T*" for line in page_lines)
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1", errors="replace")
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {stream_id} 0 R >>".encode()
        )
        objects.append(
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
            + stream + b"\nendstream"
        )
    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode())
    trailer = f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
    pdf.extend(f"{trailer}startxref\n{xref}\n%%EOF".encode())
    return bytes(pdf)


CORRELATION_VERSION = CORRELATION_ALGORITHM_VERSION
SCORING_VERSION = SCORING_ALGORITHM_VERSION
