from __future__ import annotations

import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import (
    CorrelationResult,
    Incident,
    TimelineEvent,
)
from app.schemas import (
    ConfidenceAssessment,
    CorrelationResponse,
    LinkageItem,
    RiskAssessment,
)

logger = logging.getLogger(__name__)

SUSPICIOUS_IMPORT_APIS = {
    "urldownloadtofilea",
    "urldownloadtofilew",
    "virtualalloc",
    "virtualallocex",
    "createremotethread",
    "writeprocessmemory",
    "winexec",
    "shellexecutea",
    "shellexecutew",
    "internetopenurla",
    "internetopenurlw",
    "wsastartup",
    "connect",
    "httprequest",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return utc_now()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_email_sent_at(sent_at_str: str | None, fallback: datetime) -> datetime:
    if not sent_at_str:
        return _ensure_utc(fallback)
    try:
        dt = parsedate_to_datetime(sent_at_str)
        return _ensure_utc(dt)
    except Exception:
        return _ensure_utc(fallback)


def parse_pe_timestamp(timestamp_val: Any, fallback: datetime) -> datetime:
    if isinstance(timestamp_val, (int, float)):
        # Validate timestamp is between 1990 and 2038
        if 631152000 <= timestamp_val <= 2147483647:
            try:
                return datetime.fromtimestamp(timestamp_val, tz=timezone.utc)
            except Exception:
                pass
    return _ensure_utc(fallback)


def build_evidence_linkages(incident: Incident) -> list[LinkageItem]:
    linkages: list[LinkageItem] = []

    # 1. Email to Attachments
    for email in incident.emails:
        for artifact in email.artifacts:
            subj = email.subject or "No Subject"
            sender = email.sender or "unknown"
            desc = (
                f"Email '{subj}' from '{sender}' contains attachment "
                f"'{artifact.filename}' ({artifact.size} bytes)"
            )
            linkages.append(
                LinkageItem(
                    source_type="email",
                    source_id=email.id,
                    target_type="artifact",
                    target_id=artifact.id,
                    relation="CONTAINS_ATTACHMENT",
                    description=desc,
                    metadata={"filename": artifact.filename, "sha256": artifact.sha256},
                )
            )

    # 2. Artifact to Analysis, Hashes & YARA Findings
    for artifact in incident.artifacts:
        # Cryptographic Hashes
        linkages.append(
            LinkageItem(
                source_type="artifact",
                source_id=artifact.id,
                target_type="hash",
                target_id=artifact.sha256,
                relation="COMPUTED_HASH",
                description=f"Artifact '{artifact.filename}' SHA-256 digest: {artifact.sha256}",
                metadata={"sha256": artifact.sha256},
            )
        )

        analysis = artifact.analysis
        if analysis:
            linkages.append(
                LinkageItem(
                    source_type="artifact",
                    source_id=artifact.id,
                    target_type="analysis",
                    target_id=analysis.id,
                    relation="STATIC_ANALYSIS",
                    description=(
                        f"Static analysis performed on '{artifact.filename}': "
                        f"status={analysis.status}, is_pe={analysis.is_pe}"
                    ),
                    metadata={
                        "status": analysis.status,
                        "is_pe": analysis.is_pe,
                        "file_type": analysis.file_type,
                    },
                )
            )

            # YARA Matches
            for match in analysis.yara_matches:
                rule_name = str(match.get("rule", "UnknownRule"))
                desc = f"YARA rule '{rule_name}' matched on '{artifact.filename}'"
                linkages.append(
                    LinkageItem(
                        source_type="artifact",
                        source_id=artifact.id,
                        target_type="yara_rule",
                        target_id=rule_name,
                        relation="YARA_RULE_MATCH",
                        description=desc,
                        metadata={
                            "rule": rule_name,
                            "tags": match.get("tags", []),
                            "meta": match.get("meta", {}),
                        },
                    )
                )

        # Artifact to IOC records
        for ioc in artifact.iocs:
            linkages.append(
                LinkageItem(
                    source_type="artifact",
                    source_id=artifact.id,
                    target_type="ioc",
                    target_id=ioc.id,
                    relation="EXTRACTED_IOC",
                    description=(
                        f"IOC extracted from '{artifact.filename}': "
                        f"{ioc.ioc_type}={ioc.normalized_value} ({ioc.source})"
                    ),
                    metadata={"ioc_type": ioc.ioc_type, "value": ioc.normalized_value},
                )
            )

    # 3. IOCs to Threat Intelligence Results
    for ti in incident.threat_intel_results:
        votes = f"{ti.malicious_votes}/{ti.total_engines}"
        desc = (
            f"Threat intelligence for {ti.ioc_type} '{ti.normalized_value}': "
            f"status={ti.query_status}, malicious_votes={votes}, "
            f"reputation={ti.reputation_score}"
        )
        linkages.append(
            LinkageItem(
                source_type="ioc",
                source_id=ti.normalized_value,
                target_type="threat_intel",
                target_id=ti.id,
                relation="THREAT_INTEL_VERDICT",
                description=desc,
                metadata={
                    "provider": ti.provider,
                    "malicious_votes": ti.malicious_votes,
                    "reputation_score": ti.reputation_score,
                    "query_status": ti.query_status,
                },
            )
        )

    # 4. Cross-Source Corroborating Linkages
    # Cross-reference 1: Email URLs/Domains matching Artifact IOCs or Strings
    email_network_indicators: set[str] = set()
    for email in incident.emails:
        email_network_indicators.update(url.lower().rstrip("/") for url in email.urls)
        email_network_indicators.update(dom.lower() for dom in email.domains)

    for artifact in incident.artifacts:
        for ioc in artifact.iocs:
            norm_val = ioc.normalized_value.lower().rstrip("/")
            if norm_val in email_network_indicators:
                linkages.append(
                    LinkageItem(
                        source_type="email",
                        source_id=artifact.email_id or "email",
                        target_type="artifact",
                        target_id=artifact.id,
                        relation="CORROBORATING_NETWORK_INDICATOR",
                        description=(
                            f"Email network indicator '{norm_val}' matches IOC extracted "
                            f"from attachment artifact '{artifact.filename}'"
                        ),
                        metadata={"indicator": norm_val, "ioc_type": ioc.ioc_type},
                    )
                )

    # Cross-reference 2: Known Malicious Hash in VT Corroborating Artifact
    for ti in incident.threat_intel_results:
        if ti.ioc_type.lower() in {"sha256", "md5", "sha1"} and ti.malicious_votes > 0:
            linkages.append(
                LinkageItem(
                    source_type="threat_intel",
                    source_id=ti.id,
                    target_type="artifact",
                    target_id=ti.artifact_id or "artifact",
                    relation="CORROBORATED_MALICIOUS_HASH",
                    description=(
                        f"Threat intelligence confirmed malicious hash '{ti.normalized_value}' "
                        f"with {ti.malicious_votes} vendor detections"
                    ),
                    metadata={"malicious_votes": ti.malicious_votes},
                )
            )

    return linkages


def compute_correlation_confidence(
    incident: Incident,
    linkages: list[LinkageItem],
) -> ConfidenceAssessment:
    score = 0.0
    reasons: list[str] = []

    has_email = len(incident.emails) > 0
    has_artifacts = len(incident.artifacts) > 0
    has_analyses = any(art.analysis is not None for art in incident.artifacts)
    has_iocs = len(incident.iocs) > 0
    has_ti = len(incident.threat_intel_results) > 0
    has_cross_links = any(
        lnk.relation in {"CORROBORATING_NETWORK_INDICATOR", "CORROBORATED_MALICIOUS_HASH"}
        for lnk in linkages
    )

    if has_email:
        score += 15.0
        reasons.append("Email evidence captured and metadata parsed (+15%)")

    if has_artifacts:
        score += 20.0
        reasons.append("Attachment artifact linkage established with digests (+20%)")

    if has_analyses:
        score += 20.0
        reasons.append("Static PE inspection and architectural analysis completed (+20%)")

    if has_iocs:
        score += 15.0
        reasons.append("Structured IOCs extracted with source provenance (+15%)")

    if has_ti:
        score += 15.0
        reasons.append("External threat intelligence queried and associated with IOCs (+15%)")

    if has_cross_links:
        score += 15.0
        reasons.append("Cross-source corroboration identified across multiple stages (+15%)")

    score = min(score, 100.0)

    if score >= 70.0:
        level = "HIGH"
    elif score >= 40.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    return ConfidenceAssessment(score=round(score, 2), level=level, reasons=reasons)


def compute_incident_risk(incident: Incident) -> RiskAssessment:
    score = 0
    reasons: list[str] = []

    # 1. YARA Rule Matches (+25 pts per distinct rule, max 40)
    seen_yara_rules: set[str] = set()
    for art in incident.artifacts:
        if art.analysis and art.analysis.yara_matches:
            for match in art.analysis.yara_matches:
                rule_name = str(match.get("rule", "UnknownRule"))
                if rule_name not in seen_yara_rules:
                    seen_yara_rules.add(rule_name)
                    points = 25 if len(seen_yara_rules) == 1 else 15
                    score += points
                    tags = match.get("tags", [])
                    reasons.append(
                        f"YARA rule '{rule_name}' matched on '{art.filename}' "
                        f"(tags: {', '.join(tags) if tags else 'none'}) (+{points})"
                    )

    # 2. Known Malicious File Hash via Threat Intelligence
    for ti in incident.threat_intel_results:
        if ti.ioc_type.lower() in {"sha256", "md5", "sha1"}:
            if ti.malicious_votes >= 5:
                pts = 30
                score += pts
                reasons.append(
                    f"VirusTotal flagged file hash '{ti.normalized_value[:16]}...' with "
                    f"{ti.malicious_votes} malicious detections (+{pts})"
                )
            elif (
                ti.malicious_votes >= 1
                or (ti.reputation_score is not None and ti.reputation_score < -20)
            ):
                pts = 15
                score += pts
                reasons.append(
                    f"VirusTotal identified suspicious file hash '{ti.normalized_value[:16]}...' "
                    f"(votes: {ti.malicious_votes}, rep: {ti.reputation_score}) (+{pts})"
                )

    # 3. Malicious Network IOCs in Threat Intelligence
    for ti in incident.threat_intel_results:
        if ti.ioc_type.lower() in {"url", "domain", "ipv4"} and ti.malicious_votes >= 2:
            pts = 20
            score += pts
            reasons.append(
                f"Threat intelligence flagged {ti.ioc_type} '{ti.normalized_value}' with "
                f"{ti.malicious_votes} malicious detections (+{pts})"
            )

    # 4. Static PE Anomalies: High Section Entropy (Packing / Obfuscation)
    for art in incident.artifacts:
        if art.analysis and art.analysis.is_pe:
            for section in art.analysis.sections:
                entropy = float(section.get("entropy", 0.0))
                sec_name = str(section.get("name", "unknown"))
                if entropy > 7.0:
                    pts = 15
                    score += pts
                    reasons.append(
                        f"High Shannon entropy ({entropy:.2f}) in section '{sec_name}' "
                        f"of '{art.filename}', indicating packing or obfuscation (+{pts})"
                    )
                    break

    # 5. Suspicious Process Execution / Downloader API Imports
    for art in incident.artifacts:
        if art.analysis and art.analysis.imports:
            found_apis: list[str] = []
            for imp in art.analysis.imports:
                funcs = imp.get("functions", [])
                if isinstance(funcs, list):
                    for fn in funcs:
                        if isinstance(fn, str) and fn.lower() in SUSPICIOUS_IMPORT_APIS:
                            found_apis.append(fn)
            if found_apis:
                pts = 15
                score += pts
                apis_str = ", ".join(sorted(set(found_apis))[:5])
                reasons.append(
                    f"Suspicious execution/download APIs imported in '{art.filename}': "
                    f"{apis_str} (+{pts})"
                )

    # 6. Phishing Indicators in Email
    for email in incident.emails:
        has_exec = any(
            art.filename.lower().endswith(
                (".exe", ".dll", ".vbs", ".ps1", ".bat", ".scr", ".bin")
            )
            for art in email.artifacts
        )
        if (email.urls or email.domains) and has_exec:
            pts = 10
            score += pts
            subj = email.subject or "No Subject"
            reasons.append(
                f"Phishing indicator: email '{subj}' contains embedded links "
                f"and executable attachments (+{pts})"
            )

    score = min(score, 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "NONE"

    if not reasons:
        reasons.append("No suspicious indicators or malware characteristics detected (score=0)")

    return RiskAssessment(score=score, level=level, reasons=reasons)


def generate_incident_timeline(incident: Incident) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []

    # 1. Emails
    for email in incident.emails:
        email_time = parse_email_sent_at(email.sent_at, email.created_at)
        subj = email.subject or "No Subject"
        sender = email.sender or "unknown"
        events.append(
            TimelineEvent(
                incident_id=incident.id,
                timestamp=email_time,
                event_type="EMAIL_RECEIVED",
                source="email_intake",
                description=(
                    f"Email received: '{subj}' from '{sender}' "
                    f"to {len(email.recipients)} recipients"
                ),
                event_data={
                    "email_id": email.id,
                    "sender": email.sender,
                    "subject": email.subject,
                    "urls_count": len(email.urls),
                    "attachments_count": len(email.artifacts),
                },
            )
        )

    # 2. Attachments & PE Compilation Timestamps
    for art in incident.artifacts:
        art_time = _ensure_utc(art.created_at)
        events.append(
            TimelineEvent(
                incident_id=incident.id,
                timestamp=art_time,
                event_type="ATTACHMENT_EXTRACTED",
                source="artifact_storage",
                description=(
                    f"Attachment artifact '{art.filename}' ({art.size} bytes) "
                    f"extracted and verified (SHA-256: {art.sha256[:12]}...)"
                ),
                artifact_id=art.id,
                event_data={"filename": art.filename, "size": art.size, "sha256": art.sha256},
            )
        )

        analysis = art.analysis
        if analysis:
            # PE Compilation Timestamp if available
            time_stamp_val = analysis.pe_headers.get("time_date_stamp")
            if time_stamp_val:
                pe_time = parse_pe_timestamp(time_stamp_val, art.created_at)
                events.append(
                    TimelineEvent(
                        incident_id=incident.id,
                        timestamp=pe_time,
                        event_type="PE_COMPILED",
                        source="pe_header",
                        description=(
                            f"PE binary compilation header for '{art.filename}': "
                            f"{pe_time.isoformat()}"
                        ),
                        artifact_id=art.id,
                        event_data={"time_date_stamp": time_stamp_val},
                    )
                )

            # Static Analysis completion
            analysis_time = _ensure_utc(analysis.created_at)
            events.append(
                TimelineEvent(
                    incident_id=incident.id,
                    timestamp=analysis_time,
                    event_type="STATIC_ANALYSIS_COMPLETED",
                    source="pe_static_analysis",
                    description=(
                        f"Static PE analysis completed for '{art.filename}': "
                        f"status={analysis.status}, sections={len(analysis.sections)}, "
                        f"imports={len(analysis.imports)}"
                    ),
                    artifact_id=art.id,
                    event_data={
                        "status": analysis.status,
                        "is_pe": analysis.is_pe,
                        "sections_count": len(analysis.sections),
                    },
                )
            )

            # YARA matches
            for match in analysis.yara_matches:
                rule_name = str(match.get("rule", "UnknownRule"))
                events.append(
                    TimelineEvent(
                        incident_id=incident.id,
                        timestamp=analysis_time,
                        event_type="YARA_MATCH",
                        source="yara_scanner",
                        description=f"YARA rule '{rule_name}' triggered on '{art.filename}'",
                        artifact_id=art.id,
                        event_data={"rule": rule_name, "tags": match.get("tags", [])},
                    )
                )

    # 3. IOC extractions
    for ioc in incident.iocs:
        ioc_time = _ensure_utc(ioc.created_at)
        events.append(
            TimelineEvent(
                incident_id=incident.id,
                timestamp=ioc_time,
                event_type="IOC_EXTRACTED",
                source=ioc.source,
                description=f"Extracted {ioc.ioc_type} IOC: {ioc.normalized_value}",
                artifact_id=ioc.artifact_id,
                ioc_id=ioc.id,
                event_data={"ioc_type": ioc.ioc_type, "value": ioc.normalized_value},
            )
        )

    # 4. Threat Intelligence Queries
    for ti in incident.threat_intel_results:
        ti_time = _ensure_utc(ti.queried_at)
        events.append(
            TimelineEvent(
                incident_id=incident.id,
                timestamp=ti_time,
                event_type="THREAT_INTEL_QUERIED",
                source=ti.provider,
                description=(
                    f"Threat intelligence for {ti.ioc_type} '{ti.normalized_value}': "
                    f"status={ti.query_status}, malicious_votes={ti.malicious_votes}"
                ),
                artifact_id=ti.artifact_id,
                ioc_id=ti.ioc_id,
                event_data={
                    "provider": ti.provider,
                    "query_status": ti.query_status,
                    "malicious_votes": ti.malicious_votes,
                    "reputation_score": ti.reputation_score,
                },
            )
        )

    # 5. Chronological Sort
    events.sort(key=lambda ev: ev.timestamp)
    return events


def run_incident_correlation(db: Session, incident_id: int) -> CorrelationResponse:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    linkages = build_evidence_linkages(incident)
    confidence = compute_correlation_confidence(incident, linkages)
    risk = compute_incident_risk(incident)

    now = utc_now()
    linkage_dicts = [lnk.model_dump() for lnk in linkages]

    # Persist or update CorrelationResult
    corr_record = (
        db.execute(
            select(CorrelationResult).where(CorrelationResult.incident_id == incident_id)
        )
        .scalars()
        .first()
    )

    if corr_record is None:
        corr_record = CorrelationResult(
            incident_id=incident_id,
            confidence_score=confidence.score,
            confidence_level=confidence.level,
            confidence_reasons=confidence.reasons,
            risk_score=risk.score,
            risk_level=risk.level,
            risk_reasons=risk.reasons,
            linkages=linkage_dicts,
            created_at=now,
            updated_at=now,
        )
        db.add(corr_record)
    else:
        corr_record.confidence_score = confidence.score
        corr_record.confidence_level = confidence.level
        corr_record.confidence_reasons = confidence.reasons
        corr_record.risk_score = risk.score
        corr_record.risk_level = risk.level
        corr_record.risk_reasons = risk.reasons
        corr_record.linkages = linkage_dicts
        corr_record.updated_at = now

    # Refresh Timeline Events
    db.execute(delete(TimelineEvent).where(TimelineEvent.incident_id == incident_id))
    timeline_events = generate_incident_timeline(incident)

    # Add final timeline event for correlation assessment
    timeline_events.append(
        TimelineEvent(
            incident_id=incident_id,
            timestamp=now,
            event_type="CORRELATION_ASSESSED",
            source="correlation_engine",
            description=(
                f"Incident correlation assessed: Risk={risk.level} ({risk.score}/100), "
                f"Confidence={confidence.level} ({confidence.score}%)"
            ),
            event_data={
                "risk_level": risk.level,
                "risk_score": risk.score,
                "confidence_level": confidence.level,
                "confidence_score": confidence.score,
                "linkages_count": len(linkages),
            },
            created_at=now,
        )
    )

    for ev in timeline_events:
        db.add(ev)

    db.commit()
    db.refresh(corr_record)

    return CorrelationResponse(
        incident_id=incident_id,
        confidence=confidence,
        risk=risk,
        linkages=linkages,
        created_at=corr_record.created_at,
    )


def get_incident_timeline_events(db: Session, incident_id: int) -> list[TimelineEvent]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        return []

    stmt = (
        select(TimelineEvent)
        .where(TimelineEvent.incident_id == incident_id)
        .order_by(TimelineEvent.timestamp.asc())
    )
    events = list(db.execute(stmt).scalars().all())

    # If timeline events haven't been generated yet, generate them dynamically
    if not events:
        events = generate_incident_timeline(incident)

    return events
