from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import (
    CorrelationResult,
    EndpointEvent,
    Incident,
    ThreatIntelResult,
    TimelineEvent,
)
from app.schemas import (
    ConfidenceAssessment,
    CorrelationResponse,
    LinkageItem,
    RiskAssessment,
)

logger = logging.getLogger(__name__)

CORRELATION_ALGORITHM_VERSION = "2.1.0"
SCORING_ALGORITHM_VERSION = "2.1.0"

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
    "ntqueueapcthread",
    "zwunmapviewofsection",
    "minidumpwritedump",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return utc_now()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class TimestampProvenance:
    normalized_utc: datetime
    original_timestamp: Any
    timezone_name: str
    source: str
    normalization_method: str
    fallback_reason: str | None
    is_uncertain: bool = False
    clock_skew_flag: str | None = None


def normalize_email_timestamp(sent_at_str: str | None, fallback: datetime) -> TimestampProvenance:
    if not sent_at_str:
        return TimestampProvenance(
            normalized_utc=_ensure_utc(fallback),
            original_timestamp=None,
            timezone_name="UTC",
            source="fallback_incident_or_receipt_time",
            normalization_method="fallback",
            fallback_reason="Missing Date header in email evidence",
            is_uncertain=True,
            clock_skew_flag="No email Date header provided",
        )
    try:
        dt = parsedate_to_datetime(sent_at_str)
        tz_name = dt.tzname() or str(dt.tzinfo or "UTC")
        utc_dt = _ensure_utc(dt)
        is_uncertain = False
        clock_skew = None
        if utc_dt > utc_now() + timedelta(hours=1):
            is_uncertain = True
            clock_skew = f"Future timestamp detected in email Date header: {utc_dt.isoformat()}"
        return TimestampProvenance(
            normalized_utc=utc_dt,
            original_timestamp=sent_at_str,
            timezone_name=tz_name,
            source="email_header_date",
            normalization_method="rfc2822_parsedate",
            fallback_reason=None,
            is_uncertain=is_uncertain,
            clock_skew_flag=clock_skew,
        )
    except Exception as exc:
        return TimestampProvenance(
            normalized_utc=_ensure_utc(fallback),
            original_timestamp=sent_at_str,
            timezone_name="UTC",
            source="fallback_incident_or_receipt_time",
            normalization_method="fallback_after_parse_error",
            fallback_reason=f"Failed to parse email Date header: {exc}",
            is_uncertain=True,
            clock_skew_flag="Unparseable email Date header format",
        )


def normalize_pe_timestamp(timestamp_val: Any, fallback: datetime) -> TimestampProvenance:
    current_year = datetime.now(timezone.utc).year
    if isinstance(timestamp_val, (int, float)):
        min_epoch = 631152000  # 1990-01-01
        max_epoch = int(datetime(current_year + 1, 12, 31, tzinfo=timezone.utc).timestamp())
        if min_epoch <= timestamp_val <= max_epoch:
            try:
                utc_dt = datetime.fromtimestamp(timestamp_val, tz=timezone.utc)
                return TimestampProvenance(
                    normalized_utc=utc_dt,
                    original_timestamp=timestamp_val,
                    timezone_name="UTC",
                    source="pe_header_timedatestamp",
                    normalization_method="posix_epoch_to_utc",
                    fallback_reason=None,
                    is_uncertain=False,
                    clock_skew_flag=None,
                )
            except Exception:
                pass
        else:
            return TimestampProvenance(
                normalized_utc=_ensure_utc(fallback),
                original_timestamp=timestamp_val,
                timezone_name="UTC",
                source="fallback_artifact_creation_time",
                normalization_method="fallback_due_to_anachronistic_pe_header",
                fallback_reason=(
                    f"PE TimeDateStamp ({timestamp_val}) outside realistic window "
                    f"[1990..{current_year + 1}]"
                ),
                is_uncertain=True,
                clock_skew_flag=f"Suspicious or stomped PE compilation timestamp: {timestamp_val}",
            )
    return TimestampProvenance(
        normalized_utc=_ensure_utc(fallback),
        original_timestamp=timestamp_val,
        timezone_name="UTC",
        source="fallback_artifact_creation_time",
        normalization_method="fallback",
        fallback_reason="Missing or non-numeric PE TimeDateStamp",
        is_uncertain=True,
        clock_skew_flag="Missing PE TimeDateStamp",
    )


def normalize_endpoint_timestamp(raw_dt: datetime, fallback: datetime) -> TimestampProvenance:
    utc_dt = _ensure_utc(raw_dt)
    is_uncertain = False
    clock_skew = None
    if utc_dt > utc_now() + timedelta(hours=1):
        is_uncertain = True
        clock_skew = f"Endpoint event timestamp is in the future: {utc_dt.isoformat()}"
    return TimestampProvenance(
        normalized_utc=utc_dt,
        original_timestamp=raw_dt.isoformat() if hasattr(raw_dt, "isoformat") else str(raw_dt),
        timezone_name="UTC",
        source="sysmon_event_timestamp",
        normalization_method="sysmon_utc_normalization",
        fallback_reason=None,
        is_uncertain=is_uncertain,
        clock_skew_flag=clock_skew,
    )


def parse_email_sent_at(sent_at_str: str | None, fallback: datetime) -> datetime:
    return normalize_email_timestamp(sent_at_str, fallback).normalized_utc


def parse_pe_timestamp(timestamp_val: Any, fallback: datetime) -> datetime:
    return normalize_pe_timestamp(timestamp_val, fallback).normalized_utc


def build_evidence_linkages(incident: Incident) -> list[LinkageItem]:
    linkages: list[LinkageItem] = []

    # 1. Email to Attachments
    for email in incident.emails:
        email_id = email.id if email.id is not None else 0
        for artifact in email.artifacts:
            art_id = artifact.id if artifact.id is not None else 0
            subj = email.subject or "No Subject"
            sender = email.sender or "unknown"
            desc = (
                f"Email '{subj}' from '{sender}' contains attachment "
                f"'{artifact.filename}' ({artifact.size} bytes)"
            )
            linkages.append(
                LinkageItem(
                    source_type="email",
                    source_id=email_id,
                    target_type="artifact",
                    target_id=art_id,
                    relation="CONTAINS_ATTACHMENT",
                    description=desc,
                    evidence_ref=f"email:{email_id}->artifact:{art_id}",
                    metadata={"filename": artifact.filename, "sha256": artifact.sha256},
                )
            )

    # 2. Artifact to Analysis, Hashes & YARA Findings
    for artifact in incident.artifacts:
        art_id = artifact.id if artifact.id is not None else 0
        linkages.append(
            LinkageItem(
                source_type="artifact",
                source_id=art_id,
                target_type="hash",
                target_id=artifact.sha256,
                relation="COMPUTED_HASH",
                description=f"Artifact '{artifact.filename}' SHA-256 digest: {artifact.sha256}",
                evidence_ref=f"artifact:{art_id}:sha256:{artifact.sha256[:16]}",
                metadata={"sha256": artifact.sha256},
            )
        )

        analysis = artifact.analysis
        if analysis:
            analysis_id = analysis.id if analysis.id is not None else 0
            linkages.append(
                LinkageItem(
                    source_type="artifact",
                    source_id=art_id,
                    target_type="analysis",
                    target_id=analysis_id,
                    relation="STATIC_ANALYSIS",
                    description=(
                        f"Static analysis performed on '{artifact.filename}': "
                        f"status={analysis.status}, is_pe={analysis.is_pe}"
                    ),
                    evidence_ref=f"artifact:{art_id}->analysis:{analysis_id}",
                    metadata={
                        "status": analysis.status,
                        "is_pe": analysis.is_pe,
                        "file_type": analysis.file_type,
                    },
                )
            )

            # YARA Matches
            for match in analysis.yara_matches or []:
                rule_name = str(match.get("rule", "UnknownRule"))
                desc = f"YARA rule '{rule_name}' matched on '{artifact.filename}'"
                linkages.append(
                    LinkageItem(
                        source_type="artifact",
                        source_id=art_id,
                        target_type="yara_rule",
                        target_id=rule_name,
                        relation="YARA_RULE_MATCH",
                        description=desc,
                        evidence_ref=f"artifact:{art_id}->yara:{rule_name}",
                        metadata={
                            "rule": rule_name,
                            "tags": match.get("tags", []),
                            "meta": match.get("meta", {}),
                        },
                    )
                )

        # Artifact to IOC records
        for ioc in artifact.iocs:
            ioc_id = ioc.id if ioc.id is not None else 0
            linkages.append(
                LinkageItem(
                    source_type="artifact",
                    source_id=art_id,
                    target_type="ioc",
                    target_id=ioc_id,
                    relation="EXTRACTED_IOC",
                    description=(
                        f"IOC extracted from '{artifact.filename}': "
                        f"{ioc.ioc_type}={ioc.normalized_value} ({ioc.source})"
                    ),
                    evidence_ref=f"artifact:{art_id}->ioc:{ioc_id}",
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
                evidence_ref=f"ioc:{ti.ioc_id or ti.normalized_value}->threat_intel:{ti.id}",
                metadata={
                    "provider": ti.provider,
                    "malicious_votes": ti.malicious_votes,
                    "reputation_score": ti.reputation_score,
                    "query_status": ti.query_status,
                },
            )
        )

    # 4. Cross-Source Corroborating Linkages
    email_network_indicators: dict[str, set[int]] = {}
    for email in incident.emails:
        email_id = email.id if email.id is not None else 0
        for indicator in [*email.urls, *email.domains]:
            email_network_indicators.setdefault(
                indicator.lower().rstrip("/"), set()
            ).add(email_id)

    for artifact in incident.artifacts:
        for ioc in artifact.iocs:
            norm_val = ioc.normalized_value.lower().rstrip("/")
            for email_id in sorted(email_network_indicators.get(norm_val, set())):
                linkages.append(
                    LinkageItem(
                        source_type="email",
                        source_id=email_id,
                        target_type="artifact",
                        target_id=artifact.id,
                        relation="CORROBORATING_NETWORK_INDICATOR",
                        description=(
                            f"Email network indicator '{norm_val}' matches IOC extracted "
                            f"from attachment artifact '{artifact.filename}'"
                        ),
                        evidence_ref=(
                            f"email:{email_id}->artifact:{artifact.id}:"
                            f"indicator:{norm_val}"
                        ),
                        metadata={"indicator": norm_val, "ioc_type": ioc.ioc_type},
                    )
                )

    for ti in incident.threat_intel_results:
        if ti.ioc_type.lower() in {"sha256", "md5", "sha1"} and ti.malicious_votes > 0:
            target_artifact_id = ti.artifact_id or (
                incident.artifacts[0].id if incident.artifacts else 0
            )
            linkages.append(
                LinkageItem(
                    source_type="threat_intel",
                    source_id=ti.id,
                    target_type="artifact",
                    target_id=target_artifact_id,
                    relation="CORROBORATED_MALICIOUS_HASH",
                    description=(
                        f"Threat intelligence confirmed malicious hash '{ti.normalized_value}' "
                        f"with {ti.malicious_votes} vendor detections"
                    ),
                    evidence_ref=f"threat_intel:{ti.id}->artifact:{target_artifact_id}:sha256",
                    metadata={"malicious_votes": ti.malicious_votes},
                )
            )

    for event in incident.endpoint_events:
        for digest in (event.hashes or {}).values():
            for artifact in incident.artifacts:
                if digest.lower() == artifact.sha256.lower():
                    linkages.append(
                        LinkageItem(
                            source_type="endpoint_event",
                            source_id=event.id,
                            target_type="artifact",
                            target_id=artifact.id,
                            relation="ENDPOINT_HASH_MATCH",
                            description=(
                                f"Endpoint event {event.event_id} on "
                                f"{event.hostname or 'unknown host'} observed artifact "
                                f"'{artifact.filename}'"
                            ),
                            evidence_ref=f"endpoint_event:{event.id}->artifact:{artifact.id}:hash:{digest[:16]}",
                            metadata={
                                "hash": digest,
                                "hostname": event.hostname,
                                "image": event.image,
                            },
                        )
                    )
        for ioc in incident.iocs:
            observed = {event.destination_ip, event.destination_hostname}
            if ioc.normalized_value.lower().rstrip("/") in {
                str(v).lower().rstrip("/") for v in observed if v
            }:
                linkages.append(
                    LinkageItem(
                        source_type="endpoint_event",
                        source_id=event.id,
                        target_type="ioc",
                        target_id=ioc.id,
                        relation="ENDPOINT_NETWORK_IOC_MATCH",
                        description=(
                            f"Endpoint event {event.event_id} contacted "
                            f"{ioc.normalized_value}"
                        ),
                        evidence_ref=f"endpoint_event:{event.id}->ioc:{ioc.id}:net:{ioc.normalized_value}",
                        metadata={
                            "hostname": event.hostname,
                            "destination_port": event.destination_port,
                        },
                    )
                )

    # Process GUIDs are scoped to an endpoint. Exact GUID matching avoids PID reuse.
    process_index: dict[tuple[str, str], EndpointEvent] = {}
    for event in incident.endpoint_events:
        endpoint = event.endpoint_id or event.hostname
        if endpoint and event.process_guid:
            process_index[(endpoint.casefold(), event.process_guid.casefold())] = event
    seen_lineage: set[tuple[str, str]] = set()
    for child in incident.endpoint_events:
        endpoint = child.endpoint_id or child.hostname
        if not endpoint or not child.parent_process_guid:
            continue
        parent = process_index.get((endpoint.casefold(), child.parent_process_guid.casefold()))
        if parent is None or parent is child:
            continue
        parent_ref = str(parent.id if parent.id is not None else parent.fingerprint)
        child_ref = str(child.id if child.id is not None else child.fingerprint)
        pair = (parent_ref, child_ref)
        if pair in seen_lineage:
            continue
        seen_lineage.add(pair)
        linkages.append(
            LinkageItem(
                source_type="endpoint_event",
                source_id=parent.id if parent.id is not None else parent.fingerprint,
                target_type="endpoint_event",
                target_id=child.id if child.id is not None else child.fingerprint,
                relation="PROCESS_PARENT_CHILD",
                description=(
                    f"Process {child.process_guid} ({child.image or 'unknown image'}) was "
                    f"created by parent process {parent.process_guid} "
                    f"({parent.image or 'unknown image'}) on {endpoint}"
                ),
                evidence_ref=(
                    f"endpoint_event:{parent_ref}->endpoint_event:{child_ref}:parent_guid"
                ),
                metadata={
                    "endpoint_id": endpoint,
                    "parent_process_guid": parent.process_guid,
                    "child_process_guid": child.process_guid,
                    "parent_image": parent.image,
                    "child_image": child.image,
                    "parent_timestamp": _ensure_utc(parent.timestamp).isoformat(),
                    "child_timestamp": _ensure_utc(child.timestamp).isoformat(),
                },
            )
        )

    # Deterministic sort for 100% reproducible results
    linkages.sort(
        key=lambda lnk: (
            str(lnk.source_type),
            str(lnk.source_id),
            str(lnk.target_type),
            str(lnk.target_id),
            str(lnk.relation),
        )
    )
    return linkages


def compute_correlation_confidence(
    incident: Incident,
    linkages: list[LinkageItem],
) -> ConfidenceAssessment:
    score = 0.0
    reasons: list[str] = []
    missing_evidence: list[str] = []
    failed_evidence: list[str] = []
    score_breakdown: list[dict[str, Any]] = []

    has_email = len(incident.emails) > 0
    has_artifacts = len(incident.artifacts) > 0
    has_analyses = any(
        art.analysis is not None and art.analysis.status == "completed"
        for art in incident.artifacts
    )
    failed_analyses = [
        art.filename
        for art in incident.artifacts
        if art.analysis and art.analysis.status == "failed"
    ]
    has_iocs = len(incident.iocs) > 0
    successful_ti = [
        result for result in incident.threat_intel_results
        if str(result.query_status).upper() in {"SUCCESS", "COMPLETED"}
    ]
    cutoff = utc_now() - timedelta(days=30)
    stale_evidence: list[str] = []
    failed_ti = [
        result for result in incident.threat_intel_results
        if str(result.query_status).upper() not in {"SUCCESS", "COMPLETED"}
    ]
    for result in successful_ti:
        queried_at = _ensure_utc(result.queried_at)
        if queried_at < cutoff:
            stale_evidence.append(
                f"Threat intelligence for {result.ioc_type}:{result.normalized_value} "
                f"is stale (queried {queried_at.isoformat()})"
            )
    fresh_ti = [result for result in successful_ti if _ensure_utc(result.queried_at) >= cutoff]
    has_ti = bool(fresh_ti)
    if failed_ti:
        failed_evidence.extend(
            f"Threat intelligence unavailable for {result.ioc_type}:{result.normalized_value} "
            f"(status={result.query_status})"
            for result in failed_ti
        )
    endpoint_times = [_ensure_utc(event.timestamp) for event in incident.endpoint_events]
    if endpoint_times and max(endpoint_times) < cutoff:
        stale_evidence.append(
            f"Sysmon telemetry is stale (latest event {max(endpoint_times).isoformat()})"
        )
    ti_by_indicator: dict[tuple[str, str], set[bool]] = {}
    for result in successful_ti:
        key = (str(result.ioc_type).lower(), str(result.normalized_value).lower().rstrip("/"))
        ti_by_indicator.setdefault(key, set()).add(result.malicious_votes > 0)
    conflicting_evidence = [
        f"Threat intelligence sources conflict for {kind}:{value}"
        for (kind, value), verdicts in sorted(ti_by_indicator.items())
        if len(verdicts) > 1
    ]
    has_endpoint = len(incident.endpoint_events) > 0

    has_cross_links = any(
        lnk.relation in {"CORROBORATING_NETWORK_INDICATOR", "CORROBORATED_MALICIOUS_HASH"}
        for lnk in linkages
    )

    # 1. Email evidence
    if has_email:
        pts = 15.0
        score += pts
        reasons.append("Email evidence captured and metadata parsed (+15%)")
        score_breakdown.append(
            {
                "component": "EMAIL_INTAKE",
                "points": pts,
                "reason": "Email metadata and headers captured",
                "evidence_ref": f"emails:{[e.id for e in incident.emails]}",
            }
        )
    else:
        missing_evidence.append("Email evidence absent")

    # 2. Artifact attachments
    if has_artifacts:
        pts = 20.0
        score += pts
        reasons.append("Attachment artifact linkage established with digests (+20%)")
        score_breakdown.append(
            {
                "component": "ATTACHMENTS",
                "points": pts,
                "reason": "Attachment artifacts captured and verified with SHA-256 digests",
                "evidence_ref": f"artifacts:{[a.id for a in incident.artifacts]}",
            }
        )
    else:
        missing_evidence.append("Attachment artifacts absent")

    # 3. Static Analysis
    if has_analyses:
        pts = 20.0
        score += pts
        reasons.append("Static PE inspection and architectural analysis completed (+20%)")
        score_breakdown.append(
            {
                "component": "STATIC_ANALYSIS",
                "points": pts,
                "reason": "Static PE inspection and section analysis completed",
                "evidence_ref": f"analyses:{[a.id for a in incident.artifacts if a.analysis]}",
            }
        )
    elif has_artifacts:
        missing_evidence.append("Static PE inspection not yet performed")

    if failed_analyses:
        failed_evidence.append(
            f"Static PE analysis failed for artifact(s): {', '.join(failed_analyses)}"
        )

    # 4. Structured IOCs
    if has_iocs:
        pts = 15.0
        score += pts
        reasons.append("Structured IOCs extracted with source provenance (+15%)")
        score_breakdown.append(
            {
                "component": "IOC_EXTRACTION",
                "points": pts,
                "reason": "Structured IOCs extracted with source provenance",
                "evidence_ref": f"iocs_count:{len(incident.iocs)}",
            }
        )
    else:
        missing_evidence.append("Structured IOC records absent")

    # 5. Threat Intelligence
    if has_ti:
        pts = 15.0
        score += pts
        reasons.append("External threat intelligence queried and associated with IOCs (+15%)")
        score_breakdown.append(
            {
                "component": "THREAT_INTEL",
                "points": pts,
                "reason": "External reputation queried and associated with IOCs",
                "evidence_ref": f"threat_intel_count:{len(fresh_ti)}",
            }
        )
    else:
        missing_evidence.append("Threat intelligence not queried")

    # 6. Cross-source corroboration
    if has_cross_links:
        pts = 15.0
        score += pts
        reasons.append("Cross-source corroboration identified across multiple stages (+15%)")
        score_breakdown.append(
            {
                "component": "CROSS_STAGE_CORROBORATION",
                "points": pts,
                "reason": (
                    "Corroboration identified across email, static analysis, or threat intel stages"
                ),
                "evidence_ref": "linkages:cross_stage",
            }
        )

    if not has_endpoint:
        missing_evidence.append("Endpoint Sysmon telemetry not available for this incident")

    score = min(score, 100.0)

    if score >= 70.0:
        level = "HIGH"
    elif score >= 40.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    return ConfidenceAssessment(
        score=round(score, 2),
        level=level,
        reasons=reasons,
        missing_evidence=missing_evidence,
        failed_evidence=failed_evidence,
        stale_evidence=stale_evidence,
        conflicting_evidence=conflicting_evidence,
        score_breakdown=score_breakdown,
    )


def compute_incident_risk(incident: Incident) -> RiskAssessment:
    score = 0
    reasons: list[str] = []
    score_breakdown: list[dict[str, Any]] = []
    ti_cutoff = utc_now() - timedelta(days=30)
    usable_threat_intel = [
        result for result in incident.threat_intel_results
        if str(result.query_status).upper() in {"SUCCESS", "COMPLETED"}
        and _ensure_utc(result.queried_at) >= ti_cutoff
    ]
    usable_endpoint_events = [
        event for event in incident.endpoint_events
        if _ensure_utc(event.timestamp) >= ti_cutoff
    ]

    # 1. YARA Rule Matches - deduplicated by distinct rule name
    distinct_yara_matches: dict[str, list[tuple[int, str]]] = {}
    for art in incident.artifacts:
        if art.analysis and art.analysis.yara_matches:
            for match in art.analysis.yara_matches:
                rule_name = str(match.get("rule", "UnknownRule"))
                distinct_yara_matches.setdefault(rule_name, []).append((art.id, art.filename))

    yara_rule_order = sorted(distinct_yara_matches.keys())
    for idx, rule_name in enumerate(yara_rule_order):
        points = 25 if idx == 0 else 15
        if score + points > 40:
            points = max(0, 40 - score)
        if points > 0:
            score += points
            arts_info = distinct_yara_matches[rule_name]
            first_art_id, first_filename = arts_info[0]
            reason = (
                f"YARA rule '{rule_name}' matched on '{first_filename}' "
                f"(and {len(arts_info)-1} other artifact(s)) (+{points})"
                if len(arts_info) > 1
                else f"YARA rule '{rule_name}' matched on '{first_filename}' (+{points})"
            )
            reasons.append(reason)
            score_breakdown.append(
                {
                    "category": "YARA_RULE",
                    "points": points,
                    "reason": reason,
                    "evidence_ref": f"artifact:{first_art_id}:yara:{rule_name}",
                }
            )

    # 2. Known Malicious File Hashes - deduplicated by unique normalized digest
    distinct_file_hashes: dict[str, ThreatIntelResult] = {}
    for ti in usable_threat_intel:
        if ti.ioc_type.lower() in {"sha256", "md5", "sha1"}:
            norm = ti.normalized_value.lower()
            if norm not in distinct_file_hashes or (
                ti.malicious_votes > distinct_file_hashes[norm].malicious_votes
            ):
                distinct_file_hashes[norm] = ti

    for norm_hash, ti in sorted(distinct_file_hashes.items()):
        if ti.malicious_votes >= 5:
            pts = 30
            score += pts
            r = (
                f"VirusTotal flagged file hash '{ti.normalized_value[:16]}...' with "
                f"{ti.malicious_votes} malicious detections (+{pts})"
            )
            reasons.append(r)
            score_breakdown.append(
                {
                    "category": "MALICIOUS_HASH",
                    "points": pts,
                    "reason": r,
                    "evidence_ref": f"threat_intel:{ti.id}:hash:{norm_hash[:16]}",
                }
            )
        elif ti.malicious_votes >= 1 or (
            ti.reputation_score is not None and ti.reputation_score < -20
        ):
            pts = 15
            score += pts
            r = (
                f"VirusTotal identified suspicious file hash '{ti.normalized_value[:16]}...' "
                f"(votes: {ti.malicious_votes}, rep: {ti.reputation_score}) (+{pts})"
            )
            reasons.append(r)
            score_breakdown.append(
                {
                    "category": "SUSPICIOUS_HASH",
                    "points": pts,
                    "reason": r,
                    "evidence_ref": f"threat_intel:{ti.id}:hash:{norm_hash[:16]}",
                }
            )

    # 3. Malicious Network IOCs - deduplicated by unique indicator
    distinct_network_ti: dict[str, ThreatIntelResult] = {}
    for ti in usable_threat_intel:
        if ti.ioc_type.lower() in {"url", "domain", "ipv4", "ipv6"}:
            norm = ti.normalized_value.lower().rstrip("/")
            if norm not in distinct_network_ti or (
                ti.malicious_votes > distinct_network_ti[norm].malicious_votes
            ):
                distinct_network_ti[norm] = ti

    for norm_net, ti in sorted(distinct_network_ti.items()):
        if ti.malicious_votes >= 2:
            pts = 20
            score += pts
            r = (
                f"Threat intelligence flagged {ti.ioc_type} '{ti.normalized_value}' with "
                f"{ti.malicious_votes} malicious detections (+{pts})"
            )
            reasons.append(r)
            score_breakdown.append(
                {
                    "category": "MALICIOUS_NETWORK_IOC",
                    "points": pts,
                    "reason": r,
                    "evidence_ref": f"threat_intel:{ti.id}:ioc:{norm_net}",
                }
            )

    # 4. Static PE Anomalies: High Section Entropy (Packing)
    scored_entropy_artifacts: set[int] = set()
    for art in incident.artifacts:
        if art.analysis and art.analysis.is_pe and art.id not in scored_entropy_artifacts:
            for section in art.analysis.sections or []:
                entropy = float(section.get("entropy", 0.0))
                sec_name = str(section.get("name", "unknown"))
                if entropy > 7.0:
                    pts = 15
                    score += pts
                    scored_entropy_artifacts.add(art.id)
                    r = (
                        f"High Shannon entropy ({entropy:.2f}) in section '{sec_name}' "
                        f"of '{art.filename}', indicating packing or obfuscation (+{pts})"
                    )
                    reasons.append(r)
                    score_breakdown.append(
                        {
                            "category": "PACKING_ENTROPY",
                            "points": pts,
                            "reason": r,
                            "evidence_ref": f"artifact:{art.id}:section_entropy:{sec_name}",
                        }
                    )
                    break

    # 5. Suspicious Process Execution / Downloader API Imports
    scored_import_artifacts: set[int] = set()
    for art in incident.artifacts:
        if art.analysis and art.analysis.imports and art.id not in scored_import_artifacts:
            found_apis: list[str] = []
            for imp in art.analysis.imports or []:
                funcs = imp.get("functions", [])
                if isinstance(funcs, list):
                    for fn in funcs:
                        if isinstance(fn, str) and fn.lower() in SUSPICIOUS_IMPORT_APIS:
                            found_apis.append(fn)
            if found_apis:
                pts = 15
                score += pts
                scored_import_artifacts.add(art.id)
                apis_str = ", ".join(sorted(set(found_apis))[:5])
                r = (
                    f"Suspicious execution/download APIs imported in '{art.filename}': "
                    f"{apis_str} (+{pts})"
                )
                reasons.append(r)
                score_breakdown.append(
                    {
                        "category": "SUSPICIOUS_IMPORTS",
                        "points": pts,
                        "reason": r,
                        "evidence_ref": f"artifact:{art.id}:imports",
                    }
                )

    # 6. Phishing Indicators in Email - deduplicated per email
    for email in incident.emails:
        has_exec = any(
            art.filename.lower().endswith((".exe", ".dll", ".vbs", ".ps1", ".bat", ".scr", ".bin"))
            for art in email.artifacts
        )
        if (email.urls or email.domains) and has_exec:
            pts = 10
            score += pts
            subj = email.subject or "No Subject"
            r = (
                f"Phishing indicator: email '{subj}' contains embedded links "
                f"and executable attachments (+{pts})"
            )
            reasons.append(r)
            score_breakdown.append(
                {
                    "category": "PHISHING_INDICATOR",
                    "points": pts,
                    "reason": r,
                    "evidence_ref": f"email:{email.id}:phishing_indicator",
                }
            )

    # 7. Endpoint Telemetry Hash Matches - deduplicated by unique artifact hash & host observation
    unique_endpoint_hash_matches: set[tuple[str, str, str]] = set()
    for event in usable_endpoint_events:
        for digest in event.hashes.values():
            for artifact in incident.artifacts:
                if digest.lower() == artifact.sha256.lower():
                    key = (
                        artifact.sha256.lower(),
                        str(event.endpoint_id or event.hostname or "unknown_host"),
                        str(event.image or "unknown_image"),
                    )
                    unique_endpoint_hash_matches.add(key)

    endpoint_hash_count = len(unique_endpoint_hash_matches)
    if endpoint_hash_count > 0:
        points = min(25, endpoint_hash_count * 15)
        score += points
        r = (
            f"Endpoint telemetry observed execution or file activity matching "
            f"{endpoint_hash_count} distinct artifact hash instance(s) (+{points})"
        )
        reasons.append(r)
        score_breakdown.append(
            {
                "category": "ENDPOINT_HASH_MATCH",
                "points": points,
                "reason": r,
                "evidence_ref": f"endpoint_events:hash_matches:{endpoint_hash_count}",
            }
        )

    # 8. Endpoint Telemetry Network IOC Matches - deduplicated by unique IOC & destination
    unique_endpoint_net_matches: set[tuple[str, str, str]] = set()
    for event in usable_endpoint_events:
        observed = {event.destination_ip, event.destination_hostname}
        for ioc in incident.iocs:
            norm_val = ioc.normalized_value.lower().rstrip("/")
            if norm_val in {str(v).lower().rstrip("/") for v in observed if v}:
                key = (
                    norm_val,
                    str(event.endpoint_id or event.hostname or "unknown_host"),
                    str(event.destination_ip or event.destination_hostname or "unknown_dest"),
                )
                unique_endpoint_net_matches.add(key)

    endpoint_net_count = len(unique_endpoint_net_matches)
    if endpoint_net_count > 0:
        points = min(20, endpoint_net_count * 10)
        score += points
        r = (
            f"Endpoint telemetry contacted {endpoint_net_count} distinct network IOC instance(s) "
            f"(+{points})"
        )
        reasons.append(r)
        score_breakdown.append(
            {
                "category": "ENDPOINT_NETWORK_MATCH",
                "points": points,
                "reason": r,
                "evidence_ref": f"endpoint_events:network_matches:{endpoint_net_count}",
            }
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

    return RiskAssessment(
        score=score,
        level=level,
        reasons=reasons,
        score_breakdown=score_breakdown,
    )


def generate_incident_timeline(incident: Incident) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []

    # 1. Endpoint Events (Sysmon)
    for endpoint_event in incident.endpoint_events:
        event_names = {
            1: "PROCESS_CREATED",
            3: "NETWORK_CONNECTION",
            11: "FILE_CREATED",
            12: "REGISTRY_OBJECT_CREATED",
            13: "REGISTRY_VALUE_SET",
            14: "REGISTRY_OBJECT_RENAMED",
        }
        prov = normalize_endpoint_timestamp(endpoint_event.timestamp, endpoint_event.created_at)
        events.append(
            TimelineEvent(
                incident_id=incident.id,
                timestamp=prov.normalized_utc,
                event_type=event_names.get(endpoint_event.event_id, "ENDPOINT_EVENT"),
                source="sysmon",
                description=(
                    f"Sysmon Event ID {endpoint_event.event_id} on "
                    f"{endpoint_event.hostname or 'unknown host'}"
                ),
                event_data={
                    "endpoint_event_id": endpoint_event.id,
                    "event_id": endpoint_event.event_id,
                    "hostname": endpoint_event.hostname,
                    "endpoint_id": endpoint_event.endpoint_id,
                    "image": endpoint_event.image,
                    "destination_ip": endpoint_event.destination_ip,
                    "destination_hostname": endpoint_event.destination_hostname,
                    "destination_port": endpoint_event.destination_port,
                    "fingerprint": endpoint_event.fingerprint,
                    "original_timestamp": prov.original_timestamp,
                    "timestamp_source": prov.source,
                    "timezone": prov.timezone_name,
                    "normalization_method": prov.normalization_method,
                    "fallback_reason": prov.fallback_reason,
                    "is_uncertain": prov.is_uncertain,
                    "clock_skew_flag": prov.clock_skew_flag,
                },
            )
        )

    # 2. Emails
    for email in incident.emails:
        prov = normalize_email_timestamp(email.sent_at, email.created_at)
        subj = email.subject or "No Subject"
        sender = email.sender or "unknown"
        events.append(
            TimelineEvent(
                incident_id=incident.id,
                timestamp=prov.normalized_utc,
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
                    "original_timestamp": prov.original_timestamp,
                    "timestamp_source": prov.source,
                    "timezone": prov.timezone_name,
                    "normalization_method": prov.normalization_method,
                    "fallback_reason": prov.fallback_reason,
                    "is_uncertain": prov.is_uncertain,
                    "clock_skew_flag": prov.clock_skew_flag,
                },
            )
        )

    # 3. Attachments & PE Compilation Timestamps
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
                event_data={
                    "filename": art.filename,
                    "size": art.size,
                    "sha256": art.sha256,
                    "original_timestamp": art.created_at.isoformat() if art.created_at else None,
                    "timestamp_source": "artifact_creation_time",
                    "normalization_method": "db_utc_conversion",
                    "is_uncertain": False,
                },
            )
        )

        analysis = art.analysis
        if analysis:
            time_stamp_val = (analysis.pe_headers or {}).get("time_date_stamp")
            if time_stamp_val:
                pe_prov = normalize_pe_timestamp(time_stamp_val, art.created_at)
                events.append(
                    TimelineEvent(
                        incident_id=incident.id,
                        timestamp=pe_prov.normalized_utc,
                        event_type="PE_COMPILED",
                        source="pe_header",
                        description=(
                            f"PE binary compilation header for '{art.filename}': "
                            f"{pe_prov.normalized_utc.isoformat()}"
                        ),
                        artifact_id=art.id,
                        event_data={
                            "time_date_stamp": time_stamp_val,
                            "original_timestamp": pe_prov.original_timestamp,
                            "timestamp_source": pe_prov.source,
                            "normalization_method": pe_prov.normalization_method,
                            "fallback_reason": pe_prov.fallback_reason,
                            "is_uncertain": pe_prov.is_uncertain,
                            "clock_skew_flag": pe_prov.clock_skew_flag,
                        },
                    )
                )

            analysis_time = _ensure_utc(analysis.created_at)
            events.append(
                TimelineEvent(
                    incident_id=incident.id,
                    timestamp=analysis_time,
                    event_type="STATIC_ANALYSIS_COMPLETED",
                    source="pe_static_analysis",
                    description=(
                        f"Static PE analysis completed for '{art.filename}': "
                        f"status={analysis.status}, sections={len(analysis.sections or [])}, "
                        f"imports={len(analysis.imports or [])}"
                    ),
                    artifact_id=art.id,
                    event_data={
                        "status": analysis.status,
                        "is_pe": analysis.is_pe,
                        "sections_count": len(analysis.sections or []),
                        "timestamp_source": "analysis_completion_time",
                        "is_uncertain": False,
                    },
                )
            )

            for match in analysis.yara_matches or []:
                rule_name = str(match.get("rule", "UnknownRule"))
                events.append(
                    TimelineEvent(
                        incident_id=incident.id,
                        timestamp=analysis_time,
                        event_type="YARA_MATCH",
                        source="yara_scanner",
                        description=f"YARA rule '{rule_name}' triggered on '{art.filename}'",
                        artifact_id=art.id,
                        event_data={
                            "rule": rule_name,
                            "tags": match.get("tags", []),
                            "timestamp_source": "yara_scan_time",
                            "is_uncertain": False,
                        },
                    )
                )

    # 4. IOC extractions
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
                event_data={
                    "ioc_type": ioc.ioc_type,
                    "value": ioc.normalized_value,
                    "timestamp_source": "ioc_extraction_time",
                    "is_uncertain": False,
                },
            )
        )

    # 5. Threat Intelligence Queries
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
                    "timestamp_source": "threat_intel_query_time",
                    "is_uncertain": False,
                },
            )
        )

    # 6. Chronological Sort with deterministic tie-breaking
    events.sort(key=lambda ev: (ev.timestamp, str(ev.event_type), str(ev.source)))
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

    score_breakdown = {
        "risk": risk.score_breakdown,
        "confidence": confidence.score_breakdown,
        "failed_evidence": confidence.failed_evidence,
        "stale_evidence": confidence.stale_evidence,
        "conflicting_evidence": confidence.conflicting_evidence,
    }

    corr_record = (
        db.execute(select(CorrelationResult).where(CorrelationResult.incident_id == incident_id))
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
            algorithm_version=CORRELATION_ALGORITHM_VERSION,
            scoring_version=SCORING_ALGORITHM_VERSION,
            missing_evidence=confidence.missing_evidence,
            score_breakdown=score_breakdown,
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
        corr_record.algorithm_version = CORRELATION_ALGORITHM_VERSION
        corr_record.scoring_version = SCORING_ALGORITHM_VERSION
        corr_record.missing_evidence = confidence.missing_evidence
        corr_record.score_breakdown = score_breakdown
        corr_record.updated_at = now

    # Refresh Timeline Events
    db.execute(delete(TimelineEvent).where(TimelineEvent.incident_id == incident_id))
    timeline_events = generate_incident_timeline(incident)

    # Final timeline event for correlation assessment
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
                "algorithm_version": CORRELATION_ALGORITHM_VERSION,
                "scoring_version": SCORING_ALGORITHM_VERSION,
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
        algorithm_version=corr_record.algorithm_version,
        scoring_version=corr_record.scoring_version,
        missing_evidence=corr_record.missing_evidence,
        score_breakdown=corr_record.score_breakdown,
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

    if not events:
        events = generate_incident_timeline(incident)

    return events
