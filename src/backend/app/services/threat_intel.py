from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Artifact, Incident, IOCRecord, ThreatIntelResult
from app.services.virustotal_client import VirusTotalClient, VTLookupResult

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _find_recent_db_result(
    db: Session,
    ioc_type: str,
    normalized_value: str,
    incident_id: int | None = None,
) -> ThreatIntelResult | None:
    stmt = (
        select(ThreatIntelResult)
        .where(
            ThreatIntelResult.ioc_type == ioc_type,
            ThreatIntelResult.normalized_value == normalized_value,
        )
        .order_by(ThreatIntelResult.queried_at.desc())
    )
    if incident_id is not None:
        stmt = stmt.where(ThreatIntelResult.incident_id == incident_id)

    existing = db.execute(stmt).scalars().first()
    if existing is None:
        return None

    queried_at = existing.queried_at
    if queried_at.tzinfo is None:
        queried_at = queried_at.replace(tzinfo=timezone.utc)

    age = (utc_now() - queried_at).total_seconds()
    if age < settings.vt_cache_ttl_seconds:
        return existing
    return None


def enrich_single_ioc(
    *,
    db: Session,
    ioc: IOCRecord,
    vt_client: VirusTotalClient,
    force_refresh: bool = False,
) -> ThreatIntelResult:
    if not force_refresh:
        cached = _find_recent_db_result(
            db=db,
            ioc_type=ioc.ioc_type,
            normalized_value=ioc.normalized_value,
            incident_id=ioc.incident_id,
        )
        if cached is not None:
            logger.debug(
                "Using existing fresh ThreatIntelResult for IOC %s:%s",
                ioc.ioc_type,
                ioc.normalized_value,
            )
            # Ensure artifact_id is populated on cached record if newly discovered under an artifact
            if cached.artifact_id is None and ioc.artifact_id is not None:
                cached.artifact_id = ioc.artifact_id
                db.commit()
                db.refresh(cached)
            return cached

    vt_res: VTLookupResult = vt_client.lookup_ioc(ioc.ioc_type, ioc.normalized_value)

    record = ThreatIntelResult(
        incident_id=ioc.incident_id,
        artifact_id=ioc.artifact_id,
        ioc_id=ioc.id,
        ioc_type=vt_res.ioc_type,
        ioc_value=vt_res.ioc_value,
        normalized_value=vt_res.normalized_value,
        provider=vt_res.provider,
        query_status=vt_res.query_status,
        reputation_score=vt_res.reputation_score,
        malicious_votes=vt_res.malicious_votes,
        suspicious_votes=vt_res.suspicious_votes,
        harmless_votes=vt_res.harmless_votes,
        undetected_votes=vt_res.undetected_votes,
        total_engines=vt_res.total_engines,
        detection_details=vt_res.detection_details,
        raw_response=vt_res.raw_response,
        queried_at=vt_res.queried_at,
    )
    if vt_res.malicious_votes > 0 or vt_res.suspicious_votes > 0:
        ioc.classification = "intelligence_supported"
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def enrich_incident_iocs(
    *,
    db: Session,
    incident_id: int,
    vt_client: VirusTotalClient,
    ioc_types: Sequence[str] | None = None,
) -> list[ThreatIntelResult]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        return []

    target_types = set(
        [t.lower() for t in ioc_types]
        if ioc_types
        else ["sha256", "md5", "sha1", "url", "domain", "ipv4"]
    )

    eligible_iocs = [
        ioc for ioc in incident.iocs if ioc.ioc_type.lower() in target_types
    ]

    results: list[ThreatIntelResult] = []
    # Deduplicate IOCs by (ioc_type, normalized_value) during batch enrichment
    seen: set[tuple[str, str]] = set()

    for ioc in eligible_iocs:
        key = (ioc.ioc_type.lower(), ioc.normalized_value)
        if key in seen:
            continue
        seen.add(key)
        try:
            res = enrich_single_ioc(db=db, ioc=ioc, vt_client=vt_client)
            results.append(res)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error enriching IOC %s: %s", ioc.normalized_value, exc)

    return results


def enrich_artifact_iocs(
    *,
    db: Session,
    artifact_id: int,
    vt_client: VirusTotalClient,
) -> list[ThreatIntelResult]:
    artifact = db.get(Artifact, artifact_id)
    if artifact is None:
        return []

    results: list[ThreatIntelResult] = []
    target_types = {"sha256", "md5", "sha1", "url", "domain", "ipv4"}
    seen: set[tuple[str, str]] = set()

    for ioc in artifact.iocs:
        if ioc.ioc_type.lower() not in target_types:
            continue
        key = (ioc.ioc_type.lower(), ioc.normalized_value)
        if key in seen:
            continue
        seen.add(key)
        try:
            res = enrich_single_ioc(db=db, ioc=ioc, vt_client=vt_client)
            results.append(res)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error enriching artifact IOC %s: %s", ioc.normalized_value, exc)

    return results
