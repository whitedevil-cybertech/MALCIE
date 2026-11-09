from __future__ import annotations

import logging
from typing import Sequence

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Artifact, Incident, ThreatIntelResult
from app.schemas import (
    IncidentEnrichRequest,
    ThreatIntelLookupRequest,
    ThreatIntelResultRead,
)
from app.services.threat_intel import (
    enrich_artifact_iocs,
    enrich_incident_iocs,
)
from app.services.virustotal_client import (
    VirusTotalClient,
    get_virustotal_client,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["threat-intel"])
DB_SESSION = Depends(get_db)
VT_SERVICE = Depends(get_virustotal_client)


def _get_incident_or_404(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    return incident


def _get_artifact_or_404(db: Session, artifact_id: int) -> Artifact:
    artifact = db.get(Artifact, artifact_id)
    if artifact is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )
    return artifact


@router.post(
    "/incidents/{incident_id}/enrich",
    response_model=list[ThreatIntelResultRead],
    status_code=status.HTTP_200_OK,
)
def enrich_incident(
    incident_id: int,
    payload: IncidentEnrichRequest | None = None,
    db: Session = DB_SESSION,
    vt_client: VirusTotalClient = VT_SERVICE,
) -> Sequence[ThreatIntelResult]:
    _get_incident_or_404(db, incident_id)
    ioc_types = payload.ioc_types if payload else None
    results = enrich_incident_iocs(
        db=db,
        incident_id=incident_id,
        vt_client=vt_client,
        ioc_types=ioc_types,
    )
    return results


@router.get(
    "/incidents/{incident_id}/threat-intel",
    response_model=list[ThreatIntelResultRead],
)
def get_incident_threat_intel(
    incident_id: int,
    db: Session = DB_SESSION,
) -> Sequence[ThreatIntelResult]:
    _get_incident_or_404(db, incident_id)
    stmt = (
        select(ThreatIntelResult)
        .where(ThreatIntelResult.incident_id == incident_id)
        .order_by(ThreatIntelResult.queried_at.desc())
    )
    return db.execute(stmt).scalars().all()


@router.post(
    "/artifacts/{artifact_id}/enrich",
    response_model=list[ThreatIntelResultRead],
    status_code=status.HTTP_200_OK,
)
def enrich_artifact(
    artifact_id: int,
    db: Session = DB_SESSION,
    vt_client: VirusTotalClient = VT_SERVICE,
) -> Sequence[ThreatIntelResult]:
    _get_artifact_or_404(db, artifact_id)
    results = enrich_artifact_iocs(
        db=db,
        artifact_id=artifact_id,
        vt_client=vt_client,
    )
    return results


@router.get(
    "/artifacts/{artifact_id}/threat-intel",
    response_model=list[ThreatIntelResultRead],
)
def get_artifact_threat_intel(
    artifact_id: int,
    db: Session = DB_SESSION,
) -> Sequence[ThreatIntelResult]:
    _get_artifact_or_404(db, artifact_id)
    stmt = (
        select(ThreatIntelResult)
        .where(ThreatIntelResult.artifact_id == artifact_id)
        .order_by(ThreatIntelResult.queried_at.desc())
    )
    return db.execute(stmt).scalars().all()


@router.post(
    "/threat-intel/lookup",
    response_model=ThreatIntelResultRead,
)
def adhoc_threat_intel_lookup(
    payload: ThreatIntelLookupRequest,
    vt_client: VirusTotalClient = VT_SERVICE,
) -> ThreatIntelResultRead:
    res = vt_client.lookup_ioc(ioc_type=payload.ioc_type, value=payload.value)
    return ThreatIntelResultRead(
        id=0,
        incident_id=0,
        artifact_id=None,
        ioc_id=None,
        ioc_type=res.ioc_type,
        ioc_value=res.ioc_value,
        normalized_value=res.normalized_value,
        provider=res.provider,
        query_status=res.query_status,
        reputation_score=res.reputation_score,
        malicious_votes=res.malicious_votes,
        suspicious_votes=res.suspicious_votes,
        harmless_votes=res.harmless_votes,
        undetected_votes=res.undetected_votes,
        total_engines=res.total_engines,
        detection_details=res.detection_details,
        queried_at=res.queried_at,
        created_at=res.queried_at,
    )
