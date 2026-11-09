from __future__ import annotations

from typing import Sequence

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import EndpointEvent, Incident
from app.schemas import (
    ConfidenceAssessment,
    CorrelationResponse,
    EndpointEventRead,
    IncidentCreate,
    IncidentRead,
    IOCRecordRead,
    LinkageItem,
    RiskAssessment,
    TimelineEventRead,
)
from app.services.correlation_engine import (
    get_incident_timeline_events,
    run_incident_correlation,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])
DB_SESSION = Depends(get_db)


def _get_incident_or_404(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


@router.post("", response_model=IncidentRead)
def create_incident(payload: IncidentCreate, db: Session = DB_SESSION) -> Incident:
    incident = Incident(title=payload.title, description=payload.description)
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(incident_id: int, db: Session = DB_SESSION) -> Incident:
    return _get_incident_or_404(db, incident_id)


@router.get("/{incident_id}/iocs", response_model=list[IOCRecordRead])
def get_incident_iocs(incident_id: int, db: Session = DB_SESSION) -> list[IOCRecordRead]:
    incident = _get_incident_or_404(db, incident_id)
    return incident.iocs


@router.post("/{incident_id}/correlate", response_model=CorrelationResponse)
def correlate_incident(incident_id: int, db: Session = DB_SESSION) -> CorrelationResponse:
    _get_incident_or_404(db, incident_id)
    return run_incident_correlation(db=db, incident_id=incident_id)


@router.get("/{incident_id}/correlations", response_model=CorrelationResponse)
def get_incident_correlations(incident_id: int, db: Session = DB_SESSION) -> CorrelationResponse:
    incident = _get_incident_or_404(db, incident_id)
    corr = incident.correlation_result
    if corr is None:
        return run_incident_correlation(db=db, incident_id=incident_id)

    linkage_items = [LinkageItem(**item) for item in corr.linkages]
    return CorrelationResponse(
        incident_id=incident.id,
        confidence=ConfidenceAssessment(
            score=corr.confidence_score,
            level=corr.confidence_level,
            reasons=corr.confidence_reasons,
        ),
        risk=RiskAssessment(
            score=corr.risk_score,
            level=corr.risk_level,
            reasons=corr.risk_reasons,
        ),
        linkages=linkage_items,
        created_at=corr.created_at,
    )


@router.get("/{incident_id}/timeline", response_model=list[TimelineEventRead])
def get_incident_timeline(
    incident_id: int,
    db: Session = DB_SESSION,
) -> Sequence[TimelineEventRead]:
    _get_incident_or_404(db, incident_id)
    events = get_incident_timeline_events(db=db, incident_id=incident_id)
    return [
        TimelineEventRead(
            id=ev.id,
            incident_id=ev.incident_id,
            timestamp=ev.timestamp,
            event_type=ev.event_type,
            source=ev.source,
            description=ev.description,
            artifact_id=ev.artifact_id,
            ioc_id=ev.ioc_id,
            event_data=ev.event_data,
            created_at=ev.created_at,
        )
        for ev in events
    ]


@router.get("/{incident_id}/telemetry", response_model=list[EndpointEventRead])
def get_incident_endpoint_telemetry(
    incident_id: int,
    db: Session = DB_SESSION,
) -> list[EndpointEvent]:
    _get_incident_or_404(db, incident_id)
    return list(
        db.query(EndpointEvent)
        .filter(EndpointEvent.incident_id == incident_id)
        .order_by(EndpointEvent.timestamp.asc(), EndpointEvent.fingerprint.asc())
        .all()
    )
