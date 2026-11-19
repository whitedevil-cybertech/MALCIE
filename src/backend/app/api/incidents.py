from __future__ import annotations

from typing import Sequence

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.security import AuthenticatedUser, get_current_user, require_role
from app.db import get_db
from app.models import EndpointEvent, Incident, InvestigationReport
from app.schemas import (
    ConfidenceAssessment,
    CorrelationResponse,
    EndpointEventRead,
    IncidentCreate,
    IncidentListResponse,
    IncidentRead,
    IOCRecordRead,
    LinkageItem,
    ReportCreateRequest,
    ReportDetailRead,
    ReportRead,
    RiskAssessment,
    TimelineEventRead,
)
from app.services.correlation_engine import (
    get_incident_timeline_events,
    run_incident_correlation,
)
from app.services.investigation_reports import create_investigation_report, render_report_pdf

router = APIRouter(prefix="/incidents", tags=["incidents"])
DB_SESSION = Depends(get_db)


def _get_incident_or_404(
    db: Session, incident_id: int, user: AuthenticatedUser | None = None
) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if user and user.id is not None and user.role != "admin" and incident.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Incident access denied")
    return incident


@router.post("", response_model=IncidentRead)
def create_incident(
    payload: IncidentCreate,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(require_role("analyst")),
) -> Incident:
    incident = Incident(
        title=payload.title, description=payload.description, owner_id=user.id if user else None
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    search: str | None = Query(None, max_length=255),
    status_filter: str | None = Query(None, alias="status", max_length=50),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> IncidentListResponse:
    query = select(Incident)
    count_query = select(func.count()).select_from(Incident)
    if user and user.id is not None and user.role != "admin":
        query = query.where(Incident.owner_id == user.id)
        count_query = count_query.where(Incident.owner_id == user.id)
    if search:
        pattern = f"%{search.strip()}%"
        predicate = or_(Incident.title.ilike(pattern), Incident.description.ilike(pattern))
        query = query.where(predicate)
        count_query = count_query.where(predicate)
    if status_filter:
        query = query.where(Incident.status == status_filter)
        count_query = count_query.where(Incident.status == status_filter)
    total = db.scalar(count_query) or 0
    items = list(
        db.scalars(
            query.order_by(Incident.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    pages = (total + page_size - 1) // page_size
    return IncidentListResponse(
        items=items, total=total, page=page, page_size=page_size, pages=pages
    )


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(
    incident_id: int,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> Incident:
    return _get_incident_or_404(db, incident_id, user)


@router.get("/{incident_id}/iocs", response_model=list[IOCRecordRead])
def get_incident_iocs(
    incident_id: int,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> list[IOCRecordRead]:
    incident = _get_incident_or_404(db, incident_id, user)
    return incident.iocs


@router.post("/{incident_id}/correlate", response_model=CorrelationResponse)
def correlate_incident(
    incident_id: int,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(require_role("analyst")),
) -> CorrelationResponse:
    _get_incident_or_404(db, incident_id, user)
    return run_incident_correlation(db=db, incident_id=incident_id)


@router.get("/{incident_id}/correlations", response_model=CorrelationResponse)
def get_incident_correlations(
    incident_id: int,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> CorrelationResponse:
    incident = _get_incident_or_404(db, incident_id, user)
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
            missing_evidence=corr.missing_evidence,
            failed_evidence=corr.score_breakdown.get("failed_evidence", []),
            stale_evidence=corr.score_breakdown.get("stale_evidence", []),
            conflicting_evidence=corr.score_breakdown.get("conflicting_evidence", []),
            score_breakdown=corr.score_breakdown.get("confidence", []),
        ),
        risk=RiskAssessment(
            score=corr.risk_score,
            level=corr.risk_level,
            reasons=corr.risk_reasons,
            score_breakdown=corr.score_breakdown.get("risk", []),
        ),
        linkages=linkage_items,
        algorithm_version=corr.algorithm_version,
        scoring_version=corr.scoring_version,
        missing_evidence=corr.missing_evidence,
        score_breakdown=corr.score_breakdown,
        created_at=corr.created_at,
    )


@router.get("/{incident_id}/timeline", response_model=list[TimelineEventRead])
def get_incident_timeline(
    incident_id: int,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> Sequence[TimelineEventRead]:
    _get_incident_or_404(db, incident_id, user)
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
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> list[EndpointEvent]:
    _get_incident_or_404(db, incident_id, user)
    return list(
        db.query(EndpointEvent)
        .filter(EndpointEvent.incident_id == incident_id)
        .order_by(EndpointEvent.timestamp.asc(), EndpointEvent.fingerprint.asc())
        .all()
    )


@router.post("/{incident_id}/reports", response_model=ReportDetailRead, status_code=201)
def create_report(
    incident_id: int,
    payload: ReportCreateRequest,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(require_role("analyst")),
) -> InvestigationReport:
    incident = _get_incident_or_404(db, incident_id, user)
    return create_investigation_report(
        db, incident, author_id=user.id if user else None,
        author_email=user.email if user else "development-anonymous",
        title=payload.title, summary=payload.summary, disposition=payload.disposition,
    )


@router.get("/{incident_id}/reports", response_model=list[ReportRead])
def list_reports(
    incident_id: int,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> list[InvestigationReport]:
    _get_incident_or_404(db, incident_id, user)
    return list(db.scalars(
        select(InvestigationReport).where(InvestigationReport.incident_id == incident_id)
        .order_by(InvestigationReport.version.desc())
    ))


@router.get("/{incident_id}/reports/{report_id}", response_model=ReportDetailRead)
def get_report(
    incident_id: int,
    report_id: str,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> InvestigationReport:
    _get_incident_or_404(db, incident_id, user)
    report = db.scalar(select(InvestigationReport).where(
        InvestigationReport.report_id == report_id,
        InvestigationReport.incident_id == incident_id,
    ))
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{incident_id}/reports/{report_id}/pdf")
def get_report_pdf(
    incident_id: int,
    report_id: str,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> Response:
    report = get_report(incident_id, report_id, db, user)
    return Response(
        content=render_report_pdf(report), media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="malcie-report-v{report.version}.pdf"'
        },
    )
