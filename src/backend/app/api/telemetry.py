from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    AuthenticatedUser,
    ensure_incident_access,
    get_current_user,
    require_role,
)
from app.db import get_db
from app.models import EndpointEvent, Incident
from app.schemas import EndpointEventRead, TelemetryUploadResponse
from app.services.sysmon_ingestion import ingest_payload

router = APIRouter(prefix="/telemetry", tags=["telemetry"])
DB_SESSION = Depends(get_db)


@router.post("/upload", response_model=TelemetryUploadResponse)
async def upload_telemetry(
    request: Request,
    incident_id: int | None = Query(default=None),
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(require_role("analyst")),
) -> TelemetryUploadResponse:
    if incident_id is not None:
        incident = db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        ensure_incident_access(incident, user)
    payload = bytearray()
    async for chunk in request.stream():
        payload.extend(chunk)
        if len(payload) > settings.max_telemetry_size_bytes:
            raise HTTPException(
                status_code=413, detail="Telemetry payload exceeds configured size limit"
            )
    try:
        records, duplicates = ingest_payload(
            db, bytes(payload), request.headers.get("content-type"), incident_id
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return TelemetryUploadResponse(
        ingested_count=len(records) - duplicates,
        duplicate_count=duplicates,
        unassociated_count=sum(record.incident_id is None for record in records),
        events=records,
    )


@router.get("/incidents/{incident_id}", response_model=list[EndpointEventRead])
def get_incident_telemetry(
    incident_id: int,
    db: Session = DB_SESSION,
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> list[EndpointEvent]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    ensure_incident_access(incident, user)
    return list(
        db.execute(
            select(EndpointEvent)
            .where(EndpointEvent.incident_id == incident_id)
            .order_by(EndpointEvent.timestamp.asc(), EndpointEvent.fingerprint.asc())
        ).scalars()
    )
