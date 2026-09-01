from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Artifact, EmailEvidence, Incident
from app.schemas import (
    EmailEvidenceRead,
    GraphAuthUrlResponse,
    GraphEmailIngestRequest,
    GraphTokenExchangeRequest,
    GraphTokenResponse,
)
from app.services.email_intake import (
    hash_bytes,
    parse_eml_bytes,
    store_evidence_blob,
    validate_eml_upload,
)
from app.services.graph_client import GraphClient, get_graph_client

router = APIRouter(prefix="/emails", tags=["emails"])
DB_SESSION = Depends(get_db)
GRAPH_SERVICE = Depends(get_graph_client)


def _get_incident_or_404(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def _persist_email_evidence(
    *,
    db: Session,
    incident_id: int,
    source: str,
    eml_content: bytes,
    original_name: str,
    graph_message_id: str | None = None,
) -> EmailEvidence:
    parsed = parse_eml_bytes(eml_content)
    raw_email_hash = hash_bytes(eml_content)
    raw_email_path = store_evidence_blob(
        subdirectory="emails",
        filename=f"{raw_email_hash}.eml",
        content=eml_content,
    )

    email_record = EmailEvidence(
        incident_id=incident_id,
        source=source,
        graph_message_id=graph_message_id,
        sender=parsed.sender,
        recipients=parsed.recipients,
        subject=parsed.subject,
        sent_at=parsed.sent_at,
        message_id=parsed.message_id,
        headers=parsed.headers,
        urls=parsed.urls,
        domains=parsed.domains,
        body_preview=parsed.body_preview,
        raw_email_sha256=raw_email_hash,
        raw_email_path=str(raw_email_path),
    )
    db.add(email_record)
    db.flush()

    for index, attachment in enumerate(parsed.attachments, start=1):
        attachment_path = store_evidence_blob(
            subdirectory=f"attachments_{email_record.id}",
            filename=f"{index}_{attachment.sha256}.bin",
            content=attachment.payload,
        )
        db.add(
            Artifact(
                incident_id=incident_id,
                email_id=email_record.id,
                filename=attachment.filename,
                content_type=attachment.content_type,
                size=len(attachment.payload),
                sha256=attachment.sha256,
                storage_path=str(attachment_path),
            )
        )

    db.commit()
    db.refresh(email_record)
    return email_record


@router.get("/graph/auth-url", response_model=GraphAuthUrlResponse)
def graph_auth_url(
    redirect_uri: str,
    graph_client: GraphClient = GRAPH_SERVICE,
) -> GraphAuthUrlResponse:
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri is required")
    auth_url, state = graph_client.build_auth_url(redirect_uri=redirect_uri)
    return GraphAuthUrlResponse(auth_url=auth_url, state=state)


@router.post("/graph/oauth/token", response_model=GraphTokenResponse)
def graph_exchange_token(
    payload: GraphTokenExchangeRequest,
    graph_client: GraphClient = GRAPH_SERVICE,
) -> GraphTokenResponse:
    token_payload = graph_client.exchange_code_for_token(
        code=payload.code,
        redirect_uri=payload.redirect_uri,
    )
    return GraphTokenResponse(**token_payload)


@router.post("/upload-eml", response_model=EmailEvidenceRead, status_code=status.HTTP_201_CREATED)
def upload_eml(
    incident_id: int = Form(...),  # noqa: B008
    eml_file: UploadFile = File(...),  # noqa: B008
    db: Session = DB_SESSION,
) -> EmailEvidence:
    _get_incident_or_404(db, incident_id)
    eml_content = eml_file.file.read()
    validate_eml_upload(eml_file, eml_content)
    return _persist_email_evidence(
        db=db,
        incident_id=incident_id,
        source="manual_eml",
        eml_content=eml_content,
        original_name=eml_file.filename or "email.eml",
    )


@router.post(
    "/graph/messages/{message_id}/ingest",
    response_model=EmailEvidenceRead,
    status_code=status.HTTP_201_CREATED,
)
def ingest_graph_message(
    message_id: str,
    payload: GraphEmailIngestRequest,
    db: Session = DB_SESSION,
    graph_client: GraphClient = GRAPH_SERVICE,
) -> EmailEvidence:
    _get_incident_or_404(db, payload.incident_id)
    graph_message = graph_client.get_message_eml(
        access_token=payload.access_token,
        message_id=message_id,
    )
    if not graph_message.eml_content:
        raise HTTPException(status_code=400, detail="Retrieved message is empty")
    return _persist_email_evidence(
        db=db,
        incident_id=payload.incident_id,
        source="microsoft_graph",
        eml_content=graph_message.eml_content,
        original_name=f"{message_id}.eml",
        graph_message_id=message_id,
    )


@router.get("/{email_id}", response_model=EmailEvidenceRead)
def get_email(email_id: int, db: Session = DB_SESSION) -> EmailEvidence:
    email_record = db.get(EmailEvidence, email_id)
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email evidence not found")
    return email_record
