from __future__ import annotations

import logging
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import get_db
from app.models import Artifact, EmailEvidence, Incident
from app.schemas import (
    EmailEvidenceRead,
    GraphAuthUrlResponse,
    GraphEmailIngestRequest,
    GraphMessageSummary,
    GraphPollRequest,
    GraphPollResponse,
    GraphSubscriptionCreateRequest,
    GraphSubscriptionResponse,
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

logger = logging.getLogger(__name__)

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


@router.get("/graph/messages", response_model=list[GraphMessageSummary])
def list_graph_messages(
    access_token: str,
    folder_id: str = "inbox",
    top: int = 10,
    search: str | None = None,
    graph_client: GraphClient = GRAPH_SERVICE,
) -> list[GraphMessageSummary]:
    messages = graph_client.list_messages(
        access_token=access_token,
        folder_id=folder_id,
        top=top,
        search=search,
    )
    return [GraphMessageSummary(**msg) for msg in messages]


@router.post("/graph/poll", response_model=GraphPollResponse)
def poll_graph_messages(
    payload: GraphPollRequest,
    db: Session = DB_SESSION,
    graph_client: GraphClient = GRAPH_SERVICE,
) -> GraphPollResponse:
    if payload.auto_ingest and payload.incident_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="incident_id is required when auto_ingest is True",
        )

    if payload.incident_id is not None:
        _get_incident_or_404(db, payload.incident_id)

    raw_messages = graph_client.list_messages(
        access_token=payload.access_token,
        folder_id=payload.folder_id,
        top=payload.top,
    )

    summaries = [GraphMessageSummary(**msg) for msg in raw_messages]
    ingested_emails: list[EmailEvidence] = []

    if payload.auto_ingest and payload.incident_id is not None:
        for msg in raw_messages:
            msg_id = msg["id"]
            try:
                graph_msg = graph_client.get_message_eml(
                    access_token=payload.access_token,
                    message_id=msg_id,
                )
                if graph_msg.eml_content:
                    email_rec = _persist_email_evidence(
                        db=db,
                        incident_id=payload.incident_id,
                        source="microsoft_graph_poll",
                        eml_content=graph_msg.eml_content,
                        original_name=f"{msg_id}.eml",
                        graph_message_id=msg_id,
                    )
                    ingested_emails.append(email_rec)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to auto-ingest polled message %s: %s", msg_id, exc)

    return GraphPollResponse(
        messages=summaries,
        ingested_count=len(ingested_emails),
        ingested_emails=ingested_emails,  # type: ignore[arg-type]
    )


@router.post("/graph/subscriptions", response_model=GraphSubscriptionResponse)
def create_graph_subscription(
    payload: GraphSubscriptionCreateRequest,
    graph_client: GraphClient = GRAPH_SERVICE,
) -> GraphSubscriptionResponse:
    sub_data = graph_client.create_subscription(
        access_token=payload.access_token,
        notification_url=payload.notification_url,
        resource=payload.resource,
        change_type=payload.change_type,
        client_state=payload.client_state,
        expiration_minutes=payload.expiration_minutes,
    )
    return GraphSubscriptionResponse(
        subscription_id=sub_data["id"],
        resource=sub_data.get("resource", payload.resource),
        change_type=sub_data.get("changeType", payload.change_type),
        notification_url=sub_data.get("notificationUrl", payload.notification_url),
        expiration_date_time=sub_data.get("expirationDateTime", ""),
        client_state=sub_data.get("clientState"),
    )


@router.delete("/graph/subscriptions/{subscription_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_graph_subscription(
    subscription_id: str,
    access_token: str,
    graph_client: GraphClient = GRAPH_SERVICE,
) -> Response:
    success = graph_client.delete_subscription(
        access_token=access_token,
        subscription_id=subscription_id,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to delete Microsoft Graph subscription",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/graph/webhook")
async def graph_webhook(
    request: Request,
    validationToken: str | None = Query(None),
) -> Response:
    # 1. Handle Microsoft Graph validation handshake
    if validationToken:
        logger.info("Handling Microsoft Graph webhook validation handshake")
        return Response(
            content=validationToken,
            media_type="text/plain",
            status_code=status.HTTP_200_OK,
        )

    # 2. Process incoming change notifications
    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from None

    notifications = body.get("value", [])
    expected_client_state = settings.graph_webhook_client_state

    processed = 0
    for notif in notifications:
        client_state = notif.get("clientState")
        if expected_client_state and client_state != expected_client_state:
            logger.warning("Rejected webhook notification with mismatched clientState")
            continue

        resource_data = notif.get("resourceData", {})
        message_id = resource_data.get("id")
        change_type = notif.get("changeType")
        logger.info(
            "Received Graph notification: type=%s, message_id=%s, resource=%s",
            change_type,
            message_id,
            notif.get("resource"),
        )
        processed += 1

    # Microsoft Graph expects an HTTP 202 Accepted response within 3 seconds
    return Response(
        content=f'{{"status":"accepted","processed_notifications":{processed}}}',
        media_type="application/json",
        status_code=status.HTTP_202_ACCEPTED,
    )


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
