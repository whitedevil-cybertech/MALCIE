from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IncidentCreate(BaseModel):
    title: str
    description: str | None = None


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: str | None
    status: str
    created_at: datetime


class GraphAuthUrlResponse(BaseModel):
    auth_url: str
    state: str


class GraphTokenExchangeRequest(BaseModel):
    code: str
    redirect_uri: str
    state: str


class GraphTokenRefreshRequest(BaseModel):
    refresh_token: str


class GraphTokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None


class GraphEmailIngestRequest(BaseModel):
    incident_id: int
    access_token: str


class ArtifactRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    content_type: str | None
    size: int
    sha256: str


class EmailEvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    source: str
    graph_message_id: str | None
    sender: str | None
    recipients: list[str]
    subject: str | None
    sent_at: str | None
    message_id: str | None
    headers: dict[str, str]
    urls: list[str]
    domains: list[str]
    body_preview: str
    raw_email_sha256: str
    artifacts: list[ArtifactRead]
    created_at: datetime


class GraphPollRequest(BaseModel):
    access_token: str
    incident_id: int | None = None
    folder_id: str = "inbox"
    top: int = 10
    auto_ingest: bool = False


class GraphMessageSummary(BaseModel):
    id: str
    subject: str | None = None
    sender: str | None = None
    received_at: str | None = None
    has_attachments: bool = False
    is_read: bool = False


class GraphPollResponse(BaseModel):
    messages: list[GraphMessageSummary]
    ingested_count: int = 0
    ingested_emails: list[EmailEvidenceRead] = []


class GraphSubscriptionCreateRequest(BaseModel):
    access_token: str
    notification_url: str
    resource: str = "/me/messages"
    change_type: str = "created"
    client_state: str | None = None
    expiration_minutes: int = 4230


class GraphSubscriptionResponse(BaseModel):
    subscription_id: str
    resource: str
    change_type: str
    notification_url: str
    expiration_date_time: str
    client_state: str | None = None


class GraphNotificationPayload(BaseModel):
    value: list[dict[str, object]] = []


class IOCRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    artifact_id: int | None
    ioc_type: str
    value: str
    normalized_value: str
    source: str
    classification: str
    context: dict[str, object]
    created_at: datetime


class ArtifactAnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    artifact_id: int
    incident_id: int
    status: str
    error_message: str | None
    is_pe: bool
    file_type: str | None
    pe_headers: dict[str, str | int | None]
    sections: list[dict[str, str | int | float]]
    imports: list[dict[str, object]]
    extracted_strings: list[str]
    md5: str | None = None
    sha1: str | None = None
    yara_matches: list[dict[str, object]] = []
    iocs: list[IOCRecordRead] = []
    created_at: datetime
    updated_at: datetime


class ThreatIntelResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    artifact_id: int | None
    ioc_id: int | None
    ioc_type: str
    ioc_value: str
    normalized_value: str
    provider: str
    query_status: str
    reputation_score: int | None
    malicious_votes: int
    suspicious_votes: int
    harmless_votes: int
    undetected_votes: int
    total_engines: int
    detection_details: dict[str, object]
    queried_at: datetime
    created_at: datetime


class ThreatIntelLookupRequest(BaseModel):
    ioc_type: str
    value: str


class IncidentEnrichRequest(BaseModel):
    ioc_types: list[str] | None = None


class LinkageItem(BaseModel):
    source_type: str
    source_id: str | int
    target_type: str
    target_id: str | int
    relation: str
    description: str
    metadata: dict[str, object] = {}


class ConfidenceAssessment(BaseModel):
    score: float
    level: str
    reasons: list[str] = []


class RiskAssessment(BaseModel):
    score: int
    level: str
    reasons: list[str] = []


class CorrelationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: int
    confidence: ConfidenceAssessment
    risk: RiskAssessment
    linkages: list[LinkageItem] = []
    created_at: datetime


class TimelineEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    timestamp: datetime
    event_type: str
    source: str
    description: str
    artifact_id: int | None = None
    ioc_id: int | None = None
    event_data: dict[str, object] = {}
    created_at: datetime


class EndpointEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int | None
    event_id: int
    timestamp: datetime
    hostname: str | None
    endpoint_id: str | None
    user_name: str | None
    process_guid: str | None
    process_id: str | None
    parent_process_guid: str | None
    parent_process_id: str | None
    image: str | None
    command_line: str | None
    hashes: dict[str, str]
    destination_ip: str | None
    destination_hostname: str | None
    destination_port: int | None
    protocol: str | None
    target_filename: str | None
    registry_key: str | None
    registry_value_name: str | None
    registry_value_data: str | None
    raw_evidence: str
    provenance: dict[str, object]
    fingerprint: str
    created_at: datetime


class TelemetryUploadResponse(BaseModel):
    ingested_count: int
    duplicate_count: int
    unassociated_count: int
    events: list[EndpointEventRead]
