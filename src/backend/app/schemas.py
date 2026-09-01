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
    created_at: datetime
    updated_at: datetime


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
