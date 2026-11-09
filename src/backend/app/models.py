from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="new", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    emails: Mapped[list[EmailEvidence]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    iocs: Mapped[list[IOCRecord]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    threat_intel_results: Mapped[list[ThreatIntelResult]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    correlation_result: Mapped[CorrelationResult | None] = relationship(
        back_populates="incident", cascade="all, delete-orphan", uselist=False
    )
    timeline_events: Mapped[list[TimelineEvent]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="TimelineEvent.timestamp"
    )


class EmailEvidence(Base):
    __tablename__ = "emails"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    graph_message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sender: Mapped[str | None] = mapped_column(String(320), nullable=True)
    recipients: Mapped[list[str]] = mapped_column(JSON, default=list)
    subject: Mapped[str | None] = mapped_column(String(998), nullable=True)
    sent_at: Mapped[str | None] = mapped_column(String(128), nullable=True)
    message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    headers: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    body_preview: Mapped[str] = mapped_column(Text, default="")
    raw_email_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_email_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    incident: Mapped[Incident] = relationship(back_populates="emails")
    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="email", cascade="all, delete-orphan"
    )


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"))
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    incident: Mapped[Incident] = relationship(back_populates="artifacts")
    email: Mapped[EmailEvidence] = relationship(back_populates="artifacts")
    analysis: Mapped[ArtifactAnalysis | None] = relationship(
        back_populates="artifact",
        cascade="all, delete-orphan",
        uselist=False,
    )
    iocs: Mapped[list[IOCRecord]] = relationship(
        back_populates="artifact", cascade="all, delete-orphan"
    )
    threat_intel_results: Mapped[list[ThreatIntelResult]] = relationship(
        back_populates="artifact", cascade="all, delete-orphan"
    )


class ArtifactAnalysis(Base):
    __tablename__ = "artifact_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    artifact_id: Mapped[int] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_pe: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    file_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pe_headers: Mapped[dict[str, str | int | None]] = mapped_column(JSON, default=dict)
    sections: Mapped[list[dict[str, str | int | float]]] = mapped_column(JSON, default=list)
    imports: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    extracted_strings: Mapped[list[str]] = mapped_column(JSON, default=list)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    yara_matches: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    artifact: Mapped[Artifact] = relationship(back_populates="analysis")
    incident: Mapped[Incident] = relationship()

    @property
    def iocs(self) -> list[IOCRecord]:
        if hasattr(self, "_iocs_override") and self._iocs_override is not None:
            return self._iocs_override
        return self.artifact.iocs if self.artifact else []

    @iocs.setter
    def iocs(self, value: list[IOCRecord]) -> None:
        self._iocs_override = value


class IOCRecord(Base):
    __tablename__ = "ioc_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    artifact_id: Mapped[int | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    context: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    incident: Mapped[Incident] = relationship(back_populates="iocs")
    artifact: Mapped[Artifact | None] = relationship(back_populates="iocs")
    threat_intel_results: Mapped[list[ThreatIntelResult]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )


class ThreatIntelResult(Base):
    __tablename__ = "threat_intel_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    artifact_id: Mapped[int | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    ioc_id: Mapped[int | None] = mapped_column(
        ForeignKey("ioc_records.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    ioc_value: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(50), default="VirusTotal", nullable=False)
    query_status: Mapped[str] = mapped_column(String(32), nullable=False)
    reputation_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    malicious_votes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    suspicious_votes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    harmless_votes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    undetected_votes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_engines: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    detection_details: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    raw_response: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    queried_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    incident: Mapped[Incident] = relationship(back_populates="threat_intel_results")
    artifact: Mapped[Artifact | None] = relationship(back_populates="threat_intel_results")
    ioc: Mapped[IOCRecord | None] = relationship(back_populates="threat_intel_results")


class CorrelationResult(Base):
    __tablename__ = "correlation_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confidence_level: Mapped[str] = mapped_column(String(32), nullable=False, default="LOW")
    confidence_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False, default="LOW")
    risk_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    linkages: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    incident: Mapped[Incident] = relationship(back_populates="correlation_result")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_id: Mapped[int | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ioc_id: Mapped[int | None] = mapped_column(
        ForeignKey("ioc_records.id", ondelete="SET NULL"), nullable=True, index=True
    )
    event_data: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    incident: Mapped[Incident] = relationship(back_populates="timeline_events")
    artifact: Mapped[Artifact | None] = relationship()
    ioc: Mapped[IOCRecord | None] = relationship()
