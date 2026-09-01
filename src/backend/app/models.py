from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    artifact: Mapped[Artifact] = relationship(back_populates="analysis")
    incident: Mapped[Incident] = relationship()
