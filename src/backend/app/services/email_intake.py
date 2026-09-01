from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from urllib.parse import urlparse

from fastapi import HTTPException, UploadFile, status

from app.core.config import settings

URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
SAFE_FILENAME_PATTERN = re.compile(r"[^a-zA-Z0-9._-]")


@dataclass
class ParsedAttachment:
    filename: str
    content_type: str | None
    payload: bytes
    sha256: str


@dataclass
class ParsedEmailEvidence:
    sender: str | None
    recipients: list[str]
    subject: str | None
    sent_at: str | None
    message_id: str | None
    headers: dict[str, str]
    body_preview: str
    urls: list[str]
    domains: list[str]
    attachments: list[ParsedAttachment]


def validate_eml_upload(upload: UploadFile, content: bytes) -> None:
    if not upload.filename or not upload.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only .eml files are accepted")
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded .eml is empty")
    if len(content) > settings.max_eml_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Uploaded .eml exceeds configured size limit",
        )


def sanitize_filename(filename: str, fallback: str) -> str:
    candidate = Path(filename or fallback).name
    candidate = SAFE_FILENAME_PATTERN.sub("_", candidate)
    return candidate[:255] or fallback


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_recipients(raw_values: list[str] | None) -> list[str]:
    addresses = getaddresses(raw_values or [])
    return sorted({address.lower() for _, address in addresses if address})


def extract_urls_domains(text: str) -> tuple[list[str], list[str]]:
    urls = sorted({match.rstrip(".,;)") for match in URL_PATTERN.findall(text)})
    domains = {urlparse(url).hostname.lower() for url in urls if urlparse(url).hostname}
    domains.update({domain.lower() for domain in DOMAIN_PATTERN.findall(text)})
    return urls, sorted(domains)


def parse_eml_bytes(content: bytes) -> ParsedEmailEvidence:
    message = BytesParser(policy=policy.default).parsebytes(content)
    headers = {key: str(value) for key, value in message.items()}

    body_chunks: list[str] = []
    attachments: list[ParsedAttachment] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        disposition = part.get_content_disposition()
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename()

        if disposition == "attachment" or filename:
            safe_name = sanitize_filename(filename or "attachment.bin", "attachment.bin")
            if len(payload) > settings.max_attachment_size_bytes:
                continue
            attachments.append(
                ParsedAttachment(
                    filename=safe_name,
                    content_type=part.get_content_type(),
                    payload=payload,
                    sha256=hash_bytes(payload),
                )
            )
            continue

        if part.get_content_type() in {"text/plain", "text/html"}:
            charset = part.get_content_charset() or "utf-8"
            body_chunks.append(payload.decode(charset, errors="replace"))

    body_text = "\n".join(body_chunks).strip()
    body_preview = body_text[:2000]
    urls, domains = extract_urls_domains(body_text)

    recipients = extract_recipients(message.get_all("to", []))
    recipients.extend(
        value
        for value in extract_recipients(message.get_all("cc", []))
        if value not in recipients
    )

    return ParsedEmailEvidence(
        sender=message.get("from"),
        recipients=recipients,
        subject=message.get("subject"),
        sent_at=message.get("date"),
        message_id=message.get("message-id"),
        headers=headers,
        body_preview=body_preview,
        urls=urls,
        domains=domains,
        attachments=attachments,
    )


def evidence_root() -> Path:
    root = Path(settings.artifact_storage_path)
    root.mkdir(parents=True, exist_ok=True)
    return root


def write_evidence_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
