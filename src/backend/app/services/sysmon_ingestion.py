from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Artifact, EndpointEvent, Incident, IOCRecord

SUPPORTED_EVENT_IDS = {1, 3, 11, 12, 13, 14}
HASH_KEYS = {"md5", "sha1", "sha256", "imphash"}


def _utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError("Sysmon event timestamp is missing or invalid") from exc
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _get(data: dict[str, Any], *names: str) -> Any:
    lowered = {str(k).lower(): v for k, v in data.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _event_data(raw: dict[str, Any]) -> dict[str, Any]:
    data = _get(raw, "EventData", "event_data", "data")
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        result: dict[str, Any] = {}
        for item in data:
            if isinstance(item, dict):
                name = _get(item, "Name", "name", "key")
                value = _get(item, "Value", "value", "text")
                if name:
                    result[str(name)] = value
        return result
    return raw


def _parse_xml(payload: str) -> list[dict[str, Any]]:
    root = ET.fromstring(payload)
    records = (
        [root]
        if root.tag.rsplit("}", 1)[-1] == "Event"
        else [node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "Event"]
    )
    parsed: list[dict[str, Any]] = []
    for event in records:
        system: dict[str, Any] = {}
        event_data: dict[str, Any] = {}
        for node in event:
            name = node.tag.rsplit("}", 1)[-1]
            if name == "System":
                for child in node:
                    child_name = child.tag.rsplit("}", 1)[-1]
                    if child_name == "EventID":
                        system["EventID"] = child.text
                    elif child_name == "TimeCreated":
                        system["UtcTime"] = child.attrib.get("SystemTime")
                    elif child_name == "Computer":
                        system["Computer"] = child.text
            elif name == "EventData":
                for child in node:
                    event_data[child.attrib.get("Name", child.tag.rsplit("}", 1)[-1])] = child.text
        parsed.append(
            {
                "System": system,
                "EventData": event_data,
                "_raw": ET.tostring(event, encoding="unicode"),
            }
        )
    return parsed


def _records(payload: bytes, content_type: str | None) -> list[dict[str, Any]]:
    if len(payload) > settings.max_telemetry_size_bytes:
        raise ValueError("Telemetry payload exceeds configured size limit")
    text = payload.decode("utf-8-sig")
    if "<!doctype" in text.lower() or "<!entity" in text.lower():
        raise ValueError("Telemetry XML must not declare entities or a doctype")
    if "xml" in (content_type or "").lower() or text.lstrip().startswith("<"):
        records = _parse_xml(text)
        if len(records) > settings.max_telemetry_events:
            raise ValueError("Telemetry payload contains too many events")
        return records
    decoded = json.loads(text)
    if isinstance(decoded, list):
        records = [item for item in decoded if isinstance(item, dict)]
        if len(records) > settings.max_telemetry_events:
            raise ValueError("Telemetry payload contains too many events")
        return records
    if isinstance(decoded, dict) and isinstance(decoded.get("Events"), list):
        records = [item for item in decoded["Events"] if isinstance(item, dict)]
        if len(records) > settings.max_telemetry_events:
            raise ValueError("Telemetry payload contains too many events")
        return records
    if not isinstance(decoded, dict):
        raise ValueError("Telemetry JSON must be an object or array of event objects")
    return [decoded]


@dataclass(frozen=True)
class NormalizedSysmonEvent:
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


def normalize_event(raw: dict[str, Any], source_name: str = "sysmon") -> NormalizedSysmonEvent:
    system = _get(raw, "System", "system") or {}
    if not isinstance(system, dict):
        system = {}
    data = _event_data(raw)
    event_id = int(_get(system, "EventID", "event_id") or _get(raw, "EventID", "event_id") or 0)
    if event_id not in SUPPORTED_EVENT_IDS:
        raise ValueError(f"Unsupported Sysmon Event ID: {event_id}")
    timestamp = _utc(
        _get(system, "UtcTime", "TimeCreated", "timestamp") or _get(raw, "UtcTime", "timestamp")
    )
    hashes: dict[str, str] = {}
    raw_hashes = _get(data, "Hashes", "hashes")
    if isinstance(raw_hashes, dict):
        for key, value in raw_hashes.items():
            if str(key).lower() in HASH_KEYS and _clean(value):
                hashes[str(key).lower()] = str(value).strip().lower()
    elif raw_hashes:
        for key, value in re.findall(r"(MD5|SHA1|SHA256|IMPHASH)=([^,; ]+)", str(raw_hashes), re.I):
            hashes[key.lower()] = value.lower()
    for key in HASH_KEYS:
        value = _clean(_get(data, key))
        if value:
            hashes[key] = value.lower()
    hostname = (
        _clean(_get(system, "Computer", "Hostname", "host"))
        or _clean(_get(raw, "Computer", "Hostname", "host"))
        or _clean(_get(data, "Computer"))
    )
    endpoint_id = _clean(_get(data, "EndpointId", "EndpointIdentity", "AgentId")) or hostname
    normalized = {
        "event_id": event_id,
        "timestamp": timestamp,
        "hostname": hostname,
        "endpoint_id": endpoint_id,
        "user_name": _clean(_get(data, "User", "UserName")),
        "process_guid": _clean(_get(data, "ProcessGuid")),
        "process_id": _clean(_get(data, "ProcessId")),
        "parent_process_guid": _clean(_get(data, "ParentProcessGuid")),
        "parent_process_id": _clean(_get(data, "ParentProcessId")),
        "image": _clean(_get(data, "Image")),
        "command_line": _clean(_get(data, "CommandLine")),
        "hashes": hashes,
        "destination_ip": _clean(_get(data, "DestinationIp", "DestinationIP")),
        "destination_hostname": _clean(_get(data, "DestinationHostname", "DestinationDomain")),
        "destination_port": int(_get(data, "DestinationPort") or 0) or None,
        "protocol": _clean(_get(data, "Protocol")),
        "target_filename": _clean(_get(data, "TargetFilename")),
        "registry_key": _clean(_get(data, "TargetObject", "RegistryKey")),
        "registry_value_name": _clean(_get(data, "Details", "ValueName")),
        "registry_value_data": _clean(_get(data, "EventType", "Value")),
    }
    raw_evidence = str(raw.get("_raw") or json.dumps(raw, sort_keys=True, default=str))
    fingerprint = hashlib.sha256(
        json.dumps(
            {"source": source_name, **normalized, "raw": raw_evidence},
            sort_keys=True,
            default=str,
        ).encode()
    ).hexdigest()
    return NormalizedSysmonEvent(
        **normalized,
        raw_evidence=raw_evidence,
        provenance={"source": source_name, "event_id": event_id, "hostname": hostname},
        fingerprint=fingerprint,
    )


def _candidate_incident_ids(db: Session, event: NormalizedSysmonEvent) -> set[int]:
    candidates: set[int] = set()
    for digest in event.hashes.values():
        rows = db.execute(
            select(Incident.id)
            .join(Artifact, Artifact.incident_id == Incident.id)
            .where(Artifact.sha256 == digest)
        ).scalars()
        candidates.update(rows)
    network_values = {
        value.lower().rstrip("/")
        for value in (event.destination_ip, event.destination_hostname)
        if value
    }
    if network_values:
        rows = db.execute(
            select(Incident.id)
            .join(IOCRecord, IOCRecord.incident_id == Incident.id)
            .where(IOCRecord.normalized_value.in_(network_values))
        ).scalars()
        candidates.update(rows)
    return candidates


def persist_events(
    db: Session, events: list[NormalizedSysmonEvent], incident_id: int | None = None
) -> tuple[list[EndpointEvent], int]:
    stored: list[EndpointEvent] = []
    duplicates = 0
    for event in events:
        existing = db.execute(
            select(EndpointEvent).where(EndpointEvent.fingerprint == event.fingerprint)
        ).scalar_one_or_none()
        if existing:
            duplicates += 1
            stored.append(existing)
            continue
        selected_incident = incident_id
        if selected_incident is None:
            candidates = _candidate_incident_ids(db, event)
            selected_incident = next(iter(candidates)) if len(candidates) == 1 else None
        record = EndpointEvent(
            incident_id=selected_incident,
            event_id=event.event_id,
            timestamp=event.timestamp,
            hostname=event.hostname,
            endpoint_id=event.endpoint_id,
            user_name=event.user_name,
            process_guid=event.process_guid,
            process_id=event.process_id,
            parent_process_guid=event.parent_process_guid,
            parent_process_id=event.parent_process_id,
            image=event.image,
            command_line=event.command_line,
            hashes=event.hashes,
            destination_ip=event.destination_ip,
            destination_hostname=event.destination_hostname,
            destination_port=event.destination_port,
            protocol=event.protocol,
            target_filename=event.target_filename,
            registry_key=event.registry_key,
            registry_value_name=event.registry_value_name,
            registry_value_data=event.registry_value_data,
            raw_evidence=event.raw_evidence,
            provenance=event.provenance,
            fingerprint=event.fingerprint,
        )
        try:
            with db.begin_nested():
                db.add(record)
                db.flush()
            stored.append(record)
        except Exception as exc:
            from sqlalchemy.exc import IntegrityError

            if not isinstance(exc, IntegrityError):
                raise
            duplicate = db.execute(
                select(EndpointEvent).where(EndpointEvent.fingerprint == event.fingerprint)
            ).scalar_one()
            duplicates += 1
            stored.append(duplicate)
    db.commit()
    for record in stored:
        db.refresh(record)
    return stored, duplicates


def ingest_payload(
    db: Session, payload: bytes, content_type: str | None, incident_id: int | None = None
) -> tuple[list[EndpointEvent], int]:
    normalized = [normalize_event(raw) for raw in _records(payload, content_type)]
    return persist_events(db, normalized, incident_id)
