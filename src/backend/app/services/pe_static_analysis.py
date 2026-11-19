import hashlib
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pefile

from app.models import Artifact, ArtifactAnalysis, IOCRecord
from app.services.email_intake import evidence_root
from app.services.ioc_extraction import extract_artifact_iocs
from app.services.yara_scanner import scan_content_with_yara

logger = logging.getLogger(__name__)
PRINTABLE_STRING_PATTERN = re.compile(rb"[\x20-\x7e]{4,}")
MAX_STRINGS = 200

SUSPICIOUS_API_NAMES = {
    "urldownloadtofilea",
    "urldownloadtofilew",
    "internetreadfile",
    "winhttpopen",
    "virtualalloc",
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "winexec",
    "shellexecutea",
    "shellexecutew",
    "ntqueueapcthread",
    "zwunmapviewofsection",
    "minidumpwritedump",
    "setwindowshookexa",
    "getasynckeystate",
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
}


@dataclass
class PEAnalysisData:
    status: str
    error_message: str | None
    is_pe: bool
    file_type: str | None
    pe_headers: dict[str, Any]
    sections: list[dict[str, Any]]
    imports: list[dict[str, object]]
    extracted_strings: list[str]
    md5: str | None = None
    sha1: str | None = None
    imphash: str | None = None
    file_entropy: float | None = None
    suspicious_indicators: list[str] = field(default_factory=list)
    yara_matches: list[dict[str, Any]] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)



def _section_entropy(raw_data: bytes) -> float:
    if not raw_data:
        return 0.0
    frequencies = Counter(raw_data)
    entropy = 0.0
    length = len(raw_data)
    for count in frequencies.values():
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 6)


def _extract_strings(content: bytes) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for match in PRINTABLE_STRING_PATTERN.finditer(content):
        text = match.group(0).decode("utf-8", errors="ignore")
        if text in seen:
            continue
        seen.add(text)
        unique.append(text)
        if len(unique) >= MAX_STRINGS:
            break
    return unique


def _parse_pe(content: bytes) -> PEAnalysisData:
    if not content:
        return PEAnalysisData(
            status="failed",
            error_message="Artifact file is empty",
            is_pe=False,
            file_type=None,
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=[],
        )

    strings = _extract_strings(content)

    if not content.startswith(b"MZ"):
        return PEAnalysisData(
            status="unsupported",
            error_message="Artifact is not a Portable Executable (missing MZ header)",
            is_pe=False,
            file_type="non_pe",
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=strings,
        )

    try:
        pe = pefile.PE(data=content, fast_load=False)
        machine_type = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine)

        imphash: str | None = None
        try:
            imphash = pe.get_imphash()
            if not imphash:
                imphash = None
        except Exception:
            imphash = None

        file_entropy = _section_entropy(content)
        suspicious_indicators: list[str] = []

        if file_entropy > 7.2:
            suspicious_indicators.append(
                f"High overall binary Shannon entropy ({file_entropy:.2f}), "
                "suggesting packing or encryption"
            )

        sections: list[dict[str, Any]] = []
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").replace("\x00", "")
            raw_bytes = section.get_data()
            entropy = _section_entropy(raw_bytes)
            characteristics = getattr(section, "Characteristics", 0)
            is_writable = bool(characteristics & 0x80000000)
            is_executable = bool(characteristics & 0x20000000)
            is_readable = bool(characteristics & 0x40000000)

            if is_writable and is_executable:
                suspicious_indicators.append(
                    f"Section '{name}' has both Writable and Executable permissions (W^X violation)"
                )
            if entropy > 7.0:
                suspicious_indicators.append(
                    f"Section '{name}' has high Shannon entropy ({entropy:.2f}), "
                    "indicating packing or obfuscation"
                )
            if any(p in name.upper() for p in ("UPX", "ASPACK", "FSG", "THEMIDA", "VMP")):
                suspicious_indicators.append(
                    f"Section name '{name}' matches known packer signature"
                )

            sections.append(
                {
                    "name": name,
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": entropy,
                    "characteristics": hex(characteristics),
                    "is_writable": is_writable,
                    "is_executable": is_executable,
                    "is_readable": is_readable,
                }
            )

        imports: list[dict[str, object]] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "unknown"
                functions: list[str] = []
                for imported in entry.imports:
                    if imported.name:
                        fn_name = imported.name.decode("utf-8", errors="ignore")
                        functions.append(fn_name)
                        if fn_name.lower() in SUSPICIOUS_API_NAMES:
                            suspicious_indicators.append(
                                f"Suspicious API import '{fn_name}' from '{dll_name}'"
                            )
                    elif imported.ordinal is not None:
                        functions.append(f"ordinal:{imported.ordinal}")
                imports.append({"dll": dll_name, "functions": functions})

        file_type = "pe32+" if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else "pe32"

        pe_headers = {
            "machine": machine_type,
            "machine_hex": hex(pe.FILE_HEADER.Machine),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "time_date_stamp": pe.FILE_HEADER.TimeDateStamp,
            "characteristics": hex(pe.FILE_HEADER.Characteristics),
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
            "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
            "imphash": imphash,
            "file_entropy": file_entropy,
            "suspicious_indicators": suspicious_indicators,
        }

        return PEAnalysisData(
            status="completed",
            error_message=None,
            is_pe=True,
            file_type=file_type,
            pe_headers=pe_headers,
            sections=sections,
            imports=imports,
            extracted_strings=strings,
            imphash=imphash,
            file_entropy=file_entropy,
            suspicious_indicators=suspicious_indicators,
        )
    except pefile.PEFormatError as exc:
        logger.warning("PE format error during static analysis: %s", exc)
        return PEAnalysisData(
            status="failed",
            error_message=f"Malformed PE file: {exc.value}",
            is_pe=True,
            file_type="pe_malformed",
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=strings,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected static analysis error")
        return PEAnalysisData(
            status="failed",
            error_message=f"Static analysis error: {exc}",
            is_pe=content.startswith(b"MZ"),
            file_type=None,
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=strings,
        )


def _read_artifact_bytes(storage_path: str) -> bytes:
    root = evidence_root().resolve()
    artifact_path = Path(storage_path).resolve()
    if root != artifact_path and root not in artifact_path.parents:
        raise ValueError("Artifact path is outside evidence storage")
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact file does not exist: {storage_path}")

    file_size = artifact_path.stat().st_size
    from app.core.config import settings

    if file_size > settings.max_attachment_size_bytes:
        raise ValueError(
            f"Artifact size ({file_size} bytes) exceeds configured maximum allowed size "
            f"({settings.max_attachment_size_bytes} bytes)"
        )
    return artifact_path.read_bytes()


def analyze_artifact(artifact: Artifact) -> PEAnalysisData:
    try:
        content = _read_artifact_bytes(artifact.storage_path)
    except FileNotFoundError:
        logger.warning("Artifact file missing: artifact_id=%s", artifact.id)
        return PEAnalysisData(
            status="failed",
            error_message="Artifact file does not exist in storage",
            is_pe=False,
            file_type=None,
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=[],
        )
    except ValueError as exc:
        logger.warning(
            "Artifact storage validation error: artifact_id=%s error=%s",
            artifact.id,
            exc,
        )
        return PEAnalysisData(
            status="failed",
            error_message=str(exc),
            is_pe=False,
            file_type=None,
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=[],
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Artifact read error: artifact_id=%s", artifact.id)
        return PEAnalysisData(
            status="failed",
            error_message=f"Unable to read artifact from storage: {exc}",
            is_pe=False,
            file_type=None,
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=[],
        )

    if hashlib.sha256(content).hexdigest() != artifact.sha256:
        logger.error("Artifact integrity check failed: artifact_id=%s", artifact.id)
        return PEAnalysisData(
            status="failed",
            error_message="Artifact content hash does not match stored SHA-256",
            is_pe=False,
            file_type=None,
            pe_headers={},
            sections=[],
            imports=[],
            extracted_strings=[],
        )

    analysis = _parse_pe(content)
    if content:
        analysis.md5 = hashlib.md5(content).hexdigest()
        analysis.sha1 = hashlib.sha1(content).hexdigest()
        analysis.yara_matches = scan_content_with_yara(content)
        extracted = extract_artifact_iocs(
            content=content,
            extracted_strings=analysis.extracted_strings,
            imports=analysis.imports,
            yara_matches=analysis.yara_matches,
        )
        analysis.iocs = [item.to_dict() for item in extracted]

    return analysis


def persist_artifact_analysis(
    *,
    artifact: Artifact,
    analysis: PEAnalysisData,
) -> ArtifactAnalysis:
    if artifact.analysis is None:
        artifact.analysis = ArtifactAnalysis(
            artifact_id=artifact.id,
            incident_id=artifact.incident_id,
            status=analysis.status,
            error_message=analysis.error_message,
            is_pe=analysis.is_pe,
            file_type=analysis.file_type,
            pe_headers=analysis.pe_headers,
            sections=analysis.sections,
            imports=analysis.imports,
            extracted_strings=analysis.extracted_strings,
            md5=analysis.md5,
            sha1=analysis.sha1,
            yara_matches=analysis.yara_matches,
        )
    else:
        artifact.analysis.status = analysis.status
        artifact.analysis.error_message = analysis.error_message
        artifact.analysis.is_pe = analysis.is_pe
        artifact.analysis.file_type = analysis.file_type
        artifact.analysis.pe_headers = analysis.pe_headers
        artifact.analysis.sections = analysis.sections
        artifact.analysis.imports = analysis.imports
        artifact.analysis.extracted_strings = analysis.extracted_strings
        artifact.analysis.md5 = analysis.md5
        artifact.analysis.sha1 = analysis.sha1
        artifact.analysis.yara_matches = analysis.yara_matches

    # Synchronize IOC records
    artifact.iocs.clear()
    for item in analysis.iocs:
        ioc_record = IOCRecord(
            incident_id=artifact.incident_id,
            artifact_id=artifact.id,
            ioc_type=item["ioc_type"],
            value=item["value"],
            normalized_value=item["normalized_value"],
            source=item["source"],
            classification="extracted",
            context=item.get("context", {}),
        )
        artifact.iocs.append(ioc_record)

    return artifact.analysis
