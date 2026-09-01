from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path

import pefile

from app.models import Artifact, ArtifactAnalysis
from app.services.email_intake import evidence_root

logger = logging.getLogger(__name__)
PRINTABLE_STRING_PATTERN = re.compile(rb"[\x20-\x7e]{4,}")
MAX_STRINGS = 200


@dataclass
class PEAnalysisData:
    status: str
    error_message: str | None
    is_pe: bool
    file_type: str | None
    pe_headers: dict[str, str | int | None]
    sections: list[dict[str, str | int | float]]
    imports: list[dict[str, object]]
    extracted_strings: list[str]


def _section_entropy(raw_data: bytes) -> float:
    if not raw_data:
        return 0.0
    frequencies = [0] * 256
    for byte in raw_data:
        frequencies[byte] += 1
    entropy = 0.0
    length = len(raw_data)
    for count in frequencies:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 6)


def _extract_strings(content: bytes) -> list[str]:
    decoded = [match.decode("utf-8", errors="ignore") for match in PRINTABLE_STRING_PATTERN.findall(content)]
    unique: list[str] = []
    seen: set[str] = set()
    for item in decoded:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
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
        }

        sections: list[dict[str, str | int | float]] = []
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").replace("\x00", "")
            raw_bytes = section.get_data()
            sections.append(
                {
                    "name": name,
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": _section_entropy(raw_bytes),
                }
            )

        imports: list[dict[str, object]] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "unknown"
                functions: list[str] = []
                for imported in entry.imports:
                    if imported.name:
                        functions.append(imported.name.decode("utf-8", errors="ignore"))
                    elif imported.ordinal is not None:
                        functions.append(f"ordinal:{imported.ordinal}")
                imports.append({"dll": dll_name, "functions": functions})

        file_type = "pe32+" if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else "pe32"

        return PEAnalysisData(
            status="completed",
            error_message=None,
            is_pe=True,
            file_type=file_type,
            pe_headers=pe_headers,
            sections=sections,
            imports=imports,
            extracted_strings=strings,
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
        logger.warning("Artifact storage validation error: artifact_id=%s error=%s", artifact.id, exc)
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

    return _parse_pe(content)


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
    return artifact.analysis
