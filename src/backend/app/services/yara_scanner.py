from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara

from app.core.config import settings

logger = logging.getLogger(__name__)

MAX_STRING_MATCH_INSTANCES = 10
MAX_STRING_PREVIEW_LEN = 128


@dataclass
class YARAStringInstance:
    identifier: str
    offset: int
    length: int
    data: str


@dataclass
class YARAFinding:
    rule: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "tags": self.tags,
            "meta": self.meta,
            "strings": self.strings,
        }


def resolve_yara_rules_path(configured_path: str | None = None) -> Path:
    target_str = configured_path or settings.yara_rules_path
    candidate = Path(target_str)
    if candidate.is_absolute() and candidate.exists():
        return candidate

    search_roots = [
        Path.cwd() / target_str,
        Path(__file__).resolve().parents[2] / target_str,
        Path(__file__).resolve().parents[3] / target_str,
        Path(__file__).resolve().parents[2] / "rules" / "yara",
    ]

    for path in search_roots:
        if path.exists() and path.is_dir():
            return path.resolve()

    fallback = (Path(__file__).resolve().parents[2] / "rules" / "yara").resolve()
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def compile_yara_rules(rules_dir: Path | str | None = None) -> yara.Rules | None:
    directory = Path(rules_dir) if rules_dir else resolve_yara_rules_path()
    if not directory.exists() or not directory.is_dir():
        logger.info("YARA rules directory does not exist: %s", directory)
        return None

    rule_files: dict[str, str] = {}
    for extension in ("*.yar", "*.yara"):
        for file_path in directory.rglob(extension):
            rule_files[f"ns_{file_path.stem}_{len(rule_files)}"] = str(file_path.resolve())

    if not rule_files:
        logger.info("No YARA rule files found in: %s", directory)
        return None

    try:
        compiled = yara.compile(filepaths=rule_files)
        logger.info("Successfully compiled %d YARA rule file(s)", len(rule_files))
        return compiled
    except yara.SyntaxError as exc:
        logger.warning("YARA syntax error while compiling rules: %s", exc)
        return None
    except yara.Error as exc:
        logger.warning("YARA compilation error: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error compiling YARA rules: %s", exc)
        return None


def compile_rule_source(source: str) -> yara.Rules:
    return yara.compile(source=source)


def _format_matched_strings(match: yara.Match) -> list[dict[str, Any]]:
    formatted: list[dict[str, Any]] = []

    for item in match.strings:
        if hasattr(item, "identifier") and hasattr(item, "instances"):
            instances = getattr(item, "instances", [])
            for inst in instances[:MAX_STRING_MATCH_INSTANCES]:
                matched_raw = getattr(inst, "matched_data", b"")
                preview = matched_raw[:MAX_STRING_PREVIEW_LEN].decode("utf-8", errors="replace")
                formatted.append(
                    {
                        "identifier": str(item.identifier),
                        "offset": int(inst.offset),
                        "length": int(getattr(inst, "matched_length", len(matched_raw))),
                        "data": preview,
                    }
                )
        elif isinstance(item, tuple) and len(item) >= 3:
            offset, identifier, raw_data = item[:3]
            preview = (
                raw_data[:MAX_STRING_PREVIEW_LEN].decode("utf-8", errors="replace")
                if isinstance(raw_data, bytes)
                else str(raw_data)[:MAX_STRING_PREVIEW_LEN]
            )
            formatted.append(
                {
                    "identifier": str(identifier),
                    "offset": int(offset),
                    "length": len(raw_data),
                    "data": preview,
                }
            )

    return formatted


def scan_content_with_yara(
    content: bytes,
    rules: yara.Rules | None = None,
) -> list[dict[str, Any]]:
    if not content:
        return []

    active_rules = rules if rules is not None else compile_yara_rules()
    if active_rules is None:
        return []

    try:
        matches = active_rules.match(data=content)
    except yara.Error as exc:
        logger.warning("YARA error during content scanning: %s", exc)
        return []
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error during YARA scan: %s", exc)
        return []

    findings: list[dict[str, Any]] = []
    for match in matches:
        finding = YARAFinding(
            rule=match.rule,
            tags=list(match.tags),
            meta=dict(match.meta),
            strings=_format_matched_strings(match),
        )
        findings.append(finding.to_dict())

    return findings
