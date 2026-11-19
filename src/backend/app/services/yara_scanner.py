from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara

from app.core.config import settings

logger = logging.getLogger(__name__)

MAX_STRING_MATCH_INSTANCES = 10
MAX_STRING_PREVIEW_LEN = 128

_RULES_CACHE_LOCK = threading.Lock()
_COMPILED_RULES_CACHE: dict[str, tuple[tuple[tuple[str, int, int], ...], yara.Rules]] = {}


def clear_yara_cache() -> None:
    with _RULES_CACHE_LOCK:
        _COMPILED_RULES_CACHE.clear()
        logger.info("YARA rules cache cleared")


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


def compile_yara_rules(
    rules_dir: Path | str | None = None,
    use_cache: bool = True,
) -> yara.Rules | None:
    directory = Path(rules_dir) if rules_dir else resolve_yara_rules_path()
    if not directory.exists() or not directory.is_dir():
        logger.info("YARA rules directory does not exist: %s", directory)
        return None

    resolved_dir_key = str(directory.resolve())

    # Collect files and timestamps for cache invalidation
    files_with_mtime: list[tuple[str, int, int]] = []
    for extension in ("*.yar", "*.yara"):
        for file_path in directory.rglob(extension):
            try:
                stat = file_path.stat()
                mtime_ns = stat.st_mtime_ns
                file_size = stat.st_size
            except OSError:
                mtime_ns = 0
                file_size = -1
            files_with_mtime.append((str(file_path.resolve()), mtime_ns, file_size))

    if not files_with_mtime:
        logger.info("No YARA rule files found in: %s", directory)
        return None

    files_with_mtime.sort(key=lambda x: x[0])
    cache_fingerprint = tuple(files_with_mtime)

    if use_cache:
        with _RULES_CACHE_LOCK:
            if resolved_dir_key in _COMPILED_RULES_CACHE:
                cached_fp, cached_rules = _COMPILED_RULES_CACHE[resolved_dir_key]
                if cached_fp == cache_fingerprint:
                    return cached_rules

    rule_files: dict[str, str] = {
        f"ns_{Path(fp).stem}_{idx}": fp for idx, (fp, _, _) in enumerate(files_with_mtime)
    }

    try:
        compiled = yara.compile(filepaths=rule_files)
        logger.info("Successfully compiled %d YARA rule file(s)", len(rule_files))
        if use_cache:
            with _RULES_CACHE_LOCK:
                _COMPILED_RULES_CACHE[resolved_dir_key] = (cache_fingerprint, compiled)
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
    if len(content) > settings.max_attachment_size_bytes:
        raise ValueError(
            "YARA input exceeds configured maximum allowed size "
            f"({settings.max_attachment_size_bytes} bytes)"
        )

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
