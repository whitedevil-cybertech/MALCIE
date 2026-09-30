from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

URL_REGEX = re.compile(
    r"https?://[a-zA-Z0-9][-a-zA-Z0-9@:%._+~#=]{0,256}\b(?:/[^<>\s\"'\\]*)?",
    re.IGNORECASE,
)
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_REGEX = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b"
)
WIN_PATH_REGEX = re.compile(
    r"(?:[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n\t]+\\)*[^\\/:*?\"<>|\r\n\t]+|"
    r"%[a-zA-Z0-9_-]+%\\(?:[^\\/:*?\"<>|\r\n\t]+\\)*[^\\/:*?\"<>|\r\n\t]+|"
    r"\\\\[a-zA-Z0-9._-]+\\(?:[^\\/:*?\"<>|\r\n\t]+\\)*[^\\/:*?\"<>|\r\n\t]+)"
)
POSIX_PATH_REGEX = re.compile(
    r"(?:^|[\s\"'])(\/(?:bin|sbin|usr|tmp|var|etc|opt|dev|proc)\/[^\s\"'<>;|&]+)"
)

# Common binary extensions that should not be classified as network domains
DISALLOWED_DOMAIN_EXTENSIONS = {
    "dll",
    "exe",
    "sys",
    "pdb",
    "ocx",
    "drv",
    "cpl",
    "scr",
    "obj",
    "lib",
    "bin",
    "dat",
    "mui",
    "manifest",
    "res",
}


@dataclass
class ExtractedIOC:
    ioc_type: str
    value: str
    normalized_value: str
    source: str
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "source": self.source,
            "context": self.context,
        }


def extract_artifact_hashes(content: bytes, source: str = "artifact_content") -> list[ExtractedIOC]:
    if not content:
        return []

    sha256_val = hashlib.sha256(content).hexdigest()
    md5_val = hashlib.md5(content).hexdigest()
    sha1_val = hashlib.sha1(content).hexdigest()

    return [
        ExtractedIOC(
            ioc_type="sha256",
            value=sha256_val,
            normalized_value=sha256_val.lower(),
            source=source,
            context={"algorithm": "SHA-256", "byte_length": len(content)},
        ),
        ExtractedIOC(
            ioc_type="md5",
            value=md5_val,
            normalized_value=md5_val.lower(),
            source=source,
            context={"algorithm": "MD5", "byte_length": len(content)},
        ),
        ExtractedIOC(
            ioc_type="sha1",
            value=sha1_val,
            normalized_value=sha1_val.lower(),
            source=source,
            context={"algorithm": "SHA-1", "byte_length": len(content)},
        ),
    ]


def _normalize_ipv4(candidate: str) -> str | None:
    try:
        ip = ipaddress.IPv4Address(candidate)
        return str(ip)
    except ipaddress.AddressValueError:
        return None


def _normalize_ipv6(candidate: str) -> str | None:
    try:
        ip = ipaddress.IPv6Address(candidate)
        return ip.compressed
    except ipaddress.AddressValueError:
        return None


def _normalize_url(raw_url: str) -> str | None:
    cleaned = raw_url.rstrip(".,;:)]>'\"")
    try:
        parsed = urlsplit(cleaned)
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if not parsed.netloc:
            return None
        normalized_netloc = parsed.netloc.lower()
        normalized_scheme = parsed.scheme.lower()
        return urlunsplit(
            (normalized_scheme, normalized_netloc, parsed.path, parsed.query, parsed.fragment)
        )
    except Exception:  # noqa: BLE001
        return None


def _normalize_domain(raw_domain: str) -> str | None:
    domain = raw_domain.rstrip(".").lower()
    parts = domain.split(".")
    if len(parts) < 2:
        return None
    tld = parts[-1]
    if tld in DISALLOWED_DOMAIN_EXTENSIONS:
        return None
    if not tld.isalpha() or len(tld) < 2:
        return None
    # Reject domains that are purely numeric or resemble an IP address
    if all(part.isdigit() for part in parts):
        return None
    return domain


def _normalize_path(raw_path: str) -> str:
    cleaned = raw_path.strip().strip("'\"")
    return cleaned


def extract_iocs_from_text(
    text: str,
    source: str = "extracted_strings",
    context_extra: dict[str, Any] | None = None,
) -> list[ExtractedIOC]:
    if not text:
        return []

    extra = context_extra or {}
    results: list[ExtractedIOC] = []

    # 1. URLs
    found_urls = URL_REGEX.findall(text)
    for raw_url in found_urls:
        norm = _normalize_url(raw_url)
        if norm:
            results.append(
                ExtractedIOC(
                    ioc_type="url",
                    value=raw_url.rstrip(".,;:)]>'\""),
                    normalized_value=norm,
                    source=source,
                    context=extra,
                )
            )

    # 2. IPv4
    found_ips = IPV4_REGEX.findall(text)
    for raw_ip in found_ips:
        norm_ip = _normalize_ipv4(raw_ip)
        if norm_ip:
            results.append(
                ExtractedIOC(
                    ioc_type="ipv4",
                    value=raw_ip,
                    normalized_value=norm_ip,
                    source=source,
                    context=extra,
                )
            )

    # 3. IPv6 tokens (split text tokens and validate)
    for token in re.split(r"[\s,;\"'()<>\[\]]+", text):
        if ":" in token and len(token) >= 3:
            cleaned_token = token.strip("[]")
            norm_v6 = _normalize_ipv6(cleaned_token)
            if norm_v6:
                results.append(
                    ExtractedIOC(
                        ioc_type="ipv6",
                        value=cleaned_token,
                        normalized_value=norm_v6,
                        source=source,
                        context=extra,
                    )
                )

    # 4. Domains
    found_domains = DOMAIN_REGEX.findall(text)
    for raw_domain in found_domains:
        norm_dom = _normalize_domain(raw_domain)
        if norm_dom:
            results.append(
                ExtractedIOC(
                    ioc_type="domain",
                    value=raw_domain,
                    normalized_value=norm_dom,
                    source=source,
                    context=extra,
                )
            )

    # 5. Windows File Paths
    found_win_paths = WIN_PATH_REGEX.findall(text)
    for raw_path in found_win_paths:
        norm_path = _normalize_path(raw_path)
        if norm_path:
            results.append(
                ExtractedIOC(
                    ioc_type="file_path",
                    value=raw_path,
                    normalized_value=norm_path,
                    source=source,
                    context={"flavor": "windows", **extra},
                )
            )

    # 6. POSIX File Paths
    found_posix_paths = POSIX_PATH_REGEX.findall(text)
    for raw_path in found_posix_paths:
        norm_path = _normalize_path(raw_path)
        if norm_path:
            results.append(
                ExtractedIOC(
                    ioc_type="file_path",
                    value=raw_path,
                    normalized_value=norm_path,
                    source=source,
                    context={"flavor": "posix", **extra},
                )
            )

    return results


def deduplicate_iocs(iocs: list[ExtractedIOC]) -> list[ExtractedIOC]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[ExtractedIOC] = []

    for ioc in iocs:
        key = (ioc.ioc_type, ioc.normalized_value, ioc.source)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ioc)

    return deduped


def extract_artifact_iocs(
    *,
    content: bytes,
    extracted_strings: list[str] | None = None,
    imports: list[dict[str, Any]] | None = None,
    yara_matches: list[dict[str, Any]] | None = None,
) -> list[ExtractedIOC]:
    collected: list[ExtractedIOC] = []

    # Hashes
    collected.extend(extract_artifact_hashes(content, source="artifact_content"))

    # Printable Strings
    if extracted_strings:
        combined_text = "\n".join(extracted_strings)
        collected.extend(extract_iocs_from_text(combined_text, source="artifact_strings"))

    # Imports (DLL names, function names)
    if imports:
        for entry in imports:
            dll = entry.get("dll")
            if isinstance(dll, str):
                collected.extend(
                    extract_iocs_from_text(
                        dll,
                        source="pe_imports",
                        context_extra={"dll": dll},
                    )
                )

    # YARA match strings
    if yara_matches:
        for match in yara_matches:
            rule_name = match.get("rule", "unknown")
            for string_info in match.get("strings", []):
                preview = string_info.get("data")
                if isinstance(preview, str) and preview:
                    collected.extend(
                        extract_iocs_from_text(
                            preview,
                            source=f"yara_match:{rule_name}",
                            context_extra={"rule": rule_name},
                        )
                    )

    return deduplicate_iocs(collected)
