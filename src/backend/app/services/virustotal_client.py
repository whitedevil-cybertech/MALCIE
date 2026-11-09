from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def compute_url_id(url: str) -> str:
    """VirusTotal API v3 URL identifier: Base64-URL-encoded without padding '='."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


@dataclass
class VTLookupResult:
    ioc_type: str
    ioc_value: str
    normalized_value: str
    query_status: str  # SUCCESS, NOT_FOUND, RATE_LIMITED, ERROR, UNCONFIGURED
    provider: str = "VirusTotal"
    reputation_score: int | None = None
    malicious_votes: int = 0
    suspicious_votes: int = 0
    harmless_votes: int = 0
    undetected_votes: int = 0
    total_engines: int = 0
    detection_details: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)
    queried_at: datetime = field(default_factory=utc_now)


class VirusTotalClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        cache_ttl_seconds: int | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else settings.vt_api_key
        self.base_url = (base_url or settings.vt_base_url).rstrip("/")
        self.timeout = timeout if timeout is not None else settings.vt_timeout_seconds
        self.max_retries = max_retries if max_retries is not None else settings.vt_max_retries
        self.cache_ttl = (
            cache_ttl_seconds
            if cache_ttl_seconds is not None
            else settings.vt_cache_ttl_seconds
        )
        self._client = http_client or httpx.Client(timeout=self.timeout)
        self._cache: dict[str, tuple[float, VTLookupResult]] = {}

    def _get_from_cache(self, cache_key: str) -> VTLookupResult | None:
        entry = self._cache.get(cache_key)
        if entry is None:
            return None
        cached_time, result = entry
        if time.time() - cached_time < self.cache_ttl:
            logger.debug("Cache hit for VirusTotal indicator: %s", cache_key)
            return result
        # Expired
        self._cache.pop(cache_key, None)
        return None

    def _store_in_cache(self, cache_key: str, result: VTLookupResult) -> None:
        self._cache[cache_key] = (time.time(), result)

    def _build_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["x-apikey"] = self.api_key
        return headers

    def _execute_request_with_backoff(self, endpoint: str) -> tuple[int, dict[str, Any] | None]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        attempts = 0
        headers = self._build_headers()

        while attempts <= self.max_retries:
            try:
                response = self._client.get(url, headers=headers)
                status_code = response.status_code

                if status_code == 429 or status_code in {500, 502, 503, 504}:
                    if attempts < self.max_retries:
                        retry_after = response.headers.get("Retry-After")
                        if retry_after:
                            try:
                                delay = min(float(retry_after), 10.0)
                            except ValueError:
                                delay = 0.2 * (2**attempts)
                        else:
                            delay = 0.2 * (2**attempts)
                        logger.warning(
                            "VT transient status %s. Backing off %ss (%s/%s)",
                            status_code,
                            delay,
                            attempts + 1,
                            self.max_retries,
                        )
                        time.sleep(delay)
                        attempts += 1
                        continue

                try:
                    payload = response.json()
                except Exception:
                    payload = None
                return status_code, payload

            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempts < self.max_retries:
                    delay = 0.2 * (2**attempts)
                    logger.warning(
                        "VT network error: %s. Backing off %ss (%s/%s)",
                        exc,
                        delay,
                        attempts + 1,
                        self.max_retries,
                    )
                    time.sleep(delay)
                    attempts += 1
                    continue
                logger.error("VirusTotal request failed after %s retries: %s", attempts, exc)
                return 503, None

        return 429, None

    def lookup_ioc(self, ioc_type: str, value: str) -> VTLookupResult:
        normalized_type = ioc_type.lower().strip()
        normalized_value = value.strip()
        if normalized_type in {"sha256", "md5", "sha1"}:
            normalized_value = normalized_value.lower()
        elif normalized_type == "domain":
            normalized_value = normalized_value.lower()

        cache_key = f"{normalized_type}:{normalized_value}"
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached

        if not self.api_key:
            logger.info("VirusTotal API key is not configured; skipping remote call for %s", value)
            result = VTLookupResult(
                ioc_type=normalized_type,
                ioc_value=value,
                normalized_value=normalized_value,
                query_status="UNCONFIGURED",
                detection_details={"message": "VT_API_KEY environment secret is not configured"},
            )
            self._store_in_cache(cache_key, result)
            return result

        if normalized_type in {"sha256", "md5", "sha1", "hash"}:
            endpoint = f"files/{normalized_value}"
        elif normalized_type == "url":
            url_id = compute_url_id(normalized_value)
            endpoint = f"urls/{url_id}"
        elif normalized_type == "domain":
            endpoint = f"domains/{normalized_value}"
        elif normalized_type in {"ipv4", "ipv6", "ip"}:
            endpoint = f"ip_addresses/{normalized_value}"
        else:
            return VTLookupResult(
                ioc_type=normalized_type,
                ioc_value=value,
                normalized_value=normalized_value,
                query_status="UNSUPPORTED_TYPE",
                detection_details={"message": f"IOC type '{ioc_type}' not supported by VT"},
            )

        status_code, data = self._execute_request_with_backoff(endpoint)

        if status_code == 200 and data and "data" in data:
            attributes = data["data"].get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            reputation = attributes.get("reputation")

            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            total = malicious + suspicious + harmless + undetected

            results_dict = attributes.get("last_analysis_results", {})
            detections_summary: dict[str, Any] = {}
            for engine, details in results_dict.items():
                category = details.get("category")
                if category in {"malicious", "suspicious"}:
                    detections_summary[engine] = {
                        "category": category,
                        "result": details.get("result"),
                        "method": details.get("method"),
                    }

            result = VTLookupResult(
                ioc_type=normalized_type,
                ioc_value=value,
                normalized_value=normalized_value,
                query_status="SUCCESS",
                reputation_score=reputation,
                malicious_votes=malicious,
                suspicious_votes=suspicious,
                harmless_votes=harmless,
                undetected_votes=undetected,
                total_engines=total,
                detection_details=detections_summary,
                raw_response={
                    "meaningful_name": attributes.get("meaningful_name"),
                    "type_description": attributes.get("type_description"),
                    "tags": attributes.get("tags", []),
                    "stats": stats,
                },
            )
        elif status_code == 404:
            result = VTLookupResult(
                ioc_type=normalized_type,
                ioc_value=value,
                normalized_value=normalized_value,
                query_status="NOT_FOUND",
                detection_details={"message": "Indicator not found in VirusTotal database"},
            )
        elif status_code == 429:
            result = VTLookupResult(
                ioc_type=normalized_type,
                ioc_value=value,
                normalized_value=normalized_value,
                query_status="RATE_LIMITED",
                detection_details={"message": "VirusTotal API rate limit exceeded"},
            )
        else:
            error_message = ""
            if data and "error" in data:
                error_message = str(data["error"].get("message", ""))
            result = VTLookupResult(
                ioc_type=normalized_type,
                ioc_value=value,
                normalized_value=normalized_value,
                query_status="ERROR",
                detection_details={
                    "status_code": status_code,
                    "error": error_message or "External API request failed",
                },
            )

        self._store_in_cache(cache_key, result)
        return result


def get_virustotal_client() -> VirusTotalClient:
    return VirusTotalClient()
