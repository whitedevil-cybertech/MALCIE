"""File-spool Sysmon forwarder with retry-safe, acknowledged delivery.

The source file remains in the spool until MALCIE acknowledges it. If the process
stops after server ingestion but before archival, event fingerprints make replay safe.
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from pathlib import Path

import httpx

logger = logging.getLogger("malcie.sysmon_forwarder")
MAX_FORWARD_FILE_BYTES = 64 * 1024 * 1024


def forward_file(
    client: httpx.Client,
    source: Path,
    endpoint_url: str,
    *,
    incident_id: int | None = None,
    max_retries: int = 5,
) -> bool:
    suffix = source.suffix.lower()
    if suffix not in {".json", ".xml"}:
        logger.warning("Skipping unsupported spool file: %s", source.name)
        return False
    try:
        if source.stat().st_size > MAX_FORWARD_FILE_BYTES:
            logger.error(
                "Spool file exceeds the safe upload limit and was retained: %s", source.name
            )
            return False
    except OSError as exc:
        logger.error("Cannot inspect spool file; retained: %s (%s)", source.name, exc)
        return False
    content_type = "application/xml" if suffix == ".xml" else "application/json"
    params = {"incident_id": incident_id} if incident_id is not None else None
    for attempt in range(max_retries + 1):
        try:
            response = client.post(
                endpoint_url,
                params=params,
                content=source.read_bytes(),
                headers={"Content-Type": content_type},
            )
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict) or "ingested_count" not in result:
                raise ValueError("MALCIE returned an invalid telemetry acknowledgement")
            return True
        except (OSError, ValueError, httpx.HTTPError) as exc:
            if attempt >= max_retries:
                logger.error("Forwarding failed; spool file retained: %s (%s)", source.name, exc)
                return False
            time.sleep(min(2**attempt, 30))
    return False


def forward_spool(
    spool: Path,
    endpoint_url: str,
    *,
    incident_id: int | None = None,
    api_key: str | None = None,
    bearer_token: str | None = None,
    max_retries: int = 5,
) -> int:
    headers: dict[str, str] = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    elif api_key:
        headers["X-API-Key"] = api_key
    sent_dir = spool / "sent"
    sent_dir.mkdir(parents=True, exist_ok=True)
    delivered = 0
    with httpx.Client(headers=headers, timeout=60.0) as client:
        for source in sorted(spool.iterdir()):
            if not source.is_file():
                continue
            if forward_file(
                client, source, endpoint_url, incident_id=incident_id,
                max_retries=max_retries,
            ):
                destination = sent_dir / source.name
                if destination.exists():
                    destination = sent_dir / f"{source.stem}-{int(time.time())}{source.suffix}"
                os.replace(source, destination)
                delivered += 1
    return delivered


def main() -> int:
    parser = argparse.ArgumentParser(description="Forward Sysmon JSON/XML spool files to MALCIE")
    parser.add_argument("spool", type=Path, help="Directory containing exported Sysmon files")
    parser.add_argument(
        "--url", default=os.getenv("MALCIE_TELEMETRY_URL"),
        help="Telemetry upload URL (or MALCIE_TELEMETRY_URL)",
    )
    parser.add_argument("--incident-id", type=int)
    args = parser.parse_args()
    if not args.url:
        parser.error("--url or MALCIE_TELEMETRY_URL is required")
    delivered = forward_spool(
        args.spool, args.url,
        incident_id=args.incident_id,
        api_key=os.getenv("MALCIE_API_KEY"),
        bearer_token=os.getenv("MALCIE_BEARER_TOKEN"),
    )
    logger.info("Forwarded %d telemetry file(s)", delivered)
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    raise SystemExit(main())
