# Independent Technical Review — 2026-11-12

## Reviewed implementation

- `src/backend/app/services/graph_client.py`
- `src/backend/app/api/emails.py`
- `src/backend/app/core/security.py`
- `src/backend/app/core/config.py`
- `src/backend/app/services/ioc_extraction.py`
- `src/backend/app/services/threat_intel.py`
- `src/backend/app/services/virustotal_client.py`
- `src/backend/app/api/health.py`
- `Dockerfile`
- `docker-compose.yml`
- `alembic/env.py` and migration chain through `0008_ioc_classification.py`
- relevant backend tests under `tests/backend/`
- `src/frontend/src/App.tsx`, frontend package configuration, and backend API routers

## Findings

### Fixed

- **Medium — IPv6 enrichment omission:** IPv6 extraction and VirusTotal lookup existed,
  but incident and artifact batch enrichment only selected IPv4. Both target sets now
  include `ipv6`.
- **Medium — webhook validation weakness:** notifications with a matching client state
  but missing subscription/resource/message fields were counted as processed. Required
  Graph fields and supported change types are now validated.
- **Medium — repeated Graph ingestion:** polling and webhook delivery could persist the
  same Graph message repeatedly for one incident. Application-level duplicate checks
  now skip already-ingested message IDs.
- **Medium — misleading readiness signal:** `/api/v1/health` was liveness-only and
  returned OK when the database was unavailable. It now executes `SELECT 1` and returns
  `503` on SQLAlchemy database errors.

### Unresolved

- **High — OAuth token lifecycle:** access and refresh tokens are returned to callers,
  but no encrypted server-side token store, expiry timestamp, account ownership, or
  automatic refresh path exists. The frontend plan therefore defers account/session
  UX.
- **High — webhook durability and ingestion failure semantics:** deduplication remains
  application-level rather than backed by a durable receipt/unique constraint, and
  webhook ingestion failures are logged while the endpoint still acknowledges the
  notification. A durable receipt model and retry/dead-letter policy are needed.
- **Medium — webhook trust boundary:** production bypasses the normal API-key guard for
  the Graph handshake and notifications, relying on configured `clientState` for
  notification filtering. Graph subscription ownership and stronger notification
  authorization are not implemented.
- **Medium — IOC classification scope:** classification currently starts at `extracted`
  and is promoted to `intelligence_supported` when VT has malicious or suspicious
  votes. There is no analyst-managed benign/false-positive/manual state workflow.
- **Medium — Docker migration observability:** Compose runs migrations before Uvicorn,
  so migration failure prevents backend startup, but there is no integration test,
  restart policy, or migration-specific health/diagnostic path.
- **Low — URL/domain edge coverage:** normalization handles default ports, fragments,
  IDN/Punycode, valid IPv4/IPv6, and common binary-extension false positives. Explicit
  coverage remains limited for zone-scoped IPv6, Unicode confusables, invalid ports,
  trailing-dot variants, and broader domain false positives.

## Validation

- `cd src/backend && /tmp/malcie-review-venv/bin/pytest -q ../../tests/backend/test_security_integration_audit.py ../../tests/backend/test_edge_case_hardening.py ../../tests/backend/test_phase3_graph_and_threat_intel.py ../../tests/backend/test_health.py`
  — **24 passed**, one dependency deprecation warning.
- `/tmp/malcie-review-venv/bin/ruff check src/backend/app tests/backend alembic`
  — **passed**.
- The full backend suite and frontend suite were not run in this review; frontend
  dependencies were not installed in the environment.
