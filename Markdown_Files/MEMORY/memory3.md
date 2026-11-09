# MALCIE Session Memory — Phase 3 Completion

## Session Scope & Objective

This session executed and formally verified **Phase 3: Email & Threat Integration** per the project requirements and roadmap defined in:
- `Markdown_Files/Phases.md` (lines 35–40)
- `Markdown_Files/PRD.md` (lines 249–275, 401–425)
- `Markdown_Files/MALCIE Architecture.md` (lines 41–51, 110–125)
- `Markdown_Files/Rules.md` (lines 41–45, 88–100, 145–162)

The core objectives delivered and verified in this phase:
1. **Microsoft Graph Polling & Webhook Change Notifications:** Extended Graph mail services with folder polling (`GET /me/messages`, `GET /me/mailFolders/{folder_id}/messages`), automated email ingestion into incident pipelines, subscription lifecycle management (create/delete), and webhook endpoints with validation handshake (`validationToken`) and `clientState` security verification.
2. **VirusTotal API v3 Intelligence Enrichment:** Implemented a full-featured VirusTotal v3 client supporting hashes (SHA-256, MD5, SHA-1), URLs (base64url unpadded identifier encoding), domains, and IP addresses.
3. **Reputation Persistence:** Added `threat_intel_results` table and SQLAlchemy model (`ThreatIntelResult`) linking reputation scores, malicious/suspicious/harmless/undetected votes, engine totals, detection details, and timestamps to incidents and artifacts.
4. **Resiliency & Performance Mechanisms:** Integrated client timeouts, exponential backoff with retry on HTTP 429 (rate limits) and 5xx transient errors, multi-tiered caching (in-memory TTL cache + database cache lookup), and graceful degradation.
5. **Secure Configuration:** Environment-based secrets management via Pydantic settings (`VT_API_KEY`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`, `GRAPH_WEBHOOK_CLIENT_STATE`, etc.) without hardcoded credentials.
6. **Testing & Quality Assurance:** Added 9 focused unit and integration test cases bringing the backend test suite to 33/33 passing tests with zero linter errors.

---

## 1. Architecture & Design Implementation

### Microsoft Graph Ingestion & Polling Architecture
- **Polling (`/api/v1/emails/graph/messages`, `/api/v1/emails/graph/poll`):**
  - Allows SOC analysts or automated background workers to query messages from a user mailbox or designated folder (e.g., `inbox`, `junkemail`, or phishing quarantine).
  - When `auto_ingest=True` with a target `incident_id`, retrieved messages are automatically fetched in raw MIME (`/$value`), parsed via Python's `email` package, hashed, and persisted with extracted attachments directly into the incident evidence hierarchy.
- **Webhook Change Notifications (`/api/v1/emails/graph/webhook`):**
  - Handles Microsoft Graph validation handshakes: responds to incoming `validationToken` query parameter with `200 OK` and `text/plain` token body.
  - Receives change notification webhooks for newly created messages (`changeType: "created"`).
  - Validates `clientState` against configured `GRAPH_WEBHOOK_CLIENT_STATE` to prevent spoofed notification injections.
  - Returns `202 Accepted` within the required 3-second SLA.
- **Subscription Lifecycle (`/api/v1/emails/graph/subscriptions`):**
  - Supports programmatic creation and deletion of Graph webhook subscriptions targeting mailbox resources.

### VirusTotal API v3 Threat Intelligence Engine
- **IOC Support:**
  - Hashes: `GET /api/v3/files/{hash}` supporting SHA-256, MD5, SHA-1.
  - URLs: `GET /api/v3/urls/{url_id}` using standard RFC 4648 Base64 URL-safe encoding without padding `=` (e.g., `compute_url_id(url)`).
  - Domains: `GET /api/v3/domains/{domain}`.
  - IP Addresses: `GET /api/v3/ip_addresses/{ip}`.
- **Throttling & Backoff:**
  - Respects VirusTotal public API quotas (4 requests/minute).
  - Automatically captures HTTP 429 Too Many Requests and reads `Retry-After` response headers.
  - Implements exponential backoff (`delay = 0.2 * (2**attempts)`) with configurable max retries (`VT_MAX_RETRIES`).
- **Caching Layer:**
  - In-memory thread-safe cache with configurable TTL (`VT_CACHE_TTL_SECONDS`, default 24h).
  - Database cache lookup in `threat_intel_results` to prevent redundant external API queries for previously evaluated IOCs within the incident or workspace.
- **Defensive Resilience & Graceful Degradation:**
  - Missing or unconfigured API key (`VT_API_KEY=""`) returns structured `UNCONFIGURED` status with 0 malicious votes rather than throwing an exception or blocking the pipeline.
  - Indicators not found in VirusTotal database return `NOT_FOUND` status rather than crashing.
  - Network timeouts and 5xx errors return `ERROR` query status without terminating the incident workflow. Threat intel serves as evidentiary support, not a single point of failure.

### Database Persistence & Schema
- **Model:** `ThreatIntelResult` in `src/backend/app/models.py`.
- **Fields:**
  - `id`: Primary key
  - `incident_id`: Foreign key to `incidents.id` (cascade delete)
  - `artifact_id`: Foreign key to `artifacts.id` (optional, cascade delete)
  - `ioc_id`: Foreign key to `ioc_records.id` (optional, set null on delete)
  - `ioc_type`: Indicator type (`sha256`, `md5`, `sha1`, `url`, `domain`, `ipv4`)
  - `ioc_value` / `normalized_value`: Raw and normalized indicator values (indexed)
  - `provider`: Default `"VirusTotal"`
  - `query_status`: `"SUCCESS"`, `"NOT_FOUND"`, `"RATE_LIMITED"`, `"ERROR"`, `"UNCONFIGURED"`
  - `reputation_score`: Normalized integer score from intelligence provider
  - `malicious_votes`, `suspicious_votes`, `harmless_votes`, `undetected_votes`: Vendor verdict counts
  - `total_engines`: Total security engines reporting
  - `detection_details`: JSON object detailing engines that flagged malicious/suspicious
  - `raw_response`: JSON metadata and summary tags
  - `queried_at`: Timestamp of intelligence retrieval
  - `created_at`: Record creation timestamp
- **Migration:** `alembic/versions/0005_phase3_threat_intel_reputation.py` manages table and indices.

---

## 2. Changed & Created Files

| File | Status | Description |
|---|---|---|
| `src/backend/app/core/config.py` | Modified | Added VT and Graph configuration settings (`vt_api_key`, `vt_base_url`, `vt_timeout_seconds`, `vt_max_retries`, `vt_cache_ttl_seconds`, `graph_webhook_client_state`, `graph_timeout_seconds`, `graph_max_retries`). |
| `.env.example` | Modified | Documented all Phase 3 environment variables with safe default placeholders. |
| `src/backend/app/models.py` | Modified | Added `ThreatIntelResult` model and relationships on `Incident`, `Artifact`, and `IOCRecord`. |
| `alembic/versions/0005_phase3_threat_intel_reputation.py` | Created | Database migration script creating `threat_intel_results` table and performance indices. |
| `src/backend/app/schemas.py` | Modified | Added Pydantic schemas for Graph polling/subscriptions/webhooks and Threat Intelligence reads/lookups. |
| `src/backend/app/services/graph_client.py` | Modified | Added message listing, subscription creation/deletion, and exponential backoff retry logic on transient errors and rate limits. |
| `src/backend/app/api/emails.py` | Modified | Implemented `/graph/messages`, `/graph/poll`, `/graph/subscriptions`, and `/graph/webhook` validation handshake & notification handler. |
| `src/backend/app/services/virustotal_client.py` | Created | Standalone VirusTotal API v3 client with hashing, URL encoding, in-memory caching, exponential backoff, and graceful error handling. |
| `src/backend/app/services/threat_intel.py` | Created | Threat intelligence orchestration service for single IOC enrichment, batch incident enrichment, and artifact IOC enrichment with DB cache deduplication. |
| `src/backend/app/api/threat_intel.py` | Created | REST API endpoints for incident/artifact threat intel enrichment and ad-hoc IOC lookup. |
| `src/backend/app/main.py` | Modified | Registered `threat_intel_router` under `/api/v1`. |
| `tests/backend/test_phase3_graph_and_threat_intel.py` | Created | Comprehensive tests covering Graph polling, webhooks, VT lookups, caching, backoff, and end-to-end reputation persistence. |
| `README.md` | Modified | Updated project status, capabilities, API documentation, and test metrics. |
| `Markdown_Files/MEMORY/memory3.md` | Created | This memory document. |

---

## 3. Test & Verification Results

### Backend Test Suite
Executed via `.venv\Scripts\python -m pytest tests/backend -v`:
- `tests/backend/test_health.py` (1 test) — **PASSED**
- `tests/backend/test_phase2a_email_intake.py` (3 tests) — **PASSED**
- `tests/backend/test_phase2b_pe_static_analysis.py` (8 tests) — **PASSED**
- `tests/backend/test_phase2b_partb_analysis.py` (12 tests) — **PASSED**
- `tests/backend/test_phase3_graph_and_threat_intel.py` (9 tests) — **PASSED**
  - `test_graph_poll_and_auto_ingest`: Verified message listing, manual poll, validation error handling, and auto-ingest into incident with attachment parsing.
  - `test_graph_webhook_validation_and_notifications`: Verified Microsoft Graph validation handshake (200 OK text/plain) and clientState verification on change notifications (202 Accepted).
  - `test_graph_subscription_lifecycle`: Verified subscription creation and deletion endpoints.
  - `test_graph_client_exponential_backoff_and_timeout`: Verified retry loop on HTTP 429 with `Retry-After`.
  - `test_compute_url_id`: Verified unpadded Base64 URL-safe encoding against VT specifications.
  - `test_virustotal_client_hashes_urls_domains_enrichment`: Verified SHA-256, URL, domain lookups, and in-memory caching.
  - `test_virustotal_not_found_and_rate_limit_backoff`: Verified graceful handling of 404 (NOT_FOUND) and 429 rate limit backoff.
  - `test_virustotal_unconfigured_api_key_handles_gracefully`: Verified UNCONFIGURED handling when no secret is present.
  - `test_incident_and_artifact_enrichment_persistence_workflow`: Verified end-to-end incident enrichment, artifact enrichment, database persistence, and ad-hoc lookup.
- **Total: 33 passed in 3.04s (100% passing)**

### Backend Linting
Executed via `.venv\Scripts\python -m ruff check src/backend/app tests/backend alembic`:
- **0 errors, all checks passed** (enforcing 100-character line limit, flake8, bugbear, and import sorting).

### Frontend Component Tests
Executed via `npm run test` in `src/frontend`:
- `src/App.test.tsx` (1 test) — **PASSED**

---

## 4. Outstanding Issues & Notes

- **Sandbox Loopback Sockets on Windows:** On Windows in Standard Sandbox mode (`BypassSandbox: false`), local socket pair creation hangs due to network isolation. When executing `pytest`, `BypassSandbox: true` is necessary because `TestClient` initializes internal loopback event portals.
- **Zero Live Secrets Committed:** All tests use mocked HTTP transports (`httpx.MockTransport`) and dependency overrides. No live credentials or API tokens were added or committed.

---

## 5. Precise Next-Session Tasks (Phase 4 Handoff)

With Phase 3 complete and verified, the next session will start **Phase 4: Correlation & Linkage Engine (Weeks 9–11)** per `Markdown_Files/Phases.md` (lines 42–47).

### Specific Phase 4 Tasks:
1. **Correlation Engine Implementation:**
   - Link artifacts, extracted IOCs, and email metadata into coherent incident narratives.
   - Build relationship mapping across disparate evidence sources (e.g. matching an email sender/domain to an artifact C2 network IOC).
2. **Confidence Scoring:**
   - Implement multi-factor confidence scoring combining YARA rule severity, static PE anomalies (high entropy sections, packing heuristics), and VirusTotal threat reputation scores.
3. **Timeline Generation:**
   - Generate chronological timeline events from email headers (`sent_at`), PE compilation timestamps (`pe_headers.TimeDateStamp`), and threat query timestamps.
4. **Correlation REST Endpoints:**
   - Expose `/api/v1/incidents/{incident_id}/correlate` and `/api/v1/incidents/{incident_id}/timeline` endpoints.
5. **Testing & Validation:**
   - Add unit and integration tests using multi-stage scenarios (suspicious email + packed PE attachment + threat intelligence detections).
