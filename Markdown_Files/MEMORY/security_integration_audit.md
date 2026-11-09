# MALCIE Phases 1-5 Security and Integration Audit

## Scope and method

This audit compared the implementation with `Markdown_Files/PRD.md`,
`MALCIE Architecture.md`, `Phases.md`, `Rules.md`, and the Phase 1-5 memory
files. It inspected the FastAPI routes and dependencies, SQLAlchemy models,
Alembic revisions, evidence storage and static analysis, Graph and VirusTotal
integrations, correlation and risk services, frontend API usage, Docker
configuration, and backend/frontend tests.

The complete evidence path reviewed was email intake -> attachment extraction
-> static PE/YARA analysis -> IOC extraction -> threat intelligence ->
correlation/timeline -> Sysmon endpoint telemetry. No malware was executed.

## Findings

### HIGH - Production API access was unauthenticated

Before the audit, normal API routes had no authentication or authorization
dependency. An unauthenticated caller could submit evidence, invoke analysis,
read incidents, and access telemetry. `src/backend/app/core/security.py` now
provides production-gated API-key/Bearer authentication using constant-time
comparison, and `src/backend/app/main.py` applies it to the application.

This is a boundary mitigation, not the PRD's full OAuth2/OIDC, user, role, or
incident-ownership model. Production deployments must still provide a stronger
identity and authorization layer before handling multi-tenant or sensitive
investigations.

### HIGH - Graph access tokens were accepted in query parameters

Graph message and subscription routes accepted bearer tokens in query strings,
which can leak through logs, browser history, proxies, and monitoring. Header
tokens are now preferred and production rejects query-only Graph tokens.
Development retains query-token compatibility for existing local workflows.

The Graph webhook validation and notification endpoint is intentionally exempt
from the application API key because Microsoft Graph must reach it directly.
Notifications are filtered by configured `clientState`; deployments must set
that secret and restrict the public route at the reverse proxy where possible.

### MEDIUM - Invalid Sysmon timestamps were silently replaced

Invalid or missing timestamps previously became the current time, corrupting
timeline ordering and evidence meaning. Sysmon normalization now rejects
invalid timestamps and requires a valid event timestamp.

### MEDIUM - Stored artifact bytes were not re-verified before analysis

Static analysis could read modified bytes from the storage path while trusting
the database digest. `pe_static_analysis.py` now hashes bytes immediately before
analysis and fails closed when the digest differs from `Artifact.sha256`.

### MEDIUM - Sysmon payload resource limits and XML declaration checks were absent

Telemetry ingestion now enforces configurable request-size and event-count
limits and rejects XML `DOCTYPE`/`ENTITY` declarations before parsing. This
reduces entity-expansion, external-entity, and resource-exhaustion exposure.
Malformed XML/JSON remains a client error.

### MEDIUM - Endpoint duplicate insertion was race-prone

Endpoint deduplication used a check-then-insert sequence. The
`endpoint_events.fingerprint` unique constraint is now paired with a nested
transaction/savepoint duplicate path so concurrent retries return the existing
event instead of creating duplicates or failing the request.

### LOW - Deployment database URL was invalid

The Docker Compose backend URL contained a redacted placeholder rather than a
valid PostgreSQL SQLAlchemy URL. It now uses the PostgreSQL psycopg URL expected
by the application and migration tooling.

### INFORMATIONAL - Authorization remains incomplete

The shared API key proves possession of one application secret; it does not
provide user identity, roles, incident-level access control, audit attribution,
rotation, or revocation. Email duplicate submissions also remain a known
limitation: the current schema does not enforce a unique message/content key,
and a failed transaction can leave an orphaned evidence file. These are not
claimed as fixed by this audit.

## Tests and validation

Added or updated coverage in:

- `tests/backend/test_phase5_sysmon_telemetry.py`
- `tests/backend/test_security_integration_audit.py`

The targeted security tests cover invalid timestamps, XML entity rejection,
payload limits, production authentication, Graph webhook reachability,
artifact hash mismatch, and concurrent duplicate telemetry ingestion.

Actual validation results:

- `.venv/bin/pytest tests/backend -q` — **48 passed**, 1 existing Starlette
  deprecation warning.
- `.venv/bin/ruff check src/backend/app tests/backend alembic` — **passed**.
- `cd src/frontend && npm run lint && npm run test` — **lint passed; 1 test
  passed**.
- `DATABASE_URL=sqlite:///./audit_migration_check.db .venv/bin/alembic upgrade
  head` — **revisions 0001 through 0007 applied successfully**.

The migration check used SQLite as the repository's existing lightweight
validation path. A live PostgreSQL integration run, production reverse-proxy
configuration, Graph webhook delivery, and multi-worker concurrency remain
unverified in this environment.

## Production-readiness assessment

MALCIE is **not certified production-ready** by this audit. Core Phase 1-5
flows and the reviewed regressions pass local validation, and several concrete
security defects are mitigated. Before production use, implement real
identity/RBAC and incident authorization, verify PostgreSQL migrations and
concurrent transactions against the deployed database, harden webhook ingress,
address email deduplication/orphan cleanup, and perform deployment-level
secret, storage-permission, backup, monitoring, and rate-limit validation.
