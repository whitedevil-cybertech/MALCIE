# MALCIE Session Memory — Phase 5 Completion

## Scope

Phase 5 implements controlled Sysmon endpoint telemetry ingestion and integrates it with the existing evidence correlation, risk, and timeline pipeline. The implementation is limited to offline XML/JSON evidence ingestion; it does not add EDR, live monitoring, binary execution, or sandboxing.

## Implementation

- `src/backend/app/services/sysmon_ingestion.py` parses Sysmon XML and JSON, validates Event IDs 1, 3, 11, 12, 13, and 14, normalizes timestamps to UTC, preserves raw evidence and provenance, and handles absent hashes without fabricating values.
- `src/backend/app/models.py` adds `EndpointEvent`, including hostname, endpoint identity, process hierarchy, hashes, destinations, registry fields, raw evidence, provenance, and a unique fingerprint.
- `src/backend/app/api/telemetry.py` adds `POST /api/v1/telemetry/upload` and `GET /api/v1/telemetry/incidents/{incident_id}`. `src/backend/app/api/incidents.py` also exposes `GET /api/v1/incidents/{incident_id}/telemetry`.
- `src/backend/app/services/correlation_engine.py` links endpoint hashes to artifacts, destinations to existing IOCs, adds Sysmon events to the incident timeline, and adds explainable endpoint-match risk reasons.
- `alembic/versions/0007_phase5_sysmon_telemetry.py` creates the indexed `endpoint_events` table with a unique fingerprint constraint and nullable incident association.

## Determinism and evidence handling

Event fingerprints are SHA-256 digests over the normalized event, source, and raw evidence. Re-ingesting the same event returns it as a duplicate instead of creating another row. When no incident is supplied, association occurs only if exactly one incident matches an observed artifact hash or network IOC; ambiguous or unmatched events remain unassociated.

## Tests and actual results

- `tests/backend/test_phase5_sysmon_telemetry.py` covers JSON and XML ingestion, UTC normalization, optional hashes, raw evidence preservation, idempotency, timeline fusion, and 404 behavior.
- Backend: `.venv/bin/pytest tests/backend -q` — **41 passed**.
- Backend lint: `.venv/bin/ruff check src/backend/app tests/backend alembic` — **passed with zero errors**.
- Frontend: `cd src/frontend && npm run lint && npm run test` — **lint passed; 1 test passed**.
- Migration validation: `DATABASE_URL=sqlite:///./phase5_migration_check.db .venv/bin/alembic upgrade head` — **all revisions 0001 through 0007 applied successfully**; temporary database removed.

## Files and API summary

The README documents Phase 5 capabilities and endpoints. The production database remains PostgreSQL-compatible through SQLAlchemy/Alembic, while the existing SQLite test fixture continues to support regression tests.
