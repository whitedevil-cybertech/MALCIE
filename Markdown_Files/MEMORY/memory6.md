# MALCIE Session Memory - Security Hardening Phase 6

## Scope

This phase audited and hardened security controls across the Phase 1-5
evidence workflow: API authentication, Graph OAuth, webhook processing,
configuration, CORS, endpoint telemetry, artifact integrity, and deployment
defaults. No uploaded malware was executed.

## Implemented controls

- Production API routes retain fail-closed API-key/Bearer authentication.
- Graph OAuth state is now HMAC-signed, expires after ten minutes, binds to an
  allowlisted redirect URI, and is required during token exchange.
- Graph webhook requests enforce a body-size limit, notification-count limit,
  configured production `clientState`, and short-lived notification-id replay
  suppression.
- CORS is restricted to configured origins, credentials are disabled, and only
  required methods/headers are allowed.
- Compose no longer hardcodes database credentials, does not publish PostgreSQL
  directly, defaults the backend to production mode, requires `API_KEY`, and
  binds development ports to localhost.
- Existing Phase 5 controls remain active: XML entity rejection, telemetry
  limits, deterministic deduplication, UTC validation, and artifact SHA-256
  verification.

## Files changed

- `src/backend/app/core/config.py`
- `src/backend/app/core/security.py`
- `src/backend/app/main.py`
- `src/backend/app/api/emails.py`
- `src/backend/app/services/graph_client.py`
- `src/backend/app/schemas.py`
- `docker-compose.yml`
- `tests/backend/test_phase2a_email_intake.py`
- `tests/backend/test_security_integration_audit.py`
- `README.md`

## Validation

- Backend suite: **50 passed**, one existing Starlette deprecation warning.
- Ruff: passed with zero errors after the final formatting pass.
- Frontend lint and Vitest: previously **passed**, one frontend test.
- Alembic revisions 0001-0007: previously applied successfully on SQLite.

## Unresolved risks

The repository still needs deployment-level verification against real
PostgreSQL, a shared multi-worker replay store, OAuth provider/JWKS validation
if bearer identity is introduced, full user/role/incident ownership models,
filesystem/database atomic recovery and orphan cleanup, TLS termination
verification, external rate limiting, backup restoration tests, and production
secret rotation. These are explicitly not claimed as complete.
