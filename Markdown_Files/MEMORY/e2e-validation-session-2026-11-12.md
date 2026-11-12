# MALCIE End-to-End Validation Session — 2026-11-12

## Scope

Stabilization and verification only. No frontend features were added. Browser
integration used the actual React application and FastAPI endpoints with a newly
migrated SQLite database. The only uploaded evidence was a generated synthetic email
with the benign Windows `notepad.exe` attachment. The executable was never run.

## Issue found and fix

The browser workflow showed PE section strings such as ```.rdata``` and `@.didat`
persisted as `domain` IOCs. The Unicode-domain fallback accepted labels that did not
meet DNS label syntax. `src/backend/app/services/ioc_extraction.py` now validates each
normalized domain label against DNS hostname label rules. A regression test in
`tests/backend/test_edge_case_hardening.py` verifies those PE strings are rejected while
`example.com` is still retained.

## Backend test stall and result

The previous pytest run stalled in Starlette's `TestClient` / AnyIO Windows socketpair
setup under the restricted sandbox. Running from `src/backend` (required because the
pytest configuration sets `pythonpath = ["."]`) with local socketpair access resolved
the stall.

Command:

```powershell
& '..\..\.venv\Scripts\python.exe' -m pytest ../../tests/backend -q
```

Result: **56 passed, 1 warning, in 10.55s**. The warning is an upstream deprecation for
Starlette's use of `anyio.abc.BlockingPortal`.

## Frontend checks

- `npm run test`: **3 test files passed, 8 tests passed**.
- `npm run lint`: passed with no ESLint errors.
- `npm run build`: passed; TypeScript and Vite production build completed.

## Browser workflow and API results

Alembic migrations 0001 through 0008 were applied to a fresh temporary SQLite database.
`GET /api/v1/health` returned `200` / `ok` after its database query. The browser origin
was `http://localhost:3000`, matching configured development CORS. The interface was
connected to the corrected local backend and all workflow operations used live API
responses.

1. **Incident creation:** UI `POST /incidents` succeeded; created incident `1`.
2. **Email intake:** UI `POST /emails/upload-eml` returned `201`. The UI displayed the
   synthetic sender and subject and extracted `notepad-benign.exe` (360,448 bytes).
3. **PE analysis:** UI `POST /artifacts/1/analyze-static` returned `200`. Result was
   associated with artifact `1`, filename `notepad-benign.exe`, `is_pe=true`, type
   `pe32+`, status `completed`, 8 sections, and 50 imports.
4. **YARA and IOCs:** UI showed **0 YARA matches** and three actual file-hash IOCs
   (SHA-256, MD5, SHA-1). The malformed section-name domains found before the fix were
   absent on the corrected backend.
5. **VirusTotal:** UI `POST /incidents/1/enrich` returned three results, each
   `UNCONFIGURED`. No `VT_API_KEY` was configured and no live VirusTotal lookup was
   claimed.
6. **Correlation and timeline:** UI `POST /incidents/1/correlate` completed with risk
   `NONE` / score `0`, confidence `HIGH` / score `85`, 9 linkages, and 11 timeline
   events.
7. **JSON report:** The browser downloaded and the session inspected
   `malcie-incident-1-report.json`. It parsed as JSON, used
   `report_type=malcie_client_generated_investigation_report`,
   `persisted_by_backend=false`, had an ISO generated timestamp, referenced incident 1
   and artifact 1 / `notepad-benign.exe`, included the retrieved evidence (3 IOCs, 3
   explicitly unconfigured VT records, risk and timeline), and preserved nullable
   fields. Existing frontend tests verify the download anchor is removed and the object
   URL is revoked after 1 second.
8. **SQLite restart smoke test:** After the browser flow, FastAPI was restarted against
   the same test database. Health returned `ok` and `GET /api/v1/incidents/1` returned
   the same synthetic incident. This verifies local SQLite persistence across a process
   restart, not Docker volume persistence.

## Docker, credentials, and security review

- `docker --version` failed because Docker is not installed. Compose startup, health
  checks, database connectivity inside Compose, and Docker volume persistence are
  **not verified**.
- No root or backend `.env` was present and no VirusTotal key was configured. No
  credential value was inspected or included in this record.
- Graph OAuth token exchange and refresh responses contain `access_token` and optional
  `refresh_token`, but the backend has no durable server-side token store. Secure
  persistence needs ownership/isolation and encryption decisions that are not present
  in the current design, so it was not added here.
- Graph webhook deduplication uses `_seen_webhook_ids`, a process-local map that expires
  entries after 600 seconds. It will not provide idempotency across restarts or multiple
  workers. Durable receipt storage needs a database-backed identity and transaction
  design, so no ad hoc persistence change was made.
- The run used development-mode API-key bypass on loopback. This does not validate
  production authentication or deployment hardening.

## Modified files in this validation pass

- `src/backend/app/services/ioc_extraction.py`
- `tests/backend/test_edge_case_hardening.py`
- `Markdown_Files/Frontend Implementation Plan.md`
- `Markdown_Files/MEMORY/e2e-validation-session-2026-11-12.md`

## Assessment and next steps

**Partially Stable.** Backend regression, frontend tests/lint/build, and the full
browser workflow passed against the corrected live API, including PE analysis and a
verified client-generated report. Docker Compose and live VirusTotal enrichment remain
unverified. Before production use, address durable OAuth token handling, durable
webhook idempotency, production authentication/deployment checks, and run the Docker
Compose health and persistence workflow in an environment with Docker installed.
