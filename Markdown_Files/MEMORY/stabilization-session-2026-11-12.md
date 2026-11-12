# Frontend Stabilization & Verification — 2026-11-12

## Reviewed files and contracts

Reviewed `src/frontend/src/api.ts`, its API tests, frontend state/action paths, report
generation, FastAPI routers/schemas, backend auth/config, email parsing, static analysis,
YARA/IOC extraction, threat-intel enrichment and correlation/timeline behavior, plus
the Compose frontend environment and `.env.example`. The implementation plan and
project rules were checked. No backend application/API code was changed.

Confirmed route contracts: `GET /health`; `POST /incidents`; `GET /incidents/{id}`;
incident IOCs, telemetry, correlations, correlate and timeline routes; multipart
`POST /emails/upload-eml` (`incident_id`, `eml_file`, 201); `POST
/artifacts/{id}/analyze-static`; `POST /incidents/{id}/enrich` with optional JSON body;
`GET /incidents/{id}/threat-intel`; and raw-body `POST /telemetry/upload?incident_id=`.
Production auth accepts `X-API-Key` or Bearer; the frontend uses `X-API-Key`. JSON
success and 204 behavior match route responses.

## Issues fixed

- Compose passed `VITE_API_URL`, while the app reads `VITE_API_BASE_URL`; this made the
  Compose frontend miss its configured backend base. Corrected Compose and documented
  the variable in `.env.example`.
- Error details from FastAPI 422 arrays were reduced to a generic status; they now show
  validation messages. Invalid JSON on a successful HTTP response now raises a clear
  `ApiError`; network, 401/403 and 204 handling remains explicit. API base trailing
  slashes are normalized.
- XML telemetry uploads could inherit a browser `application/octet-stream` type. The
  client now chooses XML/JSON content type from the filename extension.
- A shared busy label did not stop same-tick duplicate actions or keep incident loading
  busy through its evidence requests. Added a synchronous operation lock and guarded
  incident epoch callbacks; stale incident responses and stale health checks are ignored.
- Incident correlation can rebuild timeline rows, but the client requested correlation
  and timeline concurrently. Changed those operations to sequence correlation before
  timeline retrieval; partial failures preserve successful data and display an error.
- One global artifact analysis could remain visible after selecting another attachment.
  Analysis is cleared on selection, response incident/artifact IDs and required arrays
  are checked, filename and artifact ID are retained together, and YARA display is
  scoped to the currently selected artifact.
- Email/telemetry intake, artifact analysis, and enrichment clear derived
  correlation/timeline data that may be stale. Telemetry responses are checked for
  association with the selected incident.
- Client report now has an explicit type, generated timestamp, current-session evidence
  scope, and `persisted_by_backend: false`; unloaded evidence is represented by null or
  empty arrays. Artifact filename/ID stay adjacent to its result. Download anchor is
  removed after click and its object URL is revoked after a delay. UI copy identifies
  the report as client-generated.

## Files changed

- `.env.example`
- `docker-compose.yml`
- `src/frontend/src/api.ts`
- `src/frontend/src/api.test.ts`
- `src/frontend/src/App.tsx`
- `src/frontend/src/report.ts`
- `src/frontend/src/report.test.ts`
- `Markdown_Files/Frontend Implementation Plan.md`
- `README.md`
- This session record.

## Frontend validation

- ESLint: passed.
- Frontend tests: **8 passed** across 3 files (workspace render, API header/401, route
  methods/payloads, 422 and malformed-success JSON, report metadata/serialization,
  artifact identity, and download anchor/object-URL cleanup).
- Production build: passed (TypeScript and Vite).

## Live API workflow

Started the existing FastAPI app with its installed virtual-environment dependencies,
applied all existing Alembic migrations to a fresh temporary SQLite database, and used
a temporary artifact directory. The backend health route returned `ok` after querying
the database. Only a synthetic `.eml`, a benign text attachment, and reserved `.test`
domains were sent; no external credentials or malware sample were used.

1. **Incident creation:** `POST /incidents` returned 200 and incident ID 1.
2. **Email upload:** `POST /emails/upload-eml` returned 201. Sender and subject parsed;
   exactly one expected `benign-notes.txt` attachment was extracted.
3. **Static analysis:** `POST /artifacts/1/analyze-static` returned 200 and result
   `artifact_id=1`, `incident_id=1`. Since the intentionally benign fixture is text,
   PE analysis correctly returned `unsupported` / `non_pe` rather than claiming a PE
   parse.
4. **YARA and IOCs:** analysis returned a YARA array with 0 matches and 5 IOC records;
   incident IOC retrieval returned 200, including the attachment SHA-256 and URL.
5. **VirusTotal:** incident enrichment returned 200 with 5 results, all explicitly
   `UNCONFIGURED`; no credentials were configured and no external lookup was claimed.
6. **Correlation and timeline:** correlation returned 200 with risk `NONE` and 13
   linkages. Timeline retrieval returned 200 with 14 events.
7. **Report serialization:** generated and JSON round-tripped a client-report structure
   using those actual response objects. It contained the expected artifact ID and
   filename, had a 24,830-byte JSON encoding, and explicitly stated that the backend
   did not persist it. The report helper and browser download lifecycle were also tested
   in Vitest; no browser E2E download was claimed.

The temporary backend/database/artifact directory was stopped/removed after verification.
The project backend regression selection did not complete in this environment: the
pytest runner produced no output for over 30 seconds and was interrupted. This does not
invalidate the successful live API exercise; no backend application change was needed.
Docker Compose was not installed, so container startup was not tested; the environment
name mismatch was corrected by inspection.

## Remaining limits and next steps

- VirusTotal reputation is not verified; backend settings reported no configured VT
  credential, so the actual provider state is `UNCONFIGURED`.
- The synthetic attachment was text, so this run validates artifact intake, unsupported
  PE handling, YARA response structure, IOC extraction, correlation and report content,
  but not parsing a valid PE file.
- Frontend API calls were contract-tested and the workflow was run against live backend
  HTTP routes, but the React interface itself was not exercised in a browser E2E run.
- Docker Compose requires a separate smoke test in an environment with Docker installed.
- Keep backend test runner stall noted; rerun focused backend tests in the project's
  normal test environment if an environment issue is resolved.
- Incident listing, email/artifact listing, standalone upload, and persisted report
  generation remain absent from the backend contract and are not simulated here.

## Assessment

**Partially Stable.** The frontend checks and the complete live backend HTTP workflow
passed, including real email/attachment storage, analysis, IOC, unconfigured enrichment,
correlation and timeline responses. The React UI was not run in a browser against that
backend, the focused backend regression runner stalled, and Compose was unavailable.
Do not treat VirusTotal reputation, valid PE parsing, browser E2E, backend regression,
or Compose runtime as verified by this pass.
