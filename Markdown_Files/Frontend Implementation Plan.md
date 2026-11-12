# Frontend Implementation Plan

## Verified backend surfaces

The current backend exposes incident creation and retrieval, email evidence retrieval
and upload, Graph OAuth/polling/ingestion/subscriptions, artifact static analysis and
IOC retrieval, VirusTotal enrichment and lookup, endpoint telemetry ingestion and
retrieval, correlation, risk/confidence results, and incident timelines.

The frontend should consume these existing routes through a typed API client. It should
not assume token persistence, background jobs, report export, editing workflows, or
webhook administration that the backend does not currently provide.

## Recommended sequence

1. **Application shell and analyst dashboard** — API client, authentication headers,
   health status, incident list/detail navigation, loading/error states.
2. **Incident management** — create and view incidents, status and evidence counts,
   then link the correlation and timeline views.
3. **Email and evidence viewer** — upload `.eml`, browse email headers/body/URLs/domains,
   list attachments, and expose raw evidence metadata.
4. **Artifact and PE analysis** — artifact details, static-analysis status, PE headers,
   sections, imports, extracted strings, hashes, and analysis errors.
5. **YARA findings and IOC investigation** — render rule matches and IOC provenance,
   normalized values, classifications, and artifact/incident relationships.
6. **Threat intelligence** — initiate enrichment or ad-hoc lookup, show provider
   status, vote counts, reputation, detection details, cache age, and explicit
   unconfigured/error states.
7. **Endpoint telemetry** — upload Sysmon XML/JSON, browse incident events, and link
   process/network/file/registry events to artifacts and IOCs.
8. **Correlation and incident timeline** — display linkages, confidence, risk reasons,
   and chronological evidence with filters by source and event type.
9. **Risk assessment and investigation reports** — compose a read-only investigation
   report from persisted correlation, timeline, evidence, analysis, IOC, VT, and
   telemetry data. Add export only after an API contract exists.

## Blocked or deferred frontend work

- Secure Graph token storage, automatic refresh, and account/session management require
  a backend token-store design before UI implementation.
- Webhook subscription administration needs durable subscription ownership and receipt
  state; the current endpoints are suitable for controlled integration, not a complete
  multi-user admin workflow.
- Pagination, filtering, and asynchronous analysis progress are not consistently
  available across current endpoints and should be added only with explicit contracts.

## Frontend milestone implementation status — 2026-11-12

The first functional analyst interface is implemented in `src/frontend`. It provides
API health and configurable API origin/key handling, incident creation and lookup by
ID, `.eml` upload and returned evidence display, attachment static analysis, YARA and
IOC inspection, incident VirusTotal enrichment, Sysmon upload and event display,
correlation/risk/linkage/timeline views, and a browser-generated JSON evidence report.

The inspected backend currently has no incident collection endpoint and no incident
email/artifact collection endpoint. The UI therefore supports creating a case or
opening a known incident ID; it does not imply a list of existing cases. Email evidence
and its attachments are shown from the upload response. Existing-case evidence details
are populated only from the separate incident routes available to the API. Do not add
mock data to fill these gaps. A durable report export endpoint is also absent; JSON
download is assembled client-side from evidence actually loaded in the current session.

Graph account/token UX, status editing, standalone artifact upload, multi-email listing,
and complete persistence-backed rehydration remain deferred until the backend exposes
appropriate contracts and token storage. No backend route or security behavior was
changed for this milestone.

## Focused stabilization pass — 2026-11-12

The API client was rechecked against the FastAPI routers and request/response schemas.
The frontend now reports invalid successful JSON, formats FastAPI validation details,
normalizes trailing API base slashes, and sets telemetry content type from the selected
XML/JSON file extension. Incident loads and evidence actions are guarded against stale
incident epochs and duplicate submissions; correlation is followed by timeline refresh
sequentially because correlation may regenerate timeline rows. Static-analysis output
is verified against the selected artifact and carries that artifact's filename into the
browser report. JSON download uses a temporary anchor and delayed object-URL cleanup.

The Compose frontend environment key was corrected to `VITE_API_BASE_URL`, matching
the client, and `.env.example` now documents its local default. A live backend workflow
was run against a temporary SQLite database after the project's Alembic migrations.
See `MEMORY/stabilization-session-2026-11-12.md` for exact endpoint results. VirusTotal
was intentionally run without credentials and returned `UNCONFIGURED`; no external
credential or provider lookup was used. Docker Compose itself was unavailable, so its
container startup was not smoke-tested.

## End-to-end validation follow-up — 2026-11-12

The backend suite stall was traced to Starlette's Windows test client using an asyncio
socketpair that the restricted test process could not create. Running pytest from
`src/backend` with the repository virtual environment and local socketpair access fixed
the stall. The full backend suite now passes: 56 tests, with one upstream Starlette /
AnyIO deprecation warning.

The browser workflow was run against a fresh SQLite database after migrations 0001 to
0008. The React UI created an incident, uploaded a synthetic `.eml` containing the
benign Windows Notepad PE, displayed parsed email and extracted attachment evidence,
completed PE static analysis, showed YARA and IOC output, requested VirusTotal
enrichment, recalculated risk and correlation, displayed the timeline, and downloaded
the current-session JSON report. An integration run exposed malformed PE section names
being classified as domains. Domain normalization now rejects invalid DNS labels; the
browser run on the corrected backend returned only the three file hashes and no false
domain indicators. The report parsed as JSON and identified itself as client-generated
and not backend-persisted.

VirusTotal returned `UNCONFIGURED` for the three file hashes because no provider key was
configured. Docker is not installed in this environment, so Compose health checks and
volume persistence remain unverified. A separate local SQLite process-restart smoke
test confirmed the synthetic incident remained available after restarting FastAPI;
this does not replace Docker volume testing.

OAuth token responses still expose access and refresh tokens to the caller without a
server-side durable token store. Webhook duplicate IDs remain in a process-local map
with a ten-minute expiry. Durable OAuth storage needs a token ownership and encryption
design; durable webhook deduplication needs database-backed receipt and transaction
semantics. Neither was changed during this validation pass.

See `MEMORY/e2e-validation-session-2026-11-12.md` for exact workflow steps, commands,
results, security limitations, and modified files.
