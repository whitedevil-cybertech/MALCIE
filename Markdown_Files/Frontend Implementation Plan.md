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
