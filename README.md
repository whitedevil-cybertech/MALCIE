# MALCIE

Malware Analysis, Linkage, Correlation and Investigation Engine.

## Current Status

**Current phase:** Phase 2A - Email & Evidence Intake

### Implemented (Phase 1 + Phase 2A)

- Project skeleton for backend (`src/backend`) and frontend (`src/frontend`)
- FastAPI backend with health endpoint
- Incident creation and retrieval API
- Microsoft Graph OAuth helper endpoints (auth URL + code exchange)
- Microsoft Graph message intake endpoint (`/$value` MIME retrieval)
- Manual `.eml` upload endpoint
- `.eml` parsing for metadata, headers, body preview, URLs, domains, and attachments
- Attachment/file validation controls (extension checks, size limits, filename sanitization)
- SHA-256 hashing for raw email evidence and extracted attachments
- Evidence/artifact storage on disk with incident/email relationships in the database
- Alembic migration for incidents, emails, and artifacts tables
- Backend tests covering parsing, validation, Graph flow, and Phase 2A end-to-end intake flow

### Not Yet Implemented (Out of Phase 2A Scope)

- PE static malware analysis
- YARA scanning
- IOC enrichment beyond basic email indicators (URL/domain extraction)
- VirusTotal enrichment pipeline
- Endpoint telemetry ingestion/correlation
- Risk scoring, timeline engine, reporting engine, advanced dashboard workflow

## Repository Layout

- `/src/backend` - FastAPI backend service
- `/src/frontend` - React + TypeScript frontend
- `/tests/backend` - backend tests
- `/alembic` - migration scaffolding
- `/.github/workflows/ci.yml` - CI lint/test workflow

## Configuration

Copy and configure environment values:

```bash
cp .env.example .env
```

Key variables for Phase 2A:

- `DATABASE_URL` (default local SQLite for development)
- `GRAPH_CLIENT_ID`
- `GRAPH_TENANT_ID`
- `GRAPH_CLIENT_SECRET`
- `GRAPH_SCOPE` (default: `offline_access Mail.Read`)
- `ARTIFACT_STORAGE_PATH`
- `MAX_EML_SIZE_BYTES`
- `MAX_ATTACHMENT_SIZE_BYTES`

## Local Setup

1. Install backend dependencies:
   ```bash
   cd src/backend
   pip install -r requirements.txt
   ```
2. Start backend:
   ```bash
   uvicorn app.main:app --reload
   ```
3. Access:
   - API root: `http://localhost:8000/`
   - Health endpoint: `http://localhost:8000/api/v1/health`
   - OpenAPI docs: `http://localhost:8000/docs`

## Phase 2A API Endpoints

- `POST /api/v1/incidents` - create incident
- `GET /api/v1/incidents/{incident_id}` - retrieve incident
- `GET /api/v1/emails/graph/auth-url?redirect_uri=...` - Graph OAuth authorize URL
- `POST /api/v1/emails/graph/oauth/token` - OAuth code exchange
- `POST /api/v1/emails/graph/messages/{message_id}/ingest` - ingest Graph message MIME into evidence
- `POST /api/v1/emails/upload-eml` - upload `.eml` file for intake
- `GET /api/v1/emails/{email_id}` - retrieve stored email evidence

## Backend Validation Commands

```bash
cd src/backend
ruff check app ../../tests/backend
pytest ../../tests/backend
```

## Frontend Development

```bash
cd src/frontend
npm install
npm run lint
npm run test
npm run dev
```

## Security Notes

- Keep secrets in `.env` only.
- Do not commit malware binaries to the repository.
- Treat uploaded email content and attachments as untrusted evidence.
- Store evidence immutably and avoid modifying raw artifacts after ingestion.
