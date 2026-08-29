# MALCIE

Malware Analysis, Linkage, Correlation and Investigation Engine.

## Current Status

**Current phase:** Phase 1 - Planning & Setup

### Completed in this phase

- Project skeleton added for backend (`src/backend`) and frontend (`src/frontend`)
- FastAPI starter service with root and health endpoints
- React + TypeScript starter app with basic status page
- Dockerfile and `docker-compose.yml` for local environment bootstrap
- Initial Alembic migration scaffolding with baseline revision
- CI workflow for backend/frontend lint and test checks
- Initial backend and frontend smoke tests
- Environment variable template in `.env.example`

### Not yet implemented

- Core malware analysis pipeline (Phase 2)
- Email and threat intelligence integrations (Phase 3)
- Incident dashboard and correlation workflow (Phase 4)
- Sysmon telemetry ingestion and end-to-end workflow completion (Phase 5)

## Repository Layout

- `/src/backend` - FastAPI backend service
- `/src/frontend` - React + TypeScript frontend
- `/tests/backend` - backend tests
- `/alembic` - migration scaffolding
- `/infra` - deployment infrastructure placeholders
- `/scripts` - utility script placeholders
- `/.github/workflows/ci.yml` - CI lint/test workflow

## Local Setup

1. Copy environment template:
   ```bash
   cp .env.example .env
   ```
2. Start the stack:
   ```bash
   docker-compose up --build
   ```
3. Access services:
   - Backend API: `http://localhost:8000`
   - Health endpoint: `http://localhost:8000/api/v1/health`
   - Frontend app: `http://localhost:3000`

## Backend Development

```bash
cd src/backend
pip install -r requirements.txt
ruff check app ../../tests/backend
pytest ../../tests/backend
uvicorn app.main:app --reload
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
- Treat uploaded artifacts as untrusted content.
