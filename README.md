# MALCIE

**M**alware **A**nalysis, **L**inkage, **C**orrelation and **I**nvestigation **E**ngine.

MALCIE is a malware-centric incident investigation and digital forensics platform designed for security operations centers (SOCs) and incident responders. It automates suspicious email and binary intake, performs static PE binary inspection, executes in-memory YARA rule scanning, extracts and deduplicates Indicators of Compromise (IOCs) with evidentiary provenance, integrates with Microsoft Graph for email polling and webhooks, enriches indicators via the VirusTotal API v3, and correlates multi-stage evidence into unified timelines with deterministic confidence and risk scoring.

---

## Current Status

- **Phase 1: Planning & Setup** — COMPLETED & VERIFIED
- **Phase 2: Core Analysis Engine** — COMPLETED & VERIFIED
  - **Phase 2A (Email & Evidence Intake):** COMPLETED & VERIFIED
  - **Phase 2B-Part A (PE Static Analysis):** COMPLETED & VERIFIED
  - **Phase 2B-Part B (Detection, IOC Extraction & Result Completion):** COMPLETED & VERIFIED
- **Phase 3: Email & Threat Integration** — COMPLETED & VERIFIED
- **Phase 4: Correlation & Linkage Engine** — **COMPLETED & VERIFIED**
- **Phase 5: Endpoint Telemetry Integration** — **COMPLETED & VERIFIED**

### Test & Code Quality Status

- **Backend Unit & Integration Tests:** **48 / 48 PASSING** (`pytest tests/backend -q`)
- **Backend Linting & Formatting:** **PASSING** (`ruff check src/backend/app tests/backend alembic`) with zero errors
- **Frontend Component Tests:** **PASSING** (`vitest run` in `src/frontend`)

---

## Implemented Capabilities

### 1. Email Intake & Evidence Ingestion (Phase 2A)
- **Manual `.eml` Upload:** Dedicated endpoint for raw `.eml` parsing and evidence extraction.
- **Microsoft Graph API Integration:** OAuth 2.0 authorization URL generation, token code exchange, and raw MIME message ingestion via `/$value`.
- **Forensic Extraction:** Parses email headers, sender, recipients, timestamps, subject, body preview, embedded URLs, and domains.
- **Attachment Handling & Safety:** Enforces strict file extension filtering, configurable maximum size thresholds, secure filename sanitization, and path boundary validation to prevent path traversal attacks.
- **Cryptographic Hashing:** Computes deterministic SHA-256 digests for raw emails and extracted artifact binaries.

### 2. Static PE Binary Analysis (Phase 2B-Part A)
- **Safe Static Inspection:** Uses `pefile` to parse binaries strictly in memory without executing uploaded files.
- **Header & Architecture Resolution:** Validates PE signatures (MZ/PE), detects machine architecture (PE32 / PE32+), entry points, image base, and compilation characteristics.
- **Section Enumeration & Entropy:** Inspects section headers, raw and virtual dimensions, characteristics flags, and calculates Shannon entropy per section to detect packing or obfuscation.
- **Import Table Resolution:** Resolves imported Dynamic Link Libraries (DLLs) and their associated API function names.
- **Printable String Extraction:** Extracts ASCII strings with configurable length limits and memory-safe result capping.
- **Defensive Error Handling:** Gracefully handles non-PE files, empty files, truncated headers, missing storage files, and path escape attempts without unhandled exceptions or crashes.

### 3. YARA Scanning & Detection (Phase 2B-Part B)
- **Engine Integration:** Integrates `yara-python` for in-memory scanning of artifact contents against compiled rule sets.
- **Project Rule Management:** Packaged rule directory (`src/backend/rules/yara`) with out-of-the-box detection for suspicious PowerShell commands, downloader API sequences, and embedded PE droppers.
- **Evidence-Centric Paradigm:** Matches are collected with metadata (severity, author, category, matched strings, and offsets). YARA matches serve as evidentiary signals rather than automated binary verdicts.
- **Robust Rule Compilation:** Handles directory rule loading, custom string compilation, and captures malformed rules safely.

### 4. Structured IOC Extraction, Normalization & Provenance (Phase 2B-Part B)
- **Multi-Type Indicator Extraction:**
  - **Cryptographic Hashes:** SHA-256, MD5, SHA-1 calculated deterministically.
  - **Network Indicators:** IPv4 addresses, IPv6 tokens, fully qualified domain names, and URLs.
  - **Host Indicators:** Windows file paths (drive-letter, UNC, `%TEMP%` environment variables) and POSIX filesystem paths.
  - **PE Artifact Elements:** Sourced from imported DLL names and printable strings.
- **Normalization & Filtering:**
  - Defangs and validates URLs via RFC-compliant parsing.
  - Standardizes IPv4/IPv6 addresses via `ipaddress` validation.
  - Filters out binary libraries (`.dll`, `.exe`, `.sys`, `.pdb`) and false-positive domains.
- **Provenance Preservation & Deduplication:**
  - Deduplicates repeated occurrences from the same source.
  - Preserves distinct evidence provenance when the same indicator is found across multiple independent contexts.
- **Persistent Evidence Association:** Links extracted IOCs (`ioc_records`) directly to the originating artifact and incident hierarchy in the database.

### 5. Microsoft Graph Polling, Webhooks & Threat Intelligence (Phase 3)
- **Microsoft Graph Polling:**
  - Mailbox querying across folders (`inbox`, `junkemail`, etc.) with message summaries.
  - Automated batch ingestion (`auto_ingest=True`) fetching raw MIME, extracting attachments, and registering evidence under designated incidents.
- **Microsoft Graph Webhook Notifications:**
  - Webhook validation handshake handler responding to `validationToken` with plain-text verification.
  - Asynchronous change notification ingestion with `clientState` signature validation.
  - Subscription lifecycle management (create, list, delete).
- **VirusTotal API v3 Threat Intelligence:**
  - Enrichment for file hashes (SHA-256, MD5, SHA-1), URLs (unpadded base64url encoding), domains, and IP addresses.
  - Extracted verdicts: reputation scores, malicious/suspicious/harmless/undetected votes, total engine counts, and detailed vendor detection breakdowns.
- **Resilience & Rate-Limiting:**
  - Multi-tiered caching (in-memory TTL cache + database cache lookup) to respect API quotas.
  - Configurable timeouts and exponential backoff retry loops on HTTP 429 and transient 5xx errors.
  - Graceful degradation: unconfigured API keys, missing indicators (404), or upstream downtime produce structured error statuses without interrupting incident analysis.
- **Reputation Persistence:**
  - Stores all enrichment records in `threat_intel_results` with foreign-key linkage to incidents, artifacts, and IOC records.

### 6. Evidence Correlation, Confidence Scoring, Risk Assessment & Timeline (Phase 4)
- **Evidence Linkage Engine:**
  - Connects emails -> attachments -> cryptographic digests -> PE structure -> YARA matches -> IOC records -> threat intelligence verdicts.
  - Detects cross-source corroboration: matching email URLs/domains with binary IOCs/strings, and linking malicious hash verdicts to artifacts.
- **Confidence Scoring (`ConfidenceAssessment`):**
  - Measures the *completeness and robustness of evidence linkages* (0.0% to 100.0%, categorized into `LOW`, `MEDIUM`, `HIGH`).
  - Completely explainable breakdown of positive linkage factors.
- **Rule-Based Risk Assessment (`RiskAssessment`):**
  - Evaluates threat maliciousness (0 to 100, categorized into `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - Rules inspect YARA detections, high-detection VT hashes, malicious network indicators, section entropy packing anomalies, suspicious process/downloader API imports, and phishing characteristics.
  - **Strict Separation:** Correlation completeness is strictly separated from malware risk so clean artifacts never trigger false risk alarms.
- **Chronological Incident Timeline:**
  - Assembles events from email `sent_at`, PE compilation `TimeDateStamp`, attachment extraction, static analysis completion, YARA hits, IOC extractions, threat intelligence queries, and correlation runs into an ordered timeline.
- **Database Persistence:**
  - Managed via Alembic migration `0006_phase4_correlation_timeline.py` storing `CorrelationResult` and `TimelineEvent` records.

### 7. Sysmon Endpoint Telemetry (Phase 5)
- Supports Sysmon Event IDs 1, 3, 11, 12, 13, and 14 for process, network, file, and registry activity.
- Accepts XML and JSON, validates event IDs, and normalizes timestamps to UTC.
- Preserves raw evidence, hostname, endpoint identity, process relationships, optional hashes, network details, registry details, and provenance.
- Uses deterministic SHA-256 fingerprints with a database uniqueness constraint for idempotent ingestion.
- Associates events with an explicit incident or, when omitted, only with a unique artifact-hash/network-IOC match.
- Extends artifact/IOC correlation, explainable risk scoring, and chronological incident timelines.
- Persists endpoint events with Alembic migration `0007_phase5_sysmon_telemetry.py`.

---

## Analysis & Detection Pipeline

```text
               Uploaded / Ingested Artifact or Email
                                │
                                ▼
              Storage Boundary & Extension Validation
                                │
                                ▼
              Deterministic Cryptographic Hashing
                    (SHA-256, MD5, SHA-1)
                                │
                                ▼
                 Static PE Inspection (pefile)
          (Headers, Sections, Entropy, Imports, Strings)
                                │
                                ▼
              In-Memory YARA Scanning (yara-python)
          (Compiled Rule Matching, Offsets, Metadata)
                                │
                                ▼
                     IOC Extraction Engine
          (Hashes, IPv4, IPv6, Domains, URLs, File Paths)
                                │
                                ▼
                Normalization & Deduplication
                (Preserves Multi-Source Provenance)
                                │
                                ▼
             Threat Intelligence Enrichment (VirusTotal v3)
             (Hashes, URLs, Domains, Reputation Persistence)
                                │
                                ▼
             Correlation & Linkage Engine (Phase 4)
          ┌─────────────────────┴─────────────────────┐
          ▼                                           ▼
   Evidence Linkages                           Chronological Timeline
  (Email ↔ File ↔ IOC ↔ VT)                   (Email, PE, IOC, VT, Corr)
          │                                           │
          ├─► Confidence Scoring (Link Completeness)  │
          └─► Risk Assessment (Malware Verdict)       │
                                │                     │
                                ▼                     ▼
             Database Persistence (Alembic Managed)
          (CorrelationResult + TimelineEvent Entities)
                                │
                                ▼
           Consolidated Incident & Threat Intelligence Output
```

---

## Repository Structure

```text
MALCIE/
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions lint and test pipeline
├── alembic/
│   ├── env.py                     # Alembic configuration supporting DATABASE_URL
│   └── versions/
│       ├── 0001_phase1_baseline.py
│       ├── 0002_phase2a_email_intake.py
│       ├── 0003_phase2b_parta_pe_static_analysis.py
│       ├── 0004_phase2b_partb_yara_ioc.py
│       ├── 0005_phase3_threat_intel_reputation.py
│       ├── 0006_phase4_correlation_timeline.py
│       └── 0007_phase5_sysmon_telemetry.py
├── Markdown_Files/
│   ├── PRD.md
│   ├── Phases.md                  # Project roadmap & acceptance criteria
│   ├── Rules.md                   # Engineering & security guidelines
│   ├── Design.md
│   ├── MALCIE Architecture.md
│   └── MEMORY/                    # Chronological milestone memories
│       ├── memory.md              # Phase 1 memory
│       ├── memory2.md             # Phase 2 memory
│       ├── memory3.md             # Phase 3 memory
│       └── memory4.md             # Phase 4 memory
├── src/
│   ├── backend/
│   │   ├── app/
│   │   │   ├── api/
│   │   │   │   ├── artifacts.py   # Upload, static analysis, artifact IOCs
│   │   │   │   ├── emails.py      # EML upload, Graph OAuth, polling, webhooks
│   │   │   │   ├── health.py      # Health check endpoint
│   │   │   │   ├── incidents.py   # Incident management, correlation & timeline
│   │   │   │   ├── threat_intel.py # VirusTotal enrichment & reputation persistence
│   │   │   │   └── telemetry.py   # Sysmon ingestion and endpoint event retrieval
│   │   │   ├── core/
│   │   │   │   └── config.py      # Application settings & environment vars
│   │   │   ├── db.py              # SQLAlchemy engine & session factory
│   │   │   ├── main.py            # FastAPI entry point & router registration
│   │   │   ├── models.py          # SQLAlchemy models
│   │   │   ├── schemas.py         # Pydantic v2 request/response schemas
│   │   │   └── services/
│   │   │       ├── correlation_engine.py   # Evidence correlation, scoring & timeline
│   │   │       ├── email_intake.py         # EML parser & boundary checks
│   │   │       ├── graph_client.py         # Microsoft Graph client & webhooks
│   │   │       ├── ioc_extraction.py       # IOC extraction & normalization
│   │   │       ├── pe_static_analysis.py   # PE analysis & persistence
│   │   │       ├── threat_intel.py         # Threat intelligence orchestration
│   │   │       ├── virustotal_client.py    # VirusTotal API v3 client
│   │   │       └── yara_scanner.py         # YARA compilation & scanning
│   │   ├── rules/
│   │   │   └── yara/
│   │   │       └── indicators.yar # Curated YARA detection rules
│   │   ├── pyproject.toml         # Ruff linter/formatter configuration
│   │   └── requirements.txt       # Python dependencies
│   └── frontend/
│       ├── src/                   # React 18 + TypeScript components
│       ├── package.json
│       └── vite.config.ts
├── tests/
│   └── backend/
│       ├── conftest.py            # Test fixtures & ephemeral test storage
│       ├── test_health.py
│       ├── test_phase2a_email_intake.py
│       ├── test_phase2b_pe_static_analysis.py
│       ├── test_phase2b_partb_analysis.py
│       ├── test_phase3_graph_and_threat_intel.py
│       └── test_phase4_correlation_and_timeline.py
├── .env.example
├── docker-compose.yml
├── Dockerfile
└── README.md
```

---

## Technologies Used

- **Backend:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic, Uvicorn, HTTPX
- **Analysis & Detection:** `pefile`, `yara-python`, standard-library `hashlib` & `ipaddress`
- **External Threat Intelligence:** VirusTotal API v3 (files, URLs, domains, IPs)
- **Email Ingestion:** Microsoft Graph Mail API v1.0 (OAuth 2.0, polling, webhooks)
- **Database:** SQLite (development / testing) & PostgreSQL (production-ready via SQLAlchemy)
- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Vitest
- **Testing & Quality:** `pytest`, `pytest-asyncio`, `ruff`

---

## API Endpoints Reference

In `APP_ENV=production`, API routes require the configured `API_KEY` via
`X-API-Key` or `Authorization: Bearer`. Microsoft Graph webhook validation and
notifications remain reachable without that application key and are protected
by the configured Graph `clientState`; use network-level ingress controls in
production. This key is not a substitute for user/role or incident-level
authorization.

Graph OAuth callbacks require an allowlisted `GRAPH_REDIRECT_URIS` value and a
signed, expiring state returned by `/graph/auth-url`. Configure
`GRAPH_CLIENT_SECRET`, `GRAPH_REDIRECT_URIS`, and
`GRAPH_WEBHOOK_CLIENT_STATE` through a secret manager or deployment environment,
never source control.

### Health & Management
- `GET /` - Root status
- `GET /api/v1/health` - Health check

### Incidents & Correlation (Phases 1 & 4)
- `POST /api/v1/incidents` - Create new incident
- `GET /api/v1/incidents/{incident_id}` - Retrieve incident details
- `GET /api/v1/incidents/{incident_id}/iocs` - Retrieve all deduplicated IOCs linked to the incident
- `POST /api/v1/incidents/{incident_id}/correlate` - Execute correlation engine, evaluate confidence/risk, and generate timeline
- `GET /api/v1/incidents/{incident_id}/correlations` - Retrieve existing correlation results and linkages
- `GET /api/v1/incidents/{incident_id}/timeline` - Retrieve chronological incident event timeline
- `GET /api/v1/incidents/{incident_id}/telemetry` - Retrieve normalized endpoint events for an incident

### Endpoint Telemetry (Phase 5)
- `POST /api/v1/telemetry/upload` - Ingest Sysmon XML or JSON; optionally pass `incident_id`
- `GET /api/v1/telemetry/incidents/{incident_id}` - Retrieve incident-scoped endpoint events

### Email & Intake (Phases 2A & 3)
- `GET /api/v1/emails/graph/auth-url` - Generate Microsoft Graph OAuth authorization URL
- `POST /api/v1/emails/graph/oauth/token` - Exchange authorization code for token
- `GET /api/v1/emails/graph/messages` - Query/list mailbox messages via Microsoft Graph
- `POST /api/v1/emails/graph/poll` - Poll messages from mailbox with optional auto-ingest into incident
- `POST /api/v1/emails/graph/subscriptions` - Create Microsoft Graph webhook subscription
- `DELETE /api/v1/emails/graph/subscriptions/{subscription_id}` - Delete webhook subscription
- `POST /api/v1/emails/graph/webhook` - Microsoft Graph validation handshake and change notification handler
- `POST /api/v1/emails/graph/messages/{message_id}/ingest` - Ingest message MIME directly from Graph
- `POST /api/v1/emails/upload-eml` - Upload `.eml` file for parsing and artifact extraction
- `GET /api/v1/emails/{email_id}` - Retrieve stored email evidence

### Artifacts & Analysis (Phase 2B)
- `POST /api/v1/artifacts/upload` - Upload standalone artifact file
- `GET /api/v1/artifacts/{artifact_id}` - Retrieve artifact metadata
- `POST /api/v1/artifacts/{artifact_id}/analyze-static` - Execute static PE analysis, YARA scanning, and IOC extraction
- `GET /api/v1/artifacts/{artifact_id}/analysis-static` - Retrieve complete analysis results including YARA matches and IOCs
- `GET /api/v1/artifacts/{artifact_id}/iocs` - Retrieve structured IOCs associated with the artifact

### Threat Intelligence & Reputation (Phase 3)
- `POST /api/v1/incidents/{incident_id}/enrich` - Trigger VirusTotal v3 enrichment for all incident IOCs
- `GET /api/v1/incidents/{incident_id}/threat-intel` - Retrieve persisted threat intelligence results for an incident
- `POST /api/v1/artifacts/{artifact_id}/enrich` - Trigger VirusTotal v3 enrichment for artifact IOCs
- `GET /api/v1/artifacts/{artifact_id}/threat-intel` - Retrieve persisted threat intelligence results for an artifact
- `POST /api/v1/threat-intel/lookup` - Ad-hoc threat intelligence lookup for an individual IOC

---

## Running Verification & Tests

### Backend Tests & Linting
From repository root (using virtual environment):
```powershell
# Run Ruff lint checks
.venv\Scripts\python -m ruff check src/backend/app tests/backend alembic

# Run all 41 backend tests
.venv\Scripts\python -m pytest tests/backend -v
```

### Frontend Tests & Linting
```powershell
cd src/frontend
npm run lint
npm run test
```

---

## Current Scope & Intentional Limitations

- **Static Analysis Only:** Artifacts are strictly inspected statically in-memory. Binary execution, emulation, and dynamic sandboxing are deliberately excluded from this layer.
- **YARA as Evidence:** YARA detections represent evidentiary findings associated with artifacts; they contribute to explainable risk scoring rather than acting as opaque verdicts.
- **Evidence Immutability:** Original uploaded emails, binaries, and logs are stored unchanged. Correlation and timeline events are derived entities without modifying underlying evidence.
- **Endpoint scope:** Sysmon ingestion is an evidence collector only; MALCIE does not execute binaries, provide EDR/live monitoring, or sandbox files.
