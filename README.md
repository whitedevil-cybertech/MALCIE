# MALCIE

**M**alware **A**nalysis, **L**inkage, **C**orrelation and **I**nvestigation **E**ngine.

MALCIE is a malware-centric incident investigation and digital forensics platform designed for security operations centers (SOCs) and incident responders. It automates suspicious email and binary intake, performs static PE binary inspection, executes in-memory YARA rule scanning, and extracts, normalizes, deduplicates, and associates Indicators of Compromise (IOCs) while preserving complete evidentiary provenance.

---

## Current Status

- **Phase 1: Planning & Setup** — COMPLETED & VERIFIED
- **Phase 2: Core Analysis Engine** — **COMPLETED & VERIFIED**
  - **Phase 2A (Email & Evidence Intake):** COMPLETED & VERIFIED
  - **Phase 2B-Part A (PE Static Analysis):** COMPLETED & VERIFIED
  - **Phase 2B-Part B (Detection, IOC Extraction & Result Completion):** COMPLETED & VERIFIED
- **Next Phase:** **Phase 3 — Email & Threat Integration** (Microsoft Graph polling/webhooks & VirusTotal API v3 threat intelligence enrichment)

### Test & Code Quality Status

- **Backend Unit & Integration Tests:** **24 / 24 PASSING** (`pytest tests/backend -v`)
- **Backend Linting & Formatting:** **PASSING** (`ruff check src/backend/app tests/backend`) with zero errors
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
  - Preserves distinct evidence provenance when the same indicator is found across multiple independent contexts (e.g. general strings vs. specific YARA rule matches).
- **Persistent Evidence Association:** Links extracted IOCs (`ioc_records`) directly to the originating artifact and incident hierarchy in the database.

---

## Analysis & Detection Pipeline

```text
               Uploaded / Ingested Artifact
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
           Database Persistence (Alembic Managed)
          (ArtifactAnalysis + IOCRecord Relationships)
                           │
                           ▼
         Consolidated Incident & Analysis API Output
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
│       ├── 0001_initial_schema.py
│       ├── 0002_phase2a_email_intake.py
│       ├── 0003_phase2b_parta_pe_static_analysis.py
│       └── 0004_phase2b_partb_yara_ioc.py
├── Markdown_Files/
│   ├── PRD.md
│   ├── Phases.md                  # Project roadmap & acceptance criteria
│   ├── Rules.md                   # Engineering & security guidelines
│   ├── Design.md
│   ├── MALCIE Architecture.md
│   └── MEMORY/                    # Chronological milestone memories
│       ├── memory.md              # Phase 1 memory
│       └── Memory_2.md            # Phase 2 memory
├── src/
│   ├── backend/
│   │   ├── app/
│   │   │   ├── api/
│   │   │   │   ├── artifacts.py   # Upload, static analysis, artifact IOCs
│   │   │   │   ├── emails.py      # EML upload, Graph OAuth & intake
│   │   │   │   ├── health.py      # Health check endpoint
│   │   │   │   └── incidents.py   # Incident management & incident IOCs
│   │   │   ├── core/
│   │   │   │   └── config.py      # Application settings & environment vars
│   │   │   ├── db.py              # SQLAlchemy engine & session factory
│   │   │   ├── main.py            # FastAPI entry point & router registration
│   │   │   ├── models.py          # Incident, Email, Artifact, Analysis, IOCRecord
│   │   │   ├── schemas.py         # Pydantic v2 request/response schemas
│   │   │   └── services/
│   │   │       ├── email_intake.py         # EML parser & boundary checks
│   │   │       ├── graph_client.py         # Microsoft Graph client
│   │   │       ├── ioc_extraction.py       # IOC extraction & normalization
│   │   │       ├── pe_static_analysis.py   # PE analysis & persistence
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
│       └── test_phase2b_partb_analysis.py
├── .env.example
├── docker-compose.yml
├── Dockerfile
└── README.md
```

---

## Technologies Used

- **Backend:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic, Uvicorn
- **Analysis & Detection:** `pefile`, `yara-python`, standard-library `hashlib` & `ipaddress`
- **Database:** SQLite (development / testing) & PostgreSQL (production-ready via SQLAlchemy)
- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Vitest
- **Testing & Quality:** `pytest`, `pytest-asyncio`, `ruff`

---

## API Endpoints Reference

### Health & Management
- `GET /` - Root status
- `GET /api/v1/health` - Health check

### Incidents
- `POST /api/v1/incidents` - Create new incident
- `GET /api/v1/incidents/{incident_id}` - Retrieve incident details
- `GET /api/v1/incidents/{incident_id}/iocs` - Retrieve all deduplicated IOCs linked to the incident

### Email & Intake (Phase 2A)
- `GET /api/v1/emails/graph/auth-url` - Generate Microsoft Graph OAuth authorization URL
- `POST /api/v1/emails/graph/oauth/token` - Exchange authorization code for token
- `POST /api/v1/emails/graph/messages/{message_id}/ingest` - Ingest message MIME directly from Graph
- `POST /api/v1/emails/upload-eml` - Upload `.eml` file for parsing and artifact extraction
- `GET /api/v1/emails/{email_id}` - Retrieve stored email evidence

### Artifacts & Analysis (Phase 2B)
- `POST /api/v1/artifacts/upload` - Upload standalone artifact file
- `GET /api/v1/artifacts/{artifact_id}` - Retrieve artifact metadata
- `POST /api/v1/artifacts/{artifact_id}/analyze-static` - Execute static PE analysis, YARA scanning, and IOC extraction
- `GET /api/v1/artifacts/{artifact_id}/analysis-static` - Retrieve complete analysis results including YARA matches and IOCs
- `GET /api/v1/artifacts/{artifact_id}/iocs` - Retrieve structured IOCs associated with the artifact

---

## Running Verification & Tests

### Backend Tests & Linting
From repository root (using virtual environment):
```powershell
# Run Ruff lint checks
.venv\Scripts\python -m ruff check src/backend/app tests/backend

# Run all 24 backend test suites
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
- **YARA as Evidence:** YARA detections represent evidentiary findings associated with artifacts; they do not trigger automated binary verdicts without analyst correlation.
- **Threat Intelligence Deferred:** External VirusTotal API v3 lookup and enrichment are scheduled for **Phase 3**.
- **Cross-Source Correlation Deferred:** Automatic correlation between email metadata, static analysis findings, and endpoint events is scheduled for **Phase 4**.
- **Endpoint Telemetry Deferred:** Sysmon log collection and process-event linkage are scheduled for **Phase 5**.
