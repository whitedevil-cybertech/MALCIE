# MALCIE Development Rules

**Executive Summary:** This document defines the development guidelines for **MALCIE** (Malware Analysis, Linkage, Correlation and Investigation Engine). It specifies permitted capabilities, forbidden practices, approved libraries, error-handling rules, and AI usage boundaries. The goal is to keep the project **focused on its core malware-investigation workflow** and maintain security and quality throughout development.

## 1. Core Principle

> **Focus on the investigation loop:** MALCIE should implement the end-to-end malware investigation flow *completely*, rather than adding unrelated security features. In practice, this means starting from a suspicious email or file, **analyzing it**, **enriching with threat intelligence**, **ingesting related endpoint telemetry**, **correlating all evidence**, and **producing a report**. Any new feature must directly support this workflow. Avoid building a full SIEM, EDR, sandbox, or other large systems unless explicitly scoped.  

## 2. What We Can Do (Allowed Capabilities)

MALCIE is a malware-centric investigation platform. The following capabilities are in scope and encouraged:

- **Email Analysis:**  
  - Retrieve authorized emails via the Microsoft Graph Mail API (requires OAuth 2.0 with Mail.Read permissions).  
  - Accept `.eml` files for offline analysis.  
  - Parse email headers, extract senders/recipients, URLs, domains, IPs, and attachments.  
  - Identify suspicious email properties (phishing indicators, malicious attachments) and associate them with an incident.

- **Malware Static Analysis:**  
  - Process suspicious attachments (especially Windows executables) in a safe way.  
  - Use the [pefile](https://github.com/erocarrera/pefile) Python library to parse PE files (headers, sections, imports, embedded strings).  
  - Compute file hashes (SHA-256, etc.) and basic file metadata.  
  - Detect known packers or anomalies.  
  - *Safety:* Do **not** execute untrusted binaries on the MALCIE server.

- **YARA Scanning:**  
  - Maintain project-specific YARA rules for malware patterns.  
  - Use the [`yara-python`](https://github.com/VirusTotal/yara-python) library to compile and apply rules.  
  - Record any matched rules as evidence, linking them to the analyzed file and incident.  
  - Treat YARA hits as **indicators**, not absolute verdicts.

- **IOC Extraction:**  
  - From emails, files, and analysis results, extract Indicators of Compromise (IOCs) such as:
    - File hashes (SHA-256, MD5, etc.)
    - Domains and URLs
    - IP addresses
    - File paths and registry keys (if parsed from artifacts)  
  - **Normalize** IOCs (e.g. lowercase domains, standard IP formats) and deduplicate before storing.  
  - Store each IOC with context (which artifact and incident it came from).

- **Threat Intelligence Enrichment:**  
  - Query approved threat-intel APIs (e.g. VirusTotal) to look up IOCs (hashes, domains, IPs).  
  - Store reputation results and metadata (e.g. number of detections) along with provider name and query timestamp.  
  - *Observe rate limits:* For example, VirusTotal’s public API allows only 500 queries/day and 4/min. Handle throttling and fallback gracefully.  
  - Use intelligence as **supporting evidence**, not the final authority.

- **Endpoint Telemetry:**  
  - Collect telemetry from controlled Windows hosts (initially via Sysmon).  
  - Ingest events such as process creation, file operations, registry changes, and network connections logged by Sysmon.  
  - Normalize and timestamp these events.  
  - Associate events with incidents (e.g. “on host X, process Y ran file Z at time T”).

- **Evidence Correlation:**  
  - Correlate all evidence across stages. For example:  
    - A hash found in the email attachment → matching Sysmon process creation event.  
    - A network connection in telemetry → a domain found as an IOC in the malware analysis.  
  - Ensure correlation logic is **deterministic and explainable**. Each linkage should be traceable to the original data.  
  - Build an incident timeline showing how the email, the malware, and the endpoint activity fit together.

- **Risk Assessment (Rule-Based):**  
  - Compute a risk score for the incident using rule-based criteria (e.g. YARA match = +1, known-malicious hash = +2, code executed on endpoint = +2, etc.).  
  - Always provide clear “Reasons” for each score component (so an analyst can understand why the incident is high/medium/low risk).  
  - For example:
    > **Risk: HIGH** – *Reasons:* YARA rule matched; file hash flagged as malicious; file executed on endpoint; related network connection observed.

- **Reporting:**  
  - Generate final reports (PDF/JSON) that include:  
    - Incident summary and timeline.  
    - Collected evidence (emails, artifacts, logs, IOCs).  
    - Analysis findings (malware scan results, YARA hits, Intel lookups).  
    - Correlation graph.  
    - Risk assessment and conclusions.  
  - Distinguish clearly between **observed data** and **analyst interpretations** in the report.

## 3. What to Avoid (Forbidden Practices)

To keep the project manageable and focused, **do not** introduce the following unless explicitly scoped:

- **Feature Creep:** Avoid adding large features out-of-scope for the MVP, such as:
  - Full-scale SIEM (complex log management and search).  
  - Enterprise EDR functions (active endpoint protection or blocking).  
  - Building a generic malware sandbox (full dynamic analysis with hypervisor).  
  - Automated incident response (isolating hosts, auto-blocking).  
  - Machine-learning malware classification.  
  - Blockchain or unrelated technologies.  
  - Complex cloud orchestration (e.g. Kubernetes) unless needed for deployment reasons.

- **Overengineering:** Do not add infrastructure that complicates the MVP:
  - Avoid unnecessary microservices (monolithic or simple multi-module app is fine).  
  - No message brokers or complex queues without use-case.  
  - Limit to one primary database (PostgreSQL).  
  - Keep deployment simple (e.g. Docker container for backend, another for frontend).

- **Storing Secrets in Source:** Never commit API keys, passwords, or tokens to Git. Use environment variables or a secure secrets manager. For example, Microsoft Graph and VirusTotal API credentials must be in `.env`, and `.env` should be in `.gitignore`.  

- **Committing Malware Samples:** Do not check in real malware binaries. If needed for tests, use synthetic samples or empty stubs. Do not put actual executables in `samples/`, `uploads/`, or similar directories. Store only metadata or hashes in Git.

- **Unsafe Malware Execution:** By default, MALCIE does **not execute** untrusted files. If any dynamic analysis is added later, it must run in a fully isolated environment (e.g. a sandbox or VM dedicated to malware analysis). The MALCIE server and container must never run malware code from investigations.

- **Log Sensitive Data:** Do not log raw passwords, tokens, or PII. Follow OWASP guidelines: logs should never contain authentication credentials or personal data.

## 4. Approved Libraries & Tools

MALCIE will use a small, well-understood stack. Each chosen library must serve a clear purpose:

| Component            | Purpose                                               |
|----------------------|-------------------------------------------------------|
| **Python 3.10+**     | Primary language (rich stdlib for security tasks)     |
| **FastAPI**          | REST API framework (async, Pydantic-based)            |
| **Pydantic**         | Data models and validation (used by FastAPI) |
| **SQLAlchemy**       | ORM for database models                               |
| **Alembic**         | Database schema migrations                            |
| **PostgreSQL**       | Relational database (incidents, IOCs, logs)           |
| **python `email`**   | Standard library for MIME/email parsing               |
| **pefile**          | PE file parsing & static analysis       |
| **yara-python**     | YARA scanning in Python                  |
| **httpx**           | Async HTTP client for external API calls              |
| **pytest**          | Testing framework                                     |
| **Ruff**            | Linting/formatting tool (Python and JS)               |
| **React + TypeScript** | Frontend UI framework                            |
| **Docker**          | Containerization for deployment                       |
| **Microsoft Graph API** | Email retrieval (OAuth 2.0; Mail.Read)    |
| **VirusTotal API**  | Threat intel lookups (respect rate limits) |
| **Sysmon**          | Windows telemetry collector (process/network logs) |

Each dependency is documented in official sources (see citations above). For example, the Graph API requires Mail.Read permission, and VirusTotal’s free tier is strictly rate-limited. **Any new library** must be justified (see Implementation Rules).

## 5. Error Handling

MALCIE will use layered error handling with clear HTTP status codes and logging:

- **Input Validation (400/422):**  
  Use FastAPI/Pydantic to validate request payloads. Return **400 Bad Request** if JSON is malformed or required fields are missing, and **422 Unprocessable Entity** if semantics/format are wrong. The response should explain the invalid field(s) without revealing internal logic. (FastAPI’s automatic validation will raise errors which result in 422 by default.)

- **Authentication/Authorization (401/403):**  
  Invalid or missing credentials yield **401 Unauthorized** (or **403 Forbidden** if the user lacks access). Do not reveal whether an account exists.

- **Not Found (404):**  
  If a requested incident, artifact, or resource ID does not exist, return **404 Not Found** with a simple message. For example, raising `HTTPException(status_code=404)` in FastAPI produces:  
  ```json
  { "detail": "Item not found" }
  ```  
  as shown in the FastAPI docs.

- **External API Failures (502/503):**  
  When calling Microsoft Graph or VirusTotal, catch exceptions (network errors, timeouts, authentication errors). Log the error with details. Return an error status (e.g. **503 Service Unavailable**) for failures beyond client control. Do not let an external API failure crash the server; continue what you can. The incident can be marked “enrichment unavailable” but still reported.

- **Analysis Errors (500/Internal for specific artifact):**  
  If static analysis on a file fails (e.g. corrupt PE), do not drop the whole request. Record the failure on that artifact (e.g. analysis status = FAILED) and continue processing other evidence. Only that artifact is omitted. The overall API request should still succeed (200) with partial data, since one broken file shouldn’t kill the entire incident.

- **Database Errors:**  
  Use transactions for multi-step DB operations. On a commit error, rollback and return **500 Internal Server Error**. Log the failure with context (which operation/record failed).

- **Unexpected Errors:**  
  Catch any unhandled exceptions at the API layer. Log a stack trace on the server (with a generated request ID) but return a generic **500 Internal Error** to the client. Example client message: `"Something went wrong (Reference ID: ABC123)"`. Never expose raw stack traces or internal details in API responses.

- **Logging:**  
  Use structured logging. Every log entry should include the essentials: **when** (timestamp), **where** (module/endpoint), **who/what** (request ID, user or incident ID), **why** (message, error). In OWASP terms, logs should record “when, where, who and what”. Include request or incident IDs to tie logs across components. Use appropriate log levels: e.g. ERROR for failures, WARN for recoverable issues, INFO for high-level flow.  

- **Graceful Degradation:**  
  Errors in optional components (like threat-intel lookup) should degrade gracefully. For example, if VirusTotal is down, log the error and proceed with the report (flagging that intel was unavailable). The system should aim to **complete the investigation workflow** even if some enrichment is missing.

## 6. AI Usage Boundaries

AI tools may assist development, but must never override project decisions:

- **Permitted AI Use:**  
  - Generating boilerplate code or documentation drafts.  
  - Writing unit tests or example data.  
  - Refactoring suggestions or linting rules (with human review).  
  - Explaining code segments to developers.  
  - Database schema or query suggestions (for human review).  
  *All AI-generated output must be critically reviewed and tested before use.* As the OpenSSF guide emphasizes: *“You Are the Developer – AI is the Assistant”*. The developer is fully responsible; always apply normal engineering practices (code reviews, testing, static analysis) to AI contributions.

- **Forbidden AI Use:**  
  - Do **not** let AI autonomously alter the architecture or add major features (e.g. “Let’s add Kubernetes” or “Let’s implement ML classifier” without discussion). Default to “not in current scope” unless explicitly approved.  
  - Do **not** rely on AI to make security decisions (e.g. “this file is definitely malware” or “isolate this host now”). AI analysis must be treated as unverified assistance.  
  - Do **not** allow AI to insert secrets or credentials (the guide warns AI can inadvertently expose secrets).  
  - Do **not** trust AI-generated code for cryptography or access control without verification. 

- **Review Requirement:**  
  Every AI suggestion (code or design) must be reviewed by a team member. Check for correctness, security, and licensing. The OpenSSF guide warns that AI can introduce security flaws (outdated crypto, bad error handling). Use this to reinforce that AI output is not the final authority.

- **Evidence Integrity:**  
  MALCIE must **never** let AI or any process alter original evidence. Store raw emails, binaries, and logs as immutable records. Derived attributes (hashes, analysis results) go in separate fields. For example, keep the uploaded `.eml` content and the raw Sysmon events unchanged in storage. Any parsing or correlation adds new data without modifying the raw inputs.

## 7. Repository Guidelines

- **`.gitignore`:** The repo should include a `.gitignore` to exclude generated files, dependencies, and secrets. At minimum, ignore:
  ```gitignore
  # Environment and credentials
  .env
  .env.*
  !.env.example

  # Python cache and virtualenv
  __pycache__/
  *.py[cod]
  .venv/
  venv/

  # Node/React build artifacts
  node_modules/
  dist/
  build/

  # Logs and databases
  *.log
  *.db
  *.sqlite
  uploads/
  artifacts/
  samples/

  # IDE/editor
  .vscode/
  .idea/

  # OS files
  .DS_Store
  Thumbs.db
  ```
  Store actual API keys and configuration only in a local `.env` file (never committed).

- **Commit Messages:** Follow a consistent style (such as [Conventional Commits](https://www.conventionalcommits.org)). Use prefixes like:
  - `feat:` for new features (e.g. `feat: add PE analysis service`)  
  - `fix:` for bug fixes (`fix: handle corrupt email attachments`)  
  - `docs:` for documentation (`docs: update rules.md with error-handling`)  
  - `test:` for adding tests (`test: add IOC extraction unit tests`)  
  - `refactor:` for code reorganizations (`refactor: move analysis logic to service class`)  

  Avoid vague messages like "stuff" or "final". A good commit message clearly summarizes *what changed and why*.

## References

- FastAPI error handling and HTTPException usage  
- Pydantic data validation in FastAPI  
- Microsoft Graph Mail API documentation (Mail.Read permissions)  
- VirusTotal Public API rate limits  
- YARA Python library usage  
- `pefile` PE analysis library  
- Sysmon (Windows Sysinternals) capabilities  
- OWASP DevSecOps (secret management) guidelines  
- OWASP Logging Cheat Sheet (log event structure)  
- OpenSSF AI Security Guide (AI in code development)  

