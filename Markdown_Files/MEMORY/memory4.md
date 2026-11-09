# MALCIE Session Memory — Phase 4 Completion

## Session Scope & Objective

This session executed and formally verified **Phase 4: Correlation & Linkage Engine** per the project requirements and roadmap defined in:
- `Markdown_Files/MEMORY/memory3.md` (Phase 3 completion and handoff)
- `Markdown_Files/Phases.md` (lines 43–49)
- `Markdown_Files/PRD.md` (lines 451–521, 525–548, 752–783, 788–822)
- `Markdown_Files/Rules.md` (lines 53–64, 145–162, 184–186)

The core objectives delivered and verified in this phase:
1. **Multi-Source Evidence Correlation:** Discovered and established deterministic linkages across emails, attachments, cryptographic digests, static PE structures, YARA detection rules, extracted IOCs, and VirusTotal threat intelligence results.
2. **Deterministic & Explainable Confidence Scoring:** Evaluated correlation completeness and linkage strength (0.0% to 100.0%, categorized into `LOW`, `MEDIUM`, `HIGH`) with an itemized, human-auditable breakdown of confidence factors.
3. **Rule-Based Malware Risk Assessment:** Designed and evaluated a rule-based risk score (0 to 100, categorized into `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), strictly separated from correlation confidence, ensuring non-malicious evidence with high correlation completeness does not receive an inflated risk verdict.
4. **Incident Timeline Reconstruction:** Reconstructed strict chronological event sequences from RFC 2822 email dates, PE header `TimeDateStamp` compilation records, artifact ingestion, static analysis completion, YARA hits, IOC extractions, and threat intelligence lookups.
5. **Persistence & REST APIs:** Exposed `/api/v1/incidents/{id}/correlate`, `/api/v1/incidents/{id}/correlations`, and `/api/v1/incidents/{id}/timeline`, persisting `CorrelationResult` and `TimelineEvent` records via Alembic migration `0006_phase4_correlation_timeline.py`.
6. **Testing & Quality Assurance:** Added 5 focused unit and integration test suites covering clean vs. malicious evidence, cross-correlation corroboration, timeline chronological ordering, idempotency, and 404 handling, bringing the test suite to 38/38 passing tests with zero linter errors.

---

## 1. Architecture & Design Implementation

### Evidence Correlation & Linkage Engine
Implemented in `src/backend/app/services/correlation_engine.py`:
- **Direct Entity Hierarchy Linkages:**
  - `email -> artifact`: Linkage type `CONTAINS_ATTACHMENT` with filename and SHA-256 digest.
  - `artifact -> hash`: Linkage type `COMPUTED_HASH` for SHA-256 digests.
  - `artifact -> analysis`: Linkage type `STATIC_ANALYSIS` capturing execution status and PE validity.
  - `artifact -> yara_rule`: Linkage type `YARA_RULE_MATCH` capturing rule name, tags, and matched metadata.
  - `artifact -> ioc` / `email -> ioc`: Linkage type `EXTRACTED_IOC` preserving indicator type, normalized value, and discovery source.
  - `ioc -> threat_intel`: Linkage type `THREAT_INTEL_VERDICT` associating external vendor detection statistics.
- **Cross-Source Corroborating Linkages:**
  - `CORROBORATING_NETWORK_INDICATOR`: Cross-matches URLs and domain names embedded in email bodies or headers with strings/IOCs discovered inside binary attachments.
  - `CORROBORATED_MALICIOUS_HASH`: Corroborates artifact file digests directly confirmed as malicious by VirusTotal telemetry.

### Confidence Scoring vs. Risk Assessment (Strict Separation)
- **Correlation Confidence (`ConfidenceAssessment`):**
  - Measures the *completeness and robustness of evidence linkages* (0.0 to 100.0%):
    - Email captured & parsed: +15%
    - Attachment linkage established: +20%
    - Static PE analysis completed: +20%
    - Structured IOCs extracted with source provenance: +15%
    - Threat intelligence queried and associated: +15%
    - Cross-source corroboration identified: +15%
  - Levels: `LOW` (0–39.9%), `MEDIUM` (40–69.9%), `HIGH` (70–100%).
  - Provides explainable `reasons` for every score increment.
- **Malware Risk Assessment (`RiskAssessment`):**
  - Measures the *severity and maliciousness of the observed threat* (0 to 100):
    - YARA matches: +25 pts for first rule, +15 pts for subsequent rules (up to 40 max).
    - Known malicious file hash in VT: +30 pts (>=5 malicious detections) or +15 pts (1-4 detections / rep < -20).
    - Malicious network IOCs in VT: +20 pts (>=2 malicious detections).
    - High Shannon entropy section (> 7.0): +15 pts (packing / obfuscation).
    - Suspicious execution/downloader APIs imported: +15 pts (`URLDownloadToFile`, `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `WinExec`, etc.).
    - Phishing email indicators: +10 pts (embedded links alongside executable attachment).
  - Levels: `NONE` (0), `LOW` (1–24), `MEDIUM` (25–49), `HIGH` (50–74), `CRITICAL` (75–100).
  - Fully explainable `reasons` justifying why the incident was categorized.
  - **Guaranteed Separation:** Benign evidence with full linkages achieves `confidence="HIGH"` while retaining `risk="NONE"`, preventing false alarms.

### Chronological Incident Timeline
- **Event Types:**
  - `EMAIL_RECEIVED`: Parsed from RFC 2822 `sent_at` or fallback `created_at`.
  - `ATTACHMENT_EXTRACTED`: Timestamp of artifact storage and digest generation.
  - `PE_COMPILED`: Validated `TimeDateStamp` from PE `FILE_HEADER` (1990–2038 epoch).
  - `STATIC_ANALYSIS_COMPLETED`: Completion timestamp of header/section/import parsing.
  - `YARA_MATCH`: Timestamp of signature detection.
  - `IOC_EXTRACTED`: Timestamp of indicator normalization and provenance capture.
  - `THREAT_INTEL_QUERIED`: Timestamp of VirusTotal lookup.
  - `CORRELATION_ASSESSED`: Timestamp of correlation synthesis and risk verdict.
- **Strict Ordering:** All timestamps normalized to timezone-aware UTC and sorted chronologically ascending.

### Database Persistence & Schema
- Added `CorrelationResult` and `TimelineEvent` models in `src/backend/app/models.py`.
- Migration `alembic/versions/0006_phase4_correlation_timeline.py` manages tables, foreign keys, and indices.

---

## 2. Changed & Created Files

| File | Status | Description |
|---|---|---|
| `src/backend/app/models.py` | Modified | Added `CorrelationResult` and `TimelineEvent` models with relationships on `Incident`. |
| `alembic/versions/0006_phase4_correlation_timeline.py` | Created | Alembic migration for `correlation_results` and `timeline_events` tables. |
| `src/backend/app/schemas.py` | Modified | Added schemas: `LinkageItem`, `ConfidenceAssessment`, `RiskAssessment`, `CorrelationResponse`, `TimelineEventRead`. |
| `src/backend/app/services/correlation_engine.py` | Created | Core correlation engine: linkages, confidence scoring, risk assessment, timeline generation, and persistence. |
| `src/backend/app/api/incidents.py` | Modified | Added endpoints: `POST /{id}/correlate`, `GET /{id}/correlations`, and `GET /{id}/timeline`. |
| `tests/backend/test_phase4_correlation_and_timeline.py` | Created | Comprehensive tests for empty incidents, confidence vs risk separation, full correlation pipeline, idempotence, and 404s. |
| `README.md` | Modified | Updated project status, capabilities, API documentation, and test metrics for Phase 4. |
| `Markdown_Files/MEMORY/memory4.md` | Created | This memory document. |

---

## 3. Test & Verification Results

### Backend Test Suite
Executed via `.venv\Scripts\python -m pytest tests/backend -v`:
- `tests/backend/test_health.py` (1 test) — **PASSED**
- `tests/backend/test_phase2a_email_intake.py` (3 tests) — **PASSED**
- `tests/backend/test_phase2b_pe_static_analysis.py` (8 tests) — **PASSED**
- `tests/backend/test_phase2b_partb_analysis.py` (12 tests) — **PASSED**
- `tests/backend/test_phase3_graph_and_threat_intel.py` (9 tests) — **PASSED**
- `tests/backend/test_phase4_correlation_and_timeline.py` (5 tests) — **PASSED**
  - `test_empty_incident_correlation`: Verified graceful correlation on incident with zero evidence (confidence=0.0 LOW, risk=0 NONE, single timeline event).
  - `test_separation_of_confidence_and_malware_risk`: Verified clean email + attachment achieves medium/high confidence while risk remains strictly 0 (NONE).
  - `test_full_pipeline_evidence_correlation_linkages`: Verified complete end-to-end pipeline linking email, attachment, PE analysis, IOCs, threat intel, YARA rules, cross-source corroboration, and strict chronological timeline ordering.
  - `test_correlation_idempotence_and_retrieval`: Verified re-running correlation updates existing records cleanly without duplication, and `GET /correlations` returns consistent data.
  - `test_correlate_and_timeline_404_on_missing_incident`: Verified 404 responses for non-existent incident IDs across all new endpoints.
- **Total: 38 passed in 5.57s (100% passing)**

### Backend Linting
Executed via `.venv\Scripts\python -m ruff check src/backend/app alembic tests/backend`:
- **0 errors, all checks passed** (enforcing 100-character line limit, flake8, bugbear, and import sorting).

### Frontend Component Tests
Executed via `npm run test` in `src/frontend`:
- `src/App.test.tsx` (1 test) — **PASSED**

---

## 4. Known Issues & Notes

- **Windows Sandbox Isolation:** As noted in Phase 3, `pytest` requires `BypassSandbox: true` because `TestClient` initializes internal loopback event portals which Windows sandboxing blocks without permission.
- **Original Evidence Immutability:** Preserved 100% of original raw files, EML bytes, and PE binaries. Correlation and timeline events are purely derived and stored in dedicated tables without mutating evidence artifacts.

---

## 5. Precise Next-Session Tasks (Phase 5 Handoff)

With Phase 4 core correlation, confidence scoring, risk assessment, and incident timeline complete and verified, the next session will start **Phase 5: Endpoint Telemetry Integration (Weeks 12–14)** per `Markdown_Files/Phases.md` (lines 51–57):

### Specific Phase 5 Tasks:
1. **Sysmon Telemetry Ingestion:**
   - Ingest Windows Sysmon XML / JSON event logs (Event ID 1: Process Creation, Event ID 3: Network Connection, Event ID 11: File Creation, Event ID 13: Registry Value Set).
   - Normalize process paths, hashes, command lines, parent-child process hierarchies, destination IPs, and ports.
2. **Endpoint-to-Incident Linkage:**
   - Correlate Sysmon process creation hashes with attachment hashes (`Artifact.sha256`).
   - Correlate Sysmon destination IPs/domains with network IOCs extracted from static analysis and phishing emails.
3. **Timeline Fusion:**
   - Merge endpoint execution timestamps into the unified incident timeline.
4. **Endpoint Telemetry Endpoints & Tests:**
   - Expose `/api/v1/incidents/{id}/telemetry` and `/api/v1/telemetry/upload` endpoints.
   - Add integration tests using synthetic Sysmon logs matching known test malware hashes.
