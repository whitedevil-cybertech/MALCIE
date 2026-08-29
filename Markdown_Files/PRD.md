# MALCIE
## Malware Analysis, Linkage, Correlation and Investigation Engine

**PRD Version:** 1.0  
**Project Type:** Cybersecurity / Malware Analysis / Incident Investigation  
**Primary Focus:** Malware-centric incident investigation

---

## 1. Product Overview

MALCIE is a malware-centric incident investigation platform that integrates phishing email analysis, static malware analysis, IOC extraction, threat-intelligence enrichment, and endpoint monitoring.

Its purpose is to connect evidence from multiple investigation stages and present it within a unified incident context.

**Core principle:**

> Collect → Analyze → Enrich → Correlate → Investigate → Report

MALCIE is not intended to replace a commercial EDR, SIEM, antivirus, or professional malware sandbox. It is a focused, modular investigation platform.

---

## 2. What Are We Going to Build?

We are going to build a web-based malware investigation platform where a security analyst can start with a suspicious phishing email or malware artifact and follow the investigation through one system.

### Core workflow

```text
Suspicious Email
       ↓
Email Analysis
       ↓
Attachment Extraction
       ↓
Malware Static Analysis
       ↓
IOC Extraction
       ↓
Threat Intelligence
       ↓
Endpoint Telemetry
       ↓
Evidence Correlation
       ↓
Risk Assessment
       ↓
Incident Timeline
       ↓
Investigation Report
```

### Main product components

1. **Analyst Dashboard** – Central interface for investigations.
2. **Incident Management** – Creates and tracks investigation cases.
3. **Email Integration** – Retrieves authorized emails through an email API.
4. **Phishing Analysis** – Parses headers, body, URLs, domains and attachments.
5. **Malware Analysis** – Performs hashing and static PE analysis.
6. **YARA Engine** – Performs signature-based scanning.
7. **IOC Engine** – Extracts and normalizes indicators.
8. **Threat Intelligence** – Enriches IOCs through external intelligence APIs.
9. **Endpoint Collector** – Receives selected Sysmon telemetry.
10. **Correlation Engine** – Links evidence from different sources.
11. **Risk Engine** – Produces explainable risk levels.
12. **Timeline Engine** – Builds chronological incident activity.
13. **Reporting Engine** – Generates PDF and JSON investigation reports.

---

# 3. Product Vision

Build a practical and deployable malware-centric investigation platform that allows an analyst to move from an initial suspicious email or malware artifact to a correlated incident timeline and investigation report.

The system should demonstrate a realistic malware-investigation workflow while remaining small enough to implement, test, deploy, and demonstrate as an academic project.

---

# 4. Problem Statement

Malware incidents can generate evidence across multiple sources:

- Phishing emails
- Email attachments
- Malware files
- File hashes
- URLs and domains
- Threat-intelligence services
- Endpoint process events
- File events
- Registry events
- Network connections

The problem is often not a lack of tools, but disconnected evidence.

An analyst may have to move between several tools and manually determine whether an email attachment, file hash, IOC, process, and network event belong to the same incident.

**MALCIE addresses this by creating a common incident context and correlating relevant evidence.**

---

# 5. Target Users

## 5.1 Security Operations Center (SOC) Analyst

**Primary target user.**

### Needs

- Investigate suspicious emails
- Analyze attachments
- Identify IOCs
- Check threat intelligence
- Review endpoint activity
- Correlate evidence
- Understand incident progression
- Generate reports

---

## 5.2 Malware Analyst

A user focused on examining suspicious files.

### Needs

- File hashing
- PE analysis
- Strings and imports
- Section and entropy analysis
- YARA scanning
- IOC extraction
- Analysis-result preservation

---

## 5.3 Incident Responder

A user investigating the scope and timeline of a security incident.

### Needs

- Review incident evidence
- Identify affected endpoints
- Correlate IOCs with endpoint events
- Build timelines
- Assess severity
- Document findings

---

## 5.4 Cybersecurity Student / Researcher

A user working in a controlled academic or research environment.

### Needs

- Learn malware investigation workflows
- Analyze controlled samples
- Study endpoint telemetry
- Experiment with correlation rules
- Generate investigation reports

---

## 5.5 Administrator

A user responsible for operating the platform.

### Needs

- Manage users and roles
- Configure integrations
- Manage API credentials
- Configure endpoints
- Review audit logs
- Maintain deployment settings

---

# 6. User Roles

| Role | Main Responsibilities |
|---|---|
| Administrator | Users, roles, integrations, system configuration |
| Analyst | Incidents, evidence, investigations, reports |
| Malware Analyst | Malware analysis, YARA, IOCs |
| Incident Responder | Endpoint evidence, correlation, timelines |
| Viewer | Read-only permitted investigations |

The role model may be simplified for the initial academic release.

---

# 7. Product Features

## 7.1 Authentication & Authorization

### Features

- User login
- Secure session/token management
- Password protection
- Role-based authorization
- Protected APIs
- Logout/session invalidation

### Security

- Passwords never stored in plaintext.
- Sensitive credentials are not hard-coded.
- Users can access only permitted resources.

---

## 7.2 Incident Management

An incident is the central container for investigation evidence.

### Features

- Create incident
- Edit incident metadata
- Assign incident
- Set severity
- Set status
- Add description
- Attach evidence
- View incident history
- Close/reopen incident

### Example status

```text
New
 ↓
Under Investigation
 ↓
Confirmed
 ↓
Contained / Resolved
 ↓
Closed
```

---

## 7.3 Email API Integration

MALCIE will securely retrieve suspicious emails through an email service API.

### Initial integration

**Microsoft Graph Mail API**

### Features

- OAuth 2.0 authorization
- Retrieve authorized messages
- Retrieve message metadata
- Retrieve message content
- Retrieve attachments
- Send retrieved email data to the analysis pipeline

### Security

- Least-privilege permissions
- Secure token storage
- Read-only access where possible
- No storage of the user's email password

### Future

Additional providers such as Gmail may be added later.

---

## 7.4 Manual `.eml` Upload

For offline investigation, analysts can upload `.eml` files.

### Features

- Upload `.eml`
- Parse headers
- Extract sender/recipient
- Extract subject
- Extract URLs
- Extract domains
- Extract attachments
- Associate email with an incident

---

## 7.5 Phishing Email Analysis

### Extracted information

- Sender
- Recipient
- Subject
- Date/time
- Message headers
- URLs
- Domains
- Attachments
- Email body
- Relevant authentication/header information where available

### Goal

Identify suspicious characteristics and extract artifacts for further investigation.

---

## 7.6 File & Attachment Handling

Attachments are treated as untrusted evidence.

### Features

- Store artifact metadata
- Calculate cryptographic hashes
- Identify file type
- Record size
- Associate file with incident
- Send file to static analysis

### Security

- File validation
- Controlled storage
- Safe filenames
- Upload-size limits
- No unintended execution
- Restricted artifact access

---

## 7.7 Malware Static Analysis

MALCIE will primarily perform static analysis.

### Initial capabilities

- SHA-256 hashing
- File-type identification
- PE header analysis
- PE section analysis
- Entropy calculation
- Import analysis
- String extraction
- Metadata inspection
- Basic suspicious-characteristic analysis

### Output

Analysis results are stored and linked to the file artifact and incident.

---

## 7.8 YARA Scanning

YARA provides rule-based malware detection.

### Features

- Scan files with configured rules
- Record matched rules
- Record rule metadata
- Associate matches with artifacts
- Display matches in the dashboard

A YARA match is treated as evidence, not automatic proof that a file is malicious.

---

## 7.9 IOC Extraction

MALCIE automatically identifies supported Indicators of Compromise.

### IOC types

- File hashes
- IPv4/IPv6 addresses
- Domains
- URLs
- File paths

### Requirements

- Normalize indicators
- Remove obvious duplicates
- Record IOC type
- Record extraction source
- Link IOC to artifact and incident

---

## 7.10 Threat Intelligence Enrichment

MALCIE will query configured threat-intelligence sources.

### Initial source

**VirusTotal API or compatible intelligence source**

### Information

- Reputation
- Detection information
- Related metadata
- Source
- Query status
- Query timestamp

### Requirements

- Secure API credentials
- Graceful API failure handling
- Rate-limit handling
- Correct IOC/incident association

---

## 7.11 Endpoint Monitoring

MALCIE will receive telemetry from a controlled Windows environment.

### Initial source

**Microsoft Sysmon**

### Event categories

- Process creation
- File activity
- Registry activity
- Network activity
- Process relationships

### Collector responsibilities

```text
Receive → Parse → Normalize → Validate → Store
```

---

## 7.12 Evidence Correlation

This is the **central differentiating feature** of MALCIE.

The system will attempt to identify relationships between evidence from different sources.

### Example

```text
Phishing Email
      ↓
Attachment
      ↓
SHA-256 Hash
      ↓
Threat Intelligence
      ↓
Endpoint Process
      ↓
Network Connection
```

### Correlation inputs

- Email
- Attachment
- File hash
- IOC
- Threat-intelligence result
- Endpoint
- Process event
- File event
- Registry event
- Network event
- Timestamp

### Example correlations

- An email attachment hash matches a file observed on an endpoint.
- A domain extracted from an email is later contacted by a monitored process.
- A suspicious executable is created and then executed on a monitored endpoint.

---

## 7.13 Risk Assessment

MALCIE will use an explainable rule-based risk model.

### Inputs may include

- YARA matches
- Malware-analysis findings
- Threat-intelligence reputation
- IOC matches
- Suspicious process activity
- Suspicious network activity
- Strength and number of correlations

### Example output

```text
Risk Level: HIGH

Reasons:
- Malicious YARA match
- Known malicious file hash
- Suspicious process execution
- Related network connection
```

The analyst should be able to understand why a risk level was assigned.

---

## 7.14 Incident Timeline

MALCIE will arrange correlated evidence chronologically.

```text
10:01  Suspicious email received
10:03  Attachment extracted
10:04  File analyzed
10:05  IOC extracted
10:07  Threat intelligence queried
10:12  Suspicious process detected
10:13  Network activity observed
10:15  Risk assessed
```

### Features

- Chronological ordering
- Event source
- Event type
- Related artifact
- Related IOC
- Endpoint information
- Correlation references

---

## 7.15 Investigation Dashboard

### Main views

- Incident summary
- Email details
- Attachments
- Malware analysis
- YARA results
- IOC list
- Threat intelligence
- Endpoint events
- Correlations
- Timeline
- Risk assessment
- Reports

### Goal

Allow an analyst to understand the main facts of an incident without manually opening separate tools for every evidence source.

---

## 7.16 Reporting

### Report types

1. Phishing Email Analysis Report
2. Malware Analysis Report
3. IOC & Threat Intelligence Report
4. Endpoint Activity Report
5. Incident Timeline Report
6. Risk Assessment Report
7. Incident Investigation Report
8. Consolidated Incident Report

### Formats

- PDF
- JSON

Reports should contain incident information, evidence, analysis results, IOCs, correlations, timeline, risk level, and investigation summary.

---

# 8. End-to-End User Journey

## Example: Phishing Email Delivering Malware

```text
1. Analyst logs in
        ↓
2. Creates incident
        ↓
3. Retrieves email through Microsoft Graph
   OR uploads .eml
        ↓
4. MALCIE parses email
        ↓
5. Extracts attachment and indicators
        ↓
6. Hashes and analyzes attachment
        ↓
7. Runs YARA
        ↓
8. Extracts IOCs
        ↓
9. Queries threat intelligence
        ↓
10. Receives endpoint telemetry
        ↓
11. Correlates evidence
        ↓
12. Calculates risk
        ↓
13. Builds timeline
        ↓
14. Analyst reviews dashboard
        ↓
15. Generates investigation report
```

---

# 9. Functional Requirements

| ID | Requirement |
|---|---|
| FR-01 | User authentication |
| FR-02 | Role-based authorization |
| FR-03 | Incident creation and management |
| FR-04 | Email API integration |
| FR-05 | `.eml` upload |
| FR-06 | Email parsing |
| FR-07 | Attachment extraction |
| FR-08 | File hashing |
| FR-09 | PE/static malware analysis |
| FR-10 | YARA scanning |
| FR-11 | IOC extraction |
| FR-12 | Threat-intelligence enrichment |
| FR-13 | Endpoint telemetry collection |
| FR-14 | Telemetry normalization |
| FR-15 | Evidence correlation |
| FR-16 | Risk assessment |
| FR-17 | Timeline generation |
| FR-18 | Investigation dashboard |
| FR-19 | PDF reporting |
| FR-20 | JSON reporting |

---

# 10. Non-Functional Requirements

## Security

- Authentication
- Role-based access
- Input validation
- Secure file handling
- Credential protection
- HTTPS in deployment
- Audit logging
- Isolated malware-analysis environment

## Reliability

- Failed integrations should not corrupt investigations.
- Partial analysis results should be preserved.
- Errors should be logged.

## Maintainability

- Modular architecture
- Clear API interfaces
- Separate analysis components
- Configuration-driven integrations
- Automated tests
- Documentation

## Scalability

Architecture should allow future addition of:

- More endpoints
- More intelligence providers
- More email providers
- Additional analysis engines
- More correlation rules

---

# 11. Technical Architecture

```text
                    Security Analyst
                           │
                           ▼
                   React Dashboard
                           │
                         REST
                           ▼
                   FastAPI Backend
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
 Email Processor    Malware Analyzer   Endpoint Collector
        │                  │                  │
        │             ┌────┴────┐             │
        │             ▼         ▼             │
        │           YARA    IOC Engine        │
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                  Correlation Engine
                           │
                    ┌──────┴──────┐
                    ▼             ▼
                PostgreSQL   Report Engine
```

---

# 12. Technology Stack

| Component | Technology |
|---|---|
| Frontend | React + TypeScript |
| Backend | Python + FastAPI |
| Database | PostgreSQL |
| Malware Analysis | Python static-analysis components |
| Signature Detection | YARA |
| Endpoint Telemetry | Microsoft Sysmon |
| Email Integration | Microsoft Graph Mail API |
| Threat Intelligence | VirusTotal API / compatible sources |
| Reports | PDF + JSON |
| Deployment | Docker |
| Test Environment | Windows VM + Linux host/server |

---

# 13. Data Model

### Main entities

- User
- Incident
- Email
- File Artifact
- Malware Analysis
- YARA Match
- IOC
- Artifact IOC
- Threat Intelligence Result
- Endpoint
- Endpoint Event
- Correlation
- Timeline Event
- Report

### Relationships

```text
User 1 ─── N Incident
Incident 1 ─── N Email
Incident 1 ─── N Artifact
Artifact 1 ─── N Analysis
Analysis 1 ─── N YARA Match
Artifact M ─── N IOC
Endpoint 1 ─── N Endpoint Event
Incident 1 ─── N Correlation
Incident 1 ─── N Timeline Event
Incident 1 ─── N Report
```

---

# 14. API Structure

The backend should expose REST APIs.

### Main API groups

```text
/auth
/users
/incidents
/emails
/artifacts
/analysis
/yara
/iocs
/threat-intelligence
/endpoints
/events
/correlations
/timeline
/reports
```

### Example operations

```text
POST   /incidents
GET    /incidents/{id}
POST   /emails/upload
GET    /emails/{id}
POST   /artifacts/{id}/analyze
POST   /iocs/enrich
GET    /incidents/{id}/timeline
GET    /incidents/{id}/correlations
POST   /incidents/{id}/reports
```

The exact API design may change during implementation.

---

# 15. Storage

## PostgreSQL

Stores:

- Users
- Incidents
- Metadata
- Analysis results
- IOCs
- Threat intelligence
- Endpoint events
- Correlations
- Timeline events
- Report metadata

## Artifact Storage

Stores:

- Original `.eml` files
- Suspicious attachments
- Relevant evidence
- Generated reports

Artifact access must be controlled and samples must be handled as untrusted content.

---

# 16. Malware Safety Requirements

Uploaded and retrieved malware artifacts are untrusted.

### Mandatory controls

- Never execute uploaded malware on the production server.
- Use isolated environments for behavioral testing.
- Validate uploaded files.
- Restrict file permissions.
- Prevent path traversal.
- Sanitize filenames.
- Limit upload size.
- Log artifact access.
- Store hashes for evidence tracking.
- Keep samples isolated from normal application data.

---

# 17. MVP

The Minimum Viable Product is complete when an analyst can perform:

```text
Login
 ↓
Create Incident
 ↓
Upload .eml / Retrieve Email
 ↓
Extract Attachment
 ↓
Hash File
 ↓
Perform Static Analysis
 ↓
Run YARA
 ↓
Extract IOC
 ↓
Query Threat Intelligence
 ↓
Receive Endpoint Telemetry
 ↓
Correlate Evidence
 ↓
Generate Timeline
 ↓
Calculate Risk
 ↓
View Dashboard
 ↓
Generate Report
```

This end-to-end workflow is the minimum acceptable demonstration.

---

# 18. Advanced Features

Advanced features should only be implemented after the MVP is stable.

### Possible additions

- MITRE ATT&CK mapping
- Multiple email-provider integrations
- Additional threat-intelligence providers
- Advanced correlation rules
- Improved timeline visualization
- Analyst comments
- Evidence tagging
- Case assignment
- Collaboration
- Detection-rule management
- Additional endpoint event types

---

# 19. Future Features

Outside the initial core scope:

- Dynamic malware sandbox integration
- Machine-learning-based classification
- Automated incident response
- Endpoint isolation
- SIEM integration
- EDR integration
- Large-scale multi-endpoint deployment
- Cloud-native scaling
- Automated threat-hunting workflows

---

# 20. Existing Alternatives

Existing technologies already provide individual capabilities:

| Technology | Main Capability |
|---|---|
| Antivirus / EDR | Endpoint detection and response |
| SIEM | Centralized security-event management |
| VirusTotal | File and IOC intelligence |
| Malware Sandbox | Dynamic analysis |
| YARA | Signature/pattern matching |

MALCIE does not attempt to replace these platforms.

---

# 21. What Makes MALCIE Different?

The main differentiator is:

> **Malware-centric evidence correlation.**

Instead of returning isolated results:

```text
Email Result
Malware Result
IOC Result
Endpoint Result
```

MALCIE attempts to connect them:

```text
Email
  ↓
Attachment
  ↓
Malware
  ↓
IOC
  ↓
Endpoint Activity
  ↓
Timeline
  ↓
Risk
```

The relationship between the evidence is the central product value.

---

# 22. What MALCIE Will Not Claim

To keep the product technically honest:

- It will not claim to detect every malware family.
- It will not claim to replace commercial EDR products.
- It will not claim to replace SIEM platforms.
- It will not claim that every YARA match proves malware.
- It will not claim that threat-intelligence reputation alone proves compromise.
- It will not automatically execute unknown malware in the main application.
- It will not claim autonomous incident response in the MVP.

---

# 23. Success Criteria

MALCIE will be successful if it can:

1. Securely accept or retrieve a suspicious email.
2. Extract and analyze its attachment.
3. Produce useful static malware-analysis results.
4. Detect configured YARA patterns.
5. Extract meaningful IOCs.
6. Enrich IOCs using a threat-intelligence API.
7. Process endpoint telemetry.
8. Correlate at least one meaningful relationship between evidence sources.
9. Generate an understandable incident timeline.
10. Provide an explainable risk assessment.
11. Display the investigation through a usable dashboard.
12. Generate a complete investigation report.
13. Run successfully in a controlled deployment environment.

---

# 24. Development Priorities

The project should be built in this order:

### Priority 1 — Foundation
Authentication, database, incidents, API structure.

### Priority 2 — Malware Investigation
Email intake, attachment handling, hashing, PE analysis, YARA.

### Priority 3 — Intelligence
IOC extraction and threat-intelligence enrichment.

### Priority 4 — Endpoint
Sysmon collector and telemetry storage.

### Priority 5 — Correlation
Evidence relationships, timeline, risk assessment.

### Priority 6 — Productization
Dashboard, reporting, security hardening, Docker deployment.

**Important:** Do not build advanced features before the core investigation pipeline works end-to-end.

---

# 25. 9-Week Development Plan

| Week | Focus |
|---|---|
| 1 | Requirement analysis and research |
| 2 | Architecture and database design |
| 3 | FastAPI, PostgreSQL, authentication, incidents |
| 4 | Email API, `.eml`, attachment and malware analysis |
| 5 | Sysmon and endpoint telemetry |
| 6 | Correlation and risk assessment |
| 7 | Dashboard and reporting |
| 8 | Integration, security and deployment |
| 9 | Testing, documentation and presentation |

---

# 26. Testing Strategy

### Unit Testing
Test individual parsing, analysis, extraction, API, and database functions.

### Integration Testing
Test the complete investigation pipeline.

```text
Email → File → Analysis → IOC → Intelligence → Correlation
```

and:

```text
Endpoint → Collector → Database → Correlation
```

### Security Testing

- Authentication
- Authorization
- File upload security
- Path traversal
- Input validation
- Credential protection
- API security

### Malware Testing

Use controlled and isolated samples or safe test artifacts.

### False-Positive Testing

Test benign files, normal email, and normal endpoint activity.

### Performance Testing

Measure:

- API response time
- Analysis duration
- Database performance
- Telemetry ingestion
- Report generation

---

# 27. Deployment

Initial deployment:

```text
                  User Browser
                       │
                       ▼
                React Frontend
                       │
                       ▼
                FastAPI Backend
                       │
              ┌────────┴────────┐
              ▼                 ▼
         PostgreSQL       Artifact Storage
              │
       ┌──────┴────────┐
       ▼               ▼
 Threat Intel      Endpoint Collector
       API               │
                         ▼
                     Sysmon VM
```

Docker will be used to simplify deployment of application components.

The initial deployment target is a controlled lab, academic SOC, or small-scale security environment.

---

# 28. Project Constraints

- Limited academic development time
- Limited hardware resources
- API rate limits
- Availability of threat-intelligence data
- Endpoint telemetry depends on test-environment configuration
- Static analysis has inherent limitations
- Full enterprise-scale deployment is outside the MVP

---

# 29. Definition of Done

The project is complete when:

- All core MVP modules are integrated.
- A complete sample investigation can be performed from email to report.
- The application operates without code changes during normal use.
- Authentication and authorization work.
- Malware artifacts are handled safely.
- Evidence is stored and linked to incidents.
- Correlation produces understandable results.
- Reports can be generated.
- The system can be deployed using documented steps.
- Testing and documentation are complete.

---

# 30. Final Product Statement

> **MALCIE is a malware-centric incident investigation platform that securely collects suspicious email and endpoint evidence, performs static malware analysis, extracts and enriches IOCs, correlates related evidence, builds an incident timeline, assesses risk, and generates investigation reports through a unified analyst workflow.**

---

# 31. Core Product Principle

> **Do not build everything. Build the investigation loop completely.**

The project's success depends on having one reliable end-to-end workflow rather than a large collection of partially implemented features.

```text
INPUT
  ↓
ANALYZE
  ↓
ENRICH
  ↓
CORRELATE
  ↓
INVESTIGATE
  ↓
REPORT
```
