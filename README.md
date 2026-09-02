# TraceX Backend

**TraceX — AI-Powered Email Threat Detection & Forensic Intelligence Platform**

## 1. Project Overview

TraceX is a cybersecurity platform designed to analyze suspicious emails and help investigators understand not only **whether an email is malicious**, but also **why it is suspicious and what technical infrastructure is associated with it**.

The backend is responsible for:

* Parsing `.eml` email files
* Extracting email headers and metadata
* Extracting URLs, domains, IPs and attachments
* Performing SPF/DKIM/DMARC analysis
* Detecting phishing, impersonation and BEC indicators
* Calculating an explainable risk score
* Reconstructing email relay paths
* Performing IP/domain intelligence analysis
* Correlating indicators with threat intelligence
* Storing investigation/case data
* Generating structured forensic reports
* Providing APIs for the TraceX frontend

---

# 2. Core Backend Workflow

```text
                    USER
                      │
                      ▼
              Upload .EML File
                      │
                      ▼
                 API Gateway
                      │
                      ▼
                Email Parser
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
     Headers         Body          URLs
        │             │             │
        └─────────────┼─────────────┘
                      ▼
              Security Analysis
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
   Auth Checks      NLP/AI       IOC Analysis
   SPF/DKIM/DMARC   Phishing      IP/Domain
                    BEC           URL
                      │
                      ▼
                Risk Engine
                      │
                      ▼
             Threat Intelligence
                      │
                      ▼
              Forensic Correlation
                      │
            ┌─────────┴─────────┐
            ▼                   ▼
        Dashboard            Report
```

---

# 3. Backend Technology Stack

## Core

* **Python 3.11+**
* **FastAPI**
* **Uvicorn**

## Email & Security Analysis

* Python `email` package
* `dnspython`
* `requests/httpx`
* `tldextract`
* `validators`
* `python-whois` or equivalent domain intelligence library
* URL parsing utilities

## AI / NLP

* Python NLP ecosystem
* Lightweight pretrained model / classifier
* Optional LLM integration for advanced explanation

## Database

* **MongoDB**
* **PyMongo / Motor**

## Authentication

* Firebase Authentication

## External Intelligence

Possible integrations:

* IP geolocation API
* DNS/MX lookup
* Threat intelligence APIs
* URL reputation services

External services will be added only after the core backend is working.

---

# 4. Backend Folder Structure

```text
backend/
│
├── app/
│   │
│   ├── __init__.py
│   ├── main.py
│   │
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py
│   │
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── health_routes.py
│   │   ├── email_routes.py
│   │   ├── analysis_routes.py
│   │   ├── intelligence_routes.py
│   │   ├── case_routes.py
│   │   └── report_routes.py
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   │
│   │   ├── email/
│   │   │   ├── parser.py
│   │   │   ├── header_analyzer.py
│   │   │   ├── body_analyzer.py
│   │   │   ├── url_extractor.py
│   │   │   └── attachment_analyzer.py
│   │   │
│   │   ├── authentication/
│   │   │   ├── spf_checker.py
│   │   │   ├── dkim_checker.py
│   │   │   └── dmarc_checker.py
│   │   │
│   │   ├── threat/
│   │   │   ├── phishing_detector.py
│   │   │   ├── bec_detector.py
│   │   │   ├── impersonation_detector.py
│   │   │   ├── url_analyzer.py
│   │   │   └── domain_analyzer.py
│   │   │
│   │   ├── intelligence/
│   │   │   ├── ip_intelligence.py
│   │   │   ├── domain_intelligence.py
│   │   │   ├── geo_intelligence.py
│   │   │   └── threat_intelligence.py
│   │   │
│   │   ├── forensic/
│   │   │   ├── relay_tracer.py
│   │   │   ├── ioc_extractor.py
│   │   │   └── correlation_engine.py
│   │   │
│   │   ├── risk/
│   │   │   ├── risk_engine.py
│   │   │   ├── scoring_rules.py
│   │   │   └── explainability.py
│   │   │
│   │   └── report/
│   │       └── report_generator.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── case_model.py
│   │   ├── email_model.py
│   │   ├── analysis_model.py
│   │   └── indicator_model.py
│   │
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── email_schema.py
│   │   ├── analysis_schema.py
│   │   ├── intelligence_schema.py
│   │   ├── case_schema.py
│   │   └── report_schema.py
│   │
│   ├── database/
│   │   ├── __init__.py
│   │   ├── connection.py
│   │   └── collections.py
│   │
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── error_handler.py
│   │   └── request_logger.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── validators.py
│       ├── text_utils.py
│       ├── domain_utils.py
│       └── ip_utils.py
│
├── tests/
│   ├── sample_emails/
│   │   ├── legitimate.eml
│   │   ├── phishing.eml
│   │   └── bec.eml
│   │
│   ├── test_parser.py
│   ├── test_headers.py
│   ├── test_risk_engine.py
│   └── test_api.py
│
├── uploads/
│   └── .gitkeep
│
├── .env
├── .env.example
├── .gitignore
├── requirements.txt
├── README.md
└── run.py
```

---

# 5. Folder Responsibilities

## `app/main.py`

Main FastAPI application.

Responsibilities:

* Create FastAPI app
* Register middleware
* Register routers
* Configure startup/shutdown
* Provide API documentation

---

## `app/config/`

Application configuration.

Example:

```text
MONGODB_URI
DATABASE_NAME
FIREBASE_CREDENTIALS
THREAT_INTEL_API_KEY
GEOLOCATION_API_KEY
UPLOAD_LIMIT
```

Secrets will never be hard-coded.

---

## `app/routes/`

Contains only API endpoints.

Routes should remain thin.

Example:

```text
Route
  ↓
Validation
  ↓
Service
  ↓
Response
```

Business logic should not be written directly inside route files.

---

# 6. Email Analysis Services

## `parser.py`

Main `.eml` parser.

Extract:

* From
* To
* CC
* BCC
* Subject
* Date
* Reply-To
* Return-Path
* Message-ID
* Received headers
* Body
* HTML body
* Attachments

---

## `header_analyzer.py`

Analyze email headers.

Checks:

* Sender consistency
* Reply-To mismatch
* Return-Path mismatch
* Message-ID anomalies
* Received chain
* Header inconsistencies
* Possible spoofing indicators

---

## `body_analyzer.py`

Analyze email content.

Detect:

* Urgency
* Credential requests
* Payment requests
* Password reset requests
* Account suspension language
* Social engineering patterns

---

## `url_extractor.py`

Extract all URLs from:

* Plain text
* HTML body
* Headers where applicable

Output:

```text
URL
Domain
Protocol
Path
Query
```

---

## `attachment_analyzer.py`

Extract attachment metadata.

For MVP:

* Filename
* Extension
* MIME type
* Size
* SHA-256 hash

Later:

* Malware reputation
* Sandbox integration

---

# 7. Authentication Analysis

## `spf_checker.py`

Check SPF-related information and return:

```json
{
  "status": "pass",
  "details": "...",
  "confidence": 0.95
}
```

---

## `dkim_checker.py`

Analyze DKIM information and signature status.

---

## `dmarc_checker.py`

Check:

* DMARC result
* Policy
* Alignment
* Failure reason

---

# 8. Threat Detection

## `phishing_detector.py`

Detect phishing indicators.

Input:

```text
Subject
Body
URLs
Sender information
Authentication results
```

Output:

```text
phishing_probability
indicators
confidence
```

---

## `bec_detector.py`

Detect Business Email Compromise patterns.

Examples:

* Executive impersonation
* Payment diversion
* Invoice fraud
* Urgent transfer requests

---

## `impersonation_detector.py`

Detect:

* Look-alike domains
* Display-name deception
* Sender/Reply-To mismatch
* Similar domain spelling

Example:

```text
paypal.com
paypa1.com
```

---

# 9. Intelligence Services

## `ip_intelligence.py`

For relevant IPs:

* Country
* Region
* City
* ISP
* ASN
* Organization
* Reputation

---

## `domain_intelligence.py`

For domains:

* DNS
* MX
* Nameservers
* Registrar information
* Domain age where available
* Hosting information

---

## `geo_intelligence.py`

Convert technical IP information into approximate geolocation data for visualisation.

Important:

The system will present this as **probable infrastructure location**, not exact attacker location.

---

## `threat_intelligence.py`

Correlate indicators with available threat intelligence sources.

Indicators:

```text
IP
Domain
URL
Hash
```

Output:

```text
Known malicious
Suspicious
Unknown
```

---

# 10. Forensic Services

## `relay_tracer.py`

Reconstruct email relay path from `Received` headers.

Example:

```text
Mail Client
     ↓
SMTP Server A
     ↓
SMTP Server B
     ↓
SMTP Server C
```

The system should identify the **probable earliest reliable sending infrastructure**, rather than blindly trusting every header.

---

## `ioc_extractor.py`

IOC = Indicator of Compromise.

Extract:

```text
IPs
Domains
URLs
Hashes
Email addresses
```

---

## `correlation_engine.py`

Connect all indicators.

Example:

```text
Email
  │
  ├── Domain
  │      └── IP
  │
  ├── URL
  │      └── Domain
  │
  └── Relay Server
         └── ASN
```

This creates the forensic intelligence graph.

---

# 11. Risk Engine

The Risk Engine combines evidence from all modules.

Example:

```text
SPF failure              +15
DMARC failure            +20
Reply-To mismatch        +15
Suspicious URL           +15
Look-alike domain        +15
Urgency language         +10
BEC indicator            +10
```

Maximum:

```text
100
```

Risk levels:

```text
0–30     LOW
31–60    MEDIUM
61–80    HIGH
81–100   CRITICAL
```

---

# 12. Explainability

TraceX should not return only:

```text
Risk = 91
```

It should return:

```text
Risk = 91 / 100
Level = CRITICAL

Reasons:
- DMARC failed
- Sender and Reply-To domains differ
- Look-alike domain detected
- Suspicious URL detected
- Urgency language detected
```

This is a major part of the product experience.

---

# 13. Database Design

MongoDB collections:

## `cases`

Stores investigation-level information.

```json
{
  "case_id": "TX-2026-0001",
  "status": "open",
  "risk_score": 91,
  "risk_level": "critical",
  "created_at": "..."
}
```

---

## `emails`

Stores parsed email information.

```json
{
  "case_id": "TX-2026-0001",
  "sender": "...",
  "reply_to": "...",
  "subject": "...",
  "message_id": "...",
  "headers": {},
  "urls": []
}
```

---

## `analyses`

Stores security-analysis results.

```json
{
  "case_id": "TX-2026-0001",
  "spf": {},
  "dkim": {},
  "dmarc": {},
  "phishing": {},
  "bec": {},
  "risk": {}
}
```

---

## `indicators`

Stores extracted IOCs.

```json
{
  "case_id": "TX-2026-0001",
  "ips": [],
  "domains": [],
  "urls": [],
  "hashes": []
}
```

---

# 14. API Structure

## Health

```http
GET /api/health
```

---

## Email

```http
POST /api/email/upload
POST /api/email/parse
GET  /api/email/{case_id}
```

---

## Analysis

```http
POST /api/analysis/run/{case_id}
GET  /api/analysis/{case_id}
```

---

## Intelligence

```http
GET /api/intelligence/ip/{ip}
GET /api/intelligence/domain/{domain}
GET /api/intelligence/url
```

---

## Cases

```http
POST /api/cases
GET  /api/cases
GET  /api/cases/{case_id}
PATCH /api/cases/{case_id}
```

---

## Reports

```http
POST /api/reports/{case_id}/generate
GET  /api/reports/{case_id}
```

---

# 15. End-to-End API Flow

The main API flow will eventually look like:

```text
POST /api/email/upload
          ↓
Create Case
          ↓
Parse Email
          ↓
Analyze Headers
          ↓
Extract IOCs
          ↓
Run Authentication Checks
          ↓
Run Threat Detection
          ↓
Run Intelligence Checks
          ↓
Trace Relay Path
          ↓
Calculate Risk
          ↓
Correlate Findings
          ↓
Store Results
          ↓
Return Investigation Result
```

---

# 16. Response Structure

The primary analysis response should eventually follow a structure similar to:

```json
{
  "case": {
    "case_id": "TX-2026-0001",
    "status": "open"
  },

  "email": {
    "sender": "...",
    "reply_to": "...",
    "subject": "...",
    "date": "..."
  },

  "authentication": {
    "spf": {},
    "dkim": {},
    "dmarc": {}
  },

  "threat_analysis": {
    "phishing": {},
    "bec": {},
    "impersonation": {}
  },

  "indicators": {
    "ips": [],
    "domains": [],
    "urls": [],
    "hashes": []
  },

  "forensics": {
    "relay_chain": [],
    "probable_source": {}
  },

  "risk": {
    "score": 91,
    "level": "critical",
    "reasons": []
  }
}
```

---

# 17. Development Roadmap

## Phase 0 — Project Setup

### Goal

Working FastAPI backend.

### Tasks

* Create project structure
* Create virtual environment
* Install dependencies
* Create FastAPI application
* Configure `.env`
* Create health endpoint
* Setup Git repository

### Output

```text
GET /api/health
→ healthy
```

---

# Phase 1 — Email Parsing MVP

### Goal

Convert `.eml` into structured JSON.

### Tasks

* `.eml` upload
* Parse email
* Extract sender
* Extract recipient
* Extract subject
* Extract date
* Extract Reply-To
* Extract Return-Path
* Extract Message-ID
* Extract Received headers
* Extract body
* Extract URLs
* Extract attachments

### Output

```text
sample.eml
      ↓
structured JSON
```

---

# Phase 2 — Header Forensics

### Goal

Understand whether the email's technical headers contain suspicious patterns.

### Tasks

* Sender/Reply-To comparison
* Return-Path comparison
* Received header parsing
* IP extraction
* Domain extraction
* Message-ID analysis
* Header consistency checks

### Output

```text
Header Findings
+
Suspicious Indicators
```

---

# Phase 3 — Email Authentication

### Goal

Add email-authentication analysis.

### Tasks

* SPF
* DKIM
* DMARC
* Alignment analysis
* Authentication result normalization

### Output

```text
SPF   → PASS/FAIL
DKIM  → PASS/FAIL
DMARC → PASS/FAIL
```

---

# Phase 4 — Rule-Based Threat Detection

### Goal

Create a reliable baseline before AI.

### Tasks

* Urgency detection
* Credential request detection
* Payment request detection
* Suspicious URL rules
* Look-alike domain detection
* Sender mismatch
* BEC indicators

### Output

```text
Threat indicators
+
Initial risk score
```

---

# Phase 5 — Risk & Explainability Engine

### Goal

Produce meaningful risk assessment.

### Tasks

* Create scoring rules
* Normalize score to 0–100
* Risk levels
* Evidence aggregation
* Explanation generation

### Output

```text
91/100
CRITICAL

Why?
- DMARC failure
- URL anomaly
- Domain mismatch
...
```

---

# Phase 6 — AI/NLP Layer

### Goal

Add intelligent content analysis.

### Tasks

* Text preprocessing
* Phishing classification
* BEC classification
* Social-engineering detection
* Confidence score
* Explainable AI output

### Output

```text
Phishing Probability
BEC Probability
Detected Patterns
Confidence
```

Rule-based detection will remain as a fallback.

---

# Phase 7 — IOC & Threat Intelligence

### Goal

Go beyond the email itself.

### Tasks

* Extract IPs
* Extract domains
* Extract URLs
* Extract hashes
* IP intelligence
* Domain intelligence
* URL reputation
* Threat intelligence correlation

### Output

```text
IOC List
+
Reputation
+
Intelligence
```

---

# Phase 8 — Forensic Trace

### Goal

Create the TraceX signature feature.

### Tasks

* Parse Received headers
* Build relay chain
* Identify probable source infrastructure
* Create relationship graph
* Add confidence level

### Output

```text
Sender
  ↓
Relay 1
  ↓
Relay 2
  ↓
Source Infrastructure
```

---

# Phase 9 — Geolocation

### Goal

Add map intelligence.

### Tasks

* IP geolocation
* ISP/ASN data
* Map-ready coordinates
* Confidence handling

### Output

```text
Probable Infrastructure Location
```

---

# Phase 10 — Database & Case Management

### Goal

Store investigations.

### Tasks

* MongoDB connection
* Case creation
* Analysis storage
* IOC storage
* Investigation history
* Search/filter

### Output

```text
Case TX-2026-0001
Case TX-2026-0002
Case TX-2026-0003
```

---

# Phase 11 — Forensic Reporting

### Goal

Create an investigator-friendly report.

### Report Sections

1. Case Information
2. Email Summary
3. Authentication Results
4. Threat Findings
5. IOCs
6. Relay Trace
7. Infrastructure Intelligence
8. Risk Score
9. Evidence/Reasons
10. Investigation Summary

### Output

```text
TraceX Forensic Report.pdf
```

---

# Phase 12 — Security & Production Hardening

### Tasks

* Authentication
* Authorization
* File-size limits
* File validation
* Rate limiting
* Input sanitization
* Error handling
* Logging
* API security
* Secret management
* Data retention policies

---

# 18. MVP Scope for SIH Presentation

Because the presentation deadline is close, the first demonstrable MVP should contain only:

```text
✅ .EML upload
✅ Email parsing
✅ Header analysis
✅ SPF/DKIM/DMARC
✅ URL extraction
✅ Basic threat detection
✅ Risk score
✅ Explainable reasons
✅ Relay-path visualization
✅ Basic IP/domain intelligence
✅ Forensic report
```

Advanced features can be marked as:

```text
Future Scope
```

---

# 19. Development Priority

The development priority is:

```text
HIGH PRIORITY
────────────────────────

1. Email Parser
2. Header Forensics
3. Authentication Analysis
4. Rule-Based Threat Detection
5. Risk Engine
6. API Integration


MEDIUM PRIORITY
────────────────────────

7. AI/NLP
8. IOC Extraction
9. Threat Intelligence
10. Relay Graph


LOWER PRIORITY
────────────────────────

11. Geolocation Map
12. Case History
13. PDF Reports
14. Advanced Analytics
15. Production Hardening
```

---

# 20. Important Design Principles

## Principle 1 — Detection is not enough

TraceX should answer:

```text
Is it malicious?
Why is it malicious?
What evidence supports it?
What infrastructure is involved?
```

---

## Principle 2 — Explainability

Every risk score should have reasons.

---

## Principle 3 — Confidence-Based Intelligence

The system should distinguish between:

```text
Confirmed
Probable
Suspicious
Unknown
```

It should not make unsupported claims.

---

## Principle 4 — Modular Architecture

Each analysis component should be independently replaceable.

For example:

```text
Rule-based detector
       ↓
can later be replaced/combined with
       ↓
ML detector
```

---

## Principle 5 — MVP First

Do not build every feature simultaneously.

Priority:

```text
Working Core
      ↓
Better Analysis
      ↓
AI
      ↓
Intelligence
      ↓
Visualization
      ↓
Polish
```

---

# 21. Testing Strategy

Every major service should have unit tests.

Examples:

```text
test_eml_parser
test_url_extraction
test_sender_reply_mismatch
test_spf_analysis
test_dkim_analysis
test_dmarc_analysis
test_phishing_rules
test_bec_rules
test_risk_score
test_ioc_extraction
```

Test emails:

```text
legitimate.eml
phishing.eml
bec.eml
```

Expected result:

```text
Legitimate
→ LOW

Phishing
→ HIGH/CRITICAL

BEC
→ HIGH/CRITICAL
```

---

# 22. Git Branch Strategy

Recommended branches:

```text
main
│
├── develop
│
├── feature/email-parser
├── feature/header-forensics
├── feature/auth-analysis
├── feature/risk-engine
├── feature/ai-analysis
├── feature/threat-intelligence
├── feature/relay-tracer
└── feature/report-generator
```

Each feature should be developed and tested independently before merging.

---

# 23. Suggested Commit Pattern

```text
feat: add fastapi project setup
feat: add eml parser
feat: extract email headers
feat: extract urls from email
feat: add sender reply-to mismatch detection
feat: add risk scoring engine
feat: add spf dkim dmarc analysis
feat: add phishing detection
feat: add IOC extraction
feat: add relay path reconstruction
feat: add threat intelligence service
feat: add forensic report generation
```

---

# 24. Final Backend Architecture

```text
                         TRACE X
                            │
                            ▼
                     FastAPI Backend
                            │
       ┌────────────────────┼────────────────────┐
       │                    │                    │
       ▼                    ▼                    ▼
 Email Processing      Threat Detection     Intelligence
       │                    │                    │
       │               ┌────┼────┐         ┌─────┼─────┐
       │               ▼    ▼    ▼         ▼     ▼     ▼
       │             Phish BEC  Imp.      IP   Domain  URL
       │
       ▼
 Header Forensics
       │
       ├── SPF
       ├── DKIM
       ├── DMARC
       ├── Received
       └── Metadata
                            │
                            ▼
                     Forensic Engine
                            │
                ┌───────────┼───────────┐
                ▼           ▼           ▼
             IOC Graph   Relay Trace  Correlation
                │           │           │
                └───────────┼───────────┘
                            ▼
                       Risk Engine
                            │
                     ┌──────┴──────┐
                     ▼             ▼
                Risk Score     Explanation
                     │
                     ▼
                  MongoDB
                     │
              ┌──────┴──────┐
              ▼             ▼
          Dashboard       Report
```

---

# 25. Final Goal

TraceX backend should ultimately transform:

```text
ONE SUSPICIOUS EMAIL
```

into:

```text
EMAIL INFORMATION
        +
HEADER FORENSICS
        +
AUTHENTICATION RESULTS
        +
AI THREAT ANALYSIS
        +
IOCs
        +
IP/DOMAIN INTELLIGENCE
        +
RELAY TRACE
        +
RISK SCORE
        +
EXPLAINABLE EVIDENCE
        +
FORENSIC REPORT
```

### Core Product Statement

> **TraceX does not simply detect malicious emails. It converts a suspicious email into an explainable forensic intelligence case.**
