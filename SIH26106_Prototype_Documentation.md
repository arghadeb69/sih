# SIH26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

## Prototype Documentation

### 1. Problem Statement

Modern phishing, spoofing, business email compromise, malicious attachments, and impersonation attacks are becoming increasingly sophisticated. Traditional email security systems often depend on static rules and signatures, making them less effective against new or evolving threats.

**SIH26106** proposes an AI-powered platform that analyzes suspicious emails, extracts technical intelligence, estimates the geographical origin of infrastructure involved in the attack, and generates a forensic report for investigators.

The prototype focuses on:

- AI-based email threat classification
- Phishing and malicious-link detection
- Email-header analysis
- Sender/domain/IP intelligence
- GeoLocation visualization
- URL and attachment risk analysis
- Digital forensic evidence collection
- Explainable threat scoring
- Automated incident reports

---

## 2. Prototype Objective

Build a working prototype where a user can upload an email (`.eml`) or paste an email's content and receive:

1. **Threat classification**
   - Safe
   - Suspicious
   - Phishing
   - Malicious

2. **Risk score**
   - 0–100 threat score
   - Low / Medium / High / Critical severity

3. **Email forensic analysis**
   - Sender and recipient information
   - Received mail-server chain
   - SPF/DKIM/DMARC results when available
   - Suspicious headers
   - Message IDs
   - Reply-To mismatch
   - Domain age/reputation indicators

4. **URL intelligence**
   - Extract URLs
   - Detect suspicious domains
   - Identify redirects
   - Check URL characteristics

5. **Infrastructure intelligence**
   - Extract public IP addresses
   - ASN/ISP information
   - Approximate GeoLocation
   - Country and city where available
   - Infrastructure relationship visualization

6. **AI explanation**
   - Why the email was flagged
   - Important indicators
   - Recommended action

7. **Forensic report**
   - Timeline
   - Indicators of Compromise (IOCs)
   - Risk assessment
   - Evidence summary
   - Exportable report

---

## 3. Proposed Solution

The system follows a pipeline architecture:

```text
                  ┌─────────────────────┐
                  │   Email Input       │
                  │ .EML / Raw Email    │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Email Parser        │
                  │ Headers + Body      │
                  │ URLs + Attachments  │
                  └──────────┬──────────┘
                             │
             ┌───────────────┼────────────────┐
             ▼               ▼                ▼
      ┌────────────┐  ┌─────────────┐  ┌──────────────┐
      │ AI Threat  │  │ Header &    │  │ URL / File   │
      │ Detection  │  │ Auth Check  │  │ Analysis     │
      └─────┬──────┘  └──────┬──────┘  └──────┬───────┘
            │                │                  │
            └────────────────┼──────────────────┘
                             ▼
                  ┌─────────────────────┐
                  │ Intelligence Layer  │
                  │ IP / Domain / ASN    │
                  │ GeoLocation / WHOIS  │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Risk Engine         │
                  │ Score + Severity    │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Investigation UI    │
                  │ Dashboard + Map     │
                  │ Timeline + IOCs     │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Forensic Report     │
                  └─────────────────────┘
```

---

# 4. Core Prototype Modules

## Module 1 — Email Ingestion

### Input Methods

The prototype should support:

- Upload `.eml` files
- Paste raw email headers
- Paste email body
- Optional `.msg` support in the future

### Extracted Data

```text
From
To
CC
BCC
Subject
Date
Reply-To
Message-ID
Return-Path
Received headers
Authentication-Results
URLs
Attachments
IP addresses
Domains
```

### Technology

Python's built-in email parser can be used for `.eml` processing.

Example:

```python
from email import policy
from email.parser import BytesParser

with open("sample.eml", "rb") as f:
    msg = BytesParser(policy=policy.default).parse(f)

print(msg["From"])
print(msg["To"])
print(msg["Subject"])
print(msg["Date"])
```

---

# 5. AI-Powered Threat Detection

The AI engine should analyze multiple signals instead of relying only on keywords.

## Features

### Email Text Features

- Urgency
- Threatening language
- Financial requests
- Credential requests
- Password reset requests
- Suspicious call-to-action
- Impersonation
- Social engineering patterns

### Sender Features

- Display-name spoofing
- Sender/reply-to mismatch
- Domain mismatch
- Look-alike domains
- Newly observed domains
- Suspicious TLDs

### Technical Features

- SPF failure
- DKIM failure
- DMARC failure
- Suspicious Received chain
- IP reputation
- URL reputation
- Attachment type

---

## 6. Threat Scoring Engine

A hybrid approach is recommended:

```text
AI Model Score
       +
Rule-Based Indicators
       +
Email Authentication
       +
URL Intelligence
       +
Infrastructure Intelligence
       =
Final Threat Score
```

Example scoring:

| Indicator | Score |
|---|---:|
| SPF failure | +10 |
| DKIM failure | +10 |
| DMARC failure | +15 |
| Reply-To mismatch | +15 |
| Suspicious URL | +20 |
| Look-alike domain | +20 |
| Malicious attachment indicator | +25 |
| Suspicious IP reputation | +15 |
| Strong phishing language | +10 |

Cap the final score at **100**.

### Severity

```text
0–24    → Safe
25–49   → Low
50–69   → Medium
70–84   → High
85–100  → Critical
```

The weights should be configurable rather than hard-coded permanently.

---

# 7. Explainable AI

The system should not simply display:

> "This email is malicious."

It should explain the decision.

Example:

```text
THREAT: PHISHING
RISK SCORE: 87/100
SEVERITY: CRITICAL

Why?

✓ Reply-To address does not match sender domain
✓ DMARC authentication failed
✓ URL uses a look-alike domain
✓ Email creates an urgent password-reset request
✓ Sending IP has suspicious infrastructure indicators
```

This makes the prototype more useful for SOC analysts and investigators.

---

# 8. GeoLocation Intelligence

The system extracts public IP addresses from:

- Received headers
- Originating-IP headers
- Authentication results
- URLs/domains where appropriate

Each public IP can be enriched with:

```text
IP Address
Country
Region
City
Latitude
Longitude
ISP
ASN
Organization
Timezone
```

### Important

IP GeoLocation should be displayed as **approximate infrastructure location**, not the physical location of the attacker.

Private/local IP addresses should not be treated as meaningful Internet-origin locations.

---

# 9. GeoLocation Dashboard

Example:

```text
                 ATTACK INFRASTRUCTURE

                         ● Germany
                        /
                       /
          ● Singapore
                                                                  ● India
                                                 ● United States
```

The actual prototype can use a map component such as:

- Leaflet
- MapLibre
- Mapbox
- Plotly maps

Recommended prototype choice:

**Leaflet + OpenStreetMap-compatible tiles**

---

# 10. Email Route Visualization

Received headers can be converted into a route:

```text
Sender
  │
  ▼
Mail Server 1
  │
  ▼
Mail Server 2
  │
  ▼
Mail Server 3
  │
  ▼
Recipient Mail Server
```

For each hop:

```text
IP
Hostname
Timestamp
ASN
Country
City
```

This allows investigators to inspect suspicious routing patterns.

---

# 11. URL Intelligence

Extract all URLs from the email.

For every URL:

```text
URL
Domain
Protocol
Port
Redirect chain
Domain age
SSL/TLS information
Suspicious patterns
Risk score
```

### Suspicious URL Indicators

Examples:

```text
http://
IP-address based URL
Very long URL
Excessive subdomains
URL shorteners
Look-alike domains
Unicode/punycode domains
Suspicious TLD
Encoded parameters
Credential-related paths
```

The prototype should flag these as indicators rather than automatically declaring every such URL malicious.

---

# 12. Attachment Analysis

The prototype can identify:

```text
Filename
Extension
MIME type
File size
SHA-256 hash
```

Potentially suspicious extensions:

```text
.exe
.scr
.bat
.cmd
.ps1
.js
.vbs
.iso
.img
.lnk
```

The prototype should initially perform **static metadata/hash analysis**.

Do not execute uploaded files.

---

# 13. IOC Extraction

The system automatically generates Indicators of Compromise.

Example:

```text
IOCs

IP:
185.xxx.xxx.xxx

Domain:
secure-login-example.com

URL:
https://secure-login-example.com/login

Email:
attacker@example.com

SHA-256:
a1b2c3d4...
```

Allow analysts to copy or export the IOC list.

---

# 14. Forensic Timeline

Create an automatically generated timeline:

```text
10:31:04
Email sent

        ↓

10:31:08
Received by external mail server

        ↓

10:31:10
Forwarded to recipient server

        ↓

10:31:12
Delivered to user

        ↓

Analysis
Suspicious URL detected

        ↓

Risk
87/100 — CRITICAL
```

This provides an investigator-friendly view.

---

# 15. Prototype Dashboard

## Dashboard Layout

```text
┌──────────────────────────────────────────────────────────────┐
│ AI EMAIL THREAT INTELLIGENCE PLATFORM                       │
├──────────────────────────────────────────────────────────────┤
│ Upload Email     [ Choose .eml ]     [ Analyze ]             │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  THREAT LEVEL       SCORE        CLASSIFICATION              │
│  CRITICAL           87/100       PHISHING                    │
│                                                              │
├───────────────────────┬──────────────────────────────────────┤
│ Sender Intelligence   │ Email Authentication                │
│                       │                                      │
│ Sender: xxx           │ SPF       FAILED                    │
│ Reply-To: xxx         │ DKIM      FAILED                    │
│ Domain: xxx           │ DMARC     FAILED                    │
├───────────────────────┼──────────────────────────────────────┤
│ GeoLocation Map       │ Threat Indicators                   │
│                       │                                      │
│       MAP             │ • Look-alike domain                 │
│                       │ • URL detected                       │
│                       │ • Reply-To mismatch                  │
├───────────────────────┴──────────────────────────────────────┤
│ Extracted IOCs                                               │
├──────────────────────────────────────────────────────────────┤
│ IPs | Domains | URLs | Hashes                                │
├──────────────────────────────────────────────────────────────┤
│ AI Explanation                                               │
├──────────────────────────────────────────────────────────────┤
│ Forensic Timeline                                            │
├──────────────────────────────────────────────────────────────┤
│ [Export Report] [Export IOCs] [Start New Investigation]      │
└──────────────────────────────────────────────────────────────┘
```

---

# 16. Recommended Technology Stack

## Frontend

**React + Vite**

Libraries:

```text
React
Tailwind CSS
Recharts
Leaflet / React-Leaflet
Lucide Icons
```

Alternative:

**Next.js**

---

## Backend

**Python + FastAPI**

Libraries:

```text
FastAPI
Pydantic
python-multipart
email
BeautifulSoup
tldextract
requests/httpx
scikit-learn
pandas
```

---

## AI/ML

For the prototype:

### Option A — Lightweight ML

```text
TF-IDF
+
Logistic Regression
```

Advantages:

- Fast
- Easy to train
- Explainable
- Works on limited hardware

### Option B — Transformer

Use a pretrained text classification model for phishing/spam classification.

Possible architecture:

```text
Email Body
    ↓
Tokenizer
    ↓
Transformer
    ↓
Classification Head
    ↓
Threat Probability
```

### Recommended SIH Prototype

Use a **hybrid AI + rules engine**.

```text
                 Email
                   ↓
             Feature Engine
              ↙    ↓    ↘
            NLP  Header  URLs
              ↘    ↓    ↙
               AI Model
                   ↓
              Risk Engine
                   ↓
            Final Decision
```

---

# 17. Database

Recommended:

**MongoDB**

Why:

- Email analysis results are JSON-like
- Flexible IOC structure
- Easy document storage
- Suitable for investigation records

Example:

```json
{
  "investigation_id": "INV-2026-0001",
  "classification": "phishing",
  "risk_score": 87,
  "severity": "critical",
  "sender": "attacker@example.com",
  "reply_to": "support@example.net",
  "ips": [
    "185.xxx.xxx.xxx"
  ],
  "domains": [
    "example-login.com"
  ],
  "urls": [
    "https://example-login.com/login"
  ],
  "indicators": [
    "DMARC failure",
    "Reply-To mismatch",
    "Look-alike domain"
  ]
}
```

---

# 18. Suggested Backend API

## Analyze Email

```http
POST /api/analyze/email
```

Input:

```text
multipart/form-data
email_file = suspicious.eml
```

Response:

```json
{
  "classification": "phishing",
  "risk_score": 87,
  "severity": "critical",
  "confidence": 0.94,
  "authentication": {
    "spf": "fail",
    "dkim": "fail",
    "dmarc": "fail"
  },
  "iocs": {
    "ips": [],
    "domains": [],
    "urls": [],
    "hashes": []
  }
}
```

---

## Get Investigation

```http
GET /api/investigations/{id}
```

---

## Export Report

```http
GET /api/investigations/{id}/report
```

---

## IOC Search

```http
GET /api/ioc/search?value=example.com
```

---

# 19. Project Folder Structure

```text
sih26106/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── ThreatScore.jsx
│   │   │   ├── GeoMap.jsx
│   │   │   ├── IOCPanel.jsx
│   │   │   ├── Timeline.jsx
│   │   │   └── AIExplanation.jsx
│   │   │
│   │   ├── pages/
│   │   │   ├── Home.jsx
│   │   │   ├── Investigation.jsx
│   │   │   └── History.jsx
│   │   │
│   │   └── App.jsx
│   │
│   └── package.json
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   │
│   │   ├── api/
│   │   │   ├── email.py
│   │   │   ├── investigation.py
│   │   │   └── ioc.py
│   │   │
│   │   ├── services/
│   │   │   ├── email_parser.py
│   │   │   ├── header_analyzer.py
│   │   │   ├── threat_detector.py
│   │   │   ├── url_analyzer.py
│   │   │   ├── ip_intelligence.py
│   │   │   └── report_generator.py
│   │   │
│   │   ├── models/
│   │   │   └── investigation.py
│   │   │
│   │   └── utils/
│   │
│   └── requirements.txt
│
├── ml/
│   ├── train.py
│   ├── predict.py
│   ├── preprocessing.py
│   └── model/
│
├── samples/
│   ├── phishing.eml
│   └── legitimate.eml
│
├── docs/
│   └── architecture.md
│
└── README.md
```

---

# 20. Prototype Workflow

## Step 1 — Upload

User uploads:

```text
invoice.eml
```

## Step 2 — Parse

System extracts:

```text
Headers
Body
URLs
Attachments
IP addresses
Domains
```

## Step 3 — Analyze

The platform checks:

```text
Sender
Authentication
Language
URLs
Attachments
IP infrastructure
```

## Step 4 — AI Classification

Model predicts:

```text
Phishing probability = 94%
```

## Step 5 — Risk Engine

Example:

```text
AI score                 74
DMARC failure            +15
Reply-To mismatch        +10
Suspicious URL           +15
--------------------------------
Final score              100
```

## Step 6 — Intelligence

Extracted IP:

```text
185.xxx.xxx.xxx
```

Enriched with:

```text
Country: Unknown/Approximate
ASN: Example ASN
ISP: Example ISP
```

## Step 7 — Visualization

Dashboard displays:

```text
Threat Score
Email Route
GeoLocation
URLs
IOCs
Timeline
AI Explanation
```

## Step 8 — Report

Generate:

```text
PDF / JSON / CSV
```

---

# 21. Sample Investigation

### Input

```text
From:
Microsoft Support <support@micros0ft-security.example>

Reply-To:
security-alert@example-mail.com

Subject:
URGENT: Your account will be suspended

Body:
Your account requires immediate verification.
Click the link below to prevent suspension.
```

### Detection

```text
Display-name impersonation     ✓
Reply-To mismatch              ✓
Urgent language                ✓
Credential request             ✓
Look-alike domain              ✓
Suspicious URL                 ✓
```

### Result

```text
Classification: PHISHING
Risk Score: 92/100
Severity: CRITICAL
Confidence: 96%
```

### Explanation

```text
The message shows multiple characteristics
associated with credential-phishing attacks.

The sender uses an impersonation-style display name,
the Reply-To domain differs from the sender domain,
and the message creates urgency around account suspension.
```

---

# 22. Differentiating Features

To make the SIH prototype stronger than a normal phishing detector, include these features:

### 1. Attack Infrastructure Graph

```text
Email
 │
 ├── Sender
 │
 ├── Domain
 │
 ├── IP
 │
 ├── ASN
 │
 ├── URL
 │
 └── Attachment Hash
```

Display these as an interactive graph.

---

### 2. Geographic Attack Map

Show infrastructure locations on a world map.

```text
Email → IP → ASN → Country
```

---

### 3. AI Investigation Assistant

Allow the analyst to ask:

```text
"Why is this email suspicious?"

"What indicators should I investigate?"

"Which IPs are associated with this email?"

"Summarize this incident."
```

The assistant should answer using the extracted evidence rather than inventing facts.

---

### 4. Forensic Evidence Chain

Every extracted indicator should retain:

```text
Source
Timestamp
Extraction method
Confidence
Original evidence
```

This improves forensic usefulness.

---

# 23. MVP Scope for SIH

Do not try to build every feature initially.

### Must Have

```text
✓ .eml upload
✓ Email parser
✓ Header analysis
✓ SPF/DKIM/DMARC detection
✓ URL extraction
✓ IP extraction
✓ AI phishing classification
✓ Risk score
✓ GeoLocation map
✓ IOC extraction
✓ Investigation dashboard
✓ PDF/JSON report
```

### Good to Have

```text
○ Attachment hash analysis
○ Domain intelligence
○ Attack graph
○ Timeline
○ Analyst notes
○ Investigation history
```

### Advanced

```text
○ Threat intelligence feeds
○ Graph database
○ Real-time email monitoring
○ LLM investigation assistant
○ Campaign clustering
○ Similar-email detection
○ Organization-wide threat correlation
```

---

# 24. Demo Flow for SIH Judges

A strong 3–5 minute demonstration:

### Scene 1 — Upload

Upload a prepared phishing `.eml`.

### Scene 2 — AI Detection

Show:

```text
PHISHING
92/100
CRITICAL
```

### Scene 3 — Explainability

Show the top reasons:

```text
DMARC Failure
Reply-To Mismatch
Look-Alike Domain
Suspicious URL
Urgent Social Engineering
```

### Scene 4 — GeoLocation

Show the extracted public IP and approximate infrastructure location.

### Scene 5 — Attack Graph

Show:

```text
Email
 ↓
Domain
 ↓
IP
 ↓
ASN
 ↓
Location
```

### Scene 6 — Forensic Report

Generate the incident report containing:

```text
Executive Summary
Evidence
IOCs
Threat Score
Timeline
Infrastructure
AI Explanation
Recommended Actions
```

This gives the judges a complete end-to-end story rather than only showing a phishing classifier.

---

# 25. Future Scope

The platform can eventually become an enterprise SOC investigation system.

Possible integrations:

```text
SIEM
SOAR
Microsoft 365
Google Workspace
Threat Intelligence Platforms
EDR
Firewall Logs
DNS Logs
Proxy Logs
```

Advanced capabilities:

- Real-time email monitoring
- Threat campaign detection
- Cross-email IOC correlation
- Automated incident response
- Threat actor infrastructure clustering
- Organization-wide phishing analytics
- Continuous threat intelligence enrichment

---

# 26. Expected Prototype Output

For every analyzed email, the system should produce:

```text
┌──────────────────────────────────────────┐
│          INVESTIGATION RESULT            │
├──────────────────────────────────────────┤
│ Classification : PHISHING                │
│ Risk Score     : 92/100                  │
│ Severity       : CRITICAL                │
│ Confidence     : 96%                     │
├──────────────────────────────────────────┤
│ Authentication                           │
│ SPF  : FAIL                              │
│ DKIM : FAIL                              │
│ DMARC: FAIL                              │
├──────────────────────────────────────────┤
│ Threat Indicators                        │
│ • Reply-To mismatch                      │
│ • Look-alike domain                      │
│ • Suspicious URL                         │
│ • Urgency-based social engineering       │
├──────────────────────────────────────────┤
│ Infrastructure                           │
│ IP / ASN / ISP / GeoLocation             │
├──────────────────────────────────────────┤
│ IOCs                                     │
│ IPs / Domains / URLs / Hashes            │
├──────────────────────────────────────────┤
│ AI Explanation                           │
│ Evidence-backed threat explanation       │
├──────────────────────────────────────────┤
│ [Export PDF] [Export JSON]               │
└──────────────────────────────────────────┘
```

---

# 27. Success Criteria

The prototype will be considered successful if it can:

- Parse a real `.eml` file
- Detect suspicious email characteristics
- Produce a meaningful threat score
- Explain why the email was flagged
- Extract URLs, domains and public IPs
- Display approximate infrastructure GeoLocation
- Generate IOCs
- Visualize email routing
- Produce a forensic report
- Complete analysis within a reasonable time
- Avoid executing potentially malicious attachments

---

# 28. One-Line Pitch

> **An AI-powered digital forensics platform that transforms suspicious emails into actionable threat intelligence by combining phishing detection, email-header forensics, infrastructure GeoLocation, IOC extraction, and explainable AI.**

---

# 29. Recommended Prototype Build Order

```text
PHASE 1
Email Upload
      ↓
Email Parser
      ↓
Header Extraction

PHASE 2
URL Extraction
      ↓
IP Extraction
      ↓
SPF/DKIM/DMARC Analysis

PHASE 3
AI Phishing Classifier
      ↓
Risk Scoring Engine

PHASE 4
IP/Domain Intelligence
      ↓
GeoLocation
      ↓
Map Visualization

PHASE 5
IOC Dashboard
      ↓
Timeline
      ↓
Attack Graph

PHASE 6
Forensic Report
      ↓
PDF + JSON Export

PHASE 7
Polish UI
      ↓
Demo Dataset
      ↓
SIH Presentation
```

---

## Conclusion

SIH26106 can be demonstrated as an **end-to-end cyber-forensics investigation platform**, not merely an email spam detector.

The key differentiator is the combination of:

**AI Detection + Email Forensics + Threat Intelligence + GeoLocation + IOC Extraction + Explainable Analysis + Investigation Reporting**

This architecture keeps the initial prototype achievable while leaving a clear path toward a production-grade SOC and digital-forensics platform.
