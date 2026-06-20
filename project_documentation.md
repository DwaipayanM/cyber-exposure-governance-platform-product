# Cyber Exposure Governance Platform (CEGP)
### Project Documentation

> A risk-based decision-support platform that turns raw vulnerability data into **business-aligned, audit-ready remediation decisions**.

**Authors:** Dwaipayan Mojumder · Deblina Das
**Programme:** M.Sc. Cyber Security (4th Semester)
**Guidance:** Prof. Sanjay Pal
**Version:** 1.0 · Prototype / decision-support tool

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem & Motivation](#2-problem--motivation)
3. [Solution Overview](#3-solution-overview)
4. [Core Capabilities](#4-core-capabilities)
5. [How It Works — The Processing Pipeline](#5-how-it-works--the-processing-pipeline)
6. [The Scoring Model](#6-the-scoring-model)
7. [The Dashboard & Views](#7-the-dashboard--views)
8. [Inputs & Data Model](#8-inputs--data-model)
9. [Security, Integrity & Governance](#9-security-integrity--governance)
10. [Bundled Datasets](#10-bundled-datasets)
11. [Technology Stack](#11-technology-stack)
12. [Running the Application](#12-running-the-application)
13. [Outcomes & Benefits](#13-outcomes--benefits)
14. [Scope & Limitations](#14-scope--limitations)
15. [Future Roadmap](#15-future-roadmap)
16. [Glossary](#16-glossary)

---

## 1. Executive Summary

Modern security teams are buried in vulnerability findings. A single mid-sized estate can surface thousands of CVEs, and traditional programmes triage them almost entirely on **technical severity** (CVSS). The result is a long, undifferentiated list where a low-impact internal finding can outrank a customer-facing system that is *actively being exploited right now*.

The **Cyber Exposure Governance Platform (CEGP)** reframes the problem from *"how severe is this vulnerability?"* to *"how much real exposure does this create for our business, and what should we do about it first?"*

It does this by **correlating five independent signals** — threat intelligence, business context, network exposure, live attack evidence, and data-privacy impact — into a single, **explainable 0–100 exposure score**. It then wraps that score in a governance layer: priority-based SLAs, remediation playbooks, risk-acceptance workflows, what-if simulation, and **tamper-evident, audit-ready reporting**.

In short: CEGP is the lightweight decision layer that sits **between a vulnerability scanner and a remediation team**.

---

## 2. Problem & Motivation

Standard vulnerability management, driven by CVSS alone, has four structural blind spots:

| Limitation | Why it matters |
|---|---|
| **No real-world threat context** | A "Critical" CVSS finding may never be exploited, while a "Medium" one is being weaponised in the wild today. Severity ≠ likelihood. |
| **No business context** | An internal test server and a customer-facing production database are treated identically. Risk is about *what is exposed*, not just *what is broken*. |
| **No live detection signal** | Scanners don't know which assets are currently under attack, so systems being actively targeted aren't escalated. |
| **No governance or verification** | Tracking remediation timelines and proving report integrity for audits (SOC 2, ISO 27001) is manual and error-prone. |

CEGP was built specifically to close these four gaps in a single, coherent workflow.

---

## 3. Solution Overview

CEGP is a **decision-support product prototype**, not a scanner. It consumes scanner-style data and enriches it until it can answer the three questions a security leader actually cares about:

- **What is genuinely exposed?** — Severity fused with exploitation likelihood, business value, network reachability, live attack evidence, and privacy impact.
- **What do we fix first?** — A ranked, explainable priority with an assigned owner and a due date.
- **Can we prove what we did?** — Signed, tamper-evident reports and an attributed audit trail.

The platform is delivered as a clean, browser-based dashboard. A security analyst uploads (or uses bundled) data, runs an assessment, and immediately sees an executive risk picture, a prioritised work queue, governance status, simulation tools, and exportable evidence.

---

## 4. Core Capabilities

The platform supports an end-to-end risk-management lifecycle:

| # | Capability | Description |
|---|---|---|
| 1 | **Multi-source ingestion** | Reads CSV and Excel (`.xlsx`, `.xls`); normalises scanner-style exports into one unified schema. |
| 2 | **Threat-intelligence enrichment** | Correlates each CVE with CISA KEV (known exploited), EPSS (exploitation probability), and CVSS (technical severity). |
| 3 | **Business-context correlation** | Joins findings to asset criticality, business process, owner, environment, and data sensitivity. |
| 4 | **Network-exposure mapping** | Factors in network zone (Internet / DMZ / VPN / Internal), open ports, firewall posture, and VPN requirement. |
| 5 | **Live alert correlation** | Matches IDS/IPS events to vulnerable hosts to flag assets under **active** target attempts. |
| 6 | **Privacy-risk quantification** | Scores PII presence, data sensitivity, encryption status, and regulatory impact. |
| 7 | **Configurable risk policy** | Scoring weights, priority thresholds, and SLAs are externalised so leaders can tune them to risk appetite. |
| 8 | **Playbooks & SLA governance** | Assigns due dates by priority, raises escalations on breach, and generates remediation guidance. |
| 9 | **What-if simulation** | Models patch/control strategies and shows the predicted reduction in overall risk *before* spending effort. |
| 10 | **Tamper-evident reporting** | Signs exported reports cryptographically so they cannot be silently altered after export. |
| 11 | **Attributed audit logging** | Records who performed each action and when, for compliance review. |
| 12 | **Control-area mapping** | Maps each exposure to cybersecurity control domains for a governance view. |

---

## 5. How It Works — The Processing Pipeline

Each assessment flows through seven phases, every one adding a layer of intelligence.

**Phase 1 — Ingestion & sanitisation.**
Reads CSV/Excel, normalises column names, checks required fields, maps optional fields, and validates formatting. Non-blocking data-quality issues (an invalid CVE format, an unexpected value, a duplicate row) are captured and surfaced separately for review rather than halting the run.

**Phase 2 — Threat-intelligence contextualisation.**
Each CVE is enriched with: whether it is actively exploited (CISA KEV), its 30-day exploitation probability (EPSS), and its technical severity (CVSS).

**Phase 3 — Asset & network context merging.**
Findings are joined to the asset inventory to derive **business impact** (criticality, environment, process relevance) and **network exposure** (zone, open ports, firewall, VPN requirement).

**Phase 4 — Active-threat & privacy mapping.**
IDS/IPS events are correlated to each vulnerable asset (assets under active attempts are flagged for expedited action), and privacy impact is evaluated from PII, sensitivity, encryption, and regulatory factors.

**Phase 5 — Score calculation & SLA assignment.**
A consolidated **0–100 exposure score** is computed and classified into Low / Medium / High / Critical. A remediation due date is derived from priority and the detection date.

**Phase 6 — Playbook generation.**
Each exposure receives a primary remediation action, compensating controls, a change category, and validation steps — calibrated to its threat, exposure, and privacy profile.

**Phase 7 — Export & integrity verification.**
Exports are sanitised against spreadsheet-injection risk and signed with a cryptographic signature. A built-in verifier can confirm whether any report has been altered.

---

## 6. The Scoring Model

The headline number is a **single, explainable 0–100 score** — every point can be traced back to a contributing factor, so the result is defensible rather than a black box. Contributions are weighted as follows (weights are configurable via policy):

| Dimension | Weight | What it captures |
|---|---:|---|
| **Threat intelligence** | 35 | CISA KEV membership, EPSS percentile, CVSS severity |
| **Network exposure** | 20 | Zone, risky open ports, firewall posture, VPN requirement |
| **Business impact** | 15 | Asset criticality, production environment, data sensitivity |
| **IDS/IPS correlation** | 15 | Alert volume/severity, exploit attempts, high-confidence signals |
| **Privacy impact** | 10 | PII, data sensitivity, encryption status, regulatory impact |
| **SLA governance** | 5 | Contribution from breached remediation timelines |

The total score maps to a **priority** and a **remediation SLA**:

| Priority | Score threshold | Remediation SLA (from detection) |
|---|---:|---:|
| **Critical** | ≥ 85 | 7 days |
| **High** | ≥ 70 | 15 days |
| **Medium** | ≥ 45 | 30 days |
| **Low** | below 45 | 90 days |

This design deliberately ensures that a *moderately severe but actively exploited, internet-facing, customer-data* asset can outrank a *severe but internal, unexploited* one — which is exactly the prioritisation CVSS-only programmes miss.

---

## 7. The Dashboard & Views

The interface is organised as a header (project identity), a row of headline KPI cards (total / critical / KEV / SLA-breached and more), and nine focused tabs.

| View | Purpose |
|---|---|
| **Executive View** | Leadership picture, anchored by an **Executive Risk Matrix** — a severity × exploitation-likelihood grid where the top-right band is the "fix-first" zone. Supported by priority mix, KEV vs non-KEV split, EPSS distribution, risk by environment, top business processes, and top riskiest assets. |
| **Analyst View** | The prioritised work queue: every exposure with its score drivers, recommended action, and context, colour-coded by priority. |
| **Network Exposure** | Risk by network zone and asset type, plus exposure detail per asset. |
| **IDS/IPS Correlation** | Correlated alert severity and the assets showing active exploit signals. |
| **Privacy Impact** | Distribution of privacy impact and the sensitive-data detail behind it. |
| **Remediation Governance** | SLA status, owner-wise risk, control-area coverage, due dates, escalations, and exception state. |
| **Simulation** | What-if scenarios (e.g. patch top assets, patch all KEV, isolate internet-facing critical assets) with the predicted risk reduction. |
| **Reports & Integrity** | Export of detailed / executive / ticket reports, each signed and verifiable. |
| **Audit Log** | Attributed action history, risk-trend snapshots, and any data-quality notices from the last run. |

Supporting material (a concept guide and project information) is tucked into the sidebar so the working surface stays clean — visible only when needed.

---

## 8. Inputs & Data Model

The platform's value comes from **correlation**, so it ingests four independent sources — mirroring how organisations actually store this data (CMDB, scanner, SIEM, GRC tool). Each can be supplied as CSV or Excel and swapped independently.

| File | Represents | Key fields |
|---|---|---|
| **Vulnerability findings** | The "what's wrong" | asset id, asset name, product, CVE, business criticality, internet-facing, environment, owner, first-detected date |
| **Asset inventory** | The "how much it matters" | application, business process, owner, network zone, open ports, firewall, VPN required, asset type, data type, PII, sensitivity, encryption, regulatory impact |
| **IDS/IPS alerts** | The "is it being attacked" | alert id, asset id, alert type, severity, source/destination IP, timestamp, signature, confidence |
| **Risk exceptions** | The "already signed off" | asset id, CVE, exception status, acceptance reason, accepted-by, expiry, compensating control |

**Why four files?** A scanner alone gives only the first. The whole point of the product is that the first file is nearly useless for *prioritisation* without the other three.

**Supported formats:** CSV, modern Excel (`.xlsx`), and legacy Excel (`.xls`). When live feeds are turned off, bundled offline threat-intelligence is used, so assessments are fully **deterministic** — ideal for demonstrations.

---

## 9. Security, Integrity & Governance

Because this is a *security* tool, it holds itself to a higher standard than a typical dashboard:

- **Tamper-evident reports (HMAC-SHA256).** Exports are signed with a secret key, so an altered report cannot be re-signed by anyone who lacks the key. This is stronger than a plain checksum, which anyone can recompute. The key is supplied via environment variable in production, or generated and stored locally otherwise.
- **Injection-safe exports.** Exported spreadsheets are sanitised so that a malicious cell cannot execute as a formula when opened in Excel, Sheets, or LibreOffice — a real risk for any tool that exports externally supplied data.
- **Attributed audit log.** Every action records the **operator** and a timestamp, so the trail can answer *who* did *what*, not merely that something happened.
- **Integrity verifier.** A built-in tool lets a reviewer upload any exported report and confirm whether its contents match the original signature.
- **Configurable governance.** SLAs, escalation, and risk-acceptance (with expiry and compensating controls) are first-class, so remediation timelines are tracked and auditable.

---

## 10. Bundled Datasets

To make the platform demonstrable out of the box, it ships with realistic, fully offline data:

- **Primary dataset** — a diversified set of roughly 300 exposures across several hundred assets, deliberately engineered to exercise **every** scoring path: all priority bands, all KEV/EPSS/CVSS combinations, all network zones, IDS exploit and multi-alert cases, every privacy level, SLA breached/due-soon/within states, and valid/expired/no-expiry exceptions. A few rows intentionally trigger non-blocking data-quality notices to demonstrate validation.
- **Small demo set** — a compact set retained for quick walkthroughs, including an Excel copy to demonstrate file upload.
- **Offline threat-intelligence** — bundled KEV/EPSS/CVSS reference data covering every CVE in the samples, so results are identical run-to-run without internet access.

---

## 11. Technology Stack

| Layer | Technology | Role |
|---|---|---|
| **User interface** | Streamlit | Browser-based dashboard and interaction |
| **Processing engine** | pandas | Data validation, enrichment, scoring |
| **Visualisation** | Plotly | Interactive charts and the risk matrix |
| **Threat-intel access** | requests | Optional live KEV / EPSS / NVD lookups |
| **Spreadsheet support** | openpyxl, xlrd | Reading modern and legacy Excel files |
| **Integrity** | HMAC-SHA256 (standard library) | Tamper-evident report signing |

The codebase is organised modularly — a set of focused processing engines and external-data services — which keeps each scoring dimension independent and easy to reason about.

---

## 12. Running the Application

The application runs locally on Streamlit. From the project directory, create a virtual environment, install dependencies, and launch:

```powershell
py -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

The interface opens automatically in the default browser at **http://localhost:8501**.

**Recommended for a stable demo:** keep *Use bundled sample files* enabled, keep live feeds off (offline data is included), enter an operator name, and click **Run Cyber Exposure Assessment**.

---

## 13. Outcomes & Benefits

| Benefit | What it delivers |
|---|---|
| **Efficient prioritisation** | Collapses hundreds of findings into a focused list of exposures that combine severity **and** real exploitation paths. |
| **Scenario planning** | Lets risk managers simulate strategies (patch the riskiest, isolate internet-facing critical assets) and see the predicted percentage risk reduction before committing effort. |
| **Audit readiness** | Signed reports plus an attributed audit log — presentable directly to auditors. |
| **Actionable remediation** | Teams receive clear playbooks and SLA countdowns instead of generic technical notes, accelerating the patch cycle. |
| **Explainability** | Every priority is traceable to its contributing factors, so decisions can be defended and challenged. |

---

## 14. Scope & Limitations

The boundaries of v1 are deliberate and stated openly — knowing exactly where a tool is weak is part of good engineering.

- **Single-operator, file-based.** State is held in files (last-write-wins); it is designed for one analyst or a small team, not concurrent multi-user production use.
- **No access control.** There is no authentication, role-based access, or single sign-on in this version.
- **No database backend.** Persistence is via files rather than a managed datastore.
- **Manual / file-based integration.** Data arrives as CSV/Excel and tickets are exported as files, rather than pulled/pushed through scanner or ITSM APIs.
- **Explainable, not certified.** The scoring model is transparent and configurable, but it is a decision-support heuristic, not a certified quantitative risk model.

These are appropriate boundaries for a focused prototype, and each maps cleanly to the roadmap below.

---

## 15. Future Roadmap

| Theme | Planned enhancement |
|---|---|
| **Identity** | Single sign-on (SSO) and role-based access control (analyst / approver / admin). |
| **Persistence** | Database backend for history, concurrency, and scale. |
| **Integration** | Live connectors to scanners (Tenable, Qualys, Rapid7) and ITSM tools (ServiceNow, Jira) via API. |
| **Standards alignment** | Mapping to NIST CSF, CIS Controls, ISO 27001, and MITRE ATT&CK; optional SSVC decision output. |
| **Deployment** | Containerised deployment, REST API, and automated testing/CI. |

---

## 16. Glossary

| Term | Meaning |
|---|---|
| **CVSS** | Common Vulnerability Scoring System — a standard 0–10 score for a vulnerability's technical severity. |
| **EPSS** | Exploit Prediction Scoring System — a probability that a CVE will be exploited in the wild within 30 days. |
| **CISA KEV** | The U.S. CISA catalogue of vulnerabilities with confirmed real-world exploitation. |
| **CVE** | Common Vulnerabilities and Exposures — a unique identifier for a publicly known vulnerability. |
| **IDS / IPS** | Intrusion Detection / Prevention System — sensors that detect or block malicious network activity. |
| **PII** | Personally Identifiable Information. |
| **SLA** | Service-Level Agreement — here, the time allowed to remediate based on priority. |
| **HMAC** | Hash-based Message Authentication Code — a keyed signature that makes a report tamper-evident. |
| **Exposure score** | The platform's consolidated 0–100 measure of overall cyber exposure for a finding. |

---

*Cyber Exposure Governance Platform — an M.Sc. Cyber Security project by Dwaipayan Mojumder and Deblina Das, under the guidance of Prof. Sanjay Pal.*
