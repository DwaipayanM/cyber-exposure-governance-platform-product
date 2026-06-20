# Cyber Exposure Governance Platform (CEGP)
### Project Documentation

> A risk-based decision-support platform that turns raw vulnerability data into **business-aligned, audit-ready remediation decisions** — and is built to grow from static file uploads into a **live, integrated, multi-user security service**.

**Authors:** Dwaipayan Mojumder · Deblina Das
**Programme:** M.Sc. Cyber Security (4th Semester)
**Guidance:** Prof. Sanjay Pal
**Version:** 1.0 · Prototype / decision-support tool

---

## Table of Contents

**Part A — The Platform Today**
1. [Executive Summary](#1-executive-summary)
2. [Problem & Motivation](#2-problem--motivation)
3. [Solution Overview](#3-solution-overview)
4. [System Architecture](#4-system-architecture)
5. [Cybersecurity Strategies & Techniques Used](#5-cybersecurity-strategies--techniques-used)
6. [Why This Approach Is Good](#6-why-this-approach-is-good)
7. [Core Capabilities](#7-core-capabilities)
8. [How It Works — The Processing Pipeline](#8-how-it-works--the-processing-pipeline)
9. [The Scoring Model](#9-the-scoring-model)
10. [The Dashboard & Views](#10-the-dashboard--views)
11. [Inputs & Data Model](#11-inputs--data-model)
12. [Security, Integrity & Governance](#12-security-integrity--governance)
13. [Bundled Datasets](#13-bundled-datasets)
14. [Technology Stack](#14-technology-stack)
15. [Running the Application Locally](#15-running-the-application-locally)

**Part B — Scaling Up: Integrations, Automation & Deployment**
16. [From Static Files to Live Data — Future Integrations](#16-from-static-files-to-live-data--future-integrations)
17. [Integration Mechanisms](#17-integration-mechanisms)
18. [Automation Possibilities](#18-automation-possibilities)
19. [Deploying for Real-Time, Multi-User Access](#19-deploying-for-real-time-multi-user-access)
20. [Authentication & Access Control](#20-authentication--access-control)
21. [Production Security & Compliance](#21-production-security--compliance)

**Part C — Reference**
22. [Outcomes & Benefits](#22-outcomes--benefits)
23. [Scope & Limitations](#23-scope--limitations)
24. [Roadmap Summary](#24-roadmap-summary)
25. [Validation, Testing & Accuracy](#25-validation-testing--accuracy)
26. [Conclusion](#26-conclusion)
27. [Glossary](#27-glossary)
28. [References & Links](#28-references--links)
29. [Frequently Asked Questions (Demo Q&A)](#29-frequently-asked-questions-demo-qa)

---

# Part A — The Platform Today

## 1. Executive Summary

Modern security teams are buried in vulnerability findings. A single mid-sized estate can surface thousands of CVEs, and traditional programmes triage them almost entirely on **technical severity** (CVSS). The result is a long, undifferentiated list where a low-impact internal finding can outrank a customer-facing system that is *actively being exploited right now*.

The **Cyber Exposure Governance Platform (CEGP)** reframes the problem from *"how severe is this vulnerability?"* to *"how much real exposure does this create for our business, and what should we do about it first?"*

It does this by **correlating five independent signals** — threat intelligence, business context, network exposure, live attack evidence, and data-privacy impact — into a single, **explainable 0–100 exposure score**. It then wraps that score in a governance layer: priority-based SLAs, remediation playbooks, risk-acceptance workflows, what-if simulation, and **tamper-evident, audit-ready reporting**.

In short: CEGP is the lightweight decision layer that sits **between a vulnerability scanner and a remediation team** — and, as Part B explains, it is designed to plug directly into those systems rather than depend on manual file uploads forever.

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

## 4. System Architecture

CEGP is built as a **layered pipeline with a clean separation between the data sources, the scoring engine, and the presentation layer**. This separation is the single most important architectural decision in the project: it means the *way data arrives* can change completely — a CSV file today, a live API tomorrow — without altering *how risk is calculated*. The engine neither knows nor cares where a row came from.

### 4.1 Architectural layers

| Layer | Responsibility | Representative modules |
|---|---|---|
| **1. Ingestion & Normalisation** | Read CSV/Excel, standardise column names into one schema, validate, and capture data-quality issues without halting. | import normaliser, validator |
| **2. Threat-Intelligence Enrichment** | Attach CVSS, EPSS and CISA KEV status to each CVE (from live feeds or the bundled offline set). | CISA KEV service, EPSS service, NVD service |
| **3. Context Correlation** | Merge asset, network, IDS/IPS and privacy context onto each finding. | asset-context engine, network-exposure engine, IDS-correlation engine, privacy-impact engine |
| **4. Scoring & Governance** | Compute the 0–100 score and priority, assign SLAs and playbooks, apply exceptions, map controls, and run simulations. | scoring engine, remediation-governance engine, playbook engine, exception engine, control-mapping engine, simulation engine |
| **5. Presentation** | Render the dashboard, charts, tables, and exports the analyst interacts with. | Streamlit application, Plotly visualisations |
| **6. Integrity & Audit (cross-cutting)** | Sign reports, sanitise exports, and record every action. | report-integrity (HMAC), CSV-security sanitiser, audit logger |

Layers 1–4 form the **engine** (pure data processing, independently testable); layer 5 is the **interface**; layer 6 is a **cross-cutting concern** that wraps the others. The risk policy (weights, thresholds, SLAs) is held in an external configuration file, so behaviour can be tuned without touching code.

### 4.2 End-to-end data flow

1. The analyst supplies four inputs (vulnerabilities, asset inventory, IDS/IPS alerts, risk exceptions) as files, or — in the future state — they arrive from live connectors.
2. The ingestion layer normalises and validates them; bad rows become data-quality notices rather than failures.
3. Each CVE is enriched with CVSS, EPSS and KEV.
4. Asset, network, IDS and privacy context is correlated onto every finding by joining on the asset and CVE identifiers.
5. The scoring engine produces the explainable 0–100 score and the Low/Medium/High/Critical priority.
6. The governance layer assigns due dates, playbooks, exception status and control mapping; the simulation engine can model "what-if" remediation.
7. Results flow to the dashboard; exports are sanitised and HMAC-signed; every step is recorded in the audit log.

### 4.3 Design principles

- **Source-agnostic engine** — the scoring logic is decoupled from the data source, which is what makes the file-to-live-data evolution in Part B possible without re-engineering.
- **Explainability by construction** — each layer contributes a named, inspectable sub-score, so the final number is always traceable.
- **Configurability** — risk appetite lives in policy, not code.
- **Deterministic, fail-safe behaviour** — with the offline intelligence set the output is reproducible, and missing data degrades to conservative defaults rather than errors.

---

## 5. Cybersecurity Strategies & Techniques Used

CEGP is not a single trick — it is a deliberate combination of recognised cybersecurity strategies, each contributing one part of the risk picture. This section names each technique, explains it briefly, and **points to exactly where it appears in the application** so the link between theory and the UI is explicit.

### 5.1 Technique-to-UI map

| # | Strategy / technique | What it is | Where it appears in the app (navigation → element) |
|---|---|---|---|
| 1 | **Risk-Based Vulnerability Management (RBVM)** | Prioritising fixes by *real-world risk* rather than raw severity. This is the core philosophy of the whole tool. | **Analyst View** → the entire *Security Analyst Exposure Queue*; **Executive View** → *Exposure Score* KPIs. |
| 2 | **Threat-Intelligence Enrichment** | Augmenting each CVE with external intelligence (KEV, EPSS, CVSS). | **Executive View** → *KEV vs Non-KEV* chart, *EPSS Percentile Distribution*; **Analyst View** → `cvss_score`, `epss_score`, `kev_status` columns. |
| 3 | **Exploit Prediction (EPSS) — likelihood-based prioritisation** | Using the probability a CVE will be exploited soon, not just how bad it is. | **Executive View** → *Risk Matrix* **Y-axis (likelihood)** and the *EPSS Percentile Distribution* histogram. |
| 4 | **Known-Exploited prioritisation (CISA KEV)** | Escalating vulnerabilities confirmed to be exploited in the wild — "weaponised first." | **Executive View** → *CISA KEV vs Non-KEV Exposures* bar; **Analyst View** → colour-coded `kev_status` column. |
| 5 | **Attack-Surface / Network-Exposure analysis (Defence-in-Depth)** | Judging how reachable an asset is — internet exposure, zone, open ports, firewall, VPN. | **Network Exposure** tab → *Risk by Network Zone*, *Risk by Asset Type*, and the per-asset exposure table. |
| 6 | **Detection & Response correlation (IDS/IPS)** | Correlating live intrusion alerts to vulnerable hosts to find assets under active attack. | **IDS/IPS Correlation** tab → *Correlated Alert Severity* chart and the `ids_alert_count` / `exploit_attempt_detected` columns. |
| 7 | **Data-Centric Security & Privacy protection** | Weighting PII, data sensitivity, encryption status and regulatory impact. | **Privacy Impact** tab → *Privacy Impact Distribution* and the `pii_present` / `encryption_status` / `regulatory_impact` columns. |
| 8 | **Business Impact Analysis (BIA)** | Weighting risk by asset criticality, environment and business process. | **Executive View** → *Top Business Processes by Aggregate Risk*, *Aggregate Risk by Environment*. |
| 9 | **Security Governance & SLA Management** | Time-bound remediation with due dates, breach tracking and escalation. | **Remediation Governance** tab → *SLA Governance Status* chart, `remediation_due_date`, `sla_status`, `escalation_required`. |
| 10 | **Risk Acceptance / Exception Management** | Formally accepting or deferring risk with expiry and compensating controls. | **Remediation Governance** tab → `exception_status`, `acceptance_reason`, `exception_validity` columns. |
| 11 | **Security Control Mapping** | Mapping each exposure to cybersecurity control domains. | **Remediation Governance** tab → *Exposures by Cybersecurity Control Area* chart. |
| 12 | **What-If / Risk-Reduction Simulation** | Modelling remediation strategies before spending effort. | **Simulation** tab → scenario selector and predicted risk-reduction output. |
| 13 | **Tamper-Evident Reporting (HMAC-SHA256)** | Cryptographically signing reports so they cannot be silently altered. | **Reports & Integrity** tab → signed report export and the *verify integrity* tool. |
| 14 | **Secure Output Handling (injection prevention)** | Sanitising exported spreadsheets against CSV/formula-injection. | **Reports & Integrity** tab → all exports are sanitised before download. |
| 15 | **Attributed Audit Logging (non-repudiation)** | Recording who did what and when. | **Audit Log** tab → the action history table. |
| 16 | **Input Validation & Data-Quality Assurance** | Catching malformed CVEs, bad values and duplicates without halting the run. | **Audit Log** tab → *Data Quality Notices* section. |
| 17 | **Explainable / Defensible Scoring** | Every priority traces back to its contributing factors. | **Executive View** → *Risk Matrix*; colour-coded priority across all tables; `score_drivers`. |

### 5.2 The unifying strategy

The single overarching strategy is **multi-signal, business-aware risk prioritisation with governance and evidence**. Threat intelligence (techniques 2–4) answers *"how likely and how bad?"*, exposure and business analysis (5, 8) answer *"how reachable and how important?"*, detection and privacy (6, 7) answer *"is it under attack and what data is at stake?"*, and the governance, simulation, reporting and audit layers (9–16) turn that into accountable, provable action. Explainability (17) ties it together so the output is defensible.

---

## 6. Why This Approach Is Good

A fair question is: *plenty of tools score vulnerabilities — why this design, and why these techniques?* This section answers it directly.

### 6.1 What other options exist in the market?

| Option | What it does | Limitation it leaves open |
|---|---|---|
| **CVSS-only triage** (spreadsheets, scanner default sort) | Ranks by technical severity. | Ignores exploitation likelihood, business value and live threat — the four gaps in §2. |
| **Native scanner dashboards** (Tenable, Qualys, Rapid7) | Show findings from that scanner. | Tied to one data source; limited business/IDS/privacy correlation in the base product. |
| **SIEM dashboards** (Splunk, Sentinel) | Show alerts and detections. | Strong on detection, weak on vulnerability prioritisation and remediation governance. |
| **GRC platforms** (Archer, ServiceNow GRC) | Track risk and compliance. | Governance-heavy, not vulnerability-prioritisation engines. |
| **Quantitative risk methods** (e.g. FAIR) | Express risk in financial terms. | Data-hungry and slow; overkill for day-to-day triage. |
| **Decision frameworks** (CISA **SSVC**) | A decision tree for patch urgency. | Excellent and complementary, but coarser than a continuous score. |

### 6.2 Are there competitors with similar capabilities?

Yes — **Risk-Based Vulnerability Management (RBVM)** is an established commercial category. Representative platforms include **Tenable Vulnerability Management (with Lumin / VPR)**, **Qualys VMDR (TruRisk)**, **Rapid7 InsightVM**, **Microsoft Defender Vulnerability Management**, and specialised risk-prioritisation tools such as **Cisco Vulnerability Management (formerly Kenna Security)**, **Nucleus Security**, **Brinqa**, and **Vulcan Cyber**.

These are mature, powerful enterprise products. But they are also **expensive, complex, and often tied to a vendor's own scanner**, and several treat business context, live IDS correlation, data-privacy impact, and tamper-evident reporting as separate add-ons rather than a single explainable score. CEGP demonstrates the *same core idea* — risk-based, multi-signal prioritisation — in a **transparent, lightweight, vendor-neutral** form.

### 6.3 What are this app's capabilities (the differentiators)?

- **Five signals in one score** — threat intel **+** business **+** network **+** live IDS **+** privacy, not just severity.
- **Fully explainable** — every point of the 0–100 score traces to a factor; nothing is a black box.
- **Live-threat aware** — IDS/IPS correlation flags assets under active attack, a signal pure scanners lack.
- **Privacy as a first-class dimension** — PII, encryption and regulatory impact are scored, not ignored.
- **Governance + simulation + evidence built in** — SLAs, exceptions, what-if modelling, signed reports and an audit trail in the same tool.
- **Vendor-neutral and integration-ready** — consumes any scanner's export today and is designed for live connectors tomorrow (Part B).
- **Transparent and low-cost** — runs on open components, ideal for learning, SMBs, and rapid evaluation.

### 6.4 What if a different technique were used instead?

| Instead of the blended model… | Trade-off |
|---|---|
| **CVSS only** | Simple, but you over-invest in severe-yet-unexploited issues and miss exploited "Medium" ones. |
| **EPSS only** | Captures likelihood but ignores how bad or how important the asset is. |
| **KEV only** | A useful binary flag, but misses CVEs trending toward exploitation that aren't listed *yet*. |
| **Pure quantitative (FAIR)** | Rigorous and financial, but heavy, data-hungry, and impractical for fast daily triage. |
| **SSVC decision tree** | Transparent and excellent — CEGP's logic is compatible with it — but produces coarse buckets rather than a continuous, rankable score. |

CEGP deliberately **blends** these into a weighted, tunable model: it keeps CVSS's severity, adds EPSS likelihood and KEV confirmation, and layers business, network, IDS and privacy context — capturing each technique's strength while compensating for its individual blind spot.

### 6.5 Why should I use this product?

Because it gives a security team the **one thing CVSS-only programmes cannot**: a ranked, defensible answer to *"what do we fix first, and why?"* that already accounts for real-world exploitation, business value, live attack evidence, and data sensitivity — and then carries that decision through to SLAs, simulation, signed reporting, and an audit trail. It is **explainable** (so it survives scrutiny from auditors and senior engineers), **lightweight and vendor-neutral** (so it fits any environment), and **integration-ready** (so it scales from a demo to a live enterprise service). For learning, evaluation, or a focused programme, it delivers enterprise-grade prioritisation thinking without enterprise cost or lock-in.

---

## 7. Core Capabilities

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

## 8. How It Works — The Processing Pipeline

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

## 9. The Scoring Model

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

## 10. The Dashboard & Views

The interface is organised as a header (project identity), a row of headline KPI cards, and nine focused tabs.

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

## 11. Inputs & Data Model

The platform's value comes from **correlation**, so it ingests four independent sources — mirroring how organisations actually store this data (CMDB, scanner, SIEM, GRC tool). Each can be supplied as CSV or Excel and swapped independently.

| File | Represents | Key fields |
|---|---|---|
| **Vulnerability findings** | The "what's wrong" | asset id, asset name, product, CVE, business criticality, internet-facing, environment, owner, first-detected date |
| **Asset inventory** | The "how much it matters" | application, business process, owner, network zone, open ports, firewall, VPN required, asset type, data type, PII, sensitivity, encryption, regulatory impact |
| **IDS/IPS alerts** | The "is it being attacked" | alert id, asset id, alert type, severity, source/destination IP, timestamp, signature, confidence |
| **Risk exceptions** | The "already signed off" | asset id, CVE, exception status, acceptance reason, accepted-by, expiry, compensating control |

**Why four files?** A scanner alone gives only the first. The whole point of the product is that the first file is nearly useless for *prioritisation* without the other three.

> **Important design note:** These four sources are exactly the four systems an enterprise already runs (scanner, CMDB, SIEM/IDS, GRC). Today they arrive as files; **Part B explains how each can instead stream in live**, with no change to the scoring engine.

**Supported formats:** CSV, modern Excel (`.xlsx`), and legacy Excel (`.xls`). When live feeds are turned off, bundled offline threat-intelligence is used, so assessments are fully **deterministic** — ideal for demonstrations.

---

## 12. Security, Integrity & Governance

Because this is a *security* tool, it holds itself to a higher standard than a typical dashboard:

- **Tamper-evident reports (HMAC-SHA256).** Exports are signed with a secret key, so an altered report cannot be re-signed by anyone who lacks the key. This is stronger than a plain checksum, which anyone can recompute. The key is supplied via environment variable in production, or generated and stored locally otherwise.
- **Injection-safe exports.** Exported spreadsheets are sanitised so that a malicious cell cannot execute as a formula when opened in Excel, Sheets, or LibreOffice — a real risk for any tool that exports externally supplied data.
- **Attributed audit log.** Every action records the **operator** and a timestamp, so the trail can answer *who* did *what*, not merely that something happened.
- **Integrity verifier.** A built-in tool lets a reviewer upload any exported report and confirm whether its contents match the original signature.
- **Configurable governance.** SLAs, escalation, and risk-acceptance (with expiry and compensating controls) are first-class, so remediation timelines are tracked and auditable.

---

## 13. Bundled Datasets

To make the platform demonstrable out of the box, it ships with realistic, fully offline data:

- **Primary dataset** — a diversified set of roughly 300 exposures across several hundred assets, deliberately engineered to exercise **every** scoring path: all priority bands, all KEV/EPSS/CVSS combinations, all network zones, IDS exploit and multi-alert cases, every privacy level, SLA breached/due-soon/within states, and valid/expired/no-expiry exceptions. A few rows intentionally trigger non-blocking data-quality notices to demonstrate validation.
- **Small demo set** — a compact set retained for quick walkthroughs, including an Excel copy to demonstrate file upload.
- **Additional mock organisations** — three independent fictional companies (retail, healthcare, finance), each with all four input files, so the tool can be demonstrated on non-default data.
- **Offline threat-intelligence** — bundled KEV/EPSS/CVSS reference data covering every CVE in the samples, so results are identical run-to-run without internet access.

---

## 14. Technology Stack

| Layer | Technology | Role |
|---|---|---|
| **User interface** | Streamlit | Browser-based dashboard and interaction |
| **Processing engine** | pandas | Data validation, enrichment, scoring |
| **Visualisation** | Plotly | Interactive charts and the risk matrix |
| **Threat-intel access** | requests | Optional live KEV / EPSS / NVD lookups |
| **Spreadsheet support** | openpyxl, xlrd | Reading modern and legacy Excel files |
| **Integrity** | HMAC-SHA256 (standard library) | Tamper-evident report signing |

The codebase is organised modularly — a set of focused processing engines and external-data services — which keeps each scoring dimension independent and easy to reason about. **This modular "services" layer is the key to integration**: each external feed is just another service the engine can call.

---

## 15. Running the Application Locally

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

# Part B — Scaling Up: Integrations, Automation & Deployment

## 16. From Static Files to Live Data — Future Integrations

Today the platform is fed **static files** — a snapshot exported from a scanner, an inventory spreadsheet, an alert dump. This is perfect for demonstrations and offline use, but the same architecture is built to consume **live, continuously updated data** from the systems an organisation already runs.

The crucial point is architectural: CEGP separates **where data comes from** (an ingestion/normalisation layer) from **how data is scored** (the engine). The engine never cares whether a row arrived from a CSV or a live API. That means **every file input can be replaced by a live connector without touching the scoring logic** — the platform simply receives fresh data on a schedule or in real time, and re-scores automatically.

Below are the integration categories, the real systems in each, what they would feed, and why it matters.

### 16.1 Vulnerability Scanners → live findings

| Source systems | Feeds | Value |
|---|---|---|
| Tenable (Nessus / Tenable.io / Tenable.sc), Qualys VMDR, Rapid7 InsightVM, Greenbone/OpenVAS, Microsoft Defender Vulnerability Management, cloud scanners (Wiz, Orca) | The **vulnerability findings** input | Findings refresh automatically after every scan — no manual export. New CVEs are scored within minutes of discovery. |

**How it connects:** most scanners expose a REST API or scheduled export. A connector pulls the latest findings, the normaliser maps them to the standard schema, and an assessment runs. ([Tenable](https://www.tenable.com), [Qualys](https://www.qualys.com), [Rapid7](https://www.rapid7.com), [Greenbone/OpenVAS](https://www.greenbone.net))

### 16.2 Asset Inventory / CMDB → live business context

| Source systems | Feeds | Value |
|---|---|---|
| ServiceNow CMDB, Device42, Lansweeper, Axonius, cloud inventories (AWS Config, Azure Resource Graph, GCP Asset Inventory) | The **asset inventory** input (criticality, owner, environment, data sensitivity) | Business context stays current as assets are added, retired, or reclassified — so prioritisation reflects today's estate, not last quarter's spreadsheet. |

**How it connects:** CMDBs and cloud inventories provide APIs that return assets with ownership and criticality. A scheduled sync keeps the platform's asset picture live. ([ServiceNow](https://www.servicenow.com), [Device42](https://www.device42.com), [Lansweeper](https://www.lansweeper.com))

### 16.3 SIEM / IDS-IPS / EDR → real-time attack evidence

| Source systems | Feeds | Value |
|---|---|---|
| Splunk, Microsoft Sentinel, Elastic Security, Suricata / Snort / Zeek sensors, CrowdStrike / SentinelOne EDR | The **IDS/IPS alerts** input | This is the biggest live-data win: an asset already flagged "High" jumps to top priority **the moment** it is actively targeted, because alerts stream in continuously instead of being dumped once. |

**How it connects:** SIEMs support search APIs, scheduled queries, or streaming outputs; sensors emit events to a collector. The platform consumes the alert stream and re-correlates against vulnerable assets. ([Splunk](https://www.splunk.com), [Microsoft Sentinel](https://azure.microsoft.com/products/microsoft-sentinel), [Elastic Security](https://www.elastic.co/security), [Suricata](https://suricata.io))

### 16.4 Threat-Intelligence Feeds → always-current exploit context

| Source systems | Feeds | Value |
|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/), [NVD](https://nvd.nist.gov/), [MISP](https://www.misp-project.org/), commercial TI (Mandiant, Recorded Future), VirusTotal | The **threat-intelligence enrichment** layer | Exploitation likelihood and "known exploited" status are refreshed daily, so a vulnerability that becomes weaponised overnight is re-prioritised the next morning. |

**How it connects:** these are already partially wired in via the platform's optional "live feeds" toggle, which queries the public KEV, EPSS, and NVD services. The same pattern extends to commercial feeds and MISP. ([NVD API](https://nvd.nist.gov/developers))

### 16.5 ITSM / Ticketing / SOAR → close the remediation loop

| Source systems | Feeds | Value |
|---|---|---|
| ServiceNow ITSM / SecOps, Jira, PagerDuty, Cortex XSOAR, Tines, Torq | **Outbound** — the platform *pushes* remediation tickets | Instead of exporting a report for someone to action, the platform can **automatically open a prioritised, playbook-filled ticket** for each critical exposure and track it to closure, enforcing SLAs end-to-end. |

**How it connects:** ITSM/SOAR tools accept tickets via REST API or webhook. The platform's existing "ticket report" becomes a live ticket. ([ServiceNow](https://www.servicenow.com), [Jira](https://www.atlassian.com/software/jira), [PagerDuty](https://www.pagerduty.com))

### 16.6 Cloud Security Posture (CSPM) → cloud exposure

| Source systems | Feeds | Value |
|---|---|---|
| AWS Security Hub, Microsoft Defender for Cloud, GCP Security Command Center | Additional **findings + asset context** for cloud workloads | Extends the same prioritisation to cloud misconfigurations and cloud-native vulnerabilities, not just traditional hosts. |

### 16.7 Identity & Directory → ownership and access

| Source systems | Feeds | Value |
|---|---|---|
| Microsoft Entra ID / Active Directory, Okta | Asset/owner resolution **and** user authentication (see §20) | Resolves "who owns this asset" automatically, and provides the identity backbone for secure multi-user access. |

### 16.8 Data Warehouse / BI → history and board reporting

| Source systems | Feeds | Value |
|---|---|---|
| Snowflake, BigQuery, Databricks; Power BI / Tableau for visualisation | **Outbound** — assessment history is persisted and published | Enables long-term trend analysis, board-level dashboards, and integration with enterprise reporting. |

### 16.9 Collaboration / Notification → alerting

| Source systems | Feeds | Value |
|---|---|---|
| Slack, Microsoft Teams, email/SMTP | **Outbound** notifications | Pushes an alert the instant a new Critical exposure appears or an SLA is about to breach, so teams act without watching the dashboard. |

---

## 17. Integration Mechanisms

Different systems integrate in different ways. The platform's service layer can support all of the patterns below:

| Pattern | How it works | Best for |
|---|---|---|
| **Scheduled API pull** | The platform calls each source's REST API on a timer (e.g. hourly) and re-runs the assessment. | Scanners, CMDB, threat-intel feeds. |
| **Event-driven webhook (push)** | A source notifies the platform the moment something changes (e.g. a new IDS alert). | SIEM/IDS, real-time escalation. |
| **Streaming / message queue** | High-volume events flow through a broker (e.g. Kafka) and are consumed continuously. | Large estates with heavy alert volume. |
| **Database / warehouse sync** | The platform reads from / writes to a shared datastore. | Persistence, BI, history. |
| **Secure file drop (SFTP / cloud bucket)** | Sources deposit exports to a watched location that the platform ingests automatically. | A gentle, low-effort step beyond manual upload. |
| **Native / pre-built connector** | A maintained connector for a specific product (e.g. ServiceNow). | Tight, supported enterprise integrations. |

This layered approach means an organisation can start with the easiest pattern (a watched SFTP folder) and graduate to full real-time streaming over time, **without re-architecting the platform**.

---

## 18. Automation Possibilities

Once data is live, the platform can move from "run on demand" to "always on":

- **Scheduled assessments** — run automatically (e.g. every hour or after each scan) so the risk picture is never stale.
- **Event-triggered re-scoring** — a new IDS alert or a newly KEV-listed CVE instantly re-prioritises the affected assets.
- **Automated ticketing** — every new Critical/High exposure becomes a remediation ticket with its playbook already attached.
- **SLA-breach escalation** — overdue items automatically notify owners and managers and raise their score contribution.
- **Proactive alerting** — Slack/Teams/email notifications for new criticals, KEV additions, or active-exploit detections.
- **Policy-as-code** — scoring weights, thresholds, and SLAs version-controlled and promoted through environments like any other configuration.
- **Scheduled signed reporting** — nightly executive and audit reports generated, signed, and archived automatically for compliance.

---

## 19. Deploying for Real-Time, Multi-User Access

To let a whole team (or auditors) reach the platform from anywhere, it moves from a local script to a hosted service. There is a natural progression:

| Stage | Deployment | Notes |
|---|---|---|
| **1. Local** | Runs on a single machine via `streamlit run`. | Current model — ideal for development and demos. |
| **2. Single server** | Hosted on a Linux VM behind a reverse proxy (e.g. Nginx) with HTTPS/TLS. | First shared, always-on deployment for a small team. |
| **3. Containerised** | Packaged as a Docker image for consistent, portable deployment. | Removes "works on my machine" problems; easy to ship. |
| **4. Orchestrated** | Run on Kubernetes for scaling, high availability, and rolling updates. | For larger, resilient production use. |
| **5. Managed cloud** | Deployed to a managed platform — Streamlit Community Cloud (demos), or Google Cloud Run / Azure App Service / AWS App Runner (production). | Lowest operational overhead; built-in TLS and scaling. |

**Reference production architecture:** users reach the app over **HTTPS** through a reverse proxy or cloud load balancer; the proxy enforces authentication (next section) before any request reaches the app; the app reads/writes a **managed database** instead of local files; secrets (the integrity key, API keys) live in a **secrets manager / vault**; and the app pulls live data from the integrations in Part B. This turns the prototype into a properly hosted, team-accessible service.

> A complete, step-by-step Google Cloud deployment (Cloud Run + Secret Manager + Identity-Aware Proxy) is provided as a separate guide and is accessible in-app via the **Future Scope — Implementation using GCP** button.

---

## 20. Authentication & Access Control

A security tool must not be openly reachable — exposing exposure data to the world would itself be a risk. In a hosted deployment, **no one should reach the dashboard without authenticating**, and different people should see different capabilities. The platform supports a layered model:

### 20.1 Authentication (proving who you are)

- **Single Sign-On (SSO)** via the organisation's identity provider using **OIDC** or **SAML 2.0** — e.g. Microsoft Entra ID, Okta, or Google Workspace. Users log in with their existing corporate account; there is no separate password to manage.
- **Multi-factor authentication (MFA)** — enforced by the identity provider, adding a second factor beyond the password.
- **Enforcement options:**
  - *Application-level* — Streamlit's native authentication / OIDC login, so the app itself gates access.
  - *Proxy-level* — an authenticating reverse proxy (e.g. [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/)) that blocks unauthenticated requests before they reach the app.
  - *Platform-level* — built-in identity (e.g. Google Cloud IAP, Azure App Service Authentication) when hosted on a managed cloud.

The result: an anonymous visitor is redirected to a corporate login and **cannot see any data** until authenticated.

### 20.2 Authorisation (what you're allowed to do)

Role-based access control (RBAC) maps each authenticated user to a role:

| Role | Can do |
|---|---|
| **Viewer** | Read dashboards and reports only. |
| **Analyst** | Run assessments, triage exposures, generate reports. |
| **Approver** | Everything an Analyst can, plus approve risk exceptions/acceptances. |
| **Administrator** | Manage policy (weights, thresholds, SLAs), integrations, and user roles. |

This enforces **least privilege** — for example, only an Approver can formally accept a risk, and only an Admin can change the scoring policy.

### 20.3 Identity-aware audit

The existing audit log already records the operator behind every action. With SSO in place, that operator becomes a **verified corporate identity** rather than a typed-in name, so the audit trail is trustworthy enough for compliance and incident review.

---

## 21. Production Security & Compliance

Beyond login, a hosted deployment should apply standard production controls:

- **Encryption in transit** — all traffic over HTTPS/TLS.
- **Encryption at rest** — database and stored reports encrypted by the platform/cloud.
- **Secrets management** — the HMAC integrity key and all API keys held in a vault or cloud key-management service, never in code or files.
- **Network controls** — host on a private network or behind a VPN, restrict access by IP allow-list, and optionally place a Web Application Firewall (WAF) in front.
- **Standards alignment** — map controls and reporting to recognised frameworks: [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework), [CIS Controls](https://www.cisecurity.org/controls), ISO 27001, and [MITRE ATT&CK](https://attack.mitre.org/); optionally adopt [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) as a decision-output format.
- **Backup & retention** — regular backups of assessment history and signed reports for audit retention requirements.

Together, §19–§21 describe how the prototype becomes a **secure, authenticated, real-time, enterprise-accessible service**.

---

# Part C — Reference

## 22. Outcomes & Benefits

| Benefit | What it delivers |
|---|---|
| **Efficient prioritisation** | Collapses hundreds of findings into a focused list of exposures that combine severity **and** real exploitation paths. |
| **Scenario planning** | Lets risk managers simulate strategies and see the predicted percentage risk reduction before committing effort. |
| **Audit readiness** | Signed reports plus an attributed audit log — presentable directly to auditors. |
| **Actionable remediation** | Teams receive clear playbooks and SLA countdowns instead of generic technical notes. |
| **Explainability** | Every priority is traceable to its contributing factors, so decisions can be defended. |
| **Integration-ready** | Designed to evolve from static files to live, automated, enterprise-wide data flows. |

---

## 23. Scope & Limitations

The boundaries of v1 are deliberate and stated openly — knowing exactly where a tool is weak is part of good engineering. Each maps directly to the enhancements in Part B.

- **Single-operator, file-based.** State is held in files (last-write-wins); designed for one analyst or a small team. → Addressed by §19 (database + hosting).
- **No access control yet.** No authentication or roles in the local prototype. → Addressed by §20.
- **Manual / file-based integration.** Data arrives as CSV/Excel. → Addressed by §16–§18 (live connectors).
- **Explainable, not certified.** The scoring model is transparent and configurable, but is a decision-support heuristic, not a certified quantitative risk model.

---

## 24. Roadmap Summary

| Theme | Enhancement | Detailed in |
|---|---|---|
| **Live data** | Connectors to scanners, CMDB, SIEM/IDS, threat-intel, cloud posture | §16 |
| **Automation** | Scheduled & event-driven assessments, auto-ticketing, alerting | §18 |
| **Hosting** | Containerised / cloud deployment for real-time, multi-user access | §19 |
| **Security** | SSO, MFA, RBAC, secrets management, network controls | §20–§21 |
| **Persistence** | Database backend and assessment history | §19 |
| **Standards** | Mapping to NIST CSF, CIS, ISO 27001, MITRE ATT&CK; SSVC output | §21 |

---

## 25. Validation, Testing & Accuracy

A reasonable challenge to any risk-scoring tool is: *how do you know the results are accurate?* The honest first step is to separate three different meanings of "accuracy," because a risk-prioritisation model is not right-or-wrong like a measurement instrument — there is no single ground-truth score for a vulnerability.

| Layer | The claim | How it is validated |
|---|---|---|
| **Data accuracy** | The intelligence is correct. | CVSS, EPSS and KEV are taken **verbatim from authoritative sources** (NVD, FIRST, CISA). The tool does not invent intelligence; accuracy here means *fidelity to those feeds*, which can be reconciled against the live services. |
| **Computational correctness** | The engine computes what it claims, reproducibly. | The pipeline is **deterministic** (same input → same output) and **fully explainable** — every point of the 0–100 score traces back to a named factor, so any result can be inspected and justified. |
| **Prioritisation validity** | The ranking makes sound sense. | The weighting follows recognised **Risk-Based Vulnerability Management** doctrine (likelihood + exploitation + impact, not CVSS alone), aligned with **CISA SSVC**, **FIRST EPSS** guidance and **NIST**. It is then validated empirically by back-testing (below). |

### 25.1 Validation methods

- **Traceability** — every exposure exposes its per-factor score drivers; the contribution of threat intel, business, network, IDS and privacy can be shown individually.
- **Reproducibility** — re-running an assessment yields identical results; the bundled offline intelligence guarantees determinism for demonstrations.
- **Back-testing against known incidents** — feeding historically exploited CVEs and confirming they surface as Critical (see §25.2).
- **Benchmarking against alternatives** — comparing the ranking with CVSS-only and EPSS-only ordering to show it catches the "exploited Medium" cases the others miss.
- **Sensitivity analysis** — varying weights and thresholds to confirm the ranking moves predictably and remains stable (e.g. raising the threat-intel weight lifts KEV items).
- **Edge-case coverage** — the bundled ~300-row dataset deliberately exercises every scoring branch, plus intentional malformed rows to prove the validation gates work.
- **Input validation** — malformed CVEs, duplicates and out-of-range values are caught and reported, so accuracy cannot be silently corrupted ("garbage in" is rejected, not scored).
- **Classifier metrics (if framed as prediction)** — treating "will this be exploited?" as a prediction allows precision / recall / F1 / ROC-AUC to be reported using KEV+EPSS as ground truth, with weights calibrated over time against what is actually exploited.
- **Expert face-validity** — a practitioner reviewing a sample ranking provides construct validity.

### 25.2 Back-testing demonstration

Seven of the most significant real-world exploited vulnerabilities of recent years were run through the engine under realistic exploitation conditions (internet-facing production assets holding sensitive data, with a correlated IDS exploit alert). **Every one is correctly prioritised as Critical** — meaning the model would have escalated these attacks early.

| CVE | Vulnerability | CVSS | EPSS %ile | KEV | CEGP score | Priority |
|---|---|---:|---:|:---:|---:|:---:|
| CVE-2021-44228 | Log4Shell (Apache Log4j) | 10.0 | 0.999 | Yes | 100.0 | **Critical** |
| CVE-2022-26134 | Atlassian Confluence OGNL RCE | 9.8 | 0.985 | Yes | 100.0 | **Critical** |
| CVE-2020-1472 | Zerologon (Netlogon) | 9.8 | 0.965 | Yes | 100.0 | **Critical** |
| CVE-2021-26855 | ProxyLogon (MS Exchange) | 9.8 | 0.993 | Yes | 100.0 | **Critical** |
| CVE-2023-34362 | MOVEit Transfer SQLi | 9.8 | 0.997 | Yes | 100.0 | **Critical** |
| CVE-2021-34527 | PrintNightmare (Print Spooler) | 8.8 | 0.960 | Yes | 97.8 | **Critical** |
| CVE-2023-4966 | Citrix Bleed | 7.5 | 0.962 | Yes | 97.8 | **Critical** |

Two further observations strengthen the result:

- **Context elevates beyond raw CVSS.** Citrix Bleed (CVSS 7.5, a "High") still reaches **Critical (97.8)** because it is KEV-listed, has a very high EPSS percentile, is internet-facing and touches sensitive data — exactly the case CVSS-only triage under-ranks.
- **The model discriminates.** A control finding — a low-severity (CVSS 2.8), internal, encrypted, no-PII asset that is *not* being exploited — scores **≈ 35 (Low)**. So the engine does not simply rate everything high; it separates genuine exposure from background noise.

### 25.3 Honest framing

CEGP is a **transparent, tunable decision-support model, not a certified quantitative risk engine**. Because the weights are configurable, "accuracy" is partly relative to the organisation's chosen risk policy — and that is deliberate. The **explainability and configurability are themselves the validation mechanism**: every factor can be inspected, challenged and adjusted, which is precisely what cannot be done with an opaque proprietary score. Validation therefore rests on *transparency, reproducibility and back-testing* rather than a single accuracy percentage.

### 25.4 Testing & quality assurance

Validation of the *results* (above) is complemented by validation of the *software itself*. During development the platform was exercised in several ways:

- **Deterministic offline runs** — with the bundled threat-intelligence set, the same input always produces the same output, so any regression in the engine is immediately visible.
- **End-to-end application tests** — the dashboard is run headlessly to confirm that every tab, chart, simulation and export renders without error on the sample data before each change is accepted.
- **Validation-gate coverage** — the ~300-row dataset deliberately includes malformed CVE identifiers, out-of-range values, duplicates and an unparseable date, so the input-validation path is genuinely tested rather than assumed; these surface as data-quality notices rather than crashes.
- **Edge-case datasets** — three independent mock organisations (retail, healthcare, finance) confirm the engine behaves sensibly on data it was not tuned against.
- **Output quality assurance** — generated reports and documents are visually checked, and exports are confirmed to be injection-sanitised and correctly signed.
- **Functional back-testing** — the seven historically exploited CVEs in §25.2 act as a standing functional test: if a future change caused any of them to drop below Critical, that would signal a scoring regression.

This combination gives confidence that the tool is correct (it computes what it claims), robust (bad input does not break it), and reproducible (results can be regenerated and compared).

---

## 26. Conclusion

The Cyber Exposure Governance Platform set out to answer a question that traditional, severity-only vulnerability management leaves open: *out of everything that is wrong, what should we fix first, and why?* By correlating five independent signals — threat intelligence, business impact, network exposure, live intrusion evidence, and data-privacy impact — into a single, explainable 0–100 exposure score, and then wrapping that score in SLA governance, what-if simulation, and tamper-evident reporting, the project turns a long, undifferentiated list of findings into a ranked, defensible, and actionable programme.

Three things distinguish the result. First, it is **explainable**: every score traces back to named factors, so it survives scrutiny from auditors and senior engineers rather than hiding behind a black box. Second, it is **validated, not merely asserted**: the back-testing demonstration shows that the most significant real-world exploited vulnerabilities of recent years are correctly escalated to Critical, while well-protected, low-severity assets are not. Third, it is **built to grow**: the deliberate separation of data source from scoring engine means the same prototype can evolve into a live, automated, multi-user enterprise service without re-architecting its core.

The platform is honest about its boundaries — it is a transparent decision-support tool, not a certified quantitative risk engine, and several enhancements (live connectors, a database backend, authentication, attack-path analysis) are mapped on the roadmap rather than claimed as done. Taken together, however, it demonstrates a complete, coherent, and practical application of modern risk-based vulnerability management principles, and provides a foundation that is genuinely ready to be taken further.

---

## 27. Glossary

| Term | Meaning |
|---|---|
| **CVSS** | Common Vulnerability Scoring System — a standard 0–10 score for a vulnerability's technical severity. |
| **EPSS** | Exploit Prediction Scoring System — a probability that a CVE will be exploited in the wild within 30 days. |
| **CISA KEV** | The U.S. CISA catalogue of vulnerabilities with confirmed real-world exploitation. |
| **CVE** | Common Vulnerabilities and Exposures — a unique identifier for a publicly known vulnerability. |
| **RBVM** | Risk-Based Vulnerability Management — prioritising remediation by real-world risk, not raw severity. |
| **BIA** | Business Impact Analysis — assessing how important an asset/process is to the business. |
| **SSVC** | Stakeholder-Specific Vulnerability Categorization — a CISA decision framework for patch urgency. |
| **IDS / IPS** | Intrusion Detection / Prevention System — sensors that detect or block malicious network activity. |
| **EDR** | Endpoint Detection and Response — agent-based detection on hosts. |
| **SIEM** | Security Information and Event Management — central log/alert analytics platform. |
| **SOAR** | Security Orchestration, Automation and Response — automates security workflows. |
| **CMDB** | Configuration Management Database — the system of record for assets and ownership. |
| **CSPM** | Cloud Security Posture Management — finds misconfigurations and risks in cloud environments. |
| **PII** | Personally Identifiable Information. |
| **SLA** | Service-Level Agreement — here, the time allowed to remediate based on priority. |
| **RBAC** | Role-Based Access Control — permissions assigned by role. |
| **SSO** | Single Sign-On — one corporate login across applications. |
| **MFA** | Multi-Factor Authentication — a second factor beyond a password. |
| **OIDC / SAML** | Standard protocols used to implement SSO. |
| **HMAC** | Hash-based Message Authentication Code — a keyed signature that makes a report tamper-evident. |
| **Exposure score** | The platform's consolidated 0–100 measure of overall cyber exposure for a finding. |

---

## 28. References & Links

**Threat intelligence & standards**
- CISA Known Exploited Vulnerabilities (KEV) — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS — https://www.first.org/epss/
- NVD (National Vulnerability Database) — https://nvd.nist.gov/ · API: https://nvd.nist.gov/developers
- NIST Cybersecurity Framework — https://www.nist.gov/cyberframework
- CIS Controls — https://www.cisecurity.org/controls
- MITRE ATT&CK — https://attack.mitre.org/
- CISA SSVC — https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
- MISP (threat-intel sharing) — https://www.misp-project.org/

**Representative market / competitor platforms**
- Tenable — https://www.tenable.com · Qualys — https://www.qualys.com · Rapid7 — https://www.rapid7.com
- Microsoft Defender Vulnerability Management — https://www.microsoft.com/security · Nucleus Security — https://nucleussec.com

**Representative integration targets**
- ServiceNow — https://www.servicenow.com · Jira — https://www.atlassian.com/software/jira · PagerDuty — https://www.pagerduty.com
- Splunk — https://www.splunk.com · Microsoft Sentinel — https://azure.microsoft.com/products/microsoft-sentinel · Elastic Security — https://www.elastic.co/security · Suricata — https://suricata.io

**Platform & deployment**
- Streamlit — https://streamlit.io · Docs — https://docs.streamlit.io
- Google Cloud Run — https://cloud.google.com/run/docs · Identity-Aware Proxy — https://cloud.google.com/iap/docs
- oauth2-proxy — https://oauth2-proxy.github.io/oauth2-proxy/ · OpenID Connect — https://openid.net/connect/

---

## 29. Frequently Asked Questions (Demo Q&A)

This section anticipates the deeper questions a specialist panel is likely to raise, with fuller, plain-spoken answers. Abbreviations are expanded on first use, and concrete examples are given so the reasoning is easy to follow and easy to be convinced by. Where a point is a known limitation, the future-scope direction is stated honestly rather than hidden.

### A. Scoring methodology & statistical rigour

**Q1. You use a weighted linear sum. Why additive aggregation when risk factors are correlated and arguably non-linear?**
The honest reason is that we are optimising for *defensibility*, not mathematical elegance. A weighted sum means that when a security manager asks "why is this number 92?", we can answer "because it's KEV-listed, internet-facing, holds customer data, and an intrusion sensor saw an exploit attempt" — and point to the exact contribution of each. The moment you move to a complex non-linear or black-box function, you lose that sentence, and in security you constantly have to justify your decisions to auditors and to engineers who don't want to be told to drop everything. Where non-linearity genuinely matters, we put it *inside* a dimension rather than in the aggregation — for example, KEV (Known Exploited Vulnerabilities, the U.S. CISA catalogue of vulnerabilities confirmed to be exploited in the real world) acts as a strong step-up, and EPSS is consumed as a percentile rather than a raw probability. We are also clear that the output is an explainable *ranking* heuristic, not a calibrated probability of breach. **Future scope:** the weights can be learned from data (see Q6), which would let the model capture interaction effects while we keep the explainable view alongside it.

**Q2. CVSS, EPSS and KEV are correlated — isn't there double-counting in the threat-intelligence sub-score?**
They do overlap, but they answer genuinely different questions, which is why all three earn a place. CVSS (Common Vulnerability Scoring System) tells you *how bad it would be if exploited* — the technical severity, 0 to 10. EPSS (Exploit Prediction Scoring System, published by FIRST) tells you *how likely it is to be exploited in the next 30 days* — a data-driven probability. KEV tells you *whether it is already being exploited right now*. A vulnerability can be severe but never exploited, or only moderately severe but exploited everywhere — Citrix Bleed (CVE-2023-4966) is the classic case: only 7.5 on CVSS, yet mass-exploited. To bound the overlap, we deliberately fold all three into a *single* threat-intelligence dimension (weight 35) instead of giving each its own top-level weight, so their shared signal can't be triple-counted. **Future scope:** if a reviewer wants the residual correlation removed entirely, re-deriving the weights from historical data (Q6) naturally accounts for the covariance between them.

**Q3. Why a weighted-sum model rather than a multiplicative, Bayesian, or decision-tree (SSVC) model?**
We looked at all of them and each has a real drawback for this use case. A multiplicative model lets a single near-zero factor collapse the whole score, which is dangerous — a critical, exploited vulnerability shouldn't score near zero just because, say, we lack its network data. A Bayesian model needs prior and conditional probabilities that are very hard to defend without a large labelled dataset, so it trades one "where did these numbers come from?" problem for a harder one. SSVC (Stakeholder-Specific Vulnerability Categorization, a CISA decision-tree framework) is genuinely excellent and we admire it, but it outputs coarse buckets like "Act" or "Track" rather than a continuous score you can rank a thousand items by. The weighted sum gives us a transparent, continuous, tunable ranking — and, importantly, it's *compatible* with SSVC, so we could emit an SSVC-style decision on top of the score. **Future scope:** offering an optional SSVC decision output is on our roadmap for organisations that prefer a framework-aligned verdict.

**Q4. How do you normalise such different inputs — a 0–10 CVSS, a 0–1 EPSS probability, a binary KEV flag, categorical network zones — onto one scale without distortion?**
Every dimension is converted to a bounded 0–100 sub-score through a documented mapping before anything is combined, so we're never adding apples to oranges. Continuous values are rescaled (a CVSS of 9.8 becomes a high contribution on a 0–100 basis), categoricals are mapped to defined bands (an "internet" network zone contributes far more than "internal"), and binaries like KEV apply a fixed step. The key point for a sceptic is that these mappings are written down in the policy configuration, not buried in code, so every normalisation choice is visible and can be challenged or changed. **Future scope:** exposing these mappings in the user interface so an administrator can adjust them without editing a file is a planned usability improvement.

**Q5. The score saturates at 100 — doesn't that hide differences among the very worst findings?**
Yes, and we'll concede it openly because it's a fair observation. Once several high-risk factors line up — exploited, reachable, sensitive — items cluster near 100, and ordering *within* that top band then leans on secondary signals like the EPSS percentile and asset criticality. For a "fix-first" workflow that's actually acceptable, because everything in that band needs urgent action anyway; the analyst isn't harmed by two items both being "100, do it now". But if a panel wants finer separation at the extreme top, the fix is straightforward: remove the cap, or add an explicit tie-breaker ordering. **Future scope:** a secondary sort key for the Critical band is a small, planned enhancement.

**Q6. How would you statistically calibrate the weights, and how do you avoid overfitting?**
Right now the weights encode expert judgement aligned to industry guidance, which is a legitimate and common starting point. To make them evidence-based, we'd frame it as a supervised learning problem: take a large set of historical CVEs, label each with whether it was actually exploited (using KEV and observed exploitation as ground truth), and fit the weights — for instance with a regularised logistic regression. The two traps are obvious and we'd guard against both: overfitting, which we'd control with regularisation and cross-validation; and a *time* leak, which we'd avoid with a strict chronological train/test split so the model is never tested on the past it was trained on. The fitted coefficients then become the new, empirically-justified weights. **Future scope:** this calibration loop, retrained periodically as new exploitation data arrives, is the single most valuable enhancement to the scoring model.

**Q7. Is the score ordinal or cardinal — can you legitimately say a 90 is "twice as risky" as a 45?**
No, and we're careful never to claim that. The score is ordinal-to-interval at best, which means it is valid for *rank-ordering and banding* but not for ratio statements — a 90 is "higher priority than" a 45, not "twice the risk of" it. We state this explicitly so the number isn't over-interpreted in a way it can't support, which is itself a sign of a model you can trust.

**Q8. A single CVE often affects dozens or hundreds of assets — how do you handle that fan-out without the list becoming unusable?**
This is a real operational issue: one library flaw like Log4Shell can appear on hundreds of hosts. CEGP scores at the level of the *finding* — the combination of a vulnerability *and* the specific asset it sits on — because the same CVE is genuinely more dangerous on an internet-facing customer database than on an isolated lab machine, and the priority should reflect that. For the analyst's sanity, the dashboard then lets the same CVE be viewed grouped, so you can see "this one vulnerability is your biggest aggregate exposure across 120 assets" as well as the per-asset detail. **Future scope:** an explicit campaign view that tracks remediation of one CVE across its whole fleet, with a single roll-up SLA, is a natural next feature.

### B. Cybersecurity domain depth

**Q9. EPSS refreshes daily and is a forward-looking 30-day probability — how do you handle that it goes stale?**
A score is always a snapshot in time, and we treat it that way rather than pretending it's permanent. In the live-data design (§16), EPSS and KEV are pulled on a schedule, so a finding is automatically re-scored as the intelligence moves — an asset can quietly sit at "Medium" for weeks and then jump to "Critical" overnight because its CVE was added to KEV or its EPSS spiked. For the demonstration we deliberately freeze the feed using the bundled offline set so results are reproducible, and we're transparent that this is a demo choice. **Future scope:** scheduled, event-driven re-assessment is precisely what turns this from a point-in-time tool into a continuous monitoring service.

**Q10. KEV is a lagging indicator — it's added only after exploitation is confirmed. Isn't prioritising on it inherently reactive?**
On its own, yes — and that's exactly why KEV is one signal of several, not the whole model. KEV is the "we know for certain" signal, and you absolutely want it, but you also want to act *before* something reaches KEV. That's the job of EPSS, which is forward-looking and will often flag a vulnerability as high-probability days or weeks before it's confirmed exploited, and of the CVSS-plus-context dimensions, which flag a dangerous, exposed, sensitive asset regardless of whether anyone has attacked it yet. So the blend is deliberately both leading (EPSS, exposure) and lagging (KEV, live IDS evidence). The Equifax breach in 2017 is the cautionary tale: the Apache Struts flaw (CVE-2017-5638) was a known, patchable vulnerability sitting on an internet-facing application holding sensitive data — exactly the profile our model escalates *before* any KEV-style confirmation.

**Q11. CVSS base scores ignore temporal and environmental metrics. You already hold asset context — why not compute environmental CVSS yourself?**
That's a sharp question and a fair enhancement to suggest. We *do* use the same underlying information that CVSS environmental metrics would — asset criticality, exposure, data sensitivity — but we apply it as separate, named weighted dimensions rather than collapsing it back into a single recomputed CVSS number. The reason is transparency: "business impact contributed 15 points" is clearer to a reviewer than "we re-derived an environmental CVSS of 8.3". Functionally the two approaches use the same signal; ours just keeps it legible. **Future scope:** emitting a recomputed environmental/temporal CVSS alongside our score, for teams that specifically want it, is a low-effort addition that wouldn't change the architecture.

**Q12. The presence of a CVE on an asset isn't the same as it being exploitable there — patch level, configuration, and compensating controls all matter. How do you deal with that?**
Completely agree, and we're careful not to overclaim. CEGP prioritises what the scanner *reports*; it does not independently prove that a given instance is exploitable. What it does to compensate is threefold: the exception workflow lets a team formally down-rank a finding that has a compensating control or is a confirmed false positive, with a recorded justification; the IDS/IPS correlation (Intrusion Detection/Prevention System — the sensors that watch network traffic for attacks) raises findings where there's *live evidence* of targeting; and the network-exposure analysis distinguishes a reachable asset from an isolated one. True per-instance exploitability checking would need integration with a validation tool. **Future scope:** connecting to breach-and-attack-simulation or exploit-validation tooling to confirm reachability is a clear roadmap item.

**Q13. How can you correlate an IDS alert to a specific vulnerability when an alert on a host doesn't prove that particular CVE is the entry point?**
We're deliberately modest about what the correlation claims. It is *asset-level*, not CVE-level: an intrusion alert tells us this host is demonstrably under attack, which raises the host's overall exposure and therefore the priority of its vulnerabilities — it is *not* a claim that one specific CVE is the vector being used. We also weight the alert by its severity and confidence so low-quality noise barely moves the needle, and we cap the whole IDS dimension at 15% of the score so it can escalate but never dominate. **Future scope:** if the IDS provides signature-to-CVE mapping, we can ingest it and tighten the correlation to the CVE level.

**Q14. IDS/IPS sensors are notorious for false positives — won't that noise pollute your score?**
It would if we treated every alert as equal truth, which we don't. Each alert contributes according to its severity and the sensor's stated confidence, so a low-confidence informational alert adds very little, while a high-confidence "known exploit signature" adds a lot. Capping the dimension at 15% is the second safeguard — even a burst of noisy alerts can't single-handedly drive an asset to Critical without corroborating threat and exposure signals. In a real deployment we'd tune this against the specific sensor's known false-positive profile, which is exactly how a SOC (Security Operations Centre) already reasons about its own tooling.

**Q15. Your model scores findings individually — what about attack paths, where a low-severity flaw is the stepping stone to a crown-jewel asset?**
This is the most important conceptual limitation of the tool and I'd rather raise it myself than have it raised for me. CEGP is a per-finding prioritiser; it does not build an attack graph, so it won't natively spot that a trivial vulnerability on a forgotten server is the pivot an attacker uses to reach the domain controller. It compensates partially — business-impact weighting pushes crown jewels up, and network-zone analysis flags lateral-movement-friendly exposure — but that's not the same as true path analysis. Genuine attack-path modelling (think BloodHound-style graphs, or exposure-graph products like those from XM Cyber) is a different and complementary class of tool. **Future scope:** ingesting an attack-graph feed and using "is this finding on a path to a crown jewel?" as an additional scoring dimension is, in my view, the most impactful future enhancement of the whole project.

**Q16. Does the model assume an external attacker? How does it treat insider threat?**
The current weighting is tuned for the external-attacker and external-exploitation case, because that's what KEV, EPSS and internet-exposure signals describe best, and it's the most common breach vector. Insider threat is partially captured — data sensitivity, privacy impact and asset criticality all matter regardless of who the attacker is — but we don't model insider-specific signals like anomalous user behaviour. We'd rather be honest that this is an external-exploitation-centric model than overclaim. **Future scope:** incorporating identity and user-behaviour-analytics signals to weight insider risk is a logical extension once those feeds are integrated.

**Q17. Can it handle findings that aren't CVEs at all — misconfigurations, weak ciphers, missing patches without a CVE identifier?**
Today the enrichment pipeline is CVE-centric, because CVSS, EPSS and KEV are all keyed on the CVE (Common Vulnerabilities and Exposures) identifier. A misconfiguration like an open storage bucket or a weak TLS cipher doesn't have a CVE, so it wouldn't get threat-intelligence enrichment — though it would still be scored on business, network and privacy context if supplied. We're clear-eyed that modern exposure management has to cover more than CVEs. **Future scope:** adding a parallel path for non-CVE findings (cloud misconfigurations from CSPM tools, CIS benchmark failures) scored on context and a severity rating is a planned broadening from "vulnerability management" toward full "exposure management".

### C. Machine learning & threat intelligence

**Q18. EPSS is itself a machine-learning model — do you understand how it's built and where it fails?**
Yes, and it's worth being precise because panels often probe this. EPSS is produced by FIRST (the Forum of Incident Response and Security Teams) by training a model on real exploitation evidence and a large set of vulnerability features, and it outputs a probability between 0 and 1 that a vulnerability will be exploited in the next 30 days. Its known weaknesses are that it's a *global* model — it doesn't know anything about *your* environment — that it can be poorly calibrated for very new or very niche vulnerabilities where there's little data, and that it shifts each time it's retrained. We consume it as exactly one input among several precisely so that no single model's blind spot decides the outcome.

**Q19. Why not use machine learning for the overall scoring? Defend the explainability-versus-accuracy trade-off.**
For a decision a human has to *act on and justify*, I'll take explainability over a marginal accuracy gain almost every time, and here's the practical reason. When you tell an engineering team to drop their sprint and patch something at 2 a.m., they will ask why, and "the model said so" is not an answer that builds trust or survives a post-incident review. A transparent weighted model lets us defend every point; a black-box model can't. If we *did* introduce machine learning — say, to learn the weights — we'd pair it with an explainability technique like SHAP (SHapley Additive exPlanations, which attributes a prediction back to its input features) so we keep the "why" alongside the "what". **Future scope:** an ML-assisted score presented *with* SHAP attributions, never instead of the transparent score, is how we'd evolve this responsibly.

**Q20. If you trained your own exploitation-prediction model, how would you handle class imbalance, label leakage, and concept drift?**
These three would genuinely make or break such a model, so it's a good test of whether we've thought it through. Class imbalance is severe — only a small fraction of CVEs are ever exploited — so plain accuracy is a useless metric (a model that says "never exploited" would look 98% accurate and be worthless); we'd use class weighting or resampling and evaluate with precision, recall and PR-AUC (the area under the precision-recall curve, which is the right metric for rare positives). Label leakage is the subtle trap: KEV can be the *label* we're predicting, so it must never also be a *feature*, or the model just learns to cheat. Concept drift — the fact that exploitation patterns change over time — is handled with time-split validation and periodic retraining while monitoring calibration. The fact that we can name these upfront is itself the reassurance that we wouldn't build it naively.

**Q21. How is the offline threat-intelligence kept current — won't a frozen copy become misleading?**
The offline set exists for one purpose: a reproducible, network-independent demonstration, where "frozen" is a feature, not a bug. In any real deployment you'd run in live mode, where CVSS, EPSS and KEV are fetched from their authoritative sources (NVD, FIRST and CISA respectively) and refreshed on a schedule, so the data is current. The offline copy would be refreshed periodically as a fallback for when those services are briefly unreachable. We'd never position a static intelligence snapshot as suitable for day-to-day production use, and the architecture doesn't require it to be.

### D. Architecture, performance & data engineering

**Q22. pandas is single-node and in-memory — at enterprise scale, with millions of findings, that won't fit in memory. What's the architecture then?**
The prototype uses pandas because the demonstration dataset is small and pandas gives us fast, readable, vectorised data processing — the right tool for proving the engine. The crucial design choice is that the scoring logic is *stateless per record* and decoupled from both the data source and the interface, so scaling it doesn't mean rewriting it. For large or continuous workloads you'd run the same logic over a distributed engine like Apache Spark, or push it down into a columnar warehouse such as BigQuery or Snowflake, or simply process in chunks — none of which changes the scoring rules. **Future scope:** a warehouse-backed batch mode is the natural path to enterprise volume, and it's explicitly on the roadmap (§16, §19).

**Q23. Streamlit re-runs the whole script on every interaction and keeps session state in memory — how does that survive real concurrency and large data?**
It's important to separate the *prototype runtime* from the *target runtime*. Streamlit is a superb tool for building a clear, interactive analytical interface quickly, which is exactly what a project at this stage needs, but it isn't the production server, and we don't pretend it is. In a hosted deployment the heavy computation moves behind a service or API with a database, so the browser interaction is lightweight and the re-run model isn't doing the expensive work. We're explicit that the current single-session, in-memory model is a prototype constraint listed in §23, not the end state.

**Q24. Four files joined on asset and CVE keys — how do you guarantee correctness with missing assets, mismatched keys, and many-to-many relationships?**
This is where a lot of well-meaning tools silently go wrong, so we were careful. The joins are *left joins anchored on the vulnerability records*, which means a finding is never silently dropped just because its asset is missing from the inventory — instead it keeps conservative default context and is flagged as a data-quality notice. Duplicates and malformed keys are caught during validation before the join. Many-to-many cases — several IDS alerts or several exceptions for the same asset and CVE — are aggregated *explicitly* (we take counts, the maximum severity, the validity status) rather than letting the join quietly multiply rows. The principle is that data problems should be *surfaced*, never hidden.

**Q25. The audit log and history are file-based with last-write-wins semantics — what about durability and concurrency?**
Those are prototype limitations and they're listed plainly in §23. File-based state is perfectly fine for a single analyst running assessments, but it isn't safe for multiple concurrent users or durable for audit retention. The production design replaces it with a transactional database, which simultaneously solves concurrency, durability, multi-user safety, and the ability to keep a proper history of assessments over time. **Future scope:** a database backend is one of the highest-priority roadmap items because it unlocks several other capabilities at once.

**Q26. How much effort is it to onboard a brand-new organisation's data — is it a heavy integration project?**
Lighter than people expect, because the tool ingests the *exports* that organisations already produce. The work is mostly a one-time column mapping: pointing the scanner's CVE and asset fields, the CMDB's (Configuration Management Database — the system of record for assets and their owners) inventory fields, and the SIEM's (Security Information and Event Management — the central log and alert platform) alert fields to our expected schema. Once that mapping exists, ingestion is repeatable. We proved this works on data the engine was never tuned for by running three independent mock organisations — retail, healthcare and finance — through it cleanly. **Future scope:** pre-built mappings for the common scanners and CMDBs would turn this from a short mapping exercise into a near-instant connect.

### E. Security of the tool & secure engineering

**Q27. What's the threat model of the tool itself? It aggregates an organisation's entire exposure map — that's a high-value target.**
Exactly right, and it's a point we take seriously rather than wave away: a consolidated map of where you're weakest is precisely what an attacker would love to steal, so the tool must be governed at least as well as the systems it assesses. The defences are layered: authentication so only known users get in (§20), role-based access so they see only what their role permits, encryption of data both in transit and at rest, secrets held in a managed vault rather than in code, network restrictions or a Web Application Firewall in front, and an attributed audit log of every action. In short, the tool is expected to live by the same governance it preaches.

**Q28. HMAC proves integrity but not cross-party authenticity — why not asymmetric digital signatures for true non-repudiation?**
That's a precise and correct distinction, and the honest answer is that it depends on who needs to trust the report. HMAC (Hash-based Message Authentication Code) uses a single shared secret key, which makes a report *tamper-evident*: anyone with the key can confirm it hasn't been altered, which is sufficient when the signer and the verifier are inside the same organisation. But because the key is shared, HMAC can't prove *to an outside party* who created the report — for that you want asymmetric digital signatures (a private key signs, a public key verifies), as with RSA or ECDSA, ideally via a key-management service. We built the integrity module so the signing primitive can be swapped. **Future scope:** offering asymmetric signing for reports that leave the organisation — say, to an external auditor or regulator — is the right upgrade and a planned one.

**Q29. Where does the HMAC key live, how is it rotated, and what's the blast radius if it's compromised?**
In production the key lives in a secrets manager or cloud KMS (Key Management Service), injected into the application as an environment variable, never written into the source code. Rotation is handled as a key-version change, and older reports stay verifiable against the version that originally signed them. If the key were compromised, the practical impact is that an attacker could forge valid-looking integrity signatures going forward — which is exactly why it's vaulted, access-controlled, and rotatable, and why moving to asymmetric signing (Q28) further limits exposure.

**Q30. Your CSV-injection defence handles the leading `=`, `+`, `-` and `@` characters — what about DDE, hyperlink, and Unicode tricks?**
Good — this tells me the questioner knows the topic. CSV or formula injection is the risk that a malicious value in an exported spreadsheet executes as a formula when someone opens it; our sanitiser neutralises the standard trigger characters, including leading tabs and carriage returns. A fully hardened pass would also explicitly cover DDE (Dynamic Data Exchange) payloads and Unicode look-alike characters that try to sneak past the filter. We treat all exported, externally-sourced data as untrusted by default, which is the right baseline. **Future scope:** extending the sanitiser to the full DDE and Unicode set is a small, bounded hardening task we'd do before any external release.

**Q31. There's an irony in a vulnerability tool having its own vulnerable dependencies — how do you manage your software supply chain?**
We feel that irony keenly, which is why it's handled deliberately rather than ignored. Dependencies (Streamlit, pandas, Plotly and the rest) are pinned to specific versions in the requirements file so we know exactly what we're shipping, they're scanned for known vulnerabilities with tools like pip-audit or Dependabot, and we can produce an SBOM (Software Bill of Materials — a formal inventory of every component in the software) so anyone can audit what's inside. In a containerised deployment the image itself is scanned in the build pipeline. A tool that preaches patching has no business running on stale, vulnerable libraries, and we hold ourselves to that.

**Q32. Uploaded files are untrusted input — how do you defend against malicious CSV/Excel: zip bombs, oversized files, formula payloads, encoding attacks?**
Every uploaded file is treated as hostile until proven otherwise. Parsing is done defensively with explicit schema validation, so malformed structures are rejected with a clear message rather than crashing the engine; exports are sanitised as above; and in a hosted deployment we'd add upload size and type limits, resource quotas to defang decompression ("zip bomb") attacks, and sandboxed processing so a malicious file can't reach anything it shouldn't. Keeping the parsing libraries current limits decoder-level vulnerabilities. The mindset throughout is least trust toward input.

**Q33. Where is the organisation's own data processed, and what about data residency and privacy of that data?**
This matters because the data the tool handles — asset inventories, exposure maps — is itself sensitive, even though it's not personal data in the usual sense. In the local prototype, nothing leaves the machine it runs on. In a cloud deployment, you'd pin the service and its database to a chosen region to satisfy data-residency requirements, encrypt everything, and restrict access by role. **Future scope:** for organisations with strict sovereignty rules, the same container can run entirely on-premises or in a private cloud, since the architecture has no hard dependency on a specific provider beyond the live intelligence feeds.

### F. Validation, evaluation & statistics

**Q34. Your back-test used seven known-exploited CVEs that all scored Critical — isn't that confirmation bias, since they're high-severity KEV anyway?**
It's a fair challenge and I want to answer it squarely rather than dodge it. That back-test is a *necessary* check, not a *sufficient* proof — its job is to confirm the model doesn't do something embarrassing, like fail to escalate Log4Shell or MOVEit. A model that missed those would be disqualified on the spot, so passing this test is the floor, not the ceiling. The evidence that the model *discriminates* rather than just rating everything high is the control case — a low-severity, internal, encrypted asset scoring around 35 (Low) — and, more rigorously, the proper evaluation we describe in §25: run a *held-out* set that includes plenty of vulnerabilities that were *never* exploited, and measure precision and recall, not just "did the famous ones score high". We're upfront that the rigorous evaluation is the next step, which is more honest than presenting seven cherry-picked wins as conclusive.

**Q35. What's your posture on false positives versus false negatives? In security the costs aren't symmetric.**
They're very much not symmetric, and the model is tuned with that in mind. A false negative — failing to escalate something that *is* being exploited — can mean a breach, whereas a false positive — escalating something that turns out to be lower risk — costs some wasted analyst time. So for the top band the model deliberately leans toward recall: it would rather over-escalate a borderline item than miss a live one. The exception workflow then provides a *controlled* way to walk back a confirmed false positive, with a recorded justification, so we get the safety of high recall without permanently inflating the queue.

**Q36. How would you actually prove this prioritisation reduces risk faster than CVSS-only triage?**
With a concrete, measurable experiment rather than an assertion. Take a historical window of findings, rank them two ways — once by CVSS alone, once by CEGP — and then measure which ordering would have caused the vulnerabilities that *later turned out to be exploited* (i.e. later appeared in KEV) to be remediated sooner. If CEGP's ordering yields a lower mean-time-to-remediate for those genuinely-exploited items, that's quantitative proof it directs effort better. That's the kind of evidence that turns a plausible story into a defended claim, and it's the evaluation we'd run with real historical data.

### G. Dependencies, limitations, benefits & challenges

**Q37. What are the tool's hard dependencies, and what happens if one of them fails?**
Functionally it leans on three things: the threat-intelligence feeds (NVD for CVSS, FIRST for EPSS, CISA for KEV) for enrichment; the Python data stack (pandas, Plotly) for computation and visualisation; and, in live mode, network access subject to those services' rate limits. The important part is the failure behaviour: if a feed is unreachable, rate-limited, or changes its format, the tool falls back to the bundled offline intelligence and conservative defaults, flags that confidence is reduced, and keeps working — it degrades gracefully rather than falling over. That fail-safe behaviour is a deliberate design choice, because a security tool that simply stops the moment an external service hiccups isn't trustworthy.

**Q38. What are the principal limitations you'd concede before being asked?**
I'd rather list them myself, because owning them is more convincing than being cornered into them. They are: it scores findings individually and doesn't yet do attack-path analysis (Q15); it's CVE-centric, so it's weak on true zero-days and non-CVE misconfigurations until intelligence exists (Q17); the scoring model is explainable but a heuristic, not a certified quantitative risk model; the IDS correlation is asset-level rather than CVE-level (Q13); and the current runtime is a single-operator, file-based prototype rather than a hardened multi-user service. Every one of these is documented in §23 and mapped to a roadmap item, which is the point — they're known and planned, not blind spots.

**Q39. What were the hardest engineering and design challenges you faced?**
Three stand out. The first was designing a scoring model that is simultaneously *meaningful* and *explainable* across wildly different assets — a hospital database and a developer's laptop have to be scored by the same logic and both come out sensible. The second was the data engineering: making four independent, imperfect, real-world data sources join together reliably without silently dropping or duplicating findings, which is exactly where naive implementations break. The third was reproducibility — building something whose results you can regenerate and compare, despite intelligence feeds that change every day. The decision that made all three tractable was separating the data source from the scoring engine early; almost everything good about the architecture flows from that one choice.

**Q40. What are the concrete benefits over a plain CVSS-only programme — can you make the value tangible?**
Yes, and I'd make it tangible with the Citrix Bleed example from §25: a vulnerability that CVSS rates only 7.5 — a "High", easily buried under dozens of 9-and-10-rated findings — is correctly pushed to Critical by our model because it's actively exploited, internet-facing, and touches sensitive data. A CVSS-only team patches the 9.8s first and might get to Citrix Bleed days later, by which time they've been breached; our model surfaces it on day one. Beyond that single case, the benefits are that it collapses a long undifferentiated list into a focused fix-first set, it attaches an owner, an SLA (Service-Level Agreement — the agreed time to remediate) and a remediation playbook so prioritisation actually becomes action, and it produces signed, auditable evidence. The measurable benefit is a lower time-to-remediate for the vulnerabilities that genuinely get exploited.

### H. Governance, compliance & operational reality

**Q41. How does this map to recognised frameworks, and would auditors actually accept its output as evidence?**
It aligns naturally with the risk-based vulnerability management approach that NIST (the U.S. National Institute of Standards and Technology) and CISA both advocate, and exposures can be mapped to control domains in NIST CSF (Cybersecurity Framework), the CIS Controls, and MITRE ATT&CK (the public knowledge base of real-world attacker tactics and techniques). On the audit question, the tamper-evident, attributed reports are designed precisely to be presentable as evidence — an auditor cares that a report is complete, attributable, and unaltered, which is what the HMAC signing and audit log provide. **Future scope:** an explicit SSVC-style decision output would make it even more directly consumable by regulators who prefer a framework verdict.

**Q42. Your SLAs assume a vulnerability can be fixed in N days — how do you handle the reality that some genuinely can't be patched (legacy systems, vendor lock-in)?**
This is the situation every real programme hits, and pretending everything is patchable would make the tool naive. For findings that can't be remediated in time — an unsupported legacy system, a flaw the vendor hasn't fixed — the risk-acceptance and exception lifecycle takes over: the item is formally accepted or deferred with a documented justification, a named owner, a compensating control, and crucially an *expiry date*. It stays visible and tracked rather than vanishing, and when the exception expires it automatically resurfaces for review. That's how you stay honest about residual risk instead of quietly ignoring it.

**Q43. How do you stop this from becoming "risk theatre" — a pretty dashboard that nobody acts on?**
By closing the loop from insight to action, which is the difference between a report and a tool. Every high-priority exposure carries an owner, an SLA countdown, and a concrete remediation playbook, so there's always a clear next step and a clear person; escalations fire automatically when an SLA is breached; and in the integrated design the findings push tickets into the team's existing ITSM or SOAR (Security Orchestration, Automation and Response) system so the work lands in their normal queue and is tracked to closure. The audit trail then makes *inaction* visible — an overdue critical is on the record — which is what creates accountability rather than theatre.

### I. Scaling, deployment & adoption

**Q44. Cloud Run is stateless and scales to zero — how do you run a stateful, WebSocket-based Streamlit app on serverless reliably?**
It works, but only if you configure for the app's nature rather than fighting it. Streamlit holds an open WebSocket connection per session, so you set a high request timeout to keep that connection alive, keep a minimum of one warm instance to avoid the cold-start delay when someone first connects, enable session affinity so a user stays pinned to their instance, and adjust the CORS and XSRF settings that otherwise clash with the authenticating proxy. Anything that genuinely must persist — assessment history, the audit log — is externalised to a database rather than held in the instance, so an instance being recycled never loses data. We're specific about these settings because "just deploy it" is exactly where naive serverless Streamlit deployments fall over.

**Q45. If it's hosted for several teams at once, how do you keep their data isolated?**
Multi-tenancy is enforced at two layers. At the identity layer, access is controlled per tenant through role-based access and the authenticating proxy, so a user only ever authenticates into their own organisation's view. At the data layer, each tenant's data is partitioned in the database so one team's exposure map is structurally inaccessible to another. This isn't an afterthought — for any shared hosted version it's a hard design requirement, and it's noted as such on the roadmap.

### J. Practical, cost & demonstration

**Q46. What does it cost to run, and are there licensing implications?**
The tool itself is built entirely on open-source components — Python, Streamlit, pandas, Plotly — so there are no per-seat or per-scan licence fees of the kind a commercial platform charges, which is a genuine advantage for a learning environment, a small organisation, or an evaluation. The only real costs are infrastructure if you host it in the cloud, and because a service like Google Cloud Run scales to zero and bills per request, light or intermittent use is inexpensive; the main always-on cost is the load balancer used for authenticated access. The threat-intelligence feeds it relies on — NVD, EPSS, KEV — are themselves free and public. So the economic story is "enterprise-grade prioritisation thinking without enterprise licensing", which is part of the point.

**Q47. Can you walk us through how one specific score is actually built up?**
Happily — a worked example makes it concrete. Take Log4Shell (CVE-2021-44228) on an internet-facing customer-portal server holding personal data, with an intrusion alert against it. The threat-intelligence dimension is near-maximal: it's KEV-listed (confirmed exploited), its EPSS percentile is around 0.99 (almost certain to be exploited), and its CVSS is 10.0 — so that 35-point dimension is essentially full. Network exposure is high because it's internet-facing with a risky open service, so most of those 20 points apply. Business impact is high because it's a production, customer-facing asset. The IDS dimension contributes because there's a live exploit alert, and the privacy dimension contributes because personal data is involved. Add the weighted contributions and it saturates at 100 — Critical, 7-day SLA. Contrast that with the same CVE on an isolated, encrypted lab box with no alert: the threat dimension is identical, but exposure, business, IDS and privacy all but disappear, and it lands far lower. *That contrast is the whole thesis of the tool in one example.*

**Q48. What data is the demonstration running on, and is any of it real or sensitive?**
None of it is real — and that's deliberate. The demonstration runs on a bundled, fully offline dataset of roughly 300 realistic but fictional exposures, engineered to exercise every scoring path, plus three independent mock organisations spanning retail, healthcare and finance. No real customer, asset, or personal data is involved, so the demo is both safe to show openly and identical every time it runs, which is exactly what you want when you're being assessed on it.

---

*Cyber Exposure Governance Platform — an M.Sc. Cyber Security project by Dwaipayan Mojumder and Deblina Das, under the guidance of Prof. Sanjay Pal.*
