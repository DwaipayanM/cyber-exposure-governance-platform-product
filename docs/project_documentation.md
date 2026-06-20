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
4. [Cybersecurity Strategies & Techniques Used](#4-cybersecurity-strategies--techniques-used)
5. [Why This Approach Is Good](#5-why-this-approach-is-good)
6. [Core Capabilities](#6-core-capabilities)
7. [How It Works — The Processing Pipeline](#7-how-it-works--the-processing-pipeline)
8. [The Scoring Model](#8-the-scoring-model)
9. [The Dashboard & Views](#9-the-dashboard--views)
10. [Inputs & Data Model](#10-inputs--data-model)
11. [Security, Integrity & Governance](#11-security-integrity--governance)
12. [Bundled Datasets](#12-bundled-datasets)
13. [Technology Stack](#13-technology-stack)
14. [Running the Application Locally](#14-running-the-application-locally)

**Part B — Scaling Up: Integrations, Automation & Deployment**
15. [From Static Files to Live Data — Future Integrations](#15-from-static-files-to-live-data--future-integrations)
16. [Integration Mechanisms](#16-integration-mechanisms)
17. [Automation Possibilities](#17-automation-possibilities)
18. [Deploying for Real-Time, Multi-User Access](#18-deploying-for-real-time-multi-user-access)
19. [Authentication & Access Control](#19-authentication--access-control)
20. [Production Security & Compliance](#20-production-security--compliance)

**Part C — Reference**
21. [Outcomes & Benefits](#21-outcomes--benefits)
22. [Scope & Limitations](#22-scope--limitations)
23. [Roadmap Summary](#23-roadmap-summary)
24. [Glossary](#24-glossary)
25. [References & Links](#25-references--links)

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

## 4. Cybersecurity Strategies & Techniques Used

CEGP is not a single trick — it is a deliberate combination of recognised cybersecurity strategies, each contributing one part of the risk picture. This section names each technique, explains it briefly, and **points to exactly where it appears in the application** so the link between theory and the UI is explicit.

### 4.1 Technique-to-UI map

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

### 4.2 The unifying strategy

The single overarching strategy is **multi-signal, business-aware risk prioritisation with governance and evidence**. Threat intelligence (techniques 2–4) answers *"how likely and how bad?"*, exposure and business analysis (5, 8) answer *"how reachable and how important?"*, detection and privacy (6, 7) answer *"is it under attack and what data is at stake?"*, and the governance, simulation, reporting and audit layers (9–16) turn that into accountable, provable action. Explainability (17) ties it together so the output is defensible.

---

## 5. Why This Approach Is Good

A fair question is: *plenty of tools score vulnerabilities — why this design, and why these techniques?* This section answers it directly.

### 5.1 What other options exist in the market?

| Option | What it does | Limitation it leaves open |
|---|---|---|
| **CVSS-only triage** (spreadsheets, scanner default sort) | Ranks by technical severity. | Ignores exploitation likelihood, business value and live threat — the four gaps in §2. |
| **Native scanner dashboards** (Tenable, Qualys, Rapid7) | Show findings from that scanner. | Tied to one data source; limited business/IDS/privacy correlation in the base product. |
| **SIEM dashboards** (Splunk, Sentinel) | Show alerts and detections. | Strong on detection, weak on vulnerability prioritisation and remediation governance. |
| **GRC platforms** (Archer, ServiceNow GRC) | Track risk and compliance. | Governance-heavy, not vulnerability-prioritisation engines. |
| **Quantitative risk methods** (e.g. FAIR) | Express risk in financial terms. | Data-hungry and slow; overkill for day-to-day triage. |
| **Decision frameworks** (CISA **SSVC**) | A decision tree for patch urgency. | Excellent and complementary, but coarser than a continuous score. |

### 5.2 Are there competitors with similar capabilities?

Yes — **Risk-Based Vulnerability Management (RBVM)** is an established commercial category. Representative platforms include **Tenable Vulnerability Management (with Lumin / VPR)**, **Qualys VMDR (TruRisk)**, **Rapid7 InsightVM**, **Microsoft Defender Vulnerability Management**, and specialised risk-prioritisation tools such as **Cisco Vulnerability Management (formerly Kenna Security)**, **Nucleus Security**, **Brinqa**, and **Vulcan Cyber**.

These are mature, powerful enterprise products. But they are also **expensive, complex, and often tied to a vendor's own scanner**, and several treat business context, live IDS correlation, data-privacy impact, and tamper-evident reporting as separate add-ons rather than a single explainable score. CEGP demonstrates the *same core idea* — risk-based, multi-signal prioritisation — in a **transparent, lightweight, vendor-neutral** form.

### 5.3 What are this app's capabilities (the differentiators)?

- **Five signals in one score** — threat intel **+** business **+** network **+** live IDS **+** privacy, not just severity.
- **Fully explainable** — every point of the 0–100 score traces to a factor; nothing is a black box.
- **Live-threat aware** — IDS/IPS correlation flags assets under active attack, a signal pure scanners lack.
- **Privacy as a first-class dimension** — PII, encryption and regulatory impact are scored, not ignored.
- **Governance + simulation + evidence built in** — SLAs, exceptions, what-if modelling, signed reports and an audit trail in the same tool.
- **Vendor-neutral and integration-ready** — consumes any scanner's export today and is designed for live connectors tomorrow (Part B).
- **Transparent and low-cost** — runs on open components, ideal for learning, SMBs, and rapid evaluation.

### 5.4 What if a different technique were used instead?

| Instead of the blended model… | Trade-off |
|---|---|
| **CVSS only** | Simple, but you over-invest in severe-yet-unexploited issues and miss exploited "Medium" ones. |
| **EPSS only** | Captures likelihood but ignores how bad or how important the asset is. |
| **KEV only** | A useful binary flag, but misses CVEs trending toward exploitation that aren't listed *yet*. |
| **Pure quantitative (FAIR)** | Rigorous and financial, but heavy, data-hungry, and impractical for fast daily triage. |
| **SSVC decision tree** | Transparent and excellent — CEGP's logic is compatible with it — but produces coarse buckets rather than a continuous, rankable score. |

CEGP deliberately **blends** these into a weighted, tunable model: it keeps CVSS's severity, adds EPSS likelihood and KEV confirmation, and layers business, network, IDS and privacy context — capturing each technique's strength while compensating for its individual blind spot.

### 5.5 Why should I use this product?

Because it gives a security team the **one thing CVSS-only programmes cannot**: a ranked, defensible answer to *"what do we fix first, and why?"* that already accounts for real-world exploitation, business value, live attack evidence, and data sensitivity — and then carries that decision through to SLAs, simulation, signed reporting, and an audit trail. It is **explainable** (so it survives scrutiny from auditors and senior engineers), **lightweight and vendor-neutral** (so it fits any environment), and **integration-ready** (so it scales from a demo to a live enterprise service). For learning, evaluation, or a focused programme, it delivers enterprise-grade prioritisation thinking without enterprise cost or lock-in.

---

## 6. Core Capabilities

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

## 7. How It Works — The Processing Pipeline

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

## 8. The Scoring Model

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

## 9. The Dashboard & Views

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

## 10. Inputs & Data Model

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

## 11. Security, Integrity & Governance

Because this is a *security* tool, it holds itself to a higher standard than a typical dashboard:

- **Tamper-evident reports (HMAC-SHA256).** Exports are signed with a secret key, so an altered report cannot be re-signed by anyone who lacks the key. This is stronger than a plain checksum, which anyone can recompute. The key is supplied via environment variable in production, or generated and stored locally otherwise.
- **Injection-safe exports.** Exported spreadsheets are sanitised so that a malicious cell cannot execute as a formula when opened in Excel, Sheets, or LibreOffice — a real risk for any tool that exports externally supplied data.
- **Attributed audit log.** Every action records the **operator** and a timestamp, so the trail can answer *who* did *what*, not merely that something happened.
- **Integrity verifier.** A built-in tool lets a reviewer upload any exported report and confirm whether its contents match the original signature.
- **Configurable governance.** SLAs, escalation, and risk-acceptance (with expiry and compensating controls) are first-class, so remediation timelines are tracked and auditable.

---

## 12. Bundled Datasets

To make the platform demonstrable out of the box, it ships with realistic, fully offline data:

- **Primary dataset** — a diversified set of roughly 300 exposures across several hundred assets, deliberately engineered to exercise **every** scoring path: all priority bands, all KEV/EPSS/CVSS combinations, all network zones, IDS exploit and multi-alert cases, every privacy level, SLA breached/due-soon/within states, and valid/expired/no-expiry exceptions. A few rows intentionally trigger non-blocking data-quality notices to demonstrate validation.
- **Small demo set** — a compact set retained for quick walkthroughs, including an Excel copy to demonstrate file upload.
- **Additional mock organisations** — three independent fictional companies (retail, healthcare, finance), each with all four input files, so the tool can be demonstrated on non-default data.
- **Offline threat-intelligence** — bundled KEV/EPSS/CVSS reference data covering every CVE in the samples, so results are identical run-to-run without internet access.

---

## 13. Technology Stack

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

## 14. Running the Application Locally

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

## 15. From Static Files to Live Data — Future Integrations

Today the platform is fed **static files** — a snapshot exported from a scanner, an inventory spreadsheet, an alert dump. This is perfect for demonstrations and offline use, but the same architecture is built to consume **live, continuously updated data** from the systems an organisation already runs.

The crucial point is architectural: CEGP separates **where data comes from** (an ingestion/normalisation layer) from **how data is scored** (the engine). The engine never cares whether a row arrived from a CSV or a live API. That means **every file input can be replaced by a live connector without touching the scoring logic** — the platform simply receives fresh data on a schedule or in real time, and re-scores automatically.

Below are the integration categories, the real systems in each, what they would feed, and why it matters.

### 15.1 Vulnerability Scanners → live findings

| Source systems | Feeds | Value |
|---|---|---|
| Tenable (Nessus / Tenable.io / Tenable.sc), Qualys VMDR, Rapid7 InsightVM, Greenbone/OpenVAS, Microsoft Defender Vulnerability Management, cloud scanners (Wiz, Orca) | The **vulnerability findings** input | Findings refresh automatically after every scan — no manual export. New CVEs are scored within minutes of discovery. |

**How it connects:** most scanners expose a REST API or scheduled export. A connector pulls the latest findings, the normaliser maps them to the standard schema, and an assessment runs. ([Tenable](https://www.tenable.com), [Qualys](https://www.qualys.com), [Rapid7](https://www.rapid7.com), [Greenbone/OpenVAS](https://www.greenbone.net))

### 15.2 Asset Inventory / CMDB → live business context

| Source systems | Feeds | Value |
|---|---|---|
| ServiceNow CMDB, Device42, Lansweeper, Axonius, cloud inventories (AWS Config, Azure Resource Graph, GCP Asset Inventory) | The **asset inventory** input (criticality, owner, environment, data sensitivity) | Business context stays current as assets are added, retired, or reclassified — so prioritisation reflects today's estate, not last quarter's spreadsheet. |

**How it connects:** CMDBs and cloud inventories provide APIs that return assets with ownership and criticality. A scheduled sync keeps the platform's asset picture live. ([ServiceNow](https://www.servicenow.com), [Device42](https://www.device42.com), [Lansweeper](https://www.lansweeper.com))

### 15.3 SIEM / IDS-IPS / EDR → real-time attack evidence

| Source systems | Feeds | Value |
|---|---|---|
| Splunk, Microsoft Sentinel, Elastic Security, Suricata / Snort / Zeek sensors, CrowdStrike / SentinelOne EDR | The **IDS/IPS alerts** input | This is the biggest live-data win: an asset already flagged "High" jumps to top priority **the moment** it is actively targeted, because alerts stream in continuously instead of being dumped once. |

**How it connects:** SIEMs support search APIs, scheduled queries, or streaming outputs; sensors emit events to a collector. The platform consumes the alert stream and re-correlates against vulnerable assets. ([Splunk](https://www.splunk.com), [Microsoft Sentinel](https://azure.microsoft.com/products/microsoft-sentinel), [Elastic Security](https://www.elastic.co/security), [Suricata](https://suricata.io))

### 15.4 Threat-Intelligence Feeds → always-current exploit context

| Source systems | Feeds | Value |
|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/), [NVD](https://nvd.nist.gov/), [MISP](https://www.misp-project.org/), commercial TI (Mandiant, Recorded Future), VirusTotal | The **threat-intelligence enrichment** layer | Exploitation likelihood and "known exploited" status are refreshed daily, so a vulnerability that becomes weaponised overnight is re-prioritised the next morning. |

**How it connects:** these are already partially wired in via the platform's optional "live feeds" toggle, which queries the public KEV, EPSS, and NVD services. The same pattern extends to commercial feeds and MISP. ([NVD API](https://nvd.nist.gov/developers))

### 15.5 ITSM / Ticketing / SOAR → close the remediation loop

| Source systems | Feeds | Value |
|---|---|---|
| ServiceNow ITSM / SecOps, Jira, PagerDuty, Cortex XSOAR, Tines, Torq | **Outbound** — the platform *pushes* remediation tickets | Instead of exporting a report for someone to action, the platform can **automatically open a prioritised, playbook-filled ticket** for each critical exposure and track it to closure, enforcing SLAs end-to-end. |

**How it connects:** ITSM/SOAR tools accept tickets via REST API or webhook. The platform's existing "ticket report" becomes a live ticket. ([ServiceNow](https://www.servicenow.com), [Jira](https://www.atlassian.com/software/jira), [PagerDuty](https://www.pagerduty.com))

### 15.6 Cloud Security Posture (CSPM) → cloud exposure

| Source systems | Feeds | Value |
|---|---|---|
| AWS Security Hub, Microsoft Defender for Cloud, GCP Security Command Center | Additional **findings + asset context** for cloud workloads | Extends the same prioritisation to cloud misconfigurations and cloud-native vulnerabilities, not just traditional hosts. |

### 15.7 Identity & Directory → ownership and access

| Source systems | Feeds | Value |
|---|---|---|
| Microsoft Entra ID / Active Directory, Okta | Asset/owner resolution **and** user authentication (see §19) | Resolves "who owns this asset" automatically, and provides the identity backbone for secure multi-user access. |

### 15.8 Data Warehouse / BI → history and board reporting

| Source systems | Feeds | Value |
|---|---|---|
| Snowflake, BigQuery, Databricks; Power BI / Tableau for visualisation | **Outbound** — assessment history is persisted and published | Enables long-term trend analysis, board-level dashboards, and integration with enterprise reporting. |

### 15.9 Collaboration / Notification → alerting

| Source systems | Feeds | Value |
|---|---|---|
| Slack, Microsoft Teams, email/SMTP | **Outbound** notifications | Pushes an alert the instant a new Critical exposure appears or an SLA is about to breach, so teams act without watching the dashboard. |

---

## 16. Integration Mechanisms

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

## 17. Automation Possibilities

Once data is live, the platform can move from "run on demand" to "always on":

- **Scheduled assessments** — run automatically (e.g. every hour or after each scan) so the risk picture is never stale.
- **Event-triggered re-scoring** — a new IDS alert or a newly KEV-listed CVE instantly re-prioritises the affected assets.
- **Automated ticketing** — every new Critical/High exposure becomes a remediation ticket with its playbook already attached.
- **SLA-breach escalation** — overdue items automatically notify owners and managers and raise their score contribution.
- **Proactive alerting** — Slack/Teams/email notifications for new criticals, KEV additions, or active-exploit detections.
- **Policy-as-code** — scoring weights, thresholds, and SLAs version-controlled and promoted through environments like any other configuration.
- **Scheduled signed reporting** — nightly executive and audit reports generated, signed, and archived automatically for compliance.

---

## 18. Deploying for Real-Time, Multi-User Access

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

## 19. Authentication & Access Control

A security tool must not be openly reachable — exposing exposure data to the world would itself be a risk. In a hosted deployment, **no one should reach the dashboard without authenticating**, and different people should see different capabilities. The platform supports a layered model:

### 19.1 Authentication (proving who you are)

- **Single Sign-On (SSO)** via the organisation's identity provider using **OIDC** or **SAML 2.0** — e.g. Microsoft Entra ID, Okta, or Google Workspace. Users log in with their existing corporate account; there is no separate password to manage.
- **Multi-factor authentication (MFA)** — enforced by the identity provider, adding a second factor beyond the password.
- **Enforcement options:**
  - *Application-level* — Streamlit's native authentication / OIDC login, so the app itself gates access.
  - *Proxy-level* — an authenticating reverse proxy (e.g. [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/)) that blocks unauthenticated requests before they reach the app.
  - *Platform-level* — built-in identity (e.g. Google Cloud IAP, Azure App Service Authentication) when hosted on a managed cloud.

The result: an anonymous visitor is redirected to a corporate login and **cannot see any data** until authenticated.

### 19.2 Authorisation (what you're allowed to do)

Role-based access control (RBAC) maps each authenticated user to a role:

| Role | Can do |
|---|---|
| **Viewer** | Read dashboards and reports only. |
| **Analyst** | Run assessments, triage exposures, generate reports. |
| **Approver** | Everything an Analyst can, plus approve risk exceptions/acceptances. |
| **Administrator** | Manage policy (weights, thresholds, SLAs), integrations, and user roles. |

This enforces **least privilege** — for example, only an Approver can formally accept a risk, and only an Admin can change the scoring policy.

### 19.3 Identity-aware audit

The existing audit log already records the operator behind every action. With SSO in place, that operator becomes a **verified corporate identity** rather than a typed-in name, so the audit trail is trustworthy enough for compliance and incident review.

---

## 20. Production Security & Compliance

Beyond login, a hosted deployment should apply standard production controls:

- **Encryption in transit** — all traffic over HTTPS/TLS.
- **Encryption at rest** — database and stored reports encrypted by the platform/cloud.
- **Secrets management** — the HMAC integrity key and all API keys held in a vault or cloud key-management service, never in code or files.
- **Network controls** — host on a private network or behind a VPN, restrict access by IP allow-list, and optionally place a Web Application Firewall (WAF) in front.
- **Standards alignment** — map controls and reporting to recognised frameworks: [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework), [CIS Controls](https://www.cisecurity.org/controls), ISO 27001, and [MITRE ATT&CK](https://attack.mitre.org/); optionally adopt [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) as a decision-output format.
- **Backup & retention** — regular backups of assessment history and signed reports for audit retention requirements.

Together, §18–§20 describe how the prototype becomes a **secure, authenticated, real-time, enterprise-accessible service**.

---

# Part C — Reference

## 21. Outcomes & Benefits

| Benefit | What it delivers |
|---|---|
| **Efficient prioritisation** | Collapses hundreds of findings into a focused list of exposures that combine severity **and** real exploitation paths. |
| **Scenario planning** | Lets risk managers simulate strategies and see the predicted percentage risk reduction before committing effort. |
| **Audit readiness** | Signed reports plus an attributed audit log — presentable directly to auditors. |
| **Actionable remediation** | Teams receive clear playbooks and SLA countdowns instead of generic technical notes. |
| **Explainability** | Every priority is traceable to its contributing factors, so decisions can be defended. |
| **Integration-ready** | Designed to evolve from static files to live, automated, enterprise-wide data flows. |

---

## 22. Scope & Limitations

The boundaries of v1 are deliberate and stated openly — knowing exactly where a tool is weak is part of good engineering. Each maps directly to the enhancements in Part B.

- **Single-operator, file-based.** State is held in files (last-write-wins); designed for one analyst or a small team. → Addressed by §18 (database + hosting).
- **No access control yet.** No authentication or roles in the local prototype. → Addressed by §19.
- **Manual / file-based integration.** Data arrives as CSV/Excel. → Addressed by §15–§17 (live connectors).
- **Explainable, not certified.** The scoring model is transparent and configurable, but is a decision-support heuristic, not a certified quantitative risk model.

---

## 23. Roadmap Summary

| Theme | Enhancement | Detailed in |
|---|---|---|
| **Live data** | Connectors to scanners, CMDB, SIEM/IDS, threat-intel, cloud posture | §15 |
| **Automation** | Scheduled & event-driven assessments, auto-ticketing, alerting | §17 |
| **Hosting** | Containerised / cloud deployment for real-time, multi-user access | §18 |
| **Security** | SSO, MFA, RBAC, secrets management, network controls | §19–§20 |
| **Persistence** | Database backend and assessment history | §18 |
| **Standards** | Mapping to NIST CSF, CIS, ISO 27001, MITRE ATT&CK; SSVC output | §20 |

---

## 24. Glossary

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

## 25. References & Links

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

*Cyber Exposure Governance Platform — an M.Sc. Cyber Security project by Dwaipayan Mojumder and Deblina Das, under the guidance of Prof. Sanjay Pal.*
