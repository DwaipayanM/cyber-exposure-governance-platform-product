# Cyber Exposure Governance Platform

A lightweight cybersecurity product prototype that converts vulnerability data into business-aligned cyber exposure decisions.

## Product Positioning

This platform is not a vulnerability scanner. It is a **risk-based cyber exposure governance and remediation decision-support product**.

It ingests vulnerability records, enriches CVEs with threat intelligence, correlates business/network/IDS/privacy context, calculates cyber exposure risk, assigns SLA, generates remediation playbooks, supports risk exceptions, simulates risk reduction, and exports audit-ready reports with tamper-evident HMAC-SHA256 integrity signatures.

## Final Project Folder Name

Recommended local Windows folder:

```powershell
C:\cyber-exposure-governance-platform-product
```

## Core Capabilities

| Capability | Description |
|---|---|
| Vulnerability intake | Upload standard or scanner-style CSV |
| Threat intelligence | CISA KEV, FIRST EPSS, NVD CVE enrichment with offline fallback |
| Asset context | Business process, owner, criticality, environment |
| Network exposure | Network zone, open ports, firewall status, VPN requirement |
| IDS/IPS correlation | Correlates alert evidence with vulnerable assets |
| Privacy impact | PII, data sensitivity, encryption status, regulatory impact |
| Configurable policy | Risk weights, SLA rules, priority thresholds in JSON |
| Final exposure scoring | Explainable 100-point cyber exposure score |
| Remediation governance | SLA, due date, breach status, owner, escalation |
| Playbook engine | Recommended action, temporary mitigation, validation |
| Risk exceptions | Accepted/deferred risks with expiry and compensating controls |
| Control mapping | Maps exposures to cybersecurity control areas |
| What-if simulator | Shows risk reduction from remediation scenarios |
| Ticket export | Jira/ServiceNow-style CSV export |
| Audit log | Logs assessment, simulation, and report activity with operator attribution |
| Report integrity | Tamper-evident HMAC-SHA256 signing and verification |
| Export safety | CSV/formula-injection sanitisation on all exported files |

## Folder Structure

```text
cyber-exposure-governance-platform-product/
├── app.py
├── requirements.txt
├── README.md
├── core/
│   ├── asset_context_engine.py
│   ├── audit_logger.py
│   ├── control_mapping_engine.py
│   ├── exception_engine.py
│   ├── ids_correlation_engine.py
│   ├── import_normalizer.py
│   ├── network_exposure_engine.py
│   ├── playbook_engine.py
│   ├── policy_engine.py
│   ├── privacy_impact_engine.py
│   ├── remediation_governance.py
│   ├── report_integrity.py
│   ├── scoring_engine.py
│   ├── simulation_engine.py
│   ├── ticket_exporter.py
│   ├── trend_engine.py
│   └── validator.py
├── services/
│   ├── cisa_kev_service.py
│   ├── epss_service.py
│   └── nvd_service.py
├── data/
│   ├── sample_input.csv
│   ├── asset_inventory.csv
│   ├── ids_alerts.csv
│   ├── risk_policy.json
│   ├── risk_exceptions.csv
│   ├── fallback_kev.json
│   ├── fallback_epss.json
│   ├── fallback_nvd.json
│   ├── audit_log.csv
│   ├── risk_snapshots.csv
│   └── cache/
└── docs/
    ├── demo_script.md
    ├── project_report_outline.md
    ├── syllabus_mapping.md
    └── test_cases.md
```

## Windows Setup in C Drive

### Step 1: Extract the ZIP

Extract the downloaded ZIP to:

```powershell
C:\
```

Final path should be:

```powershell
C:\cyber-exposure-governance-platform-product
```

### Step 2: Open PowerShell

```powershell
cd C:\cyber-exposure-governance-platform-product
```

### Step 3: Create Python Virtual Environment

```powershell
python -m venv .venv
```

### Step 4: Activate Virtual Environment

```powershell
.\.venv\Scripts\activate
```

### Step 5: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 6: Run the Application

```powershell
streamlit run app.py
```

The app should open at:

```text
http://localhost:8501
```

## Recommended Demo Settings

For a stable demo:

- Keep **Use bundled sample files** enabled.
- Keep **Use live public feeds when available** disabled.
- Click **Run Cyber Exposure Assessment**.

Offline fallback threat intelligence is included so the demo works without internet access.

## Security Hardening (v1)

This build closes three weaknesses that matter for a security tool:

- **Tamper-evident integrity (HMAC-SHA256).** Reports are signed with a secret key, so an edited report cannot be re-signed by anyone without the key. Set the key via the `REPORT_INTEGRITY_KEY` environment variable in production; otherwise a strong key is generated and stored locally at `data/.integrity_key` (git-ignored, never ship it).
- **CSV / formula-injection protection.** All exported CSVs are sanitised (`core/csv_security.py`) so a malicious cell beginning with `= + - @` cannot execute as a formula when the file is opened in Excel / Sheets / LibreOffice.
- **Operator attribution on the audit log.** Every logged action records the operator name (set in the sidebar) and timestamp, so the audit trail can answer *who* did *what*.

Out of scope for v1 (documented future scope): SSO/RBAC, database backend, live scanner/ITSM API connectors, REST API, containerised deployment.

## Optional Live Feeds

The app can attempt live public enrichment from:

- CISA Known Exploited Vulnerabilities feed
- FIRST EPSS API
- NVD CVE API

For the NVD API, an API key is optional. Without it, public rate limits may apply. The app still works using fallback data.

## Datasets and Upload Formats

- **Bundled dataset:** `data/sample_input.csv` (+ asset/IDS/exception files) ships with ~1,000 exposures across ~800 assets, engineered to exercise every scoring path (all priorities, KEV/EPSS/CVSS bands, network zones, IDS exploit/multi-alert, privacy levels, SLA breached/due-soon/within, and valid/expired/no-expiry exceptions). Offline fallback enrichment covers all CVEs, so it runs deterministically with live feeds off.
- **Small demo set:** `data/demo_small/` holds the original ~41-row set (CSV) plus `sample_input.xlsx` to quickly test Excel upload.
- **Upload formats:** the four uploaders (sidebar, after turning *Use bundled sample files* off) accept **CSV and Excel** (`.csv`, `.xlsx`, `.xls`). Excel files are read from the first sheet.
- **Data-quality notices:** non-blocking validation messages (invalid CVE format, unexpected values, duplicates) are shown on the **Audit Log** tab, not on the main screen.

## Input Files

### `data/sample_input.csv`

Main vulnerability exposure file.

Required fields:

```text
asset_id, asset_name, product, cve_id, business_criticality, internet_facing, environment, asset_owner
```

Optional field:

```text
first_detected_date
```

### `data/asset_inventory.csv`

Business, network, and privacy context.

Important fields:

```text
asset_id, application_name, business_process, business_owner, network_zone, open_ports,
firewall_status, vpn_required, asset_type, data_type, pii_present,
data_sensitivity, encryption_status, regulatory_impact
```

### `data/ids_alerts.csv`

IDS/IPS alert correlation input.

Important fields:

```text
alert_id, asset_id, alert_type, alert_severity, source_ip, destination_ip,
timestamp, signature_name, confidence
```

### `data/risk_policy.json`

Configurable policy file for risk weights, SLA days, and priority thresholds.

## Processing Pipeline

```text
Validate input
→ Normalize scanner-style data
→ Enrich CVEs with KEV, EPSS, and NVD
→ Merge asset/business context
→ Calculate network exposure
→ Correlate IDS/IPS alerts
→ Calculate privacy impact
→ Calculate final cyber exposure score
→ Assign SLA and escalation
→ Generate remediation playbook
→ Apply risk exceptions
→ Map controls
→ Generate dashboards/reports
→ Generate HMAC-SHA256 report signature
→ Write audit log
```

## Final Project Statement

This project implements a cyber exposure governance platform that automatically correlates vulnerability intelligence, asset criticality, network exposure, IDS/IPS alerts, privacy impact, and SLA governance to prioritize remediation, generate playbooks, simulate risk reduction, support risk exceptions, and produce cryptographically verifiable audit reports.

## College Syllabus Coverage

| Subject Area | Coverage |
|---|---|
| Information Security Risk Management | Risk scoring, SLA governance, remediation prioritization |
| Network Security | Internet/DMZ/Internal zones, ports, firewall/VPN context |
| IDS/IPS | IDS alert correlation and escalation |
| Data Privacy | PII, sensitivity, encryption, regulatory impact |
| Cryptography | HMAC-SHA256 tamper-evident report integrity |
| Computer Networks | Ports, IPs, zones, exposed services |
| Operating Systems / Linux Security | OS/product CVEs and remediation context |
| Algorithms | Scoring, classification, prioritization, normalization |
| Pattern Recognition / ML Concepts | Risk classification, prioritization logic, what-if simulation |
| Python Lab | Streamlit + pandas + modular Python implementation |

Biometric security is intentionally not forced into scope because it is not naturally aligned with this product problem.
