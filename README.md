# Cyber Exposure Governance Platform (CEGP)

A lightweight, risk-based **cyber exposure governance** platform built with Streamlit. It does **not** replace a vulnerability scanner — it consumes scanner-style vulnerability data and helps a team decide **what to fix first, who owns it, when it is due, and what risk reduction is achievable**, backed by audit-ready, tamper-evident evidence.

**Authors:** Dwaipayan Mojumder · Deblina Das — M.Sc. Cyber Security (4th Sem), under the guidance of Prof. Sanjay Pal.

---

## What it does

CEGP enriches CVEs with public threat intelligence and correlates them with asset, network, IDS/IPS, and privacy context to produce a single, explainable **0–100 exposure score**, SLA governance, remediation guidance, and signed reports.

- **Threat enrichment** — CISA KEV (known exploited), FIRST EPSS (exploitation likelihood), NVD (CVSS + description). Live feeds with bundled offline fallbacks for a stable demo.
- **Context scoring** — business impact, network exposure, IDS/IPS correlation, privacy/regulatory impact, and SLA governance, combined via configurable weights in `data/risk_policy.json`.
- **Remediation Action Plan** — plain-language, prioritised action items per exposure (what it is, why it matters, how to fix it, interim mitigation), downloadable as **CSV / Excel / PDF** (the PDF follows a consulting document standard).
- **Assessment History** — every run is archived with metrics and input fingerprints; reopen a past run, diff it against the previous one, and re-download its signed reports.
- **What-if simulation** — model risk reduction from patching/isolation scenarios.
- **Tamper-evident evidence** — every export is sanitised against CSV/formula injection and signed with HMAC-SHA256; a full operator-attributed audit log.

---

## Project structure

```
cyber-exposure-governance-platform/
├── app.py                       # Streamlit application (entry point)
├── requirements.txt
├── verify_pipeline.py           # offline end-to-end pipeline sanity check
├── README.md
├── .streamlit/
│   └── config.toml              # theme + upload limit
├── core/                        # scoring & governance engines (+ __init__.py)
│   ├── scoring_engine.py        privacy_impact_engine.py   policy_engine.py
│   ├── network_exposure_engine.py  ids_correlation_engine.py  asset_context_engine.py
│   ├── remediation_governance.py   playbook_engine.py     control_mapping_engine.py
│   ├── exception_engine.py     import_normalizer.py       validator.py
│   ├── simulation_engine.py    trend_engine.py            ticket_exporter.py
│   ├── report_integrity.py     csv_security.py            audit_logger.py
│   ├── run_history.py           # NEW — per-run archive (local or Cloud Storage)
│   └── storage_backend.py       # NEW — pluggable local/GCS storage
├── services/                    # public threat-intel enrichment (+ __init__.py)
│   ├── cisa_kev_service.py  epss_service.py  nvd_service.py
├── data/                        # sample inputs, policy, offline fallbacks, logs
│   ├── sample_input.csv  asset_inventory.csv  ids_alerts.csv  risk_exceptions.csv
│   ├── risk_policy.json  fallback_kev.json  fallback_epss.json  fallback_nvd.json
│   ├── audit_log.csv  risk_snapshots.csv  .integrity_key
│   └── runs/                    # created at runtime — Assessment History archive
└── docs/
    ├── project_documentation.md       gcp_deployment_guide.md   demo_script.md
    ├── project_report_outline.md      syllabus_mapping.md       test_cases.md
    ├── windows_c_drive_setup.md        ui_preview.html          CEGP_Project_Report.docx
```

`core/` and `services/` each contain an empty `__init__.py`. `data/runs/` is created automatically on the first run.

---

## Prerequisites

- **Python 3.10+** (developed/containerised on 3.12).
- The bundled `data/` folder (sample inputs + offline threat-intel fallbacks).

---

## Quick start (local)

```bash
# 1. From the project root, create and activate a virtual environment
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows (PowerShell):
.\.venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the app
streamlit run app.py
```

Then open the URL Streamlit prints (default <http://localhost:8501>).

In the app: set an **Operator name** in the sidebar, keep **"Use bundled sample files"** enabled, and click **Run Cyber Exposure Assessment**. Live public feeds are off by default (offline fallbacks are used) for a stable demo; toggle them on under **Advanced options**.

> Windows users: see `docs/windows_c_drive_setup.md` for a step-by-step C:\ setup.

---

## Verify the install

Run the offline pipeline check (no Streamlit, no network) to confirm the codebase is healthy:

```bash
python verify_pipeline.py
```

Expected: `Pipeline verification completed successfully! Codebase is healthy.`

---

## Using the app

The dashboard is organised into tabs: **Executive View · Analyst View · Network Exposure · IDS/IPS Correlation · Privacy Impact · Remediation Governance · Action Plan · Simulation · Reports & Integrity · Audit Log · Assessment History.**

- **Action Plan** — prioritised, plain-language remediation cards; download the plan as CSV, Excel, or PDF (all HMAC-signed).
- **Reports & Integrity** — detailed/executive/ticket reports with signatures, plus a verifier to detect tampering.
- **Assessment History** — browse past runs, compare a run with the previous one (new / resolved / still-open exposures), reopen full results, and re-download that run's signed Action Plan.

### Bringing your own data

Turn off **"Use bundled sample files"** and upload your own **vulnerability**, **asset inventory**, **IDS/IPS**, and optional **risk exceptions** files (CSV or Excel). Required columns are validated; see `core/validator.py` and `docs/test_cases.md`. Scoring weights, SLA windows, and priority thresholds are configurable in `data/risk_policy.json`.

---

## Deploying to Google Cloud

A complete, beginner-proof guide is in **`docs/gcp_deployment_guide.md`** — it covers containerising the app, deploying to Cloud Run, storing the signing key in Secret Manager, and locking access down with Identity-Aware Proxy (IAP).

**Cloud-persistent history (optional):** on Cloud Run the local `data/` resets on restart. To persist the Assessment History archive to a bucket instead:

1. Uncomment `google-cloud-storage` in `requirements.txt` and rebuild.
2. Grant the service account access to the bucket.
3. Set environment variables on the service:
   ```bash
   gcloud run services update cegp --region REGION \
     --set-env-vars CEGP_GCS_BUCKET=YOUR_BUCKET,CEGP_GCS_PREFIX=cegp
   ```

When `CEGP_GCS_BUCKET` is unset (the local default), the app uses the filesystem with no change in behaviour. See the guide, **Part 11**, for details.

---

## Security notes

- **Report integrity** — exports are signed with HMAC-SHA256 using a key resolved from the `REPORT_INTEGRITY_KEY` environment variable, or a local `data/.integrity_key` file that is auto-generated on first run if absent. **Treat that key as a secret** — do not commit it to public source control. In the cloud, supply it via Secret Manager (see the GCP guide).
- **Export safety** — all CSV/Excel exports pass through a formula-injection sanitiser (`core/csv_security.py`).
- **Audit trail** — every run, report, simulation, export, and history action is logged with operator and timestamp.

---

## Documentation index (`docs/`)

| File | Purpose |
|---|---|
| `project_documentation.md` | Full project documentation (also viewable in-app). |
| `gcp_deployment_guide.md` | Step-by-step Google Cloud deployment (Cloud Run + IAP + Secret Manager). |
| `project_report_outline.md` | Academic report outline. |
| `syllabus_mapping.md` | Mapping of features to the M.Sc. Cyber Security curriculum. |
| `test_cases.md` | Functional test scenarios and expected results. |
| `demo_script.md` | Suggested live-demo flow. |
| `windows_c_drive_setup.md` | Windows setup walkthrough. |
| `ui_preview.html` | Static preview of the app theme. |
| `CEGP_Project_Report.docx` | Project report (Word). |

---

*Cyber Exposure Governance Platform — an M.Sc. Cyber Security project by Dwaipayan Mojumder and Deblina Das, under the guidance of Prof. Sanjay Pal.*
