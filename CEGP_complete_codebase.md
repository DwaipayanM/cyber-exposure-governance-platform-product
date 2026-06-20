# Cyber Exposure Governance Platform (CEGP) — Complete Codebase Bundle

**Authors:** Dwaipayan Mojumder · Deblina Das — M.Sc. Cyber Security (4th Sem), under Prof. Sanjay Pal

Every file at its **latest audited version**. Recreate the folder structure exactly as in the tree; each file's heading states its path.

> **Audit:** all `.py` compile; `verify_pipeline.py` runs clean; cross-tab dedup verified (only the 4 anchors repeat across tabs); Executive PDF + Action Plan PDF + Assessment History archive all verified end-to-end.

## Folder structure

```
cyber-exposure-governance-platform/
├── .streamlit/
│   └── config.toml
├── core/
│   ├── __init__.py
│   ├── asset_context_engine.py
│   ├── audit_logger.py
│   ├── control_mapping_engine.py
│   ├── csv_security.py
│   ├── exception_engine.py
│   ├── ids_correlation_engine.py
│   ├── import_normalizer.py
│   ├── network_exposure_engine.py
│   ├── playbook_engine.py
│   ├── policy_engine.py
│   ├── privacy_impact_engine.py
│   ├── remediation_governance.py
│   ├── report_integrity.py
│   ├── run_history.py
│   ├── scoring_engine.py
│   ├── simulation_engine.py
│   ├── storage_backend.py
│   ├── ticket_exporter.py
│   ├── trend_engine.py
│   └── validator.py
├── data/
│   ├── .integrity_key
│   ├── asset_inventory.csv
│   ├── audit_log.csv
│   ├── fallback_epss.json
│   ├── fallback_kev.json
│   ├── fallback_nvd.json
│   ├── ids_alerts.csv
│   ├── risk_exceptions.csv
│   ├── risk_policy.json
│   ├── risk_snapshots.csv
│   └── sample_input.csv
├── docs/
│   ├── CEGP_Project_Report.docx
│   ├── demo_script.md
│   ├── gcp_deployment_guide.md
│   ├── project_documentation.md
│   ├── project_report_outline.md
│   ├── syllabus_mapping.md
│   ├── test_cases.md
│   ├── ui_preview.html
│   └── windows_c_drive_setup.md
├── services/
│   ├── __init__.py
│   ├── cisa_kev_service.py
│   ├── epss_service.py
│   └── nvd_service.py
├── README.md
├── app.py
├── requirements.txt
└── verify_pipeline.py
│
└── data/runs/            ← created automatically at runtime (Assessment History archive)
```

> Place each file at the path in its heading. `core/` & `services/` need their empty `__init__.py` (included). On Cloud Run set `CEGP_GCS_BUCKET` to persist history to a bucket (see `docs/gcp_deployment_guide.md`, Part 11).

---

## `README.md`  —  place at: `cyber-exposure-governance-platform/README.md`  ·  _NEW this session_

~~~markdown
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

~~~

---

## `app.py`  —  place at: `cyber-exposure-governance-platform/app.py`  ·  _UPDATED this session_

~~~python
from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core.asset_context_engine import calculate_business_impact, enrich_with_asset_context
from core.audit_logger import log_event, read_audit_log
from core.control_mapping_engine import add_control_mapping
from core.csv_security import sanitize_df_for_export
from core.exception_engine import apply_exceptions, load_exceptions
from core.ids_correlation_engine import correlate_ids_alerts
from core.import_normalizer import normalize_vulnerability_input
from core.network_exposure_engine import add_network_exposure
from core.playbook_engine import add_remediation_playbooks
from core.policy_engine import load_risk_policy
from core.privacy_impact_engine import add_privacy_impact
from core.remediation_governance import assign_remediation_governance
from core.report_integrity import generate_sha256, verify_sha256
from core.run_history import save_run, list_runs, load_run, delete_run, fingerprint_df, storage_mode
from core.scoring_engine import calculate_final_score, calculate_threat_intelligence_score, summarize_score_drivers
from core.simulation_engine import run_simulation
from core.ticket_exporter import build_ticket_export
from core.trend_engine import read_risk_snapshots, save_risk_snapshot
from core.validator import validate_asset_df, validate_ids_df, validate_vulnerability_df
from services.cisa_kev_service import enrich_with_kev
from services.epss_service import enrich_with_epss
from services.nvd_service import enrich_with_nvd


APP_TITLE = "Cyber Exposure Governance Platform"
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"

# ---------------------------------------------------------------------------
# Brand palette  (blue / grey / green / yellow, red used sparingly for Critical)
# ---------------------------------------------------------------------------
# HPE-inspired accent (brand green + charcoal) layered on the existing layout.
GREEN = "#01A982"        # HPE green - primary brand accent
GREEN_D = "#017A5E"      # darker green, legible as text on white
CHARCOAL = "#1D1F27"     # HPE charcoal - dark header band / headings
NAVY = CHARCOAL          # all former navy surfaces now render as charcoal
BLUE = "#1E50A0"         # retained only for the "Medium" priority semantic
BLUE2 = "#2E6FD0"
GREY = "#5B6675"
GREY_BG = "#EEF1F5"
YELLOW = "#C9A227"
RED = "#B23A3A"
INK = "#1F2937"

PRIORITY_COLORS = {"Critical": RED, "High": YELLOW, "Medium": BLUE, "Low": "#2E7D5B"}

# Pale cell styles for colour-coded tables (readable dark text on tint).
PRIORITY_CELL = {
    "Critical": "background-color:#F4D7D7;color:#8E2A2A;font-weight:600",
    "High": "background-color:#F6ECC9;color:#7A5E10;font-weight:600",
    "Medium": "background-color:#DCE6F6;color:#163A6B;font-weight:600",
    "Low": "background-color:#D6EAE0;color:#1C5740;font-weight:600",
}
SLA_CELL = {
    "Breached": "background-color:#F4D7D7;color:#8E2A2A;font-weight:600",
    "Due Soon": "background-color:#F6ECC9;color:#7A5E10;font-weight:600",
    "Within SLA": "background-color:#D6EAE0;color:#1C5740;font-weight:600",
}
YESNO_CELL = {
    "Yes": "background-color:#F4D7D7;color:#8E2A2A;font-weight:600",
}

st.set_page_config(page_title=APP_TITLE, page_icon="\U0001F6E1\uFE0F", layout="wide")


# ---------------------------------------------------------------------------
# Theme / look-and-feel
# ---------------------------------------------------------------------------
def inject_theme() -> None:
    st.markdown(
        """
        <style>
        .block-container {padding-top: 1.4rem; padding-bottom: 2rem; max-width: 1300px;}
        html, body, [class*="css"] {color: #1F2937;}

        /* ---- Header banner ---- */
        .cegp-header {
            background: linear-gradient(115deg, #1D1F27 0%, #23262F 52%, #015E48 88%, #01A982 122%);
            border-radius: 14px; padding: 20px 26px; color: #fff; margin-bottom: 14px;
            box-shadow: 0 6px 18px rgba(21,49,92,.18);
        }
        .cegp-header-row {display:flex; align-items:center; gap:16px;}
        .cegp-logo {font-size: 2.1rem; line-height:1; display:flex; align-items:center;}
        .cegp-authors {font-size:.82rem; color:#EAF6F1; margin-top:3px; font-weight:600;}
        .cegp-conceptcard {background:#F4F8F6; border:1px solid #CDE8DF; border-left:4px solid #01A982;
            border-radius:8px; padding:10px 14px; font-size:.9rem; color:#15315C; margin:6px 0 10px;}
        .cegp-chip {cursor: help;}
        .cegp-title {font-size: 1.5rem; font-weight: 800; letter-spacing:.2px;}
        .cegp-tag {font-size: .9rem; opacity:.92; margin-top:2px;}
        .cegp-badge {
            margin-left:auto; background: rgba(255,255,255,.16); border:1px solid rgba(255,255,255,.35);
            padding: 4px 12px; border-radius: 999px; font-size:.78rem; font-weight:700; letter-spacing:.05em;
        }
        .cegp-chips {margin-top:12px; display:flex; flex-wrap:wrap; gap:8px;}
        .cegp-chip {
            background: rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.28);
            padding: 3px 11px; border-radius: 999px; font-size:.74rem; font-weight:600;
        }

        /* ---- KPI cards ---- */
        .cegp-kpi {
            background:#fff; border:1px solid #E3E8EF; border-radius:12px; padding:13px 16px;
            box-shadow:0 1px 3px rgba(20,49,92,.06); min-height:92px;
        }
        .cegp-kpi-label {font-size:.70rem; letter-spacing:.05em; text-transform:uppercase; color:#5B6675; font-weight:700;}
        .cegp-kpi-value {font-size:1.85rem; font-weight:800; line-height:1.1; margin-top:6px;}
        .cegp-kpi-sub {font-size:.72rem; color:#8A94A6; margin-top:3px;}

        /* ---- Section headers ---- */
        .cegp-section {
            padding:7px 0 7px 12px; margin:14px 0 8px; font-size:1.05rem; font-weight:700; color:#1D1F27;
            background:#F7F9FC; border-radius:0 8px 8px 0;
        }

        /* ---- Tabs: dark band matching the header gradient, green active pill ---- */
        .stTabs [data-baseweb="tab-list"] {
            gap:4px; margin-top:10px; padding:7px; border-bottom:none; flex-wrap:wrap;
            background:linear-gradient(115deg,#1D1F27 0%,#23262F 52%,#015E48 88%,#01A982 122%);
            border-radius:12px; box-shadow:0 4px 14px rgba(21,49,92,.18);
        }
        .stTabs [data-baseweb="tab"] {
            padding:9px 16px; border-radius:8px; color:#D7DEE8; font-weight:700; background:transparent;
        }
        .stTabs [data-baseweb="tab"]:hover {background:rgba(255,255,255,.10); color:#ffffff;}
        .stTabs [data-baseweb="tab"] p {font-weight:700 !important; font-size:.95rem !important;}
        .stTabs [aria-selected="true"] {background:#01A982 !important; color:#ffffff !important;}
        .stTabs [aria-selected="true"] p {color:#ffffff !important;}
        .stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"] {display:none;}

        /* ---- Buttons ---- */
        .stButton>button, .stDownloadButton>button {border-radius:8px; font-weight:600;}

        /* ---- Metric (fallback) ---- */
        [data-testid="stMetric"] {
            background:#fff; border:1px solid #E3E8EF; border-radius:12px; padding:10px 14px;
        }

        /* ---- Sidebar ---- */
        [data-testid="stSidebar"] {
            background:linear-gradient(180deg,#F6F9FC 0%, #EEF4F1 100%);
            border-right:1px solid #E3E8EF;
        }
        /* pull sidebar options up to remove the top gap (collapse the empty header band) */
        [data-testid="stSidebarHeader"] {padding-top:0.3rem !important; padding-bottom:0 !important; min-height:0 !important; height:auto !important;}
        [data-testid="stSidebarUserContent"] {padding-top:0.4rem !important;}
        [data-testid="stSidebarContent"] {padding-top:0 !important;}
        [data-testid="stSidebar"] > div:first-child {padding-top:0 !important;}
        [data-testid="stSidebar"] .block-container {padding-top:0.4rem !important;}
        [data-testid="stSidebar"] h2 {color:#15315C;}
        /* Brand banner at top of sidebar */
        .cegp-sidebrand {
            display:flex; align-items:center; gap:10px;
            background:linear-gradient(120deg,#15171E 0%,#1D1F27 55%,#015E48 130%);
            color:#fff; border-radius:12px; padding:12px 14px; margin-bottom:12px;
            box-shadow:0 4px 12px rgba(21,49,92,.18);
        }
        .cegp-sidebrand .b1 {font-weight:800; font-size:1rem; line-height:1.1;}
        .cegp-sidebrand .b2 {font-size:.72rem; color:#CFE9DF; margin-top:2px;}
        /* Section label */
        .cegp-sidelabel {
            font-size:.74rem; font-weight:800; letter-spacing:.06em; text-transform:uppercase;
            color:#15315C; border-left:4px solid #01A982; padding:4px 0 4px 10px; margin:6px 0 10px;
            background:#FFFFFF; border-radius:0 6px 6px 0;
        }
        /* Expanders */
        [data-testid="stSidebar"] details {
            background:#FFFFFF; border:1px solid #E3E8EF; border-radius:10px; margin-bottom:8px;
        }
        [data-testid="stSidebar"] details summary {font-weight:700; color:#15315C;}
        [data-testid="stSidebar"] details summary:hover {color:#017A5E;}
        /* Inputs */
        [data-testid="stSidebar"] [data-testid="stTextInput"] input,
        [data-testid="stSidebar"] [data-baseweb="select"] > div {border-radius:8px;}
        [data-testid="stSidebar"] button[data-testid="stBaseButton-secondary"] {
            font-family: 'Outfit', 'Inter', 'Segoe UI', sans-serif !important;
            font-weight: 800 !important;
            font-size: 1.05rem !important;
            color: #ffffff !important;
            border: 2px solid #01A982 !important;
            border-radius: 8px !important;
            background-color: #01A982 !important;
            box-shadow: 0 2px 6px rgba(1, 169, 130, 0.25) !important;
        }
        [data-testid="stSidebar"] button[data-testid="stBaseButton-secondary"] p {color:#ffffff !important;}
        [data-testid="stSidebar"] button[data-testid="stBaseButton-secondary"]:hover {
            color: #ffffff !important;
            background-color: #017A5E !important;
            border-color: #017A5E !important;
            box-shadow: 0 4px 12px rgba(1, 122, 94, 0.30) !important;
        }

        /* ---- Dataframe ---- */
        [data-testid="stDataFrame"] {border:1px solid #E3E8EF; border-radius:10px;}
        </style>
        """,
        unsafe_allow_html=True,
    )


CYBER_LOGO_SVG = (
    '<svg width="50" height="50" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">'
    '<path d="M32 3 L56 12 V30 C56 46 46 56 32 61 C18 56 8 46 8 30 V12 Z" '
    'fill="#01A982" stroke="#ffffff" stroke-width="2.5" stroke-linejoin="round"/>'
    '<rect x="22" y="29" width="20" height="16" rx="2.5" fill="#15315C" stroke="#ffffff" stroke-width="2"/>'
    '<path d="M26 29 V24 a6 6 0 0 1 12 0 V29" fill="none" stroke="#ffffff" stroke-width="2.5"/>'
    '<circle cx="32" cy="36" r="2.4" fill="#ffffff"/><rect x="31" y="37" width="2" height="5" rx="1" fill="#ffffff"/>'
    '</svg>'
)

# Concept definitions for the sidebar guide (platform building blocks only).
CONCEPTS = {
    "CVSS": "Common Vulnerability Scoring System \u2014 an industry-standard 0\u201310 score for a vulnerability's technical severity (NVD).",
    "EPSS": "Exploit Prediction Scoring System (FIRST) \u2014 probability (0\u20131) that a CVE will be exploited in the wild within 30 days.",
    "CISA KEV": "CISA Known Exploited Vulnerabilities \u2014 an authoritative catalog of CVEs with confirmed real-world exploitation.",
    "IDS/IPS": "Intrusion Detection / Prevention System \u2014 sensors that detect or block malicious traffic; alerts are correlated to vulnerable assets here.",
    "Privacy Impact": "Assessment of exposure to personal/sensitive data \u2014 PII, sensitivity, encryption status and regulatory impact.",
    "SLA Governance": "Remediation Service-Level governance \u2014 priority-based due dates with breach and escalation tracking.",
    "Exposure Score": "The platform's weighted 0\u2013100 cyber-exposure score combining threat intel, business, network, IDS and privacy.",
}
DIAGRAM_CONCEPTS = ["CVSS", "EPSS", "CISA KEV", "IDS/IPS", "Privacy Impact", "SLA Governance", "Exposure Score"]

# Fuller, plain-English explanations shown in the sidebar concept guide.
CONCEPT_DETAILS = {
    "CVSS": "**Common Vulnerability Scoring System.** An industry-standard score from **0 to 10** rating a vulnerability's *technical severity* \u2014 how damaging it could be if exploited \u2014 published in the NVD. Bands: Low (0.1\u20133.9), Medium (4\u20136.9), High (7\u20138.9), Critical (9\u201310). It measures impact only, **not** whether anyone is actually exploiting it, so the platform combines it with real-world threat and business context.",
    "EPSS": "**Exploit Prediction Scoring System** (by FIRST). A **probability (0\u20131)** that a CVE will be exploited in the wild within the next **30 days** \u2014 a high value means attackers are likely to use it soon. The platform uses the EPSS percentile to weight *likelihood* alongside severity, so vulnerabilities attackers actually use rise to the top.",
    "CISA KEV": "**Known Exploited Vulnerabilities** \u2014 the U.S. CISA catalogue of CVEs **confirmed to be exploited in real attacks**. If a CVE is on this list, exploitation is not theoretical, it is happening now. The platform treats KEV membership as a strong escalator of priority.",
    "IDS/IPS": "**Intrusion Detection / Prevention Systems** \u2014 network sensors that *detect* (IDS) or *block* (IPS) malicious traffic. Their alerts are correlated to your vulnerable assets, so a host that is **both vulnerable and currently being targeted** is flagged for urgent action \u2014 the live \u201cis it under attack now?\u201d signal scanners miss.",
    "Privacy Impact": "**How much sensitive or personal data an asset holds, and how exposed it is.** The platform weighs **PII** presence, data sensitivity, **encryption status**, and regulatory impact (e.g. GDPR / HIPAA). An unencrypted system holding regulated personal data raises both the exposure score and the compliance stakes.",
    "SLA Governance": "**Service-Level governance for remediation.** Each exposure gets a priority-based **due date** (Critical = 7 days, High = 15, Medium = 30, Low = 90) and is tracked as **Within SLA / Due Soon / Breached**, with escalations for overdue items. This turns \u201cwe should fix this\u201d into an accountable, time-bound commitment.",
    "Exposure Score": "**The platform's headline number** \u2014 a single, **explainable 0\u2013100 score** combining threat intelligence (35%), network exposure (20%), business impact (15%), IDS correlation (15%), privacy impact (10%) and SLA governance (5%). It maps to a Low / Medium / High / Critical priority, and because every point traces back to a factor, the result is **defensible, not a black box**.",
}


def render_header() -> None:
    st.markdown(
        f"""
        <div class="cegp-header">
          <div class="cegp-header-row">
            <span class="cegp-logo">{CYBER_LOGO_SVG}</span>
            <div>
              <div class="cegp-title">Cyber Exposure Governance Platform (CEGP)</div>
              <div class="cegp-authors">Dwaipayan Mojumder &middot; Deblina Das &nbsp;|&nbsp; M.Sc. Cyber Security (4th Sem) &nbsp;|&nbsp; Under the guidance of Prof. Sanjay Pal</div>
              <div class="cegp-tag">Risk-based vulnerability prioritization &middot; remediation governance &middot; audit-ready evidence</div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _diagram_svg(concept: str) -> str:
    """Small palette-consistent SVG explainer for a platform concept."""
    G, C, Y, R, GR = "#01A982", "#15315C", "#C9A227", "#B23A3A", "#5B6675"
    base = 'font-family="Segoe UI,Roboto,sans-serif"'
    if concept == "CVSS":
        return (f'<svg viewBox="0 0 460 120" {base} xmlns="http://www.w3.org/2000/svg">'
                f'<text x="8" y="20" font-size="13" fill="{C}" font-weight="700">CVSS severity scale (0\u201310)</text>'
                f'<rect x="8" y="38" width="100" height="26" fill="#D6EAE0"/><rect x="108" y="38" width="120" height="26" fill="#DCE6F6"/>'
                f'<rect x="228" y="38" width="120" height="26" fill="#F6ECC9"/><rect x="348" y="38" width="104" height="26" fill="#F4D7D7"/>'
                f'<text x="58" y="56" font-size="11" fill="#1C5740" text-anchor="middle">Low 0.1\u20133.9</text>'
                f'<text x="168" y="56" font-size="11" fill="#163A6B" text-anchor="middle">Medium 4\u20136.9</text>'
                f'<text x="288" y="56" font-size="11" fill="#7A5E10" text-anchor="middle">High 7\u20138.9</text>'
                f'<text x="400" y="56" font-size="11" fill="#8E2A2A" text-anchor="middle">Critical 9\u201310</text>'
                f'<text x="8" y="92" font-size="11" fill="{GR}">Technical impact only \u2014 the platform combines it with exploitation &amp; business context.</text></svg>')
    if concept == "EPSS":
        return (f'<svg viewBox="0 0 460 120" {base} xmlns="http://www.w3.org/2000/svg">'
                f'<text x="8" y="20" font-size="13" fill="{C}" font-weight="700">EPSS exploitation probability (percentile)</text>'
                f'<rect x="8" y="36" width="440" height="14" rx="7" fill="#EEF1F5"/>'
                f'<rect x="8" y="36" width="352" height="14" rx="7" fill="{G}"/>'
                f'<line x1="228" y1="32" x2="228" y2="54" stroke="{Y}" stroke-width="2"/><text x="228" y="68" font-size="10" fill="{Y}" text-anchor="middle">0.50</text>'
                f'<line x1="360" y1="32" x2="360" y2="54" stroke="{R}" stroke-width="2"/><text x="360" y="68" font-size="10" fill="{R}" text-anchor="middle">0.80</text>'
                f'<text x="8" y="96" font-size="11" fill="{GR}">Higher percentile = more likely to be exploited soon \u2192 higher threat score.</text></svg>')
    if concept == "CISA KEV":
        return (f'<svg viewBox="0 0 460 120" {base} xmlns="http://www.w3.org/2000/svg">'
                f'<rect x="8" y="34" width="120" height="40" rx="6" fill="#EEF1F5" stroke="{GR}"/><text x="68" y="58" font-size="11" fill="{C}" text-anchor="middle">CVE in KEV?</text>'
                f'<path d="M128 54 H180" stroke="{GR}" stroke-width="2" marker-end="url(#a)"/>'
                f'<rect x="180" y="34" width="120" height="40" rx="6" fill="#F4D7D7" stroke="{R}"/><text x="240" y="58" font-size="11" fill="#8E2A2A" text-anchor="middle">Confirmed exploited</text>'
                f'<path d="M300 54 H352" stroke="{GR}" stroke-width="2" marker-end="url(#a)"/>'
                f'<rect x="352" y="34" width="100" height="40" rx="6" fill="{G}"/><text x="402" y="58" font-size="11" fill="#fff" text-anchor="middle">Prioritise</text>'
                f'<defs><marker id="a" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0 L6 3 L0 6" fill="{GR}"/></marker></defs>'
                f'<text x="8" y="100" font-size="11" fill="{GR}">KEV membership is a strong "fix this now" signal.</text></svg>')
    if concept == "IDS/IPS":
        return (f'<svg viewBox="0 0 460 120" {base} xmlns="http://www.w3.org/2000/svg">'
                f'<circle cx="40" cy="54" r="16" fill="#F4D7D7" stroke="{R}"/><text x="40" y="58" font-size="10" fill="#8E2A2A" text-anchor="middle">Attacker</text>'
                f'<path d="M58 54 H120" stroke="{GR}" stroke-width="2" marker-end="url(#b)"/>'
                f'<rect x="120" y="40" width="80" height="28" rx="6" fill="{C}"/><text x="160" y="58" font-size="10" fill="#fff" text-anchor="middle">IDS/IPS</text>'
                f'<path d="M200 54 H262" stroke="{GR}" stroke-width="2" marker-end="url(#b)"/>'
                f'<rect x="262" y="40" width="86" height="28" rx="6" fill="{Y}"/><text x="305" y="58" font-size="10" fill="#5b4708" text-anchor="middle">Alert</text>'
                f'<path d="M348 54 H410" stroke="{GR}" stroke-width="2" marker-end="url(#b)"/>'
                f'<rect x="410" y="40" width="44" height="28" rx="6" fill="{G}"/><text x="432" y="58" font-size="9" fill="#fff" text-anchor="middle">Asset</text>'
                f'<defs><marker id="b" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0 L6 3 L0 6" fill="{GR}"/></marker></defs>'
                f'<text x="8" y="100" font-size="11" fill="{GR}">Live alerts are correlated to the vulnerable asset to confirm active targeting.</text></svg>')
    if concept == "Privacy Impact":
        return (f'<svg viewBox="0 0 460 120" {base} xmlns="http://www.w3.org/2000/svg">'
                f'<rect x="8" y="34" width="84" height="40" rx="6" fill="#EEF1F5" stroke="{GR}"/><text x="50" y="58" font-size="11" fill="{C}" text-anchor="middle">PII?</text>'
                f'<rect x="118" y="34" width="110" height="40" rx="6" fill="#EEF1F5" stroke="{GR}"/><text x="173" y="53" font-size="10" fill="{C}" text-anchor="middle">Sensitivity /</text><text x="173" y="66" font-size="10" fill="{C}" text-anchor="middle">Encryption</text>'
                f'<rect x="254" y="34" width="110" height="40" rx="6" fill="#EEF1F5" stroke="{GR}"/><text x="309" y="58" font-size="10" fill="{C}" text-anchor="middle">Regulatory</text>'
                f'<rect x="390" y="34" width="62" height="40" rx="6" fill="{R}"/><text x="421" y="58" font-size="10" fill="#fff" text-anchor="middle">Impact</text>'
                f'<text x="8" y="100" font-size="11" fill="{GR}">Unencrypted, regulated personal data raises the privacy dimension of the score.</text></svg>')
    if concept == "SLA Governance":
        return (f'<svg viewBox="0 0 460 120" {base} xmlns="http://www.w3.org/2000/svg">'
                f'<text x="8" y="20" font-size="13" fill="{C}" font-weight="700">Detected \u2192 SLA window \u2192 status</text>'
                f'<circle cx="20" cy="50" r="6" fill="{C}"/><text x="14" y="74" font-size="10" fill="{GR}">Detected</text>'
                f'<rect x="20" y="46" width="300" height="8" fill="#D6EAE0"/><rect x="320" y="46" width="120" height="8" fill="#F4D7D7"/>'
                f'<line x1="320" y1="40" x2="320" y2="60" stroke="{C}" stroke-width="2"/><text x="320" y="74" font-size="10" fill="{C}" text-anchor="middle">Due date</text>'
                f'<text x="160" y="40" font-size="10" fill="#1C5740" text-anchor="middle">Within SLA</text><text x="380" y="40" font-size="10" fill="#8E2A2A" text-anchor="middle">Breached</text>'
                f'<text x="8" y="100" font-size="11" fill="{GR}">Due dates derive from priority (Critical 7d, High 15d, Medium 30d, Low 90d).</text></svg>')
    # Exposure Score
    return (f'<svg viewBox="0 0 460 130" {base} xmlns="http://www.w3.org/2000/svg">'
            f'<text x="8" y="18" font-size="13" fill="{C}" font-weight="700">Weighted exposure score (0\u2013100)</text>'
            + "".join(
                f'<rect x="8" y="{30+i*14}" width="{w*3}" height="10" rx="3" fill="{col}"/>'
                f'<text x="{14+w*3}" y="{39+i*14}" font-size="10" fill="{GR}">{lbl} ({w})</text>'
                for i,(lbl,w,col) in enumerate([("Threat intel",35,G),("Network",20,C),("Business",15,Y),("IDS",15,R),("Privacy",10,"#2E7D5B"),("SLA",5,GR)]))
            + f'<text x="8" y="126" font-size="11" fill="{GR}">Components sum to a single, explainable 0\u2013100 priority score.</text></svg>')


def render_sidebar_concepts() -> None:
    """Tucked-away concept guide at the bottom of the sidebar (only if expanded)."""
    with st.expander("\u2139\ufe0f  Concept guide", expanded=False):
        st.caption("What each metric means and how the platform uses it.")
        choice = st.selectbox(
            "View a concept", ["\u2014 all concepts \u2014"] + DIAGRAM_CONCEPTS,
            index=0, key="concept_pick", label_visibility="collapsed",
        )
        if choice and choice != "\u2014 all concepts \u2014":
            st.markdown(_diagram_svg(choice), unsafe_allow_html=True)
            st.markdown(CONCEPT_DETAILS.get(choice, CONCEPTS.get(choice, "")))
        else:
            for k in DIAGRAM_CONCEPTS:
                st.markdown(f"#### {k}")
                st.markdown(CONCEPT_DETAILS.get(k, CONCEPTS.get(k, "")))
                st.divider()


@st.dialog("Project Documentation", width="large")
def show_documentation() -> None:
    doc_path = BASE_DIR / "docs" / "project_documentation.md"
    try:
        st.markdown(doc_path.read_text(encoding="utf-8"))
    except Exception:
        st.warning("Documentation file not found at docs/project_documentation.md.")
    try:
        st.download_button("Download documentation (.md)", data=doc_path.read_bytes(),
                           file_name="project_documentation.md", mime="text/markdown")
    except Exception:
        pass


@st.dialog("Future Scope — Implementation using GCP", width="large")
def show_gcp_guide() -> None:
    guide_path = BASE_DIR / "docs" / "gcp_deployment_guide.md"
    try:
        st.markdown(guide_path.read_text(encoding="utf-8"))
    except Exception:
        st.warning("Guide not found at docs/gcp_deployment_guide.md.")
    try:
        st.download_button("Download GCP guide (.md)", data=guide_path.read_bytes(),
                           file_name="gcp_deployment_guide.md", mime="text/markdown")
    except Exception:
        pass


def section(title: str, accent: str = GREEN) -> None:
    st.markdown(
        f'<div class="cegp-section" style="border-left:4px solid {accent}">{title}</div>',
        unsafe_allow_html=True,
    )


def kpi_card(col, label: str, value, border: str, value_color: str, sub: str = "") -> None:
    col.markdown(
        f"""
        <div class="cegp-kpi" style="border-top:4px solid {border}">
          <div class="cegp-kpi-label">{label}</div>
          <div class="cegp-kpi-value" style="color:{value_color}">{value}</div>
          <div class="cegp-kpi-sub">{sub}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def style_fig(fig, color: str = GREEN):
    fig.update_layout(
        template="plotly_white",
        font=dict(family="Segoe UI, Roboto, sans-serif", color=INK, size=13),
        title=dict(font=dict(size=15, color=NAVY), x=0.01, xanchor="left"),
        margin=dict(l=10, r=10, t=54, b=48),
        plot_bgcolor="#FFFFFF",
        paper_bgcolor="#FFFFFF",
        legend=dict(orientation="h", yanchor="top", y=-0.18, x=0, title_text=""),
    )
    fig.update_xaxes(showgrid=False, title_font=dict(color=GREY), tickfont=dict(color=GREY))
    fig.update_yaxes(gridcolor="#EDF1F6", title_font=dict(color=GREY), tickfont=dict(color=GREY))
    if not fig.data or all(getattr(t, "marker", None) is None for t in fig.data):
        return fig
    for tr in fig.data:
        marker = getattr(tr, "marker", None)
        if marker is None:
            continue
        # Pie/donut markers use .colors (plural); only set .color where it exists and is unset.
        if "color" in getattr(marker, "_props", {}) or hasattr(type(marker), "color"):
            try:
                if marker.color is None:
                    marker.color = color
            except (AttributeError, ValueError):
                pass
    return fig


def _style_col(styler, col, mapping):
    if col not in styler.data.columns:
        return styler
    fn = getattr(styler, "map", None) or styler.applymap
    return fn(lambda v: mapping.get(str(v), ""), subset=[col])


def styled(df: pd.DataFrame):
    sty = df.style
    sty = _style_col(sty, "priority", PRIORITY_CELL)
    sty = _style_col(sty, "sla_status", SLA_CELL)
    sty = _style_col(sty, "kev_status", YESNO_CELL)
    sty = _style_col(sty, "exploit_attempt_detected", YESNO_CELL)
    return sty


_ACRONYMS = {"cve", "id", "kev", "ids", "ips", "sla", "epss", "cvss", "pii", "ip", "vpn", "hmac", "os", "tco", "url"}


def titleize(col: str) -> str:
    """Human, init-caps column header with security acronyms kept uppercase."""
    words = str(col).replace("_", " ").split()
    return " ".join(w.upper() if w.lower() in _ACRONYMS else w.capitalize() for w in words)


# Header + body styling for HTML tables (palette-consistent: navy header, green underline).
_TABLE_STYLES = [
    # let columns size to their content instead of being squeezed into 100% width
    {"selector": "", "props": [("border-collapse", "collapse"), ("width", "auto"), ("min-width", "100%"),
                               ("font-family", "Segoe UI, Roboto, sans-serif")]},
    {"selector": "th.col_heading",
     "props": [("background-color", "#15315C"), ("color", "#FFFFFF"), ("font-weight", "700"),
               ("text-align", "left"), ("padding", "8px 12px"), ("font-size", ".82rem"),
               ("border-bottom", "2px solid #01A982"), ("position", "sticky"), ("top", "0"),
               ("z-index", "2"), ("white-space", "nowrap"), ("resize", "horizontal"), ("overflow", "hidden")]},
    {"selector": "td", "props": [("padding", "6px 12px"), ("border-top", "1px solid #EDF1F6"),
                                  ("font-size", ".84rem"), ("color", "#1F2937"), ("white-space", "nowrap"),
                                  ("max-width", "360px"), ("overflow", "hidden"), ("text-overflow", "ellipsis"),
                                  ("vertical-align", "middle")]},
    {"selector": "tbody tr:nth-child(even) td", "props": [("background-color", "#FBFCFE")]},
    {"selector": "tbody tr:hover td", "props": [("background-color", "#F1F7F4")]},
]


def render_table(df: pd.DataFrame, height: int = 430) -> None:
    """Render a dataframe as a styled HTML table with bold, init-caps, coloured headers."""
    d = df.copy()
    d.columns = [titleize(c) for c in d.columns]
    sty = d.style
    sty = _style_col(sty, "Priority", PRIORITY_CELL)
    sty = _style_col(sty, "SLA Status", SLA_CELL)
    sty = _style_col(sty, "KEV Status", YESNO_CELL)
    sty = _style_col(sty, "Exploit Attempt Detected", YESNO_CELL)
    try:
        sty = sty.hide(axis="index")
    except Exception:
        pass
    sty = sty.set_table_styles(_TABLE_STYLES)
    st.markdown(
        f'<div style="max-height:{height}px;overflow:auto;border:1px solid #E3E8EF;border-radius:10px">{sty.to_html()}</div>',
        unsafe_allow_html=True,
    )


def operator() -> str:
    return st.session_state.get("operator", "system") or "system"


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------
def load_csv(uploaded_file, default_path: Path) -> pd.DataFrame:
    """Load an uploaded CSV or Excel file (.csv/.xlsx/.xls), else the bundled CSV.

    The Excel engine is chosen by extension: openpyxl for .xlsx, xlrd for legacy .xls.
    """
    if uploaded_file is not None:
        name = str(getattr(uploaded_file, "name", "")).lower()
        if name.endswith(".xlsx"):
            return pd.read_excel(uploaded_file, engine="openpyxl")  # first sheet
        if name.endswith(".xls"):
            return pd.read_excel(uploaded_file, engine="xlrd")      # legacy Excel
        return pd.read_csv(uploaded_file)
    return pd.read_csv(default_path)


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    # Sanitise against CSV / formula injection before producing the file bytes.
    return sanitize_df_for_export(df).to_csv(index=False).encode("utf-8")


def executive_summary_report(df: pd.DataFrame) -> pd.DataFrame:
    summary_rows = [
        {"Metric": "Total Exposures", "Value": len(df)},
        {"Metric": "Critical Exposures", "Value": int((df["priority"] == "Critical").sum())},
        {"Metric": "High Exposures", "Value": int((df["priority"] == "High").sum())},
        {"Metric": "CISA KEV Exposures", "Value": int((df["kev_status"] == "Yes").sum())},
        {"Metric": "IDS-Correlated Exposures", "Value": int((df["ids_alert_count"].fillna(0).astype(int) > 0).sum())},
        {"Metric": "Privacy Critical/High Exposures", "Value": int(df["privacy_impact_level"].isin(["Critical", "High"]).sum())},
        {"Metric": "SLA Breached Items", "Value": int((df["sla_status"] == "Breached").sum())},
        {"Metric": "Average Risk Score", "Value": round(float(df["final_score"].mean()), 2) if len(df) else 0},
    ]
    return pd.DataFrame(summary_rows)


# ---------------------------------------------------------------------------
# Remediation Action Plan — compose readable, per-exposure guidance from the
# columns the engines already produce (+ NVD description) and export it.
# ---------------------------------------------------------------------------

# Column-name candidates (the NVD enricher may name these differently across builds).
_DESC_COLS = ["cve_description", "nvd_description", "description", "vuln_description", "summary", "cve_summary"]
_CWE_COLS = ["cwe", "cwe_id", "cwe_name", "weakness", "cwe_description"]


def _val(row, names, default: str = "") -> str:
    """First present, non-empty value among candidate column names, as a clean string."""
    if isinstance(names, str):
        names = [names]
    for n in names:
        if n in row.index:
            v = row[n]
            if pd.notna(v) and str(v).strip().lower() not in ("", "nan", "none"):
                return str(v).strip()
    return default


def _is_yes(row, col) -> bool:
    return _val(row, col).strip().lower() in ("yes", "true", "1")


def _ids_active(row) -> int:
    try:
        return int(float(_val(row, "ids_alert_count", "0")))
    except Exception:
        return 0


def explain_vulnerability(row) -> str:
    """Plain-language description of what the vulnerability is."""
    cve = _val(row, "cve_id", "This exposure")
    asset = _val(row, "asset_name", "the affected asset")
    app = _val(row, "application_name")
    sev, cvss = _val(row, "severity"), _val(row, "cvss_score")
    desc, cwe = _val(row, _DESC_COLS), _val(row, _CWE_COLS)

    meta = ", ".join([m for m in (f"{sev} severity" if sev else "", f"CVSS {cvss}" if cvss else "") if m])
    lead = f"{cve}" + (f" ({meta})" if meta else "")
    target = asset + (f" — application '{app}'" if app else "")
    out = [f"{lead} affects {target}."]
    if desc:
        out.append(desc if desc.endswith(".") else desc + ".")
    else:
        out.append("It is a known security weakness in the affected component that an attacker could "
                   "leverage to compromise the asset's confidentiality, integrity, or availability.")
    if cwe:
        out.append(f"Weakness class: {cwe}.")
    return " ".join(out)


def possible_impact(row) -> str:
    """Why it matters — business, exploitation, network, IDS and privacy consequences."""
    bits = []
    bp = _val(row, "business_process")
    if bp:
        bits.append(f"The affected asset supports the {bp} business process, so a compromise has direct business consequences.")
    if _is_yes(row, "kev_status"):
        bits.append("This CVE is on the CISA KEV list — confirmed exploited in real-world attacks, so the threat is active, not theoretical.")
    nel, ner = _val(row, "network_exposure_level"), _val(row, "network_exposure_reason")
    if nel:
        bits.append(f"Network exposure is {nel}" + (f" ({ner})." if ner else "."))
    n = _ids_active(row)
    if n > 0:
        sevh = _val(row, "highest_alert_severity")
        bits.append(f"IDS/IPS has correlated {n} live alert(s)" + (f" (highest severity: {sevh})" if sevh else "")
                    + " to this asset, indicating possible active targeting.")
    pil, reg = _val(row, "privacy_impact_level"), _val(row, "regulatory_impact")
    if pil and pil.lower() not in ("none", "low"):
        bits.append(f"Privacy impact is {pil}" + (f", carrying regulatory exposure ({reg})." if reg else "."))
    drivers = _val(row, "score_drivers")
    if drivers:
        bits.append(f"Key risk drivers: {drivers}.")
    if not bits:
        bits.append("If left unremediated, this exposure raises the asset's overall cyber risk and could be chained into a broader compromise.")
    return " ".join(bits)


def remediation_steps(row) -> list:
    """Ordered list of concrete fix steps."""
    steps = []
    pa = _val(row, "primary_action")
    if pa:
        steps.append(pa)
    if _is_yes(row, "kev_status"):
        steps.append("Treat as urgent and schedule ahead of non-KEV items, given confirmed in-the-wild exploitation.")
    vs = _val(row, "validation_step")
    if vs:
        steps.append(f"Validate the fix — {vs}")
    ca = _val(row, "control_area")
    if ca:
        steps.append(f"Confirm the related security control is restored or strengthened ({ca}).")
    if not steps:
        steps.append("Apply the vendor-supplied patch or upgrade to a fixed version, then re-scan to confirm the CVE is no longer detected.")
    return steps


def interim_mitigation(row) -> list:
    """What to do now if a full fix is not yet possible."""
    bits = []
    tm = _val(row, "temporary_mitigation")
    cc = _val(row, "compensating_control")
    if tm:
        bits.append(tm)
    if cc:
        bits.append(f"Compensating control — {cc}")
    if not bits:
        bits.append("If immediate patching is not possible, restrict network access to the asset, increase monitoring, "
                    "and limit privileged access until the fix is applied.")
    return bits


def compose_action_plan(df_in: pd.DataFrame) -> pd.DataFrame:
    """Flatten per-exposure guidance into one export-ready table (single source for cards + files)."""
    rows = []
    for _, r in df_in.iterrows():
        rows.append({
            "Rank": len(rows) + 1,
            "Asset": _val(r, "asset_name"),
            "Application": _val(r, "application_name"),
            "CVE": _val(r, "cve_id"),
            "Priority": _val(r, "priority"),
            "Exposure Score": _val(r, "final_score"),
            "KEV": _val(r, "kev_status"),
            "SLA Status": _val(r, "sla_status"),
            "Owner": _val(r, "asset_owner"),
            "Due Date": _val(r, "remediation_due_date"),
            "Vulnerability Explanation": explain_vulnerability(r),
            "Possible Impact": possible_impact(r),
            "Remediation Steps": "\n".join(f"{i+1}. {s}" for i, s in enumerate(remediation_steps(r))),
            "Interim Mitigation": "\n".join(f"- {s}" for s in interim_mitigation(r)),
            "Control Area": _val(r, "control_area"),
            "Escalation": _val(r, "escalation_reason") or _val(r, "escalation_required"),
        })
    return pd.DataFrame(rows)


def to_xlsx_bytes(df_in: pd.DataFrame, sheet_name: str = "Action Plan") -> bytes:
    """Export a sanitised, formatted .xlsx (wrapped text, branded header, frozen header row)."""
    from openpyxl.styles import Font, PatternFill, Alignment

    d = sanitize_df_for_export(df_in)
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as xl:
        d.to_excel(xl, index=False, sheet_name=sheet_name)
        ws = xl.sheets[sheet_name]
        head_fill = PatternFill("solid", fgColor="15315C")
        head_font = Font(color="FFFFFF", bold=True)
        wrap_top = Alignment(wrap_text=True, vertical="top")
        wide = {"Vulnerability Explanation", "Possible Impact", "Remediation Steps", "Interim Mitigation"}
        for ci, col in enumerate(d.columns, start=1):
            cell = ws.cell(row=1, column=ci)
            cell.fill, cell.font, cell.alignment = head_fill, head_font, Alignment(vertical="center")
            ws.column_dimensions[cell.column_letter].width = 60 if col in wide else max(12, min(30, len(str(col)) + 4))
        for r_ in ws.iter_rows(min_row=2):
            for cell in r_:
                cell.alignment = wrap_top
        ws.freeze_panes = "A2"
    return buf.getvalue()


def to_pdf_bytes(plan_df: pd.DataFrame, generated_by: str = "system") -> bytes:
    """Export the action plan as a consulting-grade PDF.

    Follows the house document standard: 0.5 cm margins on all sides, justified
    body text, no header/footer except a page number at bottom-right, fixed-width
    boxes/tables that always stay within the usable page width (never overflow),
    and a formal blue / grey / green / yellow palette (red used sparingly).
    """
    from datetime import datetime
    from xml.sax.saxutils import escape
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether)

    # Palette (matches the app's PRIORITY_COLORS: Critical red, High yellow, Medium blue, Low green).
    NAVY = colors.HexColor("#15315C")
    GREEN = colors.HexColor("#01A982")
    GREY = colors.HexColor("#5B6675")
    RED = colors.HexColor("#B23A3A")
    YELLOW = colors.HexColor("#C9A227")
    BLUE = colors.HexColor("#1E50A0")
    INK = colors.HexColor("#1F2937")
    HAIR = colors.HexColor("#E3E8EF")
    BOXBG = colors.HexColor("#FBFCFE")

    MARGIN = 0.5 * cm                       # house standard: 0.5 cm all sides
    USABLE = A4[0] - 2 * MARGIN             # usable text width; everything is clamped to this

    def pcolor(pr: str):
        return {"critical": RED, "high": YELLOW, "medium": BLUE, "low": GREEN}.get(str(pr).lower(), GREY)

    def hx(c) -> str:
        return "#%02X%02X%02X" % (int(c.red * 255), int(c.green * 255), int(c.blue * 255))

    def t(x):
        return escape(str(x)).replace("\n", "<br/>")

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN, bottomMargin=MARGIN,
        title="CEGP Remediation Action Plan", author=generated_by,
    )

    ss = getSampleStyleSheet()
    title_s = ParagraphStyle("t", parent=ss["Title"], fontSize=17, textColor=colors.white, alignment=TA_LEFT, spaceAfter=0, leading=20)
    subtitle_s = ParagraphStyle("st", parent=ss["Normal"], fontSize=8.5, textColor=colors.HexColor("#EAF6F1"), alignment=TA_LEFT, leading=11)
    card_h = ParagraphStyle("ch", parent=ss["Heading3"], fontSize=11, textColor=NAVY, spaceBefore=0, spaceAfter=4, leading=14)
    lbl = ParagraphStyle("lb", parent=ss["Normal"], fontSize=8, textColor=GREEN, spaceBefore=4, spaceAfter=1, leading=10, fontName="Helvetica-Bold")
    body = ParagraphStyle("bd", parent=ss["Normal"], fontSize=9, textColor=INK, leading=13, spaceAfter=1, alignment=TA_JUSTIFY)
    steps = ParagraphStyle("sp", parent=body, alignment=TA_LEFT)
    meta = ParagraphStyle("mt", parent=ss["Normal"], fontSize=8, textColor=GREY, leading=11, alignment=TA_LEFT)
    th = ParagraphStyle("th", parent=ss["Normal"], fontSize=8, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_LEFT, leading=10)
    tv = ParagraphStyle("tv", parent=ss["Normal"], fontSize=12, textColor=NAVY, fontName="Helvetica-Bold", alignment=TA_LEFT, leading=14)

    # ---- Page number bottom-right (only footer content) ----
    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(GREY)
        canvas.drawRightString(A4[0] - MARGIN, MARGIN * 0.55, f"Page {doc_.page}")
        canvas.restoreState()

    # ---- Title band (single-cell, full usable width) ----
    title_tbl = Table([[Paragraph("CEGP — Remediation Action Plan", title_s)],
                       [Paragraph(f"Cyber Exposure Governance Platform &nbsp;|&nbsp; {len(plan_df)} action item(s) "
                                  f"&nbsp;|&nbsp; generated {datetime.now():%Y-%m-%d %H:%M} by {t(generated_by)}", subtitle_s)]],
                      colWidths=[USABLE])
    title_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("LINEBELOW", (0, -1), (-1, -1), 2, GREEN),
        ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (0, 0), 10), ("BOTTOMPADDING", (0, -1), (-1, -1), 9),
    ]))

    # ---- Summary table (fixed width = USABLE, four equal columns) ----
    total = len(plan_df)
    crit_high = int(plan_df["Priority"].astype(str).isin(["Critical", "High"]).sum()) if total else 0
    kev = int((plan_df["KEV"].astype(str).str.lower() == "yes").sum()) if total else 0
    breached = int((plan_df["SLA Status"].astype(str) == "Breached").sum()) if total else 0
    cw = USABLE / 4.0
    summary_tbl = Table(
        [[Paragraph("ACTION ITEMS", th), Paragraph("CRITICAL / HIGH", th), Paragraph("CISA KEV (FIX FIRST)", th), Paragraph("SLA BREACHED", th)],
         [Paragraph(str(total), tv), Paragraph(str(crit_high), tv), Paragraph(str(kev), tv), Paragraph(str(breached), tv)]],
        colWidths=[cw, cw, cw, cw])
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#EEF1F5")),
        ("BOX", (0, 0), (-1, -1), 0.5, HAIR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.white),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    story = [title_tbl, Spacer(1, 8), summary_tbl, Spacer(1, 10)]

    # ---- One fixed-width boxed card per exposure ----
    for _, r in plan_df.iterrows():
        pr = str(r.get("Priority", ""))
        pc = pcolor(pr)
        head = (f'<font color="{hx(pc)}"><b>[{t(pr)}]</b></font> &nbsp;'
                f'{t(r.get("Rank"))}. {t(r.get("CVE"))} on {t(r.get("Asset"))} '
                f'&nbsp;&middot;&nbsp; score {t(r.get("Exposure Score"))} '
                f'&nbsp;&middot;&nbsp; KEV {t(r.get("KEV"))} &nbsp;&middot;&nbsp; SLA {t(r.get("SLA Status"))}')
        meta_line = (f"Owner: {t(r.get('Owner') or '—')} &nbsp;|&nbsp; Due: {t(r.get('Due Date') or '—')} "
                     f"&nbsp;|&nbsp; Control area: {t(r.get('Control Area') or '—')}"
                     + (f" &nbsp;|&nbsp; Escalation: {t(r.get('Escalation'))}" if str(r.get("Escalation") or "").strip() else ""))
        inner = [
            Paragraph(head, card_h),
            Paragraph("WHAT THE VULNERABILITY IS", lbl), Paragraph(t(r.get("Vulnerability Explanation")), body),
            Paragraph("WHY IT MATTERS / POSSIBLE IMPACT", lbl), Paragraph(t(r.get("Possible Impact")), body),
            Paragraph("REMEDIATION STEPS", lbl), Paragraph(t(r.get("Remediation Steps")), steps),
            Paragraph("INTERIM MITIGATION", lbl), Paragraph(t(r.get("Interim Mitigation")), steps),
            Spacer(1, 3), Paragraph(meta_line, meta),
        ]
        # Single-cell table = the card box. colWidths=[USABLE] guarantees it never exceeds the page.
        card = Table([[inner]], colWidths=[USABLE])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BOXBG),
            ("BOX", (0, 0), (-1, -1), 0.5, HAIR),
            ("LINEBEFORE", (0, 0), (0, -1), 3, pc),     # priority-coloured left stripe
            ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(KeepTogether([card, Spacer(1, 7)]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def to_executive_pdf_bytes(df: pd.DataFrame, generated_by: str = "system") -> bytes:
    """Export the Executive view (visualisations + data analysis) as a consulting-grade PDF.

    Follows the house document standard: 0.5 cm margins, justified text, page number
    bottom-right only, fixed-width tables/boxes that never overflow, formal palette.
    Charts are rebuilt here (self-contained) and embedded as images; if static image
    export is unavailable, the PDF is still produced with the KPIs and data tables.
    """
    from datetime import datetime
    from xml.sax.saxutils import escape
    import plotly.express as _px
    import plotly.graph_objects as _go
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                                    Image as RLImage, KeepTogether)

    C_NAVY = colors.HexColor("#15315C")
    C_GREEN = colors.HexColor("#01A982")
    C_GREY = colors.HexColor("#5B6675")
    C_HAIR = colors.HexColor("#E3E8EF")
    C_INK = colors.HexColor("#1F2937")

    MARGIN = 0.5 * cm
    USABLE = A4[0] - 2 * MARGIN

    def t(x):
        return escape(str(x)).replace("\n", "<br/>")

    # ---- Rebuild the executive figures (mirrors the Executive tab; does not touch it) ----
    figs = []  # (title, fig, width_px, height_px, full_width)
    try:
        cvss_labels = ["Low 0\u20133.9", "Medium 4\u20136.9", "High 7\u20138.9", "Critical 9\u201310"]
        epss_labels = ["Low <0.50", "Medium 0.50\u20130.79", "High 0.80\u20130.94", "Very High \u22650.95"]

        def _cb(v):
            v = float(v or 0)
            return 3 if v >= 9 else 2 if v >= 7 else 1 if v >= 4 else 0

        def _eb(p):
            p = float(p or 0)
            return 3 if p >= 0.95 else 2 if p >= 0.80 else 1 if p >= 0.50 else 0

        counts = [[0] * 4 for _ in range(4)]
        for _, r in df.iterrows():
            counts[_eb(r.get("epss_percentile", 0))][_cb(r.get("cvss_score", 0))] += 1
        tier = [[(x + y) / 6 for x in range(4)] for y in range(4)]
        text = [[str(counts[y][x]) if counts[y][x] else "" for x in range(4)] for y in range(4)]
        mtx = _go.Figure(_go.Heatmap(
            z=tier, x=cvss_labels, y=epss_labels, text=text, texttemplate="%{text}",
            textfont=dict(size=18, color="#15315C"), showscale=False, xgap=4, ygap=4,
            colorscale=[[0.0, "#DCEFE6"], [0.34, "#EFF3D9"], [0.5, "#F6ECC9"], [0.72, "#EFC9A6"], [1.0, "#EBB4B4"]],
            zmin=0, zmax=1))
        mtx = style_fig(mtx)
        mtx.update_layout(title="Executive Risk Matrix \u2014 Severity \u00d7 Exploitation Likelihood", height=430)
        mtx.update_xaxes(title="CVSS severity \u2192"); mtx.update_yaxes(title="EPSS likelihood \u2192")
        figs.append(("matrix", mtx, 1000, 470, True))

        pc = df["priority"].value_counts().reset_index()
        pc.columns = ["Priority", "Count"]
        donut = _px.pie(pc, names="Priority", values="Count", hole=0.55, title="Priority Mix",
                        color="Priority", color_discrete_map=PRIORITY_COLORS,
                        category_orders={"Priority": ["Critical", "High", "Medium", "Low"]})
        donut.update_traces(textinfo="label+percent"); donut = style_fig(donut); donut.update_layout(showlegend=False)
        figs.append(("donut", donut, 560, 420, False))

        tb = df.groupby("business_process", dropna=False)["final_score"].sum().sort_values(ascending=False).head(10).reset_index()
        tbfig = style_fig(_px.bar(tb, x="final_score", y="business_process", orientation="h", title="Top Business Processes by Aggregate Risk"), GREEN)
        tbfig.update_yaxes(autorange="reversed", title=""); tbfig.update_xaxes(title="Aggregate risk score")
        figs.append(("bp", tbfig, 560, 420, False))

        kc = df["kev_status"].value_counts().reindex(["Yes", "No"]).fillna(0).reset_index()
        kc.columns = ["KEV", "Count"]
        kc["KEV"] = kc["KEV"].map({"Yes": "Known Exploited", "No": "Not in KEV"})
        kfig = style_fig(_px.bar(kc, x="KEV", y="Count", color="KEV", title="CISA KEV vs Non-KEV",
                                 color_discrete_map={"Known Exploited": RED, "Not in KEV": GREY}))
        kfig.update_layout(showlegend=False)
        figs.append(("kev", kfig, 560, 420, False))

        hfig = style_fig(_px.histogram(df, x="epss_percentile", nbins=20, title="EPSS Percentile Distribution"), BLUE)
        hfig.update_layout(bargap=0.05); hfig.update_xaxes(title="EPSS percentile"); hfig.update_yaxes(title="Exposures")
        figs.append(("epss", hfig, 560, 420, False))

        ev = df.groupby("environment")["final_score"].sum().sort_values(ascending=False).reset_index()
        efig = style_fig(_px.bar(ev, x="environment", y="final_score", title="Aggregate Risk by Environment"), GREEN)
        efig.update_yaxes(title="Total risk score")
        figs.append(("env", efig, 560, 420, False))

        ta = df.groupby("asset_name")["final_score"].sum().sort_values(ascending=False).head(10).reset_index()
        tafig = style_fig(_px.bar(ta, x="final_score", y="asset_name", orientation="h", title="Top 10 Riskiest Assets"), RED)
        tafig.update_yaxes(autorange="reversed", title=""); tafig.update_xaxes(title="Aggregate risk score")
        figs.append(("assets", tafig, 560, 420, False))
    except Exception:
        figs = []

    images, charts_ok = {}, True
    try:
        for name, fig, w, h, full in figs:
            images[name] = fig.to_image(format="png", width=w, height=h, scale=2)
    except Exception:
        charts_ok = False

    # ---- Document ----
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                            topMargin=MARGIN, bottomMargin=MARGIN,
                            title="CEGP Executive Cyber Exposure Summary", author=generated_by)
    ss = getSampleStyleSheet()
    title_s = ParagraphStyle("t", parent=ss["Title"], fontSize=17, textColor=colors.white, alignment=TA_LEFT, leading=20)
    sub_s = ParagraphStyle("s", parent=ss["Normal"], fontSize=8.5, textColor=colors.HexColor("#EAF6F1"), alignment=TA_LEFT, leading=11)
    sec = ParagraphStyle("sec", parent=ss["Heading3"], fontSize=11, textColor=C_NAVY, spaceBefore=8, spaceAfter=4)
    body = ParagraphStyle("bd", parent=ss["Normal"], fontSize=9, textColor=C_INK, leading=13, alignment=TA_JUSTIFY)
    cap = ParagraphStyle("cap", parent=ss["Normal"], fontSize=8, textColor=C_GREY, leading=10, spaceBefore=2)
    th = ParagraphStyle("th", parent=ss["Normal"], fontSize=8, textColor=colors.white, fontName="Helvetica-Bold", leading=10)
    tv = ParagraphStyle("tv", parent=ss["Normal"], fontSize=14, textColor=C_NAVY, fontName="Helvetica-Bold", leading=16)
    cell = ParagraphStyle("cell", parent=ss["Normal"], fontSize=8.5, textColor=C_INK, leading=11)

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 8); canvas.setFillColor(C_GREY)
        canvas.drawRightString(A4[0] - MARGIN, MARGIN * 0.55, f"Page {doc_.page}")
        canvas.restoreState()

    # KPI metrics
    s = executive_summary_report(df)
    m = dict(zip(s["Metric"], s["Value"]))

    title_tbl = Table([[Paragraph("CEGP \u2014 Executive Cyber Exposure Summary", title_s)],
                       [Paragraph(f"Cyber Exposure Governance Platform &nbsp;|&nbsp; {len(df)} exposures &nbsp;|&nbsp; "
                                  f"generated {datetime.now():%Y-%m-%d %H:%M} by {t(generated_by)}", sub_s)]],
                      colWidths=[USABLE])
    title_tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), C_NAVY), ("LINEBELOW", (0, -1), (-1, -1), 2, C_GREEN),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                                   ("TOPPADDING", (0, 0), (0, 0), 10), ("BOTTOMPADDING", (0, -1), (-1, -1), 9)]))

    kpis = [("TOTAL", m.get("Total Exposures", len(df))), ("CRITICAL", m.get("Critical Exposures", 0)),
            ("HIGH", m.get("High Exposures", 0)), ("CISA KEV", m.get("CISA KEV Exposures", 0)),
            ("SLA BREACHED", m.get("SLA Breached Items", 0)), ("AVG SCORE", m.get("Average Risk Score", 0))]

    def _kfmt(label, v):
        if label == "AVG SCORE":
            try:
                return f"{float(v):.2f}"
            except Exception:
                return str(v)
        try:
            f = float(v)
            return str(int(f)) if f == int(f) else str(v)
        except Exception:
            return str(v)

    cwk = USABLE / 6.0
    kpi_tbl = Table([[Paragraph(k, th) for k, _ in kpis], [Paragraph(_kfmt(k, v), tv) for k, v in kpis]],
                    colWidths=[cwk] * 6)
    kpi_tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), C_NAVY), ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#EEF1F5")),
                                 ("BOX", (0, 0), (-1, -1), 0.5, C_HAIR), ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.white),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                                 ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                                 ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))

    story = [title_tbl, Spacer(1, 8), kpi_tbl, Spacer(1, 6)]

    def _img(name, width):
        png = images.get(name)
        if not png:
            return Paragraph("(chart unavailable)", cap)
        # preserve aspect ratio
        for nm, fig, w, h, full in figs:
            if nm == name:
                return RLImage(BytesIO(png), width=width, height=width * h / w)
        return RLImage(BytesIO(png), width=width)

    if charts_ok and images:
        story += [Paragraph("Risk Matrix \u2014 fix-first is the top-right band", sec),
                  _img("matrix", USABLE),
                  Paragraph("Each cell counts exposures in that CVSS severity \u00d7 EPSS likelihood band.", cap),
                  Spacer(1, 6), Paragraph("Posture Breakdown", sec)]
        pairs = [("donut", "bp"), ("kev", "epss"), ("env", "assets")]
        colw = (USABLE - 8) / 2.0
        for a, b in pairs:
            row = Table([[_img(a, colw - 6), _img(b, colw - 6)]], colWidths=[colw, colw])
            row.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 2), ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                                     ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                                     ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story.append(row)
    else:
        story.append(Paragraph("Charts could not be rendered in this environment "
                               "(install <b>kaleido</b> to embed visualisations). KPIs and data tables follow.", body))

    # ---- Data analysis: top exposures table (fixed width, wrapped) ----
    story += [Spacer(1, 6), Paragraph("Top 15 Business-Critical Exposures", sec)]
    cols = [("Asset", "asset_name", 0.22), ("Business Process", "business_process", 0.22),
            ("CVE", "cve_id", 0.16), ("Priority", "priority", 0.12), ("Score", "final_score", 0.10),
            ("KEV", "kev_status", 0.18)]
    head = [Paragraph(h, th) for h, _, _ in cols]
    rows = [head]
    top = df.sort_values("final_score", ascending=False).head(15)
    for _, r in top.iterrows():
        rows.append([Paragraph(t(r.get(c, "")), cell) for _, c, _ in cols])
    data_tbl = Table(rows, colWidths=[USABLE * w for _, _, w in cols], repeatRows=1)
    data_tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), C_NAVY),
                                  ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FBFCFE")]),
                                  ("BOX", (0, 0), (-1, -1), 0.5, C_HAIR), ("INNERGRID", (0, 0), (-1, -1), 0.4, C_HAIR),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                                  ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                                  ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(data_tbl)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def run_assessment(vuln_df, asset_df, ids_df, exceptions_df, import_type, use_live_feeds, nvd_api_key):
    vuln_df = normalize_vulnerability_input(vuln_df, import_type=import_type)
    vuln_df, vuln_errors, vuln_warnings = validate_vulnerability_df(vuln_df)
    asset_df, asset_errors, asset_warnings = validate_asset_df(asset_df)
    ids_df, ids_errors, ids_warnings = validate_ids_df(ids_df) if ids_df is not None else (pd.DataFrame(), [], [])

    errors = vuln_errors + asset_errors + ids_errors
    warnings = vuln_warnings + asset_warnings + ids_warnings
    if errors:
        return None, errors, warnings

    policy = load_risk_policy(DATA_DIR / "risk_policy.json")

    df = enrich_with_kev(vuln_df, use_live=use_live_feeds)
    df = enrich_with_epss(df, use_live=use_live_feeds)
    df = enrich_with_nvd(df, use_live=use_live_feeds, api_key=nvd_api_key or None)

    df = enrich_with_asset_context(df, asset_df)
    df = calculate_business_impact(df)
    df = add_network_exposure(df)
    df = correlate_ids_alerts(df, ids_df)
    df = add_privacy_impact(df)

    df = calculate_threat_intelligence_score(df, policy)
    df = calculate_final_score(df, policy, include_sla_score=False)
    df = assign_remediation_governance(df, policy)
    df = calculate_final_score(df, policy, include_sla_score=True)
    df = assign_remediation_governance(df, policy)

    df = add_remediation_playbooks(df)
    df = apply_exceptions(df, exceptions_df)
    df = add_control_mapping(df)
    df["score_drivers"] = df.apply(summarize_score_drivers, axis=1)

    priority_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    df["_priority_order"] = df["priority"].map(priority_order).fillna(5)
    df = df.sort_values(["_priority_order", "final_score"], ascending=[True, False]).drop(columns=["_priority_order"])

    log_event("Assessment completed", details=f"{len(df)} exposure rows assessed", operator=operator())
    try:
        save_risk_snapshot(df, DATA_DIR / "risk_snapshots.csv")
    except Exception:
        pass

    return df, errors, warnings


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
inject_theme()
render_header()

with st.sidebar:
    st.markdown(
        '<div class="cegp-sidebrand"><span style="font-size:1.5rem">\U0001F6E1\uFE0F</span>'
        '<div><div class="b1">CEGP Console</div><div class="b2">Cyber Exposure Governance</div></div></div>',
        unsafe_allow_html=True,
    )
    if st.button("\U0001F4C4  Project Documentation", use_container_width=True, key="docs_btn"):
        show_documentation()
    if st.button("\U0001F680  Future Scope  \nImplementation using GCP", use_container_width=True, key="gcp_btn"):
        show_gcp_guide()
    st.divider()

    st.markdown('<div class="cegp-sidelabel">Assessment Setup</div>', unsafe_allow_html=True)
    st.session_state.operator = st.text_input("Operator name", value=st.session_state.get("operator", "analyst"),
                                               help="Stamped against every action in the audit log.")
    use_samples = st.toggle("Use bundled sample files", value=True)
    if not use_samples:
        vuln_file = st.file_uploader("Vulnerability file (CSV / Excel)", type=["csv", "xlsx", "xls"])
        asset_file = st.file_uploader("Asset inventory (CSV / Excel)", type=["csv", "xlsx", "xls"])
        ids_file = st.file_uploader("IDS/IPS alerts (CSV / Excel)", type=["csv", "xlsx", "xls"])
        exception_file = st.file_uploader("Risk exceptions (CSV / Excel, optional)", type=["csv", "xlsx", "xls"])
    else:
        vuln_file = asset_file = ids_file = exception_file = None

    run_button = st.button("Run Cyber Exposure Assessment", type="primary", use_container_width=True)

    # ---- Bottom of sidebar: optional / advanced, shown only if expanded ----
    st.markdown("<div style='height:18px'></div>", unsafe_allow_html=True)
    with st.expander("Advanced options", expanded=False):
        import_type = st.selectbox(
            "Vulnerability input type",
            ["Standard Template", "Scanner Export - Basic", "OpenVAS-like CSV", "Manual CVE List"],
            index=0,
            help="How to parse the uploaded file. Use Standard Template for the bundled data and matching files.",
        )
        use_live_feeds = st.toggle("Use live public feeds when available", value=False,
                                   help="When off, bundled offline threat-intel is used (recommended for a stable demo).")
        nvd_api_key = st.text_input("NVD API key (optional)", type="password",
                                    help="Only used with live feeds on; raises NVD rate limits.")
    render_sidebar_concepts()
    with st.expander("About this project", expanded=False):
        st.markdown(
            "**Cyber Exposure Governance Platform** \u2014 v1\n\n"
            "An M.Sc. Cyber Security project by **Dwaipayan Mojumder** and **Deblina Das**, "
            "under the guidance of **Prof. Sanjay Pal**.\n\n"
            "A risk-based decision-support tool: it correlates vulnerability intelligence with "
            "asset, network, IDS/IPS and privacy context to prioritise remediation and produce "
            "audit-ready, tamper-evident reports."
        )


if "assessment_df" not in st.session_state:
    st.session_state.assessment_df = None
if "last_hashes" not in st.session_state:
    st.session_state.last_hashes = {}
if "dq_notices" not in st.session_state:
    st.session_state.dq_notices = []


if run_button:
    try:
        vuln_df = load_csv(vuln_file, DATA_DIR / "sample_input.csv")
        asset_df = load_csv(asset_file, DATA_DIR / "asset_inventory.csv")
        ids_df = load_csv(ids_file, DATA_DIR / "ids_alerts.csv")
        exceptions_df = load_csv(exception_file, DATA_DIR / "risk_exceptions.csv") if (exception_file is not None or (DATA_DIR / "risk_exceptions.csv").exists()) else load_exceptions(DATA_DIR / "risk_exceptions.csv")

        with st.spinner("Running cyber exposure assessment..."):
            result_df, errors, warnings = run_assessment(
                vuln_df, asset_df, ids_df, exceptions_df,
                import_type=import_type, use_live_feeds=use_live_feeds, nvd_api_key=nvd_api_key,
            )

        # Data-quality warnings are not printed at the top of the page; they are
        # stored and surfaced under the Audit Log tab so the first screen stays clean.
        st.session_state.dq_notices = warnings

        if errors:
            for error in errors:
                st.error(error)
        else:
            st.session_state.assessment_df = result_df
            # Archive this run to history (full results + input fingerprints). Never block the run.
            try:
                run_id = save_run(
                    result_df, operator=operator(), data_dir=str(DATA_DIR),
                    inputs={
                        "vuln_rows": len(vuln_df),
                        "asset_rows": len(asset_df),
                        "ids_rows": (len(ids_df) if ids_df is not None else 0),
                        "vuln_fingerprint": fingerprint_df(vuln_df),
                        "asset_fingerprint": fingerprint_df(asset_df),
                        "ids_fingerprint": fingerprint_df(ids_df) if ids_df is not None else "",
                    },
                )
                log_event("Assessment archived to history", details=f"run_id={run_id}", operator=operator())
            except Exception:
                pass
            note = f" ({len(warnings)} data-quality notice{'s' if len(warnings) != 1 else ''} \u2014 see Audit Log tab)" if warnings else ""
            st.success("Assessment completed successfully." + note)
    except Exception as exc:
        st.error(f"Assessment failed: {exc}")
        log_event("Assessment failed", details=str(exc), operator=operator())


df = st.session_state.assessment_df

if df is None:
    section("Welcome", GREEN)
    st.markdown(
        "This platform turns raw vulnerability data into **business-aligned remediation decisions**. "
        "It enriches CVEs with threat intelligence (CISA KEV, EPSS, CVSS) and correlates asset, network, "
        "IDS/IPS and privacy context to produce an explainable exposure score, SLA governance, and "
        "tamper-evident reports."
    )
    c1, c2, c3 = st.columns(3)
    kpi_card(c1, "Prioritise", "Explainable 0\u2013100 score", GREEN, GREEN_D, "Threat + business + network + IDS + privacy")
    kpi_card(c2, "Govern", "SLA \u00b7 Owners \u00b7 Exceptions", BLUE, NAVY, "Due dates, escalation, risk acceptance")
    kpi_card(c3, "Evidence", "Audit log + HMAC", YELLOW, "#8A6D0E", "Tamper-evident, injection-safe reports")
    st.info("Set your operator name in the sidebar, then click **Run Cyber Exposure Assessment** to begin.")
    st.stop()


# ---- Executive KPI cards ----
summary = executive_summary_report(df)
m = dict(zip(summary["Metric"], summary["Value"]))

section("Cyber Exposure Posture", NAVY)
r1 = st.columns(4)
kpi_card(r1[0], "Total Exposures", m["Total Exposures"], GREEN, NAVY)
kpi_card(r1[1], "Critical", m["Critical Exposures"], RED, RED)
kpi_card(r1[2], "CISA KEV", m["CISA KEV Exposures"], YELLOW, "#8A6D0E")
kpi_card(r1[3], "SLA Breached", m["SLA Breached Items"], RED, RED)

r2 = st.columns(4)
kpi_card(r2[0], "IDS-Correlated", m["IDS-Correlated Exposures"], GREEN, GREEN_D)
kpi_card(r2[1], "Privacy Critical/High", m["Privacy Critical/High Exposures"], GREY, NAVY)
kpi_card(r2[2], "Average Risk Score", m["Average Risk Score"], GREEN, GREEN_D)
kpi_card(r2[3], "High", m["High Exposures"], YELLOW, "#8A6D0E")

st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)

tabs = st.tabs(
    [
        "Executive View", "Analyst View", "Network Exposure", "IDS/IPS Correlation",
        "Privacy Impact", "Remediation Governance", "Action Plan", "Simulation", "Reports & Integrity", "Audit Log",
        "Assessment History",
    ]
)

with tabs[0]:
    section("Executive Cyber Exposure View", NAVY)

    # Hero: executive risk matrix — exposures binned by severity x exploitation likelihood.
    pc = df["priority"].value_counts().reset_index()
    pc.columns = ["Priority", "Count"]

    cvss_labels = ["Low<br>0\u20133.9", "Medium<br>4\u20136.9", "High<br>7\u20138.9", "Critical<br>9\u201310"]
    epss_labels = ["Low<br>&lt;0.50", "Medium<br>0.50\u20130.79", "High<br>0.80\u20130.94", "Very High<br>\u22650.95"]

    def _cvss_band(v):
        v = float(v or 0)
        return 3 if v >= 9 else 2 if v >= 7 else 1 if v >= 4 else 0

    def _epss_band(p):
        p = float(p or 0)
        return 3 if p >= 0.95 else 2 if p >= 0.80 else 1 if p >= 0.50 else 0

    counts = [[0] * 4 for _ in range(4)]   # [epss_band][cvss_band]
    for _, r in df.iterrows():
        counts[_epss_band(r.get("epss_percentile", 0))][_cvss_band(r.get("cvss_score", 0))] += 1

    tier = [[(x + y) / 6 for x in range(4)] for y in range(4)]            # 0 (cool) .. 1 (hot)
    text = [[str(counts[y][x]) if counts[y][x] else "" for x in range(4)] for y in range(4)]

    matrix = go.Figure(go.Heatmap(
        z=tier, x=cvss_labels, y=epss_labels,
        text=text, texttemplate="%{text}", textfont=dict(size=20, color="#15315C", family="Segoe UI"),
        customdata=counts,
        hovertemplate="Severity: %{x}<br>Likelihood: %{y}<br>Exposures: %{customdata}<extra></extra>",
        xgap=5, ygap=5, showscale=False,
        colorscale=[[0.0, "#DCEFE6"], [0.34, "#EFF3D9"], [0.5, "#F6ECC9"], [0.72, "#EFC9A6"], [1.0, "#EBB4B4"]],
        zmin=0, zmax=1,
    ))
    matrix = style_fig(matrix)
    matrix.update_layout(
        title=dict(text="Executive Risk Matrix \u2014 Severity \u00d7 Exploitation Likelihood", font=dict(size=16, color=NAVY)),
        height=430, margin=dict(t=56, l=10, r=10, b=10),
    )
    matrix.update_xaxes(title="CVSS severity \u2192", side="bottom", showgrid=False, tickfont=dict(size=12, color=GREY))
    matrix.update_yaxes(title="EPSS likelihood \u2192", showgrid=False, tickfont=dict(size=12, color=GREY))
    st.plotly_chart(matrix, use_container_width=True)
    st.caption("Each cell shows the number of exposures in that severity \u00d7 likelihood band. The **top-right** band (high severity **and** high exploitation likelihood) is the fix-first zone; the bottom-left is monitor-and-defer.")


    r1l, r1r = st.columns(2)
    with r1l:
        donut = px.pie(pc, names="Priority", values="Count", hole=0.55, title="Priority Mix",
                       color="Priority", color_discrete_map=PRIORITY_COLORS,
                       category_orders={"Priority": ["Critical", "High", "Medium", "Low"]})
        donut.update_traces(textinfo="label+percent", textfont_size=12)
        donut = style_fig(donut)
        donut.update_layout(showlegend=False)
        st.plotly_chart(donut, use_container_width=True)
    with r1r:
        tb = df.groupby("business_process", dropna=False)["final_score"].sum().sort_values(ascending=False).head(10).reset_index()
        tbfig = px.bar(tb, x="final_score", y="business_process", orientation="h", title="Top Business Processes by Aggregate Risk")
        tbfig = style_fig(tbfig, GREEN)
        tbfig.update_yaxes(autorange="reversed", title="")
        tbfig.update_xaxes(title="Aggregate risk score")
        st.plotly_chart(tbfig, use_container_width=True)

    r2l, r2r = st.columns(2)
    with r2l:
        kc = df["kev_status"].value_counts().reindex(["Yes", "No"]).fillna(0).reset_index()
        kc.columns = ["KEV", "Count"]
        kc["KEV"] = kc["KEV"].map({"Yes": "Known Exploited (KEV)", "No": "Not in KEV"})
        kfig = px.bar(kc, x="KEV", y="Count", color="KEV", title="CISA KEV vs Non-KEV Exposures",
                      color_discrete_map={"Known Exploited (KEV)": RED, "Not in KEV": GREY})
        kfig = style_fig(kfig)
        kfig.update_layout(showlegend=False)
        st.plotly_chart(kfig, use_container_width=True)
    with r2r:
        hfig = px.histogram(df, x="epss_percentile", nbins=20, title="EPSS Percentile Distribution")
        hfig = style_fig(hfig, BLUE)
        hfig.update_layout(bargap=0.05)
        hfig.update_xaxes(title="EPSS percentile (exploitation likelihood)")
        hfig.update_yaxes(title="Exposures")
        st.plotly_chart(hfig, use_container_width=True)

    r3l, r3r = st.columns(2)
    with r3l:
        ev = df.groupby("environment")["final_score"].sum().sort_values(ascending=False).reset_index()
        efig = px.bar(ev, x="environment", y="final_score", title="Aggregate Risk by Environment")
        efig = style_fig(efig, GREEN)
        efig.update_yaxes(title="Total risk score")
        st.plotly_chart(efig, use_container_width=True)
    with r3r:
        ta = df.groupby("asset_name")["final_score"].sum().sort_values(ascending=False).head(10).reset_index()
        tafig = px.bar(ta, x="final_score", y="asset_name", orientation="h", title="Top 10 Riskiest Assets")
        tafig = style_fig(tafig, RED)
        tafig.update_yaxes(autorange="reversed", title="")
        tafig.update_xaxes(title="Aggregate risk score")
        st.plotly_chart(tafig, use_container_width=True)

    section("Top 10 Business-Critical Exposures", GREEN)
    cols = ["asset_name", "cve_id", "priority", "final_score"]
    render_table(df[cols].head(10))

    section("Download Executive Summary", NAVY)
    st.caption("A consulting-format PDF of this Executive view \u2014 risk matrix, posture charts, KPIs, and the "
               "top business-critical exposures \u2014 signed for integrity.")
    try:
        exec_pdf = to_executive_pdf_bytes(df, generated_by=operator())
        st.download_button("\u2b07\ufe0f  Download Executive Summary (PDF)", data=exec_pdf,
                           file_name="cegp_executive_summary.pdf", mime="application/pdf")
        st.caption("HMAC-SHA256")
        st.code(generate_sha256(exec_pdf), language="text")
    except ImportError:
        st.warning("PDF export needs the `reportlab` package (and `kaleido` for embedded charts). "
                   "Add them to requirements.txt and rebuild.")
    except Exception as exc:
        st.warning(f"Executive PDF unavailable: {exc}")

with tabs[1]:
    section("Security Analyst Exposure Queue", NAVY)
    st.caption("Threat & scoring lens \u2014 severity, exploitation likelihood, and why each exposure scored as it did. "
               "Network, IDS, privacy, and remediation detail live in their own tabs.")
    analyst_cols = [
        "asset_name", "application_name", "cve_id", "severity", "cvss_score",
        "epss_score", "epss_percentile", "kev_status", "score_drivers", "priority", "final_score",
    ]
    sub = df[[c for c in analyst_cols if c in df.columns]]
    render_table(sub)

with tabs[2]:
    section("Network Exposure", NAVY)
    c = st.columns(2)
    with c[0]:
        zs = df.groupby("network_zone")["final_score"].sum().sort_values(ascending=False).reset_index()
        st.plotly_chart(style_fig(px.bar(zs, x="network_zone", y="final_score", title="Risk by Network Zone"), GREEN), use_container_width=True)
    with c[1]:
        if "asset_type" in df.columns:
            at = df.groupby("asset_type")["final_score"].sum().sort_values(ascending=False).reset_index()
            st.plotly_chart(style_fig(px.bar(at, x="asset_type", y="final_score", title="Risk by Asset Type"), BLUE), use_container_width=True)
    cols = ["asset_name", "network_zone", "open_ports", "firewall_status", "vpn_required",
            "network_exposure_level", "network_exposure_reason", "final_score"]
    render_table(df[cols].sort_values("final_score", ascending=False))

with tabs[3]:
    section("IDS/IPS Correlation", NAVY)
    c = st.columns(2)
    with c[0]:
        isum = df.groupby("highest_alert_severity")["asset_id"].count().reset_index()
        isum.columns = ["Highest Alert Severity", "Exposure Count"]
        st.plotly_chart(style_fig(px.bar(isum, x="Highest Alert Severity", y="Exposure Count", title="Correlated IDS/IPS Alert Severity"), YELLOW), use_container_width=True)
    with c[1]:
        cols = ["asset_name", "cve_id", "ids_alert_count", "highest_alert_severity",
                "exploit_attempt_detected", "signatures", "ids_correlation_reason"]
        ids_view = df.sort_values(["ids_alert_count", "final_score"], ascending=False)[cols]
        render_table(ids_view)

with tabs[4]:
    section("Privacy Impact", NAVY)
    c = st.columns(2)
    with c[0]:
        ps = df.groupby("privacy_impact_level")["asset_id"].count().reset_index()
        ps.columns = ["Privacy Impact", "Count"]
        st.plotly_chart(style_fig(px.bar(ps, x="Privacy Impact", y="Count", title="Privacy Impact Distribution"), GREEN), use_container_width=True)
    with c[1]:
        cols = ["asset_name", "data_type", "pii_present", "data_sensitivity", "encryption_status",
                "regulatory_impact", "privacy_impact_level", "privacy_reason"]
        priv_view = df.sort_values("privacy_impact_score", ascending=False)[cols] if "privacy_impact_score" in df.columns else df[cols]
        render_table(priv_view)

with tabs[5]:
    section("Remediation Governance", NAVY)
    c = st.columns(2)
    with c[0]:
        ss = df.groupby("sla_status")["asset_id"].count().reset_index()
        ss.columns = ["SLA Status", "Count"]
        sla_map = {"Breached": RED, "Due Soon": YELLOW, "Within SLA": GREEN}
        sla_fig = style_fig(px.bar(ss, x="SLA Status", y="Count", color="SLA Status", color_discrete_map=sla_map, title="SLA Governance Status"))
        sla_fig.update_layout(showlegend=False)
        st.plotly_chart(sla_fig, use_container_width=True)
    with c[1]:
        os_ = df.groupby("asset_owner")["final_score"].sum().sort_values(ascending=False).head(10).reset_index()
        ofig = px.bar(os_, x="final_score", y="asset_owner", orientation="h", title="Owner-wise Aggregate Risk")
        ofig = style_fig(ofig, GREEN)
        ofig.update_yaxes(autorange="reversed", title="")
        ofig.update_xaxes(title="Aggregate risk score")
        st.plotly_chart(ofig, use_container_width=True)

    if "control_area" in df.columns:
        ca = df["control_area"].dropna().str.split(",").explode().str.strip()
        ca = ca[ca != ""].value_counts().head(10).reset_index()
        ca.columns = ["Control Area", "Exposures"]
        cafig = px.bar(ca, x="Exposures", y="Control Area", orientation="h",
                       title="Exposures by Cybersecurity Control Area")
        cafig = style_fig(cafig, BLUE)
        cafig.update_yaxes(autorange="reversed", title="")
        st.plotly_chart(cafig, use_container_width=True)

    gov_cols = ["asset_name", "cve_id", "priority", "final_score", "asset_owner", "remediation_due_date",
                "days_remaining", "sla_status", "escalation_required", "escalation_reason",
                "exception_status", "exception_validity", "acceptance_reason", "accepted_by"]
    render_table(df[[c for c in gov_cols if c in df.columns]])

with tabs[6]:
    section("Remediation Action Plan", NAVY)
    st.caption(
        "Plain-language, prioritised **action items** for every identified exposure \u2014 what the "
        "vulnerability is, why it matters, exactly how to fix it, and what to do in the meantime. "
        "Worst-first ordering (KEV / Critical at the top)."
    )

    # Worst-first ordering: KEV, then priority, then exposure score.
    ap = df.copy()
    _po = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    ap["_kev"] = (ap.get("kev_status", "").astype(str).str.lower() == "yes").map({True: 0, False: 1})
    ap["_pr"] = ap.get("priority", "").map(_po).fillna(5)
    ap["_sc"] = pd.to_numeric(ap.get("final_score", 0), errors="coerce").fillna(0)
    ap = ap.sort_values(["_kev", "_pr", "_sc"], ascending=[True, True, False]).drop(columns=["_kev", "_pr", "_sc"])

    # ---- Action summary KPIs ----
    a1 = st.columns(4)
    kpi_card(a1[0], "Action Items", len(ap), GREEN, NAVY)
    kpi_card(a1[1], "Critical / High", int(ap["priority"].isin(["Critical", "High"]).sum()), RED, RED)
    kpi_card(a1[2], "CISA KEV (fix first)", int((ap.get("kev_status", "").astype(str).str.lower() == "yes").sum()), YELLOW, "#8A6D0E")
    kpi_card(a1[3], "SLA Breached", int((ap.get("sla_status", "") == "Breached").sum()), RED, RED)

    # ---- Filters ----
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    f = st.columns([2, 1, 1, 2])
    pr_opts = [p for p in ["Critical", "High", "Medium", "Low"] if p in set(ap["priority"].astype(str))]
    with f[0]:
        pr_sel = st.multiselect("Priority", pr_opts, default=pr_opts, key="ap_pr")
    with f[1]:
        kev_only = st.toggle("KEV only", value=False, key="ap_kev")
    with f[2]:
        breached_only = st.toggle("SLA breached only", value=False, key="ap_breach")
    with f[3]:
        query = st.text_input("Search asset / CVE / owner", key="ap_q", placeholder="e.g. CVE-2024 or web-server")

    view = ap[ap["priority"].astype(str).isin(pr_sel)] if pr_sel else ap.iloc[0:0]
    if kev_only:
        view = view[view.get("kev_status", "").astype(str).str.lower() == "yes"]
    if breached_only:
        view = view[view.get("sla_status", "") == "Breached"]
    if query.strip():
        q = query.strip().lower()

        def _s(frame, name):
            return frame[name].astype(str) if name in frame.columns else pd.Series([""] * len(frame), index=frame.index)

        hay = (_s(view, "asset_name") + " " + _s(view, "cve_id") + " "
               + _s(view, "asset_owner") + " " + _s(view, "application_name")).str.lower()
        view = view[hay.str.contains(q, na=False)]

    plan = compose_action_plan(view)

    # ---- Downloads (CSV / Excel / PDF), reflecting the current filter, HMAC-signed ----
    section("Download Action Plan", GREEN)
    st.caption(f"{len(plan)} action item(s) in the current view. Files are sanitised against CSV/formula injection and HMAC-signed (tamper-evident).")
    if plan.empty:
        st.info("No exposures match the current filters.")
    else:
        d1, d2, d3 = st.columns(3)
        csv_bytes = to_csv_bytes(plan)
        with d1:
            st.download_button("\u2b07\ufe0f  Download CSV", data=csv_bytes, file_name="cegp_action_plan.csv",
                               mime="text/csv", use_container_width=True)
            st.caption("HMAC-SHA256")
            st.code(generate_sha256(csv_bytes), language="text")
        with d2:
            try:
                xlsx_bytes = to_xlsx_bytes(plan)
                st.download_button("\u2b07\ufe0f  Download Excel (.xlsx)", data=xlsx_bytes, file_name="cegp_action_plan.xlsx",
                                   mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)
                st.caption("HMAC-SHA256")
                st.code(generate_sha256(xlsx_bytes), language="text")
            except Exception as exc:
                st.warning(f"Excel export unavailable: {exc}")
        with d3:
            try:
                pdf_bytes = to_pdf_bytes(plan, generated_by=operator())
                st.download_button("\u2b07\ufe0f  Download PDF", data=pdf_bytes, file_name="cegp_action_plan.pdf",
                                   mime="application/pdf", use_container_width=True)
                st.caption("HMAC-SHA256")
                st.code(generate_sha256(pdf_bytes), language="text")
            except ImportError:
                st.warning("PDF export needs the `reportlab` package. Add `reportlab>=4.0,<5.0` to requirements.txt and rebuild.")
            except Exception as exc:
                st.warning(f"PDF export unavailable: {exc}")
        log_event("Action plan exported", details=f"{len(plan)} items (CSV/XLSX/PDF prepared)", operator=operator())

    # ---- Expandable action cards ----
    section("Action Items", GREEN)
    if not plan.empty:
        max_cards = st.slider("Cards to display", 5, max(5, len(plan)), min(25, len(plan)), step=5, key="ap_n",
                              help="Limits on-screen cards for readability. Downloads above always include the full filtered set.")
        for _, c in plan.head(max_cards).iterrows():
            pr = str(c["Priority"])
            chip = PRIORITY_COLORS.get(pr, GREY)
            kev_tag = "  \u00b7  KEV" if str(c["KEV"]).lower() == "yes" else ""
            label = f"{c['Rank']}.  [{pr}]  {c['CVE']}  on  {c['Asset']}   \u00b7  score {c['Exposure Score']}  \u00b7  SLA {c['SLA Status']}{kev_tag}"
            with st.expander(label, expanded=False):
                st.markdown(
                    f"<div style='border-left:5px solid {chip};padding:2px 0 2px 12px;margin-bottom:6px'>"
                    f"<span style='color:{chip};font-weight:700'>{pr} priority</span>"
                    f" &nbsp;\u2014&nbsp; <span style='color:{GREY}'>Owner: {c['Owner'] or '\u2014'} &nbsp;|&nbsp; "
                    f"Due: {c['Due Date'] or '\u2014'} &nbsp;|&nbsp; Control area: {c['Control Area'] or '\u2014'}</span></div>",
                    unsafe_allow_html=True,
                )
                st.markdown(f"<span style='color:{GREEN_D};font-weight:700'>\U0001F50D What the vulnerability is</span>", unsafe_allow_html=True)
                st.markdown(c["Vulnerability Explanation"])
                st.markdown(f"<span style='color:{RED};font-weight:700'>\u26A0\uFE0F Why it matters / possible impact</span>", unsafe_allow_html=True)
                st.markdown(c["Possible Impact"])
                st.markdown(f"<span style='color:{NAVY};font-weight:700'>\U0001F6E0\uFE0F Remediation steps</span>", unsafe_allow_html=True)
                st.markdown(c["Remediation Steps"])
                st.markdown(f"<span style='color:{YELLOW};font-weight:700'>\U0001F9EF Interim mitigation (if you can't fix immediately)</span>", unsafe_allow_html=True)
                st.markdown(c["Interim Mitigation"])
                if str(c["Escalation"]).strip():
                    st.markdown(f"<span style='color:{GREY}'><b>Escalation:</b> {c['Escalation']}</span>", unsafe_allow_html=True)
        if len(plan) > max_cards:
            st.caption(f"Showing {max_cards} of {len(plan)} items. Increase the slider, refine filters, or use the downloads above for the full set.")

with tabs[7]:
    section("What-If Risk Reduction Simulator", NAVY)
    scenario = st.selectbox(
        "Select simulation scenario",
        [
            "Patch Top 5 Highest-Risk Exposures",
            "Patch All CISA KEV Exposures",
            "Isolate Internet-Facing Critical Assets",
            "Fix IDS-Correlated Exposures",
            "Encrypt Sensitive Unencrypted/Unknown Assets",
        ],
    )
    sim_summary, sim_df = run_simulation(df, scenario, load_risk_policy(DATA_DIR / "risk_policy.json"))
    log_event("Simulation executed", details=scenario, operator=operator())

    before_total = sim_summary.loc[sim_summary["Metric"] == "Total Risk", "Before"].iloc[0]
    after_total = sim_summary.loc[sim_summary["Metric"] == "Total Risk", "After"].iloc[0]
    try:
        reduction = round(float(before_total) - float(after_total), 2)
        pct = round((reduction / float(before_total)) * 100, 1) if float(before_total) else 0
    except Exception:
        reduction, pct = "-", "-"
    k = st.columns(3)
    kpi_card(k[0], "Total Risk Before", before_total, GREY, NAVY)
    kpi_card(k[1], "Total Risk After", after_total, GREEN, GREEN_D)
    kpi_card(k[2], "Risk Reduced", reduction, GREEN, GREEN_D, f"{pct}% lower" if pct != "-" else "")

    render_table(sim_summary, height=320)
    section("Simulated Exposure Queue", GREEN)
    ds = sim_df[["asset_name", "cve_id", "priority", "final_score", "simulated_score"]].sort_values("simulated_score", ascending=False)
    render_table(ds)

with tabs[8]:
    section("Reports, Ticket Export, and Integrity Verification", NAVY)
    st.caption("Reports are sanitised against CSV/formula injection and signed with HMAC-SHA256 (tamper-evident).")

    detailed_cols = [
        "asset_id", "asset_name", "application_name", "business_process", "cve_id", "severity", "cvss_score",
        "epss_score", "epss_percentile", "kev_status", "network_zone", "open_ports",
        "ids_alert_count", "privacy_impact_level", "final_score", "priority", "asset_owner",
        "remediation_due_date", "sla_status", "primary_action", "temporary_mitigation",
        "compensating_control", "validation_step", "control_area", "exception_status", "exception_validity",
    ]
    detailed_report = df[[c for c in detailed_cols if c in df.columns]].copy()
    executive_report = executive_summary_report(df)
    ticket_report = build_ticket_export(df)

    rc = st.columns(3)
    reports = {
        "detailed_remediation_report.csv": detailed_report,
        "executive_summary_report.csv": executive_report,
        "ticket_import_report.csv": ticket_report,
    }
    for idx, (filename, report_df) in enumerate(reports.items()):
        csv_bytes = to_csv_bytes(report_df)
        sig = generate_sha256(csv_bytes)
        st.session_state.last_hashes[filename] = sig
        with rc[idx]:
            st.markdown(f"**{filename.replace('_', ' ').replace('.csv', '').title()}**")
            st.download_button(f"Download CSV", data=csv_bytes, file_name=filename, mime="text/csv", use_container_width=True)
            st.caption("HMAC-SHA256 signature")
            st.code(sig, language="text")
            st.download_button("Download signature", data=f"{filename}\nHMAC-SHA256: {sig}\n".encode("utf-8"),
                               file_name=f"{filename}.hmac.txt", mime="text/plain", use_container_width=True)

    log_event("Reports prepared", details="Detailed, executive, and ticket export reports generated", operator=operator())

    section("Verify Report Integrity", GREEN)
    verify_file = st.file_uploader("Upload a report CSV to verify", type=["csv"], key="verify_report")
    original_hash = st.text_input("Paste original HMAC-SHA256 signature")
    if st.button("Verify Signature"):
        if verify_file is None or not original_hash.strip():
            st.warning("Upload a file and paste the original HMAC-SHA256 signature.")
        else:
            ok = verify_sha256(verify_file.getvalue(), original_hash)
            if ok:
                st.success("Verified: report integrity signature matches.")
                log_event("Report signature verified", details="Signature matched", operator=operator())
            else:
                st.error("Tampered or mismatch: signature does not match.")
                log_event("Report signature verification failed", details="Signature mismatch", operator=operator())

with tabs[9]:
    section("Audit Log and Risk Trend", NAVY)

    section("Data Quality Notices", YELLOW)
    notices = st.session_state.get("dq_notices", [])
    if notices:
        st.caption(f"{len(notices)} notice(s) raised during validation of the last assessment. These are non-blocking \u2014 rows are retained for review.")
        for n in notices:
            st.warning(n)
    else:
        st.caption("No data-quality notices from the last assessment.")

    audit_df = read_audit_log(DATA_DIR / "audit_log.csv")
    section("Audit Log", GREEN)
    render_table(audit_df.tail(100))

    section("Risk Trend Snapshots", GREEN)
    snapshots = read_risk_snapshots(DATA_DIR / "risk_snapshots.csv")
    if snapshots.empty:
        st.info("No risk snapshots found yet. Run assessment to create snapshots.")
    else:
        render_table(snapshots.tail(20), height=320)
        if len(snapshots) > 1:
            snap = snapshots.rename(columns={
                "critical_count": "Critical exposures",
                "high_count": "High exposures",
                "average_score": "Average score",
            })
            fig = px.line(
                snap, x="timestamp", y=["Critical exposures", "High exposures", "Average score"],
                title="Risk Trend Over Time", color_discrete_sequence=[RED, YELLOW, GREEN], markers=True,
            )
            fig = style_fig(fig)
            fig.update_layout(legend_title_text="")
            fig.update_xaxes(title="Snapshot time")
            fig.update_yaxes(title="Count / average score")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.caption("Run more than one assessment to see the risk trend build up over time.")

with tabs[10]:
    section("Assessment History", NAVY)
    _mode = storage_mode(str(DATA_DIR))
    _badge = ("Cloud Storage bucket" if _mode == "gcs" else "local disk")
    st.caption(
        "Every assessment run is archived here with its metrics, input fingerprints, and full "
        "results. Reopen a past run, compare it with the previous one, regenerate its Action Plan, "
        f"and re-download its signed reports \u2014 a reproducible, audit-defensible trail. "
        f"**Currently persisting to: {_badge}.**"
    )

    runs = list_runs(str(DATA_DIR))
    if runs.empty:
        st.info("No archived runs yet. Run a Cyber Exposure Assessment to create the first history entry.")
    else:
        reg_cols = ["run_id", "timestamp", "operator", "total_exposures", "critical", "high",
                    "medium", "low", "kev_count", "sla_breached", "average_score",
                    "vuln_rows", "asset_rows", "ids_rows"]
        render_table(runs[[c for c in reg_cols if c in runs.columns]], height=280)

        # Trend across runs
        if len(runs) > 1:
            tr = runs.sort_values("run_id").copy()
            for c in ["critical", "high", "average_score"]:
                tr[c] = pd.to_numeric(tr[c], errors="coerce")
            tr = tr.rename(columns={"critical": "Critical", "high": "High", "average_score": "Average score"})
            trfig = px.line(tr, x="timestamp", y=["Critical", "High", "Average score"], markers=True,
                            title="History \u2014 Critical / High / Average Score Across Runs",
                            color_discrete_sequence=[RED, YELLOW, GREEN])
            trfig = style_fig(trfig)
            trfig.update_layout(legend_title_text="")
            trfig.update_xaxes(title="Run")
            trfig.update_yaxes(title="Count / score")
            st.plotly_chart(trfig, use_container_width=True)

        section("Open a Past Run", GREEN)
        labels = [f"{r.run_id}  \u00b7  {r.timestamp}  \u00b7  {r.operator}  \u00b7  {r.total_exposures} exposures"
                  for r in runs.itertuples()]
        idx = st.selectbox("Select an archived run", range(len(runs)),
                           format_func=lambda i: labels[i], key="hist_pick")
        sel = runs.iloc[idx]
        run_df = load_run(str(sel["run_id"]), str(DATA_DIR))

        if run_df is None or run_df.empty:
            st.warning("The archived data file for this run could not be loaded.")
        else:
            h = st.columns(4)
            kpi_card(h[0], "Exposures", len(run_df), GREEN, NAVY)
            kpi_card(h[1], "Critical / High", int(run_df["priority"].astype(str).isin(["Critical", "High"]).sum()), RED, RED)
            kpi_card(h[2], "CISA KEV", int((run_df.get("kev_status", "").astype(str).str.lower() == "yes").sum()), YELLOW, "#8A6D0E")
            kpi_card(h[3], "SLA Breached", int((run_df.get("sla_status", "").astype(str) == "Breached").sum()), RED, RED)

            dash = "\u2014"
            st.caption(
                f"Input fingerprints \u2014 vuln: `{sel.get('vuln_fingerprint', '') or dash}` "
                f"\u00b7 asset: `{sel.get('asset_fingerprint', '') or dash}` "
                f"\u00b7 ids: `{sel.get('ids_fingerprint', '') or dash}`  "
                f"(these prove exactly which input data produced this run)."
            )

            # Compare with the previous run
            with st.expander("Compare with the previous run (new / resolved / persisting exposures)", expanded=False):
                order_ids = list(runs.sort_values("run_id")["run_id"].astype(str))
                cur_i = order_ids.index(str(sel["run_id"]))
                if cur_i == 0:
                    st.info("This is the earliest archived run \u2014 there is nothing earlier to compare against.")
                else:
                    prev_id = order_ids[cur_i - 1]
                    prev_df = load_run(prev_id, str(DATA_DIR))

                    def _keyset(d):
                        if d is None or d.empty or "asset_id" not in d or "cve_id" not in d:
                            return set()
                        return set((d["asset_id"].astype(str) + "|" + d["cve_id"].astype(str)).tolist())

                    cur_k, prev_k = _keyset(run_df), _keyset(prev_df)
                    new_k, gone_k, keep_k = cur_k - prev_k, prev_k - cur_k, cur_k & prev_k
                    d = st.columns(3)
                    kpi_card(d[0], "Newly appeared", len(new_k), YELLOW, "#8A6D0E", f"vs {prev_id}")
                    kpi_card(d[1], "Resolved / gone", len(gone_k), GREEN, GREEN_D, f"vs {prev_id}")
                    kpi_card(d[2], "Still open", len(keep_k), GREY, NAVY, f"vs {prev_id}")
                    if new_k:
                        new_view = run_df[(run_df["asset_id"].astype(str) + "|" + run_df["cve_id"].astype(str)).isin(new_k)]
                        nc = [c for c in ["asset_name", "cve_id", "priority", "final_score", "kev_status", "sla_status"] if c in new_view.columns]
                        st.markdown("**Newly appeared in this run**")
                        render_table(new_view[nc], height=220)

            section("Archived Exposure Results", GREEN)
            disp = [c for c in ["asset_name", "application_name", "cve_id", "severity", "cvss_score",
                                "epss_percentile", "kev_status", "network_exposure_level", "ids_alert_count",
                                "privacy_impact_level", "final_score", "priority", "sla_status", "primary_action"]
                    if c in run_df.columns]
            render_table(run_df[disp] if disp else run_df)

            # Re-download this run's Action Plan (worst-first), HMAC-signed
            section("Re-download This Run", GREEN)
            po = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
            rr = run_df.copy()
            rr["_k"] = (rr.get("kev_status", "").astype(str).str.lower() == "yes").map({True: 0, False: 1})
            rr["_p"] = rr.get("priority", "").map(po).fillna(5)
            rr["_s"] = pd.to_numeric(rr.get("final_score", 0), errors="coerce").fillna(0)
            rr = rr.sort_values(["_k", "_p", "_s"], ascending=[True, True, False]).drop(columns=["_k", "_p", "_s"])
            hplan = compose_action_plan(rr)
            rid = str(sel["run_id"])
            g = st.columns(3)
            hcsv = to_csv_bytes(hplan)
            with g[0]:
                st.download_button("Action Plan CSV", data=hcsv, file_name=f"action_plan_{rid}.csv",
                                   mime="text/csv", use_container_width=True, key=f"h_csv_{rid}")
                st.code(generate_sha256(hcsv), language="text")
            with g[1]:
                try:
                    hx = to_xlsx_bytes(hplan)
                    st.download_button("Action Plan Excel", data=hx, file_name=f"action_plan_{rid}.xlsx",
                                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                       use_container_width=True, key=f"h_xlsx_{rid}")
                    st.code(generate_sha256(hx), language="text")
                except Exception as exc:
                    st.warning(f"Excel unavailable: {exc}")
            with g[2]:
                try:
                    hp = to_pdf_bytes(hplan, generated_by=str(sel.get("operator", "system")))
                    st.download_button("Action Plan PDF", data=hp, file_name=f"action_plan_{rid}.pdf",
                                       mime="application/pdf", use_container_width=True, key=f"h_pdf_{rid}")
                    st.code(generate_sha256(hp), language="text")
                except ImportError:
                    st.warning("PDF export needs `reportlab` (add to requirements.txt).")
                except Exception as exc:
                    st.warning(f"PDF unavailable: {exc}")

            with st.expander("Delete this archived run", expanded=False):
                st.caption("Removes this run's stored results and registry entry. This cannot be undone.")
                confirm = st.checkbox("I understand this permanently deletes this archived run.", key=f"del_ok_{rid}")
                if st.button("Delete run", key=f"del_btn_{rid}", disabled=not confirm):
                    if delete_run(rid, str(DATA_DIR)):
                        log_event("Assessment history run deleted", details=f"run_id={rid}", operator=operator())
                        st.success(f"Deleted run {rid}. Refreshing\u2026")
                        st.rerun()
                    else:
                        st.error("Could not delete the run.")

    st.caption(
        "Note: on Cloud Run, local files reset on restart. Set the `CEGP_GCS_BUCKET` environment "
        "variable (and add `google-cloud-storage`) to persist this history to a Cloud Storage bucket "
        "instead \u2014 see the GCP guide, Part 11. Locally it persists on disk."
    )

~~~

---

## `requirements.txt`  —  place at: `cyber-exposure-governance-platform/requirements.txt`  ·  _UPDATED this session_

~~~text
streamlit>=1.36.0
pandas>=2.0.0
requests>=2.31.0
plotly>=5.20.0
openpyxl>=3.1.0
xlrd>=2.0.1
reportlab>=4.0,<5.0
kaleido==0.2.1
# Optional (cloud only): uncomment to persist Assessment History to a Cloud Storage bucket
# google-cloud-storage>=2.16,<4.0

~~~

---

## `verify_pipeline.py`  —  place at: `cyber-exposure-governance-platform/verify_pipeline.py`  ·  _unchanged_

~~~python
import sys
import pandas as pd
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).parent
sys.path.append(str(BASE_DIR))

# Import core engines directly (avoids importing GUI app.py)
try:
    from core.asset_context_engine import calculate_business_impact, enrich_with_asset_context
    from core.control_mapping_engine import add_control_mapping
    from core.exception_engine import apply_exceptions
    from core.ids_correlation_engine import correlate_ids_alerts
    from core.import_normalizer import normalize_vulnerability_input
    from core.network_exposure_engine import add_network_exposure
    from core.playbook_engine import add_remediation_playbooks
    from core.policy_engine import load_risk_policy
    from core.privacy_impact_engine import add_privacy_impact
    from core.remediation_governance import assign_remediation_governance
    from core.scoring_engine import calculate_final_score, calculate_threat_intelligence_score, summarize_score_drivers
    from core.validator import validate_asset_df, validate_ids_df, validate_vulnerability_df
    
    from services.cisa_kev_service import enrich_with_kev
    from services.epss_service import enrich_with_epss
    from services.nvd_service import enrich_with_nvd
    
    print("[OK] Successfully imported all core and service modules.")
except Exception as e:
    print(f"[ERROR] Failed to import core modules: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

def run_local_assessment(vuln_df, asset_df, ids_df, exceptions_df, DATA_DIR):
    # This matches the pipeline inside app.py exactly
    vuln_df = normalize_vulnerability_input(vuln_df, import_type="Standard Template")
    vuln_df, vuln_errors, vuln_warnings = validate_vulnerability_df(vuln_df)
    asset_df, asset_errors, asset_warnings = validate_asset_df(asset_df)
    ids_df, ids_errors, ids_warnings = validate_ids_df(ids_df) if ids_df is not None else (pd.DataFrame(), [], [])

    errors = vuln_errors + asset_errors + ids_errors
    warnings = vuln_warnings + asset_warnings + ids_warnings
    if errors:
        return None, errors, warnings

    policy = load_risk_policy(DATA_DIR / "risk_policy.json")

    df = enrich_with_kev(vuln_df, use_live=False)
    df = enrich_with_epss(df, use_live=False)
    df = enrich_with_nvd(df, use_live=False, api_key=None)

    df = enrich_with_asset_context(df, asset_df)
    df = calculate_business_impact(df)
    df = add_network_exposure(df)
    df = correlate_ids_alerts(df, ids_df)
    df = add_privacy_impact(df)

    df = calculate_threat_intelligence_score(df, policy)
    df = calculate_final_score(df, policy, include_sla_score=False)
    df = assign_remediation_governance(df, policy)
    df = calculate_final_score(df, policy, include_sla_score=True)
    df = assign_remediation_governance(df, policy)

    df = add_remediation_playbooks(df)
    df = apply_exceptions(df, exceptions_df)
    df = add_control_mapping(df)
    df["score_drivers"] = df.apply(summarize_score_drivers, axis=1)

    priority_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    df["_priority_order"] = df["priority"].map(priority_order).fillna(5)
    df = df.sort_values(["_priority_order", "final_score"], ascending=[True, False]).drop(columns=["_priority_order"])

    return df, errors, warnings

def main():
    print("Starting pipeline verification...")
    
    DATA_DIR = BASE_DIR / "data"
    vuln_path = DATA_DIR / "sample_input.csv"
    asset_path = DATA_DIR / "asset_inventory.csv"
    ids_path = DATA_DIR / "ids_alerts.csv"
    exceptions_path = DATA_DIR / "risk_exceptions.csv"
    
    # Load data
    try:
        vuln_df = pd.read_csv(vuln_path)
        asset_df = pd.read_csv(asset_path)
        ids_df = pd.read_csv(ids_path)
        exceptions_df = pd.read_csv(exceptions_path)
        print(f"[OK] Loaded input files successfully: vuln_df={len(vuln_df)} rows, asset_df={len(asset_df)} rows, ids_df={len(ids_df)} rows, exceptions_df={len(exceptions_df)} rows")
    except Exception as e:
        print(f"[ERROR] Failed to load sample files: {e}")
        sys.exit(1)
        
    # Execute assessment
    try:
        df, errors, warnings = run_local_assessment(
            vuln_df=vuln_df,
            asset_df=asset_df,
            ids_df=ids_df,
            exceptions_df=exceptions_df,
            DATA_DIR=DATA_DIR
        )
        
        if errors:
            print("[ERROR] Pipeline returned errors:")
            for err in errors:
                print(f"  - {err}")
            sys.exit(1)
            
        print("[OK] Pipeline executed successfully without errors.")
        if warnings:
            print(f"[INFO] Received {len(warnings)} non-blocking data quality warnings.")
            
        # Verify output dataframe integrity
        required_cols = ["final_score", "priority", "remediation_due_date", "sla_status", "primary_action"]
        missing_cols = [c for c in required_cols if c not in df.columns]
        if missing_cols:
            print(f"[ERROR] Missing critical output columns: {missing_cols}")
            sys.exit(1)
            
        print("[OK] Output dataframe verified: all critical output fields are populated.")
        print("\n=== Assessment Summary Metrics ===")
        print(f"Total processed rows: {len(df)}")
        print(f"Average final score: {df['final_score'].mean():.2f}")
        print(f"Highest risk score: {df['final_score'].max():.2f}")
        print(f"Lowest risk score: {df['final_score'].min():.2f}")
        print("\nPriority Breakdown:")
        print(df['priority'].value_counts().to_string())
        print("\nSLA Status Breakdown:")
        print(df['sla_status'].value_counts().to_string())
        
        print("\n[OK] Pipeline verification completed successfully! Codebase is healthy.")
        
    except Exception as e:
        print(f"[ERROR] Pipeline execution failed with an exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

~~~

---

## `.streamlit/config.toml`  —  place at: `cyber-exposure-governance-platform/.streamlit/config.toml`  ·  _unchanged_

~~~toml
[theme]
base = "light"
primaryColor = "#01A982"
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#EEF1F5"
textColor = "#1F2937"
font = "sans serif"

[server]
maxUploadSize = 50

~~~

---

## `core/__init__.py`  —  place at: `cyber-exposure-governance-platform/core/__init__.py`  ·  _unchanged_

~~~python

~~~

---

## `core/asset_context_engine.py`  —  place at: `cyber-exposure-governance-platform/core/asset_context_engine.py`  ·  _unchanged_

~~~python
"""Business and asset context enrichment."""
from __future__ import annotations

import pandas as pd


def enrich_with_asset_context(vuln_df: pd.DataFrame, asset_df: pd.DataFrame) -> pd.DataFrame:
    vuln_df = vuln_df.copy()
    asset_df = asset_df.copy()

    # Keep one inventory row per asset for deterministic merging.
    asset_df = asset_df.drop_duplicates(subset=["asset_id"], keep="first")

    merged = vuln_df.merge(asset_df, on="asset_id", how="left", suffixes=("", "_asset"))

    # Fill safe defaults if asset inventory is missing.
    defaults = {
        "application_name": "Unknown",
        "business_process": "Unknown",
        "business_owner": "Unknown",
        "network_zone": "Unknown",
        "open_ports": "",
        "firewall_status": "Unknown",
        "vpn_required": "Unknown",
        "asset_type": "Unknown",
        "data_type": "Unknown",
        "pii_present": "Unknown",
        "data_sensitivity": "Unknown",
        "encryption_status": "Unknown",
        "regulatory_impact": "Unknown",
    }
    for col, default in defaults.items():
        if col not in merged.columns:
            merged[col] = default
        merged[col] = merged[col].fillna(default).replace("", default)

    return merged


def calculate_business_impact(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    def score(row):
        points = 0
        reasons = []
        criticality = str(row.get("business_criticality", "")).lower()
        environment = str(row.get("environment", "")).lower()
        sensitivity = str(row.get("data_sensitivity", "")).lower()

        if criticality == "high":
            points += 8
            reasons.append("high business criticality")
        elif criticality == "medium":
            points += 5
            reasons.append("medium business criticality")
        else:
            points += 2
            reasons.append("low/unknown business criticality")

        if environment == "prod":
            points += 4
            reasons.append("production environment")
        elif environment in {"uat", "stage", "staging"}:
            points += 2

        if sensitivity == "high":
            points += 3
            reasons.append("high data sensitivity")

        return min(points, 15), "; ".join(reasons)

    values = df.apply(score, axis=1, result_type="expand")
    df["business_impact_score"] = values[0].astype(float)
    df["business_impact_reason"] = values[1]
    return df

~~~

---

## `core/audit_logger.py`  —  place at: `cyber-exposure-governance-platform/core/audit_logger.py`  ·  _unchanged_

~~~python
"""Simple CSV audit logger with operator attribution.

Every logged action records who performed it (operator) and when, so the audit
trail can answer "who accepted this risk / ran this assessment", not just that
something happened. The operator is captured in the UI session and passed in on
each call; it defaults to "system" for automated events.
"""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

FIELDNAMES = ["timestamp", "operator", "action", "asset_id", "cve_id", "details"]


def log_event(
    action: str,
    asset_id: str = "",
    cve_id: str = "",
    details: str = "",
    operator: str = "system",
    log_path: str = "data/audit_log.csv",
) -> None:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists()
    operator = (str(operator).strip() or "system")
    with path.open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not exists or path.stat().st_size == 0:
            writer.writerow(FIELDNAMES)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            operator,
            action,
            asset_id,
            cve_id,
            details,
        ])


def read_audit_log(log_path: str = "data/audit_log.csv"):
    import pandas as pd
    path = Path(log_path)
    if not path.exists():
        return pd.DataFrame(columns=FIELDNAMES)
    df = pd.read_csv(path)
    # Backward-compatibility: older logs may not have an operator column.
    if "operator" not in df.columns:
        df["operator"] = "system"
        df = df[[c for c in FIELDNAMES if c in df.columns]]
    return df

~~~

---

## `core/control_mapping_engine.py`  —  place at: `cyber-exposure-governance-platform/core/control_mapping_engine.py`  ·  _unchanged_

~~~python
"""Control mapping lite engine for academic and governance alignment."""
from __future__ import annotations

import pandas as pd


def add_control_mapping(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    def compute(row):
        areas = []
        reasons = []

        if str(row.get("kev_status", "")).lower() == "yes":
            areas.append("Vulnerability Management")
            reasons.append("known exploited vulnerability requires prioritised remediation")
        if str(row.get("network_zone", "")).lower() in {"internet", "dmz"} or str(row.get("internet_facing", "")).lower() == "yes":
            areas.append("Attack Surface Management")
            reasons.append("external or DMZ exposure")
        if int(row.get("ids_alert_count", 0) or 0) > 0:
            areas.append("Threat Detection and Response")
            reasons.append("IDS/IPS alerts correlated with asset")
        if str(row.get("pii_present", "")).lower() == "yes" or str(row.get("privacy_impact_level", "")).lower() in {"critical", "high"}:
            areas.append("Data Protection and Privacy")
            reasons.append("sensitive or personal data exposure")
        if str(row.get("encryption_status", "")).lower() in {"unknown", "not encrypted"}:
            areas.append("Cryptographic Protection")
            reasons.append("encryption control weakness or uncertainty")
        if str(row.get("sla_status", "")).lower() in {"breached", "due soon"}:
            areas.append("Security Governance")
            reasons.append("SLA governance requires attention")
        if str(row.get("exception_status", "")).strip():
            areas.append("Risk Management")
            reasons.append("risk exception/deferral workflow involved")
        if str(row.get("firewall_status", "")).lower() == "allowed":
            areas.append("Network Security")
            reasons.append("firewall allows access to affected asset")

        if not areas:
            areas.append("Routine Vulnerability Management")
            reasons.append("standard remediation tracking")

        # Preserve order and uniqueness
        unique_areas = list(dict.fromkeys(areas))
        unique_reasons = list(dict.fromkeys(reasons))
        return ", ".join(unique_areas), "; ".join(unique_reasons)

    values = df.apply(compute, axis=1, result_type="expand")
    df["control_area"] = values[0]
    df["control_mapping_reason"] = values[1]
    return df

~~~

---

## `core/csv_security.py`  —  place at: `cyber-exposure-governance-platform/core/csv_security.py`  ·  _unchanged_

~~~python
"""CSV / spreadsheet formula-injection protection for exported files.

A common weakness in security tools is that they export untrusted data to CSV.
If a cell value begins with '=', '+', '-', '@', or a control character, Excel /
Google Sheets / LibreOffice will interpret it as a live formula when the file is
opened (CSV / formula injection, CWE-1236). Because this product ingests
externally supplied vulnerability, asset, and IDS data, every export is passed
through this sanitiser so a malicious cell cannot become an executable formula in
the recipient's spreadsheet.
"""
from __future__ import annotations

import pandas as pd

# Leading characters that spreadsheet apps may treat as the start of a formula.
DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value: object) -> object:
    """Neutralise a single value if it could be read as a spreadsheet formula."""
    if value is None or isinstance(value, (int, float, bool)):
        return value
    text = str(value)
    if text and text[0] in DANGEROUS_PREFIXES:
        # Prefix with an apostrophe so the spreadsheet treats it as plain text.
        return "'" + text
    return value


def sanitize_df_for_export(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of df with all object/string cells made injection-safe."""
    safe = df.copy()
    for col in safe.columns:
        if safe[col].dtype == object:
            safe[col] = safe[col].map(sanitize_cell)
    return safe

~~~

---

## `core/exception_engine.py`  —  place at: `cyber-exposure-governance-platform/core/exception_engine.py`  ·  _unchanged_

~~~python
"""Risk acceptance / exception workflow."""
from __future__ import annotations

import pandas as pd


def load_exceptions(path: str = "data/risk_exceptions.csv") -> pd.DataFrame:
    try:
        df = pd.read_csv(path)
        df.columns = [c.strip().lower() for c in df.columns]
        return df
    except Exception:
        return pd.DataFrame(columns=[
            "asset_id", "cve_id", "exception_status", "acceptance_reason",
            "accepted_by", "acceptance_expiry_date", "compensating_control"
        ])


def apply_exceptions(exposure_df: pd.DataFrame, exceptions_df: pd.DataFrame | None) -> pd.DataFrame:
    df = exposure_df.copy()
    if exceptions_df is None or exceptions_df.empty:
        for col in ["exception_status", "acceptance_reason", "accepted_by", "acceptance_expiry_date", "exception_validity"]:
            df[col] = ""
        return df

    exceptions = exceptions_df.copy()
    exceptions.columns = [c.strip().lower() for c in exceptions.columns]
    if "cve_id" in exceptions.columns:
        exceptions["cve_id"] = exceptions["cve_id"].astype(str).str.upper().str.strip()

    for col in ["asset_id", "cve_id"]:
        if col not in exceptions.columns:
            exceptions[col] = ""

    merged = df.merge(exceptions, on=["asset_id", "cve_id"], how="left", suffixes=("", "_exception"))

    def validity(row):
        status = str(row.get("exception_status", "") or "").strip()
        if not status:
            return ""
        expiry = pd.to_datetime(row.get("acceptance_expiry_date", ""), errors="coerce")
        if pd.isna(expiry):
            return "No Expiry Provided"
        if expiry.normalize() < pd.Timestamp.now().normalize():
            return "Expired"
        return "Valid"

    merged["exception_status"] = merged["exception_status"].fillna("")
    merged["acceptance_reason"] = merged["acceptance_reason"].fillna("")
    merged["accepted_by"] = merged["accepted_by"].fillna("")
    merged["acceptance_expiry_date"] = merged["acceptance_expiry_date"].fillna("")
    if "compensating_control_exception" in merged.columns:
        merged["exception_compensating_control"] = merged["compensating_control_exception"].fillna("")
    elif "compensating_control" in merged.columns:
        # If playbook also has compensating_control, avoid overwriting. Keep exception-specific name.
        merged["exception_compensating_control"] = ""
    else:
        merged["exception_compensating_control"] = ""

    merged["exception_validity"] = merged.apply(validity, axis=1)
    merged["active_governance_state"] = merged.apply(
        lambda r: r["exception_status"] if r["exception_status"] else r.get("remediation_status", "Open"), axis=1
    )
    return merged

~~~

---

## `core/ids_correlation_engine.py`  —  place at: `cyber-exposure-governance-platform/core/ids_correlation_engine.py`  ·  _unchanged_

~~~python
"""IDS/IPS alert correlation engine."""
from __future__ import annotations

import pandas as pd


def correlate_ids_alerts(exposure_df: pd.DataFrame, ids_df: pd.DataFrame | None) -> pd.DataFrame:
    df = exposure_df.copy()

    if ids_df is None or ids_df.empty:
        df["ids_alert_count"] = 0
        df["highest_alert_severity"] = "None"
        df["exploit_attempt_detected"] = "No"
        df["ids_correlation_score_raw"] = 0.0
        df["ids_correlation_reason"] = "No IDS/IPS alerts provided"
        return df

    alerts = ids_df.copy()
    alerts.columns = [c.strip().lower() for c in alerts.columns]

    def severity_rank(value: str) -> int:
        value = str(value).lower()
        if value == "critical":
            return 4
        if value == "high":
            return 3
        if value == "medium":
            return 2
        if value == "low":
            return 1
        return 0

    alerts["sev_rank"] = alerts["alert_severity"].apply(severity_rank)
    alerts["is_exploit"] = alerts["alert_type"].str.lower().str.contains("exploit", na=False)
    alerts["high_confidence"] = alerts["confidence"].str.lower().eq("high")

    grouped = alerts.groupby("asset_id").agg(
        ids_alert_count=("alert_id", "count"),
        max_sev_rank=("sev_rank", "max"),
        exploit_attempt_detected_bool=("is_exploit", "max"),
        high_confidence_count=("high_confidence", "sum"),
        signatures=("signature_name", lambda x: "; ".join(sorted(set([str(v) for v in x if str(v).strip()]))[:5])),
    ).reset_index()

    rank_to_sev = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "None"}
    grouped["highest_alert_severity"] = grouped["max_sev_rank"].map(rank_to_sev).fillna("None")
    grouped["exploit_attempt_detected"] = grouped["exploit_attempt_detected_bool"].map({True: "Yes", False: "No"})

    def score(row):
        points = 0
        reasons = []
        alert_count = int(row.get("ids_alert_count", 0))
        max_rank = int(row.get("max_sev_rank", 0))
        exploit = bool(row.get("exploit_attempt_detected_bool", False))
        high_conf = int(row.get("high_confidence_count", 0))

        if alert_count > 0:
            points += 5
            reasons.append(f"{alert_count} IDS/IPS alert(s)")
        if max_rank >= 3:
            points += 15
            reasons.append("high/critical alert severity")
        elif max_rank == 2:
            points += 8
            reasons.append("medium alert severity")
        if exploit:
            points += 20
            reasons.append("exploit attempt detected")
        if high_conf > 0:
            points += 10
            reasons.append("high-confidence alert")
        if alert_count > 3:
            points += 10
            reasons.append("multiple alerts on same asset")

        return min(points, 35), "; ".join(reasons)

    values = grouped.apply(score, axis=1, result_type="expand")
    grouped["ids_correlation_score_raw"] = values[0].astype(float)
    grouped["ids_correlation_reason"] = values[1]

    merged = df.merge(
        grouped[
            [
                "asset_id",
                "ids_alert_count",
                "highest_alert_severity",
                "exploit_attempt_detected",
                "ids_correlation_score_raw",
                "ids_correlation_reason",
                "signatures",
            ]
        ],
        on="asset_id",
        how="left",
    )

    merged["ids_alert_count"] = merged["ids_alert_count"].fillna(0).astype(int)
    merged["highest_alert_severity"] = merged["highest_alert_severity"].fillna("None")
    merged["exploit_attempt_detected"] = merged["exploit_attempt_detected"].fillna("No")
    merged["ids_correlation_score_raw"] = merged["ids_correlation_score_raw"].fillna(0.0)
    merged["ids_correlation_reason"] = merged["ids_correlation_reason"].fillna("No IDS/IPS alerts correlated")
    merged["signatures"] = merged["signatures"].fillna("")
    return merged

~~~

---

## `core/import_normalizer.py`  —  place at: `cyber-exposure-governance-platform/core/import_normalizer.py`  ·  _unchanged_

~~~python
"""Connector-ready CSV normalization for standard and scanner-style inputs."""
from __future__ import annotations

import re
from typing import Dict

import pandas as pd

from core.validator import normalize_cve, normalize_text, normalize_yes_no


STANDARD_COLUMNS = [
    "asset_id",
    "asset_name",
    "product",
    "cve_id",
    "business_criticality",
    "internet_facing",
    "environment",
    "asset_owner",
    "first_detected_date",
]


def _first_existing(row: pd.Series, candidates: list[str], default: str = "") -> str:
    for c in candidates:
        if c in row and str(row[c]).strip():
            return str(row[c]).strip()
    return default


def normalize_vulnerability_input(df: pd.DataFrame, import_type: str = "Standard Template") -> pd.DataFrame:
    """Normalize common vulnerability scanner CSV shapes to the product schema.

    This is intentionally lightweight: it supports demo-friendly CSV exports without claiming
    to be a full Nessus/Qualys/OpenVAS parser.
    """
    df = df.copy()
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]

    if import_type == "Standard Template":
        # Ensure optional fields exist
        for col in STANDARD_COLUMNS:
            if col not in df.columns:
                df[col] = ""
        return df[STANDARD_COLUMNS]

    rows = []
    for idx, row in df.iterrows():
        cve_field = _first_existing(row, ["cve_id", "cve", "cves", "cve_list", "vulnerability_id"])
        cves = re.findall(r"CVE-\d{4}-\d{4,}", cve_field, flags=re.IGNORECASE) or [cve_field]
        host = _first_existing(row, ["asset_id", "host", "hostname", "ip", "asset", "dns_name"], f"AST-{idx+1:03d}")
        asset_name = _first_existing(row, ["asset_name", "host", "hostname", "ip", "asset", "dns_name"], host)
        product = _first_existing(row, ["product", "plugin_name", "name", "service", "solution"], "Unknown")
        severity = _first_existing(row, ["business_criticality", "criticality", "severity", "risk"], "Medium").title()
        if severity not in {"High", "Medium", "Low"}:
            if severity in {"Critical"}:
                severity = "High"
            elif severity in {"Info", "Informational", "None"}:
                severity = "Low"
            else:
                severity = "Medium"

        for cve in cves:
            rows.append(
                {
                    "asset_id": normalize_text(host),
                    "asset_name": normalize_text(asset_name),
                    "product": normalize_text(product),
                    "cve_id": normalize_cve(cve),
                    "business_criticality": severity,
                    "internet_facing": normalize_yes_no(_first_existing(row, ["internet_facing", "external", "exposed"], "No")),
                    "environment": _first_existing(row, ["environment", "env"], "Prod"),
                    "asset_owner": _first_existing(row, ["asset_owner", "owner"], "Unassigned"),
                    "first_detected_date": _first_existing(row, ["first_detected_date", "detected_date", "date"], pd.Timestamp.now().strftime("%Y-%m-%d")),
                }
            )
    return pd.DataFrame(rows, columns=STANDARD_COLUMNS)

~~~

---

## `core/network_exposure_engine.py`  —  place at: `cyber-exposure-governance-platform/core/network_exposure_engine.py`  ·  _unchanged_

~~~python
"""Network exposure scoring engine."""
from __future__ import annotations

import re

import pandas as pd

DANGEROUS_PORTS = {"22", "23", "3389", "445", "5900", "5985", "5986", "1433", "1521", "3306", "5432", "6379"}


def _parse_ports(value) -> set[str]:
    text = "" if value is None or pd.isna(value) else str(value)
    return set(re.findall(r"\d+", text))


def add_network_exposure(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    def compute(row):
        points = 0
        reasons = []

        zone = str(row.get("network_zone", "")).strip().lower()
        firewall = str(row.get("firewall_status", "")).strip().lower()
        vpn_required = str(row.get("vpn_required", "")).strip().lower()
        asset_type = str(row.get("asset_type", "")).strip().lower()
        ports = _parse_ports(row.get("open_ports", ""))

        if zone == "internet":
            points += 20
            reasons.append("internet-facing network zone")
        elif zone == "dmz":
            points += 15
            reasons.append("DMZ exposure")
        elif zone == "vpn":
            points += 8
            reasons.append("VPN zone")
        elif zone == "internal":
            points += 5
            reasons.append("internal network zone")
        else:
            points += 5
            reasons.append("unknown network zone")

        if firewall == "allowed":
            points += 10
            reasons.append("firewall allows access")
        elif firewall == "restricted":
            points += 5
            reasons.append("restricted firewall access")

        risky_ports = sorted(ports & DANGEROUS_PORTS)
        if risky_ports:
            points += 10
            reasons.append(f"risky open ports: {', '.join(risky_ports)}")

        if vpn_required == "no":
            points += 5
            reasons.append("VPN not required")

        if asset_type in {"wireless", "mobile", "network device"}:
            points += 5
            reasons.append(f"{asset_type} exposure")

        raw_score = min(points, 30)
        if raw_score >= 25:
            level = "Critical"
        elif raw_score >= 18:
            level = "High"
        elif raw_score >= 10:
            level = "Medium"
        else:
            level = "Low"

        return raw_score, level, "; ".join(reasons)

    values = df.apply(compute, axis=1, result_type="expand")
    df["network_exposure_score_raw"] = values[0].astype(float)
    df["network_exposure_level"] = values[1]
    df["network_exposure_reason"] = values[2]
    return df

~~~

---

## `core/playbook_engine.py`  —  place at: `cyber-exposure-governance-platform/core/playbook_engine.py`  ·  _unchanged_

~~~python
"""Rule-based remediation playbook generator."""
from __future__ import annotations

import pandas as pd


def add_remediation_playbooks(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    def compute(row):
        kev = str(row.get("kev_status", "")).lower() == "yes"
        internet = str(row.get("internet_facing", "")).lower() == "yes" or str(row.get("network_zone", "")).lower() == "internet"
        ids = str(row.get("exploit_attempt_detected", "")).lower() == "yes" or int(row.get("ids_alert_count", 0) or 0) > 0
        priority = str(row.get("priority", "Low"))
        privacy_level = str(row.get("privacy_impact_level", "Low"))
        encryption = str(row.get("encryption_status", "")).lower()
        sla = str(row.get("sla_status", "Within SLA"))

        if kev and internet and ids:
            primary = "Emergency patch or isolate affected service immediately"
            temporary = "Restrict inbound access, apply WAF/IPS rule, or remove public exposure until patched"
            control = "Enhanced IDS monitoring, firewall deny rule, emergency change approval"
            change = "Emergency Change"
            validation = "Rescan asset and verify IDS alerts stop after remediation"
        elif kev and internet:
            primary = "Prioritize urgent patching for known exploited internet-facing exposure"
            temporary = "Restrict public access or enforce compensating network controls"
            control = "Firewall restriction, WAF rule, continuous monitoring"
            change = "Emergency Change"
            validation = "Confirm vendor patch and validate external exposure is reduced"
        elif ids:
            primary = "Investigate correlated IDS/IPS activity and remediate vulnerable service"
            temporary = "Increase monitoring and block suspicious source indicators where appropriate"
            control = "SOC triage, IDS rule tuning, temporary network restrictions"
            change = "Expedited Change"
            validation = "Review alerts and confirm no continued exploit attempts"
        elif priority in {"Critical", "High"}:
            primary = "Patch within assigned SLA based on risk priority"
            temporary = "Apply vendor mitigation or restrict access until patched"
            control = "Patch management tracking and owner escalation"
            change = "Standard Change" if priority == "High" else "Expedited Change"
            validation = "Rescan and validate CVE closure"
        else:
            primary = "Track and remediate in normal patch cycle"
            temporary = "Monitor for change in exploitability or exposure"
            control = "Routine vulnerability management"
            change = "Standard Change"
            validation = "Validate during next scheduled scan"

        if privacy_level in {"Critical", "High"} and encryption in {"unknown", "not encrypted"}:
            primary += " and perform privacy/encryption control review"
            control += "; encryption validation"
            validation += "; verify encryption status and privacy controls"

        if sla == "Breached":
            primary = "Escalate breached remediation item and " + primary[0].lower() + primary[1:]
            change = "Escalated Remediation"

        summary = f"{primary}. Temporary mitigation: {temporary}. Validation: {validation}."
        return primary, temporary, control, change, validation, summary

    values = df.apply(compute, axis=1, result_type="expand")
    df["primary_action"] = values[0]
    df["temporary_mitigation"] = values[1]
    df["compensating_control"] = values[2]
    df["change_type"] = values[3]
    df["validation_step"] = values[4]
    df["playbook_summary"] = values[5]
    return df

~~~

---

## `core/policy_engine.py`  —  place at: `cyber-exposure-governance-platform/core/policy_engine.py`  ·  _unchanged_

~~~python
"""Risk policy loader for configurable scoring, SLA, and priority thresholds."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_POLICY = {
    "weights": {
        "threat_intelligence": 35,
        "business_impact": 15,
        "network_exposure": 20,
        "ids_correlation": 15,
        "privacy_impact": 10,
        "sla_governance": 5,
    },
    "sla_days": {"Critical": 7, "High": 15, "Medium": 30, "Low": 90},
    "priority_thresholds": {"Critical": 85, "High": 70, "Medium": 45, "Low": 0},
}


def load_risk_policy(policy_path: str | Path = "data/risk_policy.json") -> Dict[str, Any]:
    path = Path(policy_path)
    if not path.exists():
        return DEFAULT_POLICY.copy()

    try:
        with path.open("r", encoding="utf-8") as f:
            policy = json.load(f)
        # Defensive merge with defaults
        merged = DEFAULT_POLICY.copy()
        merged["weights"] = {**DEFAULT_POLICY["weights"], **policy.get("weights", {})}
        merged["sla_days"] = {**DEFAULT_POLICY["sla_days"], **policy.get("sla_days", {})}
        merged["priority_thresholds"] = {
            **DEFAULT_POLICY["priority_thresholds"],
            **policy.get("priority_thresholds", {}),
        }
        return merged
    except Exception:
        return DEFAULT_POLICY.copy()


def get_weight(policy: Dict[str, Any], section_name: str) -> float:
    return float(policy.get("weights", {}).get(section_name, DEFAULT_POLICY["weights"].get(section_name, 0)))


def get_sla_days(policy: Dict[str, Any], priority: str) -> int:
    return int(policy.get("sla_days", {}).get(priority, DEFAULT_POLICY["sla_days"].get(priority, 90)))


def get_priority_thresholds(policy: Dict[str, Any]) -> Dict[str, float]:
    return policy.get("priority_thresholds", DEFAULT_POLICY["priority_thresholds"]).copy()


def classify_priority(score: float, policy: Dict[str, Any] | None = None) -> str:
    policy = policy or DEFAULT_POLICY
    thresholds = get_priority_thresholds(policy)
    score = float(score or 0)
    if score >= float(thresholds.get("Critical", 85)):
        return "Critical"
    if score >= float(thresholds.get("High", 70)):
        return "High"
    if score >= float(thresholds.get("Medium", 45)):
        return "Medium"
    return "Low"

~~~

---

## `core/privacy_impact_engine.py`  —  place at: `cyber-exposure-governance-platform/core/privacy_impact_engine.py`  ·  _unchanged_

~~~python
"""Privacy impact scoring engine."""
from __future__ import annotations

import pandas as pd


SENSITIVE_DATA_TYPES = {"customer data", "hr data", "employee data", "financial data", "payment data", "health data", "employee access data", "partner data"}


def add_privacy_impact(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    def compute(row):
        points = 0
        reasons = []

        pii = str(row.get("pii_present", "")).strip().lower()
        sensitivity = str(row.get("data_sensitivity", "")).strip().lower()
        data_type = str(row.get("data_type", "")).strip().lower()
        encryption = str(row.get("encryption_status", "")).strip().lower()
        regulatory = str(row.get("regulatory_impact", "")).strip().lower()

        if pii == "yes":
            points += 10
            reasons.append("PII present")
        if sensitivity == "high":
            points += 10
            reasons.append("high data sensitivity")
        elif sensitivity == "medium":
            points += 5
            reasons.append("medium data sensitivity")

        if data_type in SENSITIVE_DATA_TYPES or any(term in data_type for term in ["customer", "financial", "hr", "employee", "payment", "health"]):
            points += 10
            reasons.append(f"sensitive data type: {row.get('data_type', '')}")

        if encryption == "not encrypted":
            points += 15
            reasons.append("data not encrypted")
        elif encryption == "unknown":
            points += 8
            reasons.append("encryption status unknown")

        if regulatory == "high":
            points += 10
            reasons.append("high regulatory impact")
        elif regulatory == "medium":
            points += 5
            reasons.append("medium regulatory impact")

        raw = min(points, 30)
        if raw >= 25:
            level = "Critical"
        elif raw >= 18:
            level = "High"
        elif raw >= 8:
            level = "Medium"
        else:
            level = "Low"

        return raw, level, "; ".join(reasons) if reasons else "No major privacy impact identified"

    values = df.apply(compute, axis=1, result_type="expand")
    df["privacy_impact_score_raw"] = values[0].astype(float)
    df["privacy_impact_level"] = values[1]
    df["privacy_reason"] = values[2]
    return df

~~~

---

## `core/remediation_governance.py`  —  place at: `cyber-exposure-governance-platform/core/remediation_governance.py`  ·  _unchanged_

~~~python
"""Remediation SLA and escalation governance."""
from __future__ import annotations

from datetime import datetime, timedelta

import pandas as pd

from core.policy_engine import get_sla_days


def _parse_date(value):
    if value is None or pd.isna(value) or str(value).strip() == "":
        return pd.Timestamp.now().normalize()
    parsed = pd.to_datetime(value, errors="coerce")
    if pd.isna(parsed):
        return pd.Timestamp.now().normalize()
    return parsed.normalize()


def assign_remediation_governance(df: pd.DataFrame, policy: dict, today: pd.Timestamp | None = None) -> pd.DataFrame:
    df = df.copy()
    today = today or pd.Timestamp.now().normalize()

    def compute(row):
        priority = str(row.get("priority", "Low"))
        sla_days = get_sla_days(policy, priority)
        detected = _parse_date(row.get("first_detected_date", None))
        due_date = detected + pd.Timedelta(days=sla_days)
        days_remaining = int((due_date - today).days)

        if days_remaining < 0:
            sla_status = "Breached"
        elif days_remaining <= 3:
            sla_status = "Due Soon"
        else:
            sla_status = "Within SLA"

        escalation_required = "Yes" if priority in {"Critical", "High"} or sla_status == "Breached" else "No"
        reason_parts = []
        if priority in {"Critical", "High"}:
            reason_parts.append(f"{priority} priority exposure")
        if sla_status == "Breached":
            reason_parts.append("SLA breached")
        if str(row.get("kev_status", "")).lower() == "yes":
            reason_parts.append("known exploited vulnerability")
        if str(row.get("exploit_attempt_detected", "")).lower() == "yes":
            reason_parts.append("IDS exploit signal")

        return (
            "Open",
            due_date.strftime("%Y-%m-%d"),
            sla_status,
            days_remaining,
            escalation_required,
            "; ".join(reason_parts) if reason_parts else "No immediate escalation condition",
        )

    values = df.apply(compute, axis=1, result_type="expand")
    df["remediation_status"] = values[0]
    df["remediation_due_date"] = values[1]
    df["sla_status"] = values[2]
    df["days_remaining"] = values[3].astype(int)
    df["escalation_required"] = values[4]
    df["escalation_reason"] = values[5]
    return df

~~~

---

## `core/report_integrity.py`  —  place at: `cyber-exposure-governance-platform/core/report_integrity.py`  ·  _unchanged_

~~~python
"""Tamper-evident report integrity using HMAC-SHA256.

A plain SHA-256 digest only detects accidental change: anyone who edits an
exported report can simply recompute the hash, so it is not tamper-evident.
This module signs each report with HMAC-SHA256 using a secret key that lives in
the deployment (environment variable or a locally generated key file). Without
the key an attacker cannot forge a valid signature for a modified report, which
is what makes the integrity claim meaningful.

The public function names are unchanged so the rest of the app keeps working.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

_ENV_VAR = "REPORT_INTEGRITY_KEY"
_KEY_FILE = Path("data/.integrity_key")


def _load_key() -> bytes:
    """Resolve the signing key: env var first, then a persisted local key file.

    On first run (no env var, no key file) a strong random key is generated and
    saved so verification stays consistent across sessions on the same install.
    """
    env_key = os.environ.get(_ENV_VAR)
    if env_key:
        return env_key.encode("utf-8")

    try:
        if _KEY_FILE.exists():
            data = _KEY_FILE.read_text(encoding="utf-8").strip()
            if data:
                return data.encode("utf-8")
        _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        new_key = secrets.token_hex(32)
        _KEY_FILE.write_text(new_key, encoding="utf-8")
        return new_key.encode("utf-8")
    except Exception:
        # Last-resort deterministic fallback so the app never crashes in a demo.
        return b"cyber-exposure-governance-platform-default-key"


def generate_sha256(file_bytes: bytes) -> str:
    """Return the HMAC-SHA256 signature (hex) for the given report bytes."""
    return hmac.new(_load_key(), file_bytes, hashlib.sha256).hexdigest()


def verify_sha256(file_bytes: bytes, original_hash: str) -> bool:
    """Constant-time verification of a report against its HMAC-SHA256 signature."""
    calculated = generate_sha256(file_bytes)
    return hmac.compare_digest(
        calculated.lower().strip(), str(original_hash).lower().strip()
    )

~~~

---

## `core/run_history.py`  —  place at: `cyber-exposure-governance-platform/core/run_history.py`  ·  _NEW this session_

~~~python
"""Per-run assessment history.

Each completed assessment is archived so the UI can reopen a past run in full
detail, regenerate its Action Plan / reports, and prove which input data
produced it (via input fingerprints).

Storage goes through a pluggable backend (``core.storage_backend``): the local
filesystem by default, or Google Cloud Storage when ``CEGP_GCS_BUCKET`` is set
(see the GCP guide, Part 11). Local behaviour is unchanged; cloud persistence is
purely opt-in and falls back to local automatically if anything is unavailable.
"""
from __future__ import annotations

import hashlib
import io
from datetime import datetime
from pathlib import Path

import pandas as pd

from core.storage_backend import get_backend, active_backend_name

REGISTRY_COLUMNS = [
    "run_id", "timestamp", "operator",
    "total_exposures", "critical", "high", "medium", "low",
    "kev_count", "sla_breached", "average_score",
    "vuln_rows", "asset_rows", "ids_rows",
    "vuln_fingerprint", "asset_fingerprint", "ids_fingerprint",
    "data_file", "notes",
]

_REGISTRY_KEY = "runs/runs_index.csv"


def _run_key(data_file: str) -> str:
    return f"runs/{data_file}"


def runs_dir(data_dir: str | Path = "data") -> Path:
    """Local runs directory (created on demand). Informational for local mode."""
    p = Path(data_dir) / "runs"
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return p


def storage_mode(data_dir: str | Path = "data") -> str:
    """Return 'gcs' or 'local' so the UI can show where history is persisted."""
    return active_backend_name(data_dir)


def _short_hash(text: str, n: int = 12) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def fingerprint_df(df: pd.DataFrame | None) -> str:
    """Stable short fingerprint of a dataframe's content (proves which data was used)."""
    if df is None:
        return ""
    try:
        return _short_hash(df.to_csv(index=False))
    except Exception:
        return ""


def list_runs(data_dir: str | Path = "data") -> pd.DataFrame:
    """Return the run registry, newest first (empty frame if none)."""
    be = get_backend(data_dir)
    text = be.read_text(_REGISTRY_KEY)
    if not text:
        return pd.DataFrame(columns=REGISTRY_COLUMNS)
    try:
        df = pd.read_csv(io.StringIO(text), dtype=str).fillna("")
        for c in REGISTRY_COLUMNS:
            if c not in df.columns:
                df[c] = ""
        return df[REGISTRY_COLUMNS].sort_values("run_id", ascending=False).reset_index(drop=True)
    except Exception:
        return pd.DataFrame(columns=REGISTRY_COLUMNS)


def save_run(result_df: pd.DataFrame, *, operator: str = "system",
             data_dir: str | Path = "data", inputs: dict | None = None,
             notes: str = "") -> str:
    """Archive a full assessment result and append a registry row. Returns the run_id."""
    inputs = inputs or {}
    be = get_backend(data_dir)
    now = datetime.now()
    run_id = f"{now:%Y%m%d-%H%M%S}-{now.microsecond // 1000:03d}"
    data_file = f"run_{run_id}.csv"

    # Persist the full result frame (all columns) so the run can be reopened exactly.
    be.write_text(_run_key(data_file), result_df.to_csv(index=False))

    def _cnt(col: str, value: str) -> int:
        try:
            return int((result_df[col].astype(str) == value).sum())
        except Exception:
            return 0

    avg = 0.0
    if "final_score" in result_df.columns and len(result_df):
        try:
            avg = round(float(pd.to_numeric(result_df["final_score"], errors="coerce").mean()), 2)
        except Exception:
            avg = 0.0

    row = {
        "run_id": run_id,
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "operator": operator or "system",
        "total_exposures": len(result_df),
        "critical": _cnt("priority", "Critical"),
        "high": _cnt("priority", "High"),
        "medium": _cnt("priority", "Medium"),
        "low": _cnt("priority", "Low"),
        "kev_count": _cnt("kev_status", "Yes"),
        "sla_breached": _cnt("sla_status", "Breached"),
        "average_score": avg,
        "vuln_rows": inputs.get("vuln_rows", ""),
        "asset_rows": inputs.get("asset_rows", ""),
        "ids_rows": inputs.get("ids_rows", ""),
        "vuln_fingerprint": inputs.get("vuln_fingerprint", ""),
        "asset_fingerprint": inputs.get("asset_fingerprint", ""),
        "ids_fingerprint": inputs.get("ids_fingerprint", ""),
        "data_file": data_file,
        "notes": notes,
    }

    # Read-modify-write the registry (works identically on local and GCS backends).
    existing = list_runs(data_dir)
    new_row = pd.DataFrame([row], columns=REGISTRY_COLUMNS)
    registry = new_row if existing.empty else pd.concat([existing, new_row], ignore_index=True)
    be.write_text(_REGISTRY_KEY, registry[REGISTRY_COLUMNS].to_csv(index=False))
    return run_id


def load_run(run_id: str, data_dir: str | Path = "data") -> pd.DataFrame | None:
    """Reload a previously archived run's full result frame (or None if missing)."""
    be = get_backend(data_dir)
    data_file = f"run_{run_id}.csv"
    runs = list_runs(data_dir)
    if not runs.empty:
        match = runs[runs["run_id"].astype(str) == str(run_id)]
        if not match.empty and str(match.iloc[0].get("data_file", "")).strip():
            data_file = str(match.iloc[0]["data_file"])
    text = be.read_text(_run_key(data_file))
    if text is None:
        return None
    try:
        return pd.read_csv(io.StringIO(text))
    except Exception:
        return None


def delete_run(run_id: str, data_dir: str | Path = "data") -> bool:
    """Remove a run's archived data file and its registry row."""
    be = get_backend(data_dir)
    runs = list_runs(data_dir)
    if runs.empty:
        return False
    match = runs[runs["run_id"].astype(str) == str(run_id)]
    if not match.empty:
        be.delete(_run_key(str(match.iloc[0].get("data_file", f"run_{run_id}.csv"))))
    remaining = runs[runs["run_id"].astype(str) != str(run_id)]
    try:
        be.write_text(_REGISTRY_KEY, remaining[REGISTRY_COLUMNS].to_csv(index=False))
    except Exception:
        return False
    return True

~~~

---

## `core/scoring_engine.py`  —  place at: `cyber-exposure-governance-platform/core/scoring_engine.py`  ·  _unchanged_

~~~python
"""Final cyber exposure scoring engine."""
from __future__ import annotations

import pandas as pd

from core.policy_engine import classify_priority, get_weight


def _norm(raw: float, raw_max: float, target_max: float) -> float:
    raw = float(raw or 0)
    if raw_max <= 0:
        return 0.0
    return min((raw / raw_max) * target_max, target_max)


def calculate_threat_intelligence_score(df: pd.DataFrame, policy: dict) -> pd.DataFrame:
    df = df.copy()
    target = get_weight(policy, "threat_intelligence")

    def compute(row):
        raw = 0
        reasons = []
        kev = str(row.get("kev_status", "")).lower()
        epss_percentile = float(row.get("epss_percentile", 0) or 0)
        severity = str(row.get("severity", "")).lower()
        cvss = float(row.get("cvss_score", 0) or 0)

        if kev == "yes":
            raw += 40
            reasons.append("CISA KEV known exploited")
        if epss_percentile >= 0.95:
            raw += 25
            reasons.append("very high EPSS percentile")
        elif epss_percentile >= 0.80:
            raw += 18
            reasons.append("high EPSS percentile")
        elif epss_percentile >= 0.50:
            raw += 10
            reasons.append("medium EPSS percentile")
        else:
            raw += 3

        if severity == "critical" or cvss >= 9:
            raw += 15
            reasons.append("critical CVSS severity")
        elif severity == "high" or cvss >= 7:
            raw += 10
            reasons.append("high CVSS severity")
        elif severity == "medium" or cvss >= 4:
            raw += 5
            reasons.append("medium CVSS severity")
        elif cvss > 0:
            raw += 2

        return _norm(raw, 80, target), "; ".join(reasons)

    values = df.apply(compute, axis=1, result_type="expand")
    df["threat_intelligence_score"] = values[0].astype(float).round(2)
    df["threat_intelligence_reason"] = values[1]
    return df


def calculate_final_score(df: pd.DataFrame, policy: dict, include_sla_score: bool = False) -> pd.DataFrame:
    df = df.copy()

    if "threat_intelligence_score" not in df.columns:
        df = calculate_threat_intelligence_score(df, policy)

    network_target = get_weight(policy, "network_exposure")
    ids_target = get_weight(policy, "ids_correlation")
    privacy_target = get_weight(policy, "privacy_impact")

    df["network_exposure_score"] = df.get("network_exposure_score_raw", 0).apply(lambda x: _norm(x, 30, network_target))
    df["ids_correlation_score"] = df.get("ids_correlation_score_raw", 0).apply(lambda x: _norm(x, 35, ids_target))
    df["privacy_impact_score"] = df.get("privacy_impact_score_raw", 0).apply(lambda x: _norm(x, 30, privacy_target))

    for col in ["business_impact_score", "threat_intelligence_score", "network_exposure_score", "ids_correlation_score", "privacy_impact_score"]:
        if col not in df.columns:
            df[col] = 0.0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    if include_sla_score:
        sla_target = get_weight(policy, "sla_governance")
        df["sla_governance_score"] = df.get("sla_status", "").apply(lambda s: sla_target if str(s).lower() == "breached" else 0)
    else:
        df["sla_governance_score"] = 0.0

    df["final_score"] = (
        df["threat_intelligence_score"]
        + df["business_impact_score"]
        + df["network_exposure_score"]
        + df["ids_correlation_score"]
        + df["privacy_impact_score"]
        + df["sla_governance_score"]
    ).clip(0, 100).round(2)

    df["priority"] = df["final_score"].apply(lambda x: classify_priority(x, policy))
    return df


def summarize_score_drivers(row: pd.Series) -> str:
    drivers = []
    for label, col in [
        ("Threat intelligence", "threat_intelligence_score"),
        ("Business impact", "business_impact_score"),
        ("Network exposure", "network_exposure_score"),
        ("IDS correlation", "ids_correlation_score"),
        ("Privacy impact", "privacy_impact_score"),
        ("SLA governance", "sla_governance_score"),
    ]:
        try:
            value = float(row.get(col, 0) or 0)
        except Exception:
            value = 0
        if value > 0:
            drivers.append(f"{label}: {value:.1f}")
    return " | ".join(drivers)

~~~

---

## `core/simulation_engine.py`  —  place at: `cyber-exposure-governance-platform/core/simulation_engine.py`  ·  _unchanged_

~~~python
"""What-if risk reduction simulation engine."""
from __future__ import annotations

import pandas as pd

from core.policy_engine import classify_priority


def _metrics(df: pd.DataFrame, score_col: str = "final_score") -> dict:
    if df.empty:
        return {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Average Score": 0.0, "Total Risk": 0.0}
    counts = df["priority"].value_counts().to_dict() if "priority" in df else {}
    return {
        "Critical": int(counts.get("Critical", 0)),
        "High": int(counts.get("High", 0)),
        "Medium": int(counts.get("Medium", 0)),
        "Low": int(counts.get("Low", 0)),
        "Average Score": round(float(df[score_col].mean()), 2),
        "Total Risk": round(float(df[score_col].sum()), 2),
    }


def run_simulation(df: pd.DataFrame, scenario: str, policy: dict) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return summary dataframe and simulated dataframe."""
    before_df = df.copy()
    after_df = df.copy()
    after_df["simulated_score"] = after_df["final_score"].astype(float)

    if scenario == "Patch Top 5 Highest-Risk Exposures":
        idx = after_df.sort_values("final_score", ascending=False).head(5).index
        after_df.loc[idx, "simulated_score"] = (after_df.loc[idx, "simulated_score"] * 0.15).round(2)
    elif scenario == "Patch All CISA KEV Exposures":
        mask = after_df["kev_status"].eq("Yes")
        after_df.loc[mask, "simulated_score"] = (after_df.loc[mask, "simulated_score"] - after_df.loc[mask, "threat_intelligence_score"] * 0.75).clip(lower=0).round(2)
    elif scenario == "Isolate Internet-Facing Critical Assets":
        mask = (after_df["internet_facing"].eq("Yes") | after_df["network_zone"].str.lower().eq("internet")) & after_df["priority"].isin(["Critical", "High"])
        after_df.loc[mask, "simulated_score"] = (after_df.loc[mask, "simulated_score"] - after_df.loc[mask, "network_exposure_score"] * 0.8).clip(lower=0).round(2)
    elif scenario == "Fix IDS-Correlated Exposures":
        mask = after_df["ids_alert_count"].fillna(0).astype(int) > 0
        after_df.loc[mask, "simulated_score"] = (after_df.loc[mask, "simulated_score"] - after_df.loc[mask, "ids_correlation_score"]).clip(lower=0).round(2)
    elif scenario == "Encrypt Sensitive Unencrypted/Unknown Assets":
        mask = after_df["encryption_status"].str.lower().isin(["unknown", "not encrypted"]) & after_df["privacy_impact_level"].isin(["Critical", "High", "Medium"])
        after_df.loc[mask, "simulated_score"] = (after_df.loc[mask, "simulated_score"] - after_df.loc[mask, "privacy_impact_score"] * 0.8).clip(lower=0).round(2)

    after_df["priority"] = after_df["simulated_score"].apply(lambda x: classify_priority(x, policy))
    before = _metrics(before_df, "final_score")
    after = _metrics(after_df, "simulated_score")

    rows = []
    for metric in ["Critical", "High", "Medium", "Low", "Average Score", "Total Risk"]:
        b = before[metric]
        a = after[metric]
        if isinstance(b, (int, float)) and b:
            improvement = round(((b - a) / b) * 100, 2)
        else:
            improvement = 0.0
        rows.append({"Metric": metric, "Before": b, "After": a, "Improvement %": improvement})

    return pd.DataFrame(rows), after_df

~~~

---

## `core/storage_backend.py`  —  place at: `cyber-exposure-governance-platform/core/storage_backend.py`  ·  _NEW this session_

~~~python
"""Pluggable storage backend: local filesystem (default) or Google Cloud Storage.

Cloud Storage is used **only** when the ``CEGP_GCS_BUCKET`` environment variable is
set, the ``google-cloud-storage`` package is importable, and the bucket is reachable.
In every other case this transparently falls back to the local filesystem with
identical behaviour. This keeps local runs completely unchanged while letting a
Cloud Run deployment persist data durably (see the GCP guide, Part 11).

Configuration (cloud only):
    CEGP_GCS_BUCKET   the bucket name to store data in (enables the GCS backend)
    CEGP_GCS_PREFIX   optional key prefix inside the bucket (e.g. "cegp")

The backend exposes a tiny, filesystem-like API used by the history archive:
    exists / read_text / write_text / read_bytes / write_bytes / delete
Paths are logical and relative (e.g. "runs/runs_index.csv").
"""
from __future__ import annotations

import os
from pathlib import Path

ENV_BUCKET = "CEGP_GCS_BUCKET"
ENV_PREFIX = "CEGP_GCS_PREFIX"

# Cache backends by configuration so we don't rebuild a GCS client on every call.
_CACHE: dict = {}


class LocalBackend:
    """Filesystem backend. Logical paths resolve relative to ``base``."""

    name = "local"

    def __init__(self, base: str | Path = "."):
        self.base = Path(base)

    def _p(self, path: str | Path) -> Path:
        path = Path(path)
        return path if path.is_absolute() else self.base / path

    def exists(self, path) -> bool:
        try:
            return self._p(path).exists()
        except Exception:
            return False

    def read_text(self, path) -> str | None:
        p = self._p(path)
        try:
            return p.read_text(encoding="utf-8") if p.exists() else None
        except Exception:
            return None

    def write_text(self, path, text: str) -> None:
        p = self._p(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def read_bytes(self, path) -> bytes | None:
        p = self._p(path)
        try:
            return p.read_bytes() if p.exists() else None
        except Exception:
            return None

    def write_bytes(self, path, data: bytes) -> None:
        p = self._p(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def delete(self, path) -> None:
        p = self._p(path)
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


class GCSBackend:
    """Google Cloud Storage backend. Logical paths become object keys under a prefix."""

    name = "gcs"

    def __init__(self, bucket_name: str, prefix: str = ""):
        from google.cloud import storage  # lazy import; only needed in the cloud
        self._client = storage.Client()
        self._bucket = self._client.bucket(bucket_name)
        self._prefix = (prefix or "").strip("/")

    def _key(self, path) -> str:
        rel = str(path).replace("\\", "/").lstrip("/")
        return f"{self._prefix}/{rel}" if self._prefix else rel

    def _blob(self, path):
        return self._bucket.blob(self._key(path))

    def exists(self, path) -> bool:
        try:
            return self._blob(path).exists()
        except Exception:
            return False

    def read_text(self, path) -> str | None:
        try:
            b = self._blob(path)
            return b.download_as_text() if b.exists() else None
        except Exception:
            return None

    def write_text(self, path, text: str) -> None:
        self._blob(path).upload_from_string(text, content_type="text/csv")

    def read_bytes(self, path) -> bytes | None:
        try:
            b = self._blob(path)
            return b.download_as_bytes() if b.exists() else None
        except Exception:
            return None

    def write_bytes(self, path, data: bytes) -> None:
        self._blob(path).upload_from_string(data)

    def delete(self, path) -> None:
        try:
            b = self._blob(path)
            if b.exists():
                b.delete()
        except Exception:
            pass


def get_backend(local_base: str | Path = "."):
    """Return the active backend: GCS when configured and reachable, else local.

    Never raises: any failure to construct the GCS backend falls back to local,
    so the app keeps working regardless of environment.
    """
    bucket = os.environ.get(ENV_BUCKET, "").strip()
    prefix = os.environ.get(ENV_PREFIX, "").strip()
    key = (bucket, prefix, str(local_base))
    if key in _CACHE:
        return _CACHE[key]

    backend = None
    if bucket:
        try:
            backend = GCSBackend(bucket, prefix)
            # Light reachability touch; returns False but exercises the client/creds.
            backend.exists("__cegp_healthcheck__")
        except Exception:
            backend = None  # fall back to local on any problem

    if backend is None:
        backend = LocalBackend(local_base)

    _CACHE[key] = backend
    return backend


def active_backend_name(local_base: str | Path = ".") -> str:
    """Return 'gcs' or 'local' for display in the UI."""
    try:
        return get_backend(local_base).name
    except Exception:
        return "local"

~~~

---

## `core/ticket_exporter.py`  —  place at: `cyber-exposure-governance-platform/core/ticket_exporter.py`  ·  _unchanged_

~~~python
"""Jira/ServiceNow-style remediation ticket export."""
from __future__ import annotations

import pandas as pd


def build_ticket_export(df: pd.DataFrame) -> pd.DataFrame:
    records = []
    for _, row in df.iterrows():
        title = f"{row.get('priority', 'Medium')} cyber exposure on {row.get('asset_name', 'Unknown Asset')} - {row.get('cve_id', '')}"
        desc = (
            f"Asset: {row.get('asset_name', '')}\n"
            f"CVE: {row.get('cve_id', '')}\n"
            f"Business Process: {row.get('business_process', '')}\n"
            f"Final Score: {row.get('final_score', '')}\n"
            f"Risk Driver: {row.get('score_drivers', '')}\n"
            f"Recommended Action: {row.get('primary_action', '')}\n"
            f"Temporary Mitigation: {row.get('temporary_mitigation', '')}\n"
            f"Validation: {row.get('validation_step', '')}"
        )
        records.append(
            {
                "ticket_title": title,
                "description": desc,
                "priority": row.get("priority", "Medium"),
                "asset_owner": row.get("asset_owner", row.get("business_owner", "Unassigned")),
                "due_date": row.get("remediation_due_date", ""),
                "recommended_action": row.get("primary_action", ""),
                "business_process": row.get("business_process", ""),
                "cve_id": row.get("cve_id", ""),
                "asset_name": row.get("asset_name", ""),
                "control_area": row.get("control_area", ""),
            }
        )
    return pd.DataFrame(records)

~~~

---

## `core/trend_engine.py`  —  place at: `cyber-exposure-governance-platform/core/trend_engine.py`  ·  _unchanged_

~~~python
"""Risk trend snapshot engine."""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

import pandas as pd


def save_risk_snapshot(df: pd.DataFrame, path: str = "data/risk_snapshots.csv") -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    exists = p.exists()

    counts = df.get("priority", pd.Series(dtype=str)).value_counts().to_dict()
    row = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_exposures": len(df),
        "critical_count": int(counts.get("Critical", 0)),
        "high_count": int(counts.get("High", 0)),
        "medium_count": int(counts.get("Medium", 0)),
        "low_count": int(counts.get("Low", 0)),
        "average_score": round(float(df.get("final_score", pd.Series([0])).mean()), 2) if len(df) else 0,
        "kev_count": int((df.get("kev_status", pd.Series(dtype=str)) == "Yes").sum()),
        "ids_correlated_count": int((df.get("ids_alert_count", pd.Series(dtype=int)).fillna(0).astype(int) > 0).sum()) if "ids_alert_count" in df else 0,
        "sla_breached_count": int((df.get("sla_status", pd.Series(dtype=str)) == "Breached").sum()),
    }

    with p.open("a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not exists or p.stat().st_size == 0:
            writer.writeheader()
        writer.writerow(row)


def read_risk_snapshots(path: str = "data/risk_snapshots.csv") -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        return pd.DataFrame()
    return pd.read_csv(p)

~~~

---

## `core/validator.py`  —  place at: `cyber-exposure-governance-platform/core/validator.py`  ·  _unchanged_

~~~python
"""Input validation and normalization utilities."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

import pandas as pd

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

REQUIRED_VULN_COLUMNS = {
    "asset_id",
    "asset_name",
    "cve_id",
    "business_criticality",
    "internet_facing",
}

REQUIRED_ASSET_COLUMNS = {
    "asset_id",
    "application_name",
    "business_process",
    "network_zone",
    "open_ports",
    "firewall_status",
    "vpn_required",
    "data_type",
    "pii_present",
    "data_sensitivity",
    "encryption_status",
    "regulatory_impact",
}

IDS_COLUMNS = {
    "alert_id",
    "asset_id",
    "alert_type",
    "alert_severity",
    "source_ip",
    "destination_ip",
    "timestamp",
    "signature_name",
    "confidence",
}


def normalize_text(value: object) -> str:
    if value is None or pd.isna(value):
        return ""
    return str(value).strip()


def normalize_yes_no(value: object) -> str:
    text = normalize_text(value).lower()
    if text in {"yes", "y", "true", "1", "external", "internet"}:
        return "Yes"
    if text in {"no", "n", "false", "0", "internal"}:
        return "No"
    return normalize_text(value).title() if text else "Unknown"


def normalize_cve(value: object) -> str:
    return normalize_text(value).upper()


def validate_vulnerability_df(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    df = df.copy()
    df.columns = [c.strip().lower() for c in df.columns]

    missing = sorted(REQUIRED_VULN_COLUMNS - set(df.columns))
    if missing:
        errors.append(f"Missing required vulnerability columns: {', '.join(missing)}")
        return df, errors, warnings

    df["cve_id"] = df["cve_id"].apply(normalize_cve)
    df["asset_id"] = df["asset_id"].apply(normalize_text)
    df["asset_name"] = df["asset_name"].apply(normalize_text)
    df["business_criticality"] = df["business_criticality"].apply(lambda x: normalize_text(x).title())
    df["internet_facing"] = df["internet_facing"].apply(normalize_yes_no)

    if "first_detected_date" not in df.columns:
        df["first_detected_date"] = pd.Timestamp.now().strftime("%Y-%m-%d")

    invalid_cves = df.loc[~df["cve_id"].apply(lambda x: bool(CVE_PATTERN.match(x))), "cve_id"].unique().tolist()
    if invalid_cves:
        warnings.append(f"Invalid CVE format found and retained for review: {', '.join(invalid_cves[:10])}")

    invalid_crit = df.loc[~df["business_criticality"].isin(["High", "Medium", "Low"]), "business_criticality"].unique().tolist()
    if invalid_crit:
        warnings.append(f"Unexpected business criticality values found: {', '.join(map(str, invalid_crit))}")

    duplicates = df.duplicated(subset=["asset_id", "cve_id"]).sum()
    if duplicates:
        warnings.append(f"{duplicates} duplicate asset_id + cve_id rows found.")

    return df, errors, warnings


def validate_asset_df(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    df = df.copy()
    df.columns = [c.strip().lower() for c in df.columns]

    missing = sorted(REQUIRED_ASSET_COLUMNS - set(df.columns))
    if missing:
        errors.append(f"Missing required asset inventory columns: {', '.join(missing)}")
        return df, errors, warnings

    for col in df.columns:
        df[col] = df[col].apply(normalize_text)

    yes_no_cols = ["vpn_required", "pii_present"]
    for col in yes_no_cols:
        if col in df.columns:
            df[col] = df[col].apply(normalize_yes_no)

    duplicated_assets = df.duplicated(subset=["asset_id"]).sum()
    if duplicated_assets:
        warnings.append(f"{duplicated_assets} duplicate asset_id rows found in asset inventory.")

    return df, errors, warnings


def validate_ids_df(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    df = df.copy()
    df.columns = [c.strip().lower() for c in df.columns]

    missing = sorted(IDS_COLUMNS - set(df.columns))
    if missing:
        warnings.append(f"IDS file missing columns: {', '.join(missing)}. Missing values will be treated as blank.")
        for c in missing:
            df[c] = ""

    for col in df.columns:
        df[col] = df[col].apply(normalize_text)

    return df, errors, warnings

~~~

---

## `services/__init__.py`  —  place at: `cyber-exposure-governance-platform/services/__init__.py`  ·  _unchanged_

~~~python

~~~

---

## `services/cisa_kev_service.py`  —  place at: `cyber-exposure-governance-platform/services/cisa_kev_service.py`  ·  _unchanged_

~~~python
"""CISA Known Exploited Vulnerabilities enrichment service."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import pandas as pd
import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _load_json(path: str | Path) -> dict:
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def load_kev_catalog(use_live: bool = True, fallback_path: str = "data/fallback_kev.json", cache_path: str = "data/cache/kev_cache.json") -> pd.DataFrame:
    data = None
    if use_live:
        try:
            response = requests.get(CISA_KEV_URL, timeout=15)
            response.raise_for_status()
            data = response.json()
            Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
            with Path(cache_path).open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            data = None

    if data is None:
        for path in [cache_path, fallback_path]:
            try:
                if Path(path).exists():
                    data = _load_json(path)
                    break
            except Exception:
                data = None

    vulnerabilities = (data or {}).get("vulnerabilities", [])
    rows = []
    for item in vulnerabilities:
        rows.append(
            {
                "cve_id": str(item.get("cveID", "")).upper(),
                "kev_status": "Yes",
                "kev_vendor": item.get("vendorProject", ""),
                "kev_product": item.get("product", ""),
                "kev_vulnerability_name": item.get("vulnerabilityName", ""),
                "kev_date_added": item.get("dateAdded", ""),
                "kev_required_action": item.get("requiredAction", ""),
                "kev_due_date": item.get("dueDate", ""),
                "kev_ransomware_use": item.get("knownRansomwareCampaignUse", ""),
            }
        )
    return pd.DataFrame(rows)


def enrich_with_kev(df: pd.DataFrame, use_live: bool = True) -> pd.DataFrame:
    result = df.copy()
    kev_df = load_kev_catalog(use_live=use_live)
    if kev_df.empty:
        result["kev_status"] = "No"
        return result

    result = result.merge(kev_df, on="cve_id", how="left")
    result["kev_status"] = result["kev_status"].fillna("No")
    for col in ["kev_vendor", "kev_product", "kev_vulnerability_name", "kev_date_added", "kev_required_action", "kev_due_date", "kev_ransomware_use"]:
        if col in result.columns:
            result[col] = result[col].fillna("")
    return result

~~~

---

## `services/epss_service.py`  —  place at: `cyber-exposure-governance-platform/services/epss_service.py`  ·  _unchanged_

~~~python
"""FIRST EPSS enrichment service."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import pandas as pd
import requests

EPSS_URL = "https://api.first.org/data/v1/epss"


def _load_fallback(path: str = "data/fallback_epss.json") -> dict:
    try:
        with Path(path).open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _fetch_live_epss(cves: list[str]) -> dict:
    if not cves:
        return {}
    # FIRST supports comma-separated CVEs. Keep chunks moderate for demo stability.
    out = {}
    for i in range(0, len(cves), 50):
        chunk = cves[i:i+50]
        try:
            response = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=15)
            response.raise_for_status()
            payload = response.json()
            for item in payload.get("data", []):
                out[str(item.get("cve", "")).upper()] = {
                    "epss": float(item.get("epss", 0) or 0),
                    "percentile": float(item.get("percentile", 0) or 0),
                }
        except Exception:
            continue
    return out


def enrich_with_epss(df: pd.DataFrame, use_live: bool = True) -> pd.DataFrame:
    result = df.copy()
    cves = sorted(set(result["cve_id"].dropna().astype(str).str.upper()))
    data = _fetch_live_epss(cves) if use_live else {}
    fallback = _load_fallback()

    rows = []
    for cve in cves:
        item = data.get(cve) or fallback.get(cve) or {"epss": 0.0, "percentile": 0.0}
        rows.append({"cve_id": cve, "epss_score": float(item.get("epss", 0)), "epss_percentile": float(item.get("percentile", 0))})

    epss_df = pd.DataFrame(rows)
    result = result.merge(epss_df, on="cve_id", how="left")
    result["epss_score"] = result["epss_score"].fillna(0.0)
    result["epss_percentile"] = result["epss_percentile"].fillna(0.0)

    def category(p):
        if p >= 0.95:
            return "Very High"
        if p >= 0.80:
            return "High"
        if p >= 0.50:
            return "Medium"
        return "Low"

    result["epss_category"] = result["epss_percentile"].apply(category)
    return result

~~~

---

## `services/nvd_service.py`  —  place at: `cyber-exposure-governance-platform/services/nvd_service.py`  ·  _unchanged_

~~~python
"""NVD CVE enrichment service with fallback data."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _load_fallback(path: str = "data/fallback_nvd.json") -> dict:
    try:
        with Path(path).open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _extract_cvss(metrics: dict) -> tuple[float, str]:
    """Extract CVSS score/severity across CVSS v4/v3/v2 shapes."""
    candidates = [
        ("cvssMetricV40", "cvssData"),
        ("cvssMetricV31", "cvssData"),
        ("cvssMetricV30", "cvssData"),
        ("cvssMetricV2", "cvssData"),
    ]
    for metric_key, data_key in candidates:
        if metric_key in metrics and metrics[metric_key]:
            first = metrics[metric_key][0]
            cvss_data = first.get(data_key, {})
            score = cvss_data.get("baseScore", 0) or first.get("impactScore", 0) or 0
            severity = first.get("baseSeverity") or cvss_data.get("baseSeverity") or ""
            return float(score or 0), str(severity).title() if severity else _severity_from_score(float(score or 0))
    return 0.0, "Unknown"


def _severity_from_score(score: float) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def _fetch_nvd_single(cve: str, api_key: str | None = None) -> dict | None:
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = requests.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=15)
        response.raise_for_status()
        payload = response.json()
        vulns = payload.get("vulnerabilities", [])
        if not vulns:
            return None
        cve_obj = vulns[0].get("cve", {})
        descriptions = cve_obj.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        score, severity = _extract_cvss(cve_obj.get("metrics", {}))
        return {
            "cvss_score": score,
            "severity": severity,
            "description": description,
            "published": cve_obj.get("published", ""),
            "last_modified": cve_obj.get("lastModified", ""),
        }
    except Exception:
        return None


def enrich_with_nvd(df: pd.DataFrame, use_live: bool = True, api_key: str | None = None) -> pd.DataFrame:
    result = df.copy()
    cves = sorted(set(result["cve_id"].dropna().astype(str).str.upper()))
    fallback = _load_fallback()
    rows = []

    for cve in cves:
        item = _fetch_nvd_single(cve, api_key=api_key) if use_live else None
        item = item or fallback.get(cve) or {
            "cvss_score": 0.0,
            "severity": "Unknown",
            "description": "No CVE description available from live or fallback data.",
            "published": "",
            "last_modified": "",
        }
        rows.append(
            {
                "cve_id": cve,
                "cvss_score": float(item.get("cvss_score", 0) or 0),
                "severity": str(item.get("severity", "Unknown")).title(),
                "cve_description": item.get("description", ""),
                "cve_published": item.get("published", ""),
                "cve_last_modified": item.get("last_modified", ""),
            }
        )

    nvd_df = pd.DataFrame(rows)
    result = result.merge(nvd_df, on="cve_id", how="left")
    result["cvss_score"] = result["cvss_score"].fillna(0.0)
    result["severity"] = result["severity"].fillna("Unknown")
    return result

~~~

---

## `data/.integrity_key`  —  place at: `cyber-exposure-governance-platform/data/.integrity_key`  ·  _unchanged_

~~~text
<REDACTED — HMAC signing secret. Present in the ZIP; auto-generated on first run if absent.>
~~~

---

## `data/asset_inventory.csv`  —  place at: `cyber-exposure-governance-platform/data/asset_inventory.csv`  ·  _unchanged_

~~~text
asset_id,application_name,business_process,business_owner,network_zone,open_ports,firewall_status,vpn_required,asset_type,data_type,pii_present,data_sensitivity,encryption_status,regulatory_impact
AST-0001,App-0001,Knowledge Management,R&D Lead,Internal,6379,Restricted,Yes,Server,Source Code,No,High,Encrypted,High
AST-0002,App-0002,Partner File Exchange,DevOps Lead,Internal,"80,1521,3306",Restricted,Yes,Server,Source Code,No,Medium,Not Encrypted,Low
AST-0003,App-0003,HR Operations,Data Platform Lead,VPN,"3306,8080",Restricted,Yes,Server,Operational Data,No,High,Encrypted,High
AST-0004,App-0004,Identity Management,IT Operations Lead,Internal,443,Restricted,No,Workstation,Source Code,No,Medium,Encrypted,Medium
AST-0005,App-0005,Customer API Services,Platform Eng Lead,Internet,443,Allowed,Yes,Mobile,Operational Data,No,Low,Unknown,None
AST-0006,App-0006,HR Operations,R&D Lead,Internal,"3306,5000",Restricted,Yes,Workstation,Operational Data,No,Low,Encrypted,High
AST-0007,App-0007,Remote Connectivity,WebOps Lead,Internet,"3389,8443",Allowed,No,Network Device,Internal Data,No,Low,Not Encrypted,None
AST-0008,App-0008,Patient Records,Data Platform Lead,Internal,"80,5432",Restricted,Yes,Server,Partner Data,No,Low,Encrypted,Low
AST-0009,App-0009,Partner Management,Partner IT Lead,DMZ,"23,5000",Allowed,No,Server,Payment Data,Yes,Medium,Encrypted,Medium
AST-0010,App-0010,R&D,Email Security Lead,Internet,"80,443",Allowed,Yes,Network Device,Partner Data,Yes,Medium,Encrypted,High
AST-0011,App-0011,Network Connectivity,R&D Lead,Internal,443,Restricted,Yes,Server,Partner Data,Yes,Medium,Not Encrypted,None
AST-0012,App-0012,Remote Connectivity,Data Platform Lead,Internal,"80,443,1433,3306",None,No,Server,Employee Data,No,High,Encrypted,Medium
AST-0013,App-0013,Partner File Exchange,R&D Lead,Internal,80,Restricted,No,Mobile,Internal Data,No,Medium,Encrypted,High
AST-0014,App-0014,Remote Connectivity,DBA Team Lead,Internal,9090,None,No,Network Device,Health Data,No,High,Encrypted,Low
AST-0015,App-0015,Field Operations,R&D Lead,Internet,443,Allowed,Yes,Server,HR Data,Yes,Medium,Encrypted,None
AST-0016,App-0016,R&D,Platform Eng Lead,Internal,"8080,8443",Restricted,Yes,Server,Customer Data,No,High,Encrypted,High
AST-0017,App-0017,Business Intelligence,API Platform Lead,Internal,443,Restricted,No,Network Device,Employee Access Data,Yes,High,Encrypted,High
AST-0018,App-0018,Core Banking,DBA Team Lead,Internal,5000,Restricted,Yes,Server,Operational Data,No,High,Not Encrypted,High
AST-0019,App-0019,Identity Management,Mobility Team Lead,VPN,"445,3306,8080,8443",Restricted,No,Database,HR Data,Yes,High,Not Encrypted,Low
AST-0020,App-0020,Payments,Network Security Lead,Internal,"80,9000",None,Yes,Workstation,Employee Access Data,Yes,High,Unknown,Medium
AST-0021,App-0021,Network Connectivity,Data Platform Lead,Internet,"80,443",Allowed,Yes,Workstation,Internal Data,No,Medium,Unknown,Medium
AST-0022,App-0022,Network Connectivity,Infrastructure Lead,Internet,443,Allowed,No,Network Device,Operational Data,No,Medium,Unknown,None
AST-0023,App-0023,Field Operations,Mobility Team Lead,Internal,"22,23,443",None,No,Server,Payment Data,Yes,High,Encrypted,High
AST-0024,App-0024,Email Security,Infrastructure Lead,Internal,"443,5000",Restricted,Yes,Network Device,Partner Data,Yes,Medium,Not Encrypted,None
AST-0025,App-0025,Knowledge Management,Payments Eng Lead,Internet,"22,443,9000",Allowed,Yes,Server,HR Data,Yes,Medium,Not Encrypted,None
AST-0026,App-0026,Core Banking,Infrastructure Lead,DMZ,"80,8080",Allowed,Yes,Server,Source Code,No,Medium,Not Encrypted,Low
AST-0027,App-0027,R&D,Platform Eng Lead,Internal,"22,23",None,No,Server,Payment Data,Yes,Medium,Encrypted,High
AST-0028,App-0028,Partner Management,Mobility Team Lead,VPN,443,Restricted,Yes,Database,Health Data,Yes,Low,Unknown,None
AST-0029,App-0029,Patient Records,API Platform Lead,Internal,"389,3389,9090",None,Yes,Wireless,Customer Data,Yes,Medium,Encrypted,None
AST-0030,App-0030,Identity Management,R&D Lead,Internet,"1433,9090",Allowed,No,Wireless,HR Data,Yes,Low,Not Encrypted,None
AST-0031,App-0031,Patient Records,HR IT Lead,VPN,"389,6379,8080",Restricted,No,Server,Operational Data,No,High,Encrypted,Low
AST-0032,App-0032,Network Connectivity,Data Platform Lead,Internal,"443,1433,3389,8080",Restricted,Yes,Database,Customer Data,Yes,Medium,Encrypted,High
AST-0033,App-0033,Software Delivery,HR IT Lead,DMZ,"22,3306",Allowed,Yes,Mobile,Payment Data,Yes,Medium,Encrypted,Medium
AST-0034,App-0034,Payments,Infrastructure Lead,DMZ,"23,3306,8090,9090",Allowed,No,Network Device,Financial Data,No,High,Encrypted,High
AST-0035,App-0035,Operations Support,Network Ops Lead,Internet,8080,Allowed,No,Workstation,Internal Data,No,Medium,Encrypted,Medium
AST-0036,App-0036,Identity Management,Network Security Lead,Internet,389,Allowed,Yes,Network Device,Partner Data,Yes,Low,Encrypted,None
AST-0037,App-0037,Online Sales,DBA Team Lead,Internal,443,Restricted,No,Mobile,Health Data,Yes,Medium,Unknown,None
AST-0038,App-0038,Network Connectivity,Network Ops Lead,Internet,3389,Allowed,No,Workstation,Public Data,No,Medium,Not Encrypted,None
AST-0039,App-0039,Business Intelligence,Partner IT Lead,Internet,"23,443,1521",Allowed,Yes,Server,Partner Data,Yes,Medium,Encrypted,Medium
AST-0040,App-0040,Identity Management,Payments Eng Lead,Internal,"80,9000",Restricted,No,Server,Public Data,No,High,Encrypted,None
AST-0041,App-0041,Online Sales,Identity Team Lead,DMZ,"23,445",Restricted,Yes,Mobile,Employee Data,Yes,High,Unknown,Medium
AST-0042,App-0042,Software Delivery,R&D Lead,Internal,"25,3306,5900",None,No,Server,Health Data,Yes,High,Unknown,Low
AST-0043,App-0043,Partner Management,WebOps Lead,Internal,443,None,No,Database,Operational Data,No,High,Unknown,Low
AST-0044,App-0044,Partner Management,IT Operations Lead,Internal,443,Restricted,No,Workstation,Financial Data,Yes,High,Not Encrypted,None
AST-0045,App-0045,Financial Reporting,Network Security Lead,Internet,"22,389,3306,5000",Allowed,Yes,Network Device,Operational Data,No,Medium,Encrypted,None
AST-0046,App-0046,Payments,Email Security Lead,Internal,3306,Restricted,No,Workstation,Operational Data,No,Low,Encrypted,High
AST-0047,App-0047,Network Connectivity,DBA Team Lead,Internal,443,Restricted,Yes,Database,Public Data,No,Low,Encrypted,None
AST-0048,App-0048,Identity Management,IT Operations Lead,Internet,"80,8443",Allowed,Yes,Server,Public Data,No,High,Encrypted,High
AST-0049,App-0049,Online Sales,DBA Team Lead,Internal,443,Restricted,Yes,Server,Source Code,No,High,Not Encrypted,Medium
AST-0050,App-0050,Customer API Services,Internal Apps Lead,Internal,"22,389,9090",Restricted,No,Mobile,Employee Access Data,Yes,Low,Encrypted,None
AST-0051,App-0051,Core Banking,Internal Apps Lead,Internal,"80,389",Restricted,Yes,Server,HR Data,Yes,Low,Not Encrypted,None
AST-0052,App-0052,Knowledge Management,Network Security Lead,Internal,"8080,9000",Restricted,No,Server,Operational Data,No,High,Unknown,High
AST-0053,App-0053,Customer API Services,Network Ops Lead,VPN,"80,9000",Restricted,Yes,Server,Operational Data,No,High,Encrypted,Medium
AST-0054,App-0054,Online Sales,DevOps Lead,VPN,"445,5432",Restricted,No,Server,Financial Data,No,Low,Unknown,High
AST-0055,App-0055,HR Operations,Mobility Team Lead,Internet,3306,Allowed,No,Workstation,Employee Data,Yes,Medium,Unknown,None
AST-0056,App-0056,Network Connectivity,WebOps Lead,Internet,6379,Allowed,No,Server,Operational Data,No,Medium,Not Encrypted,High
AST-0057,App-0057,Online Sales,Data Platform Lead,Internal,"1433,8090,9000",Restricted,No,Server,Public Data,No,Medium,Not Encrypted,High
AST-0058,App-0058,HR Operations,DevOps Lead,Internet,443,Restricted,Yes,Network Device,HR Data,Yes,High,Encrypted,High
AST-0059,App-0059,Corporate Email,Partner IT Lead,VPN,"5432,8090",Restricted,No,Workstation,Employee Access Data,Yes,Medium,Not Encrypted,Low
AST-0060,App-0060,Network Connectivity,Mainframe Team Lead,Internal,"3389,6379",Restricted,Yes,Workstation,Internal Data,No,Medium,Encrypted,Low
AST-0061,App-0061,Identity Management,Network Security Lead,Internal,"5432,9090",None,Yes,Server,Health Data,Yes,Medium,Encrypted,Low
AST-0062,App-0062,Operations Support,Mobility Team Lead,Internet,8080,Restricted,No,Server,Partner Data,Yes,Medium,Encrypted,High
AST-0063,App-0063,Software Delivery,Mainframe Team Lead,Unknown,9000,None,Yes,Wireless,Financial Data,Yes,High,Encrypted,Medium
AST-0064,App-0064,Partner File Exchange,Infrastructure Lead,Internal,443,None,No,Workstation,Public Data,No,Medium,Unknown,None
AST-0065,App-0065,Online Sales,Platform Eng Lead,Unknown,"5432,8443,9000",None,Yes,Server,Financial Data,Yes,High,Encrypted,None
AST-0066,App-0066,Online Sales,Network Security Lead,Internet,"3306,3389",Allowed,Yes,Network Device,Source Code,No,Medium,Unknown,High
AST-0067,App-0067,Field Operations,Identity Team Lead,Internal,443,None,Yes,Network Device,Employee Access Data,Yes,High,Encrypted,Medium
AST-0068,App-0068,HR Operations,Platform Eng Lead,Internal,1521,None,No,Network Device,Public Data,No,Medium,Encrypted,None
AST-0069,App-0069,Corporate Email,Email Security Lead,VPN,443,Restricted,No,Mobile,Public Data,No,High,Encrypted,High
AST-0070,App-0070,Field Operations,Platform Eng Lead,DMZ,9000,Allowed,No,Server,Customer Data,No,Medium,Not Encrypted,High
AST-0071,App-0071,Email Security,Infrastructure Lead,Internal,"3389,5000,9000",Restricted,No,Server,HR Data,Yes,Medium,Unknown,None
AST-0072,App-0072,Corporate Email,Partner IT Lead,Internal,"1521,9000",None,Yes,Database,Employee Data,Yes,Medium,Not Encrypted,None
AST-0073,App-0073,Partner File Exchange,Email Security Lead,DMZ,"5900,8443",Allowed,Yes,Server,Partner Data,No,High,Not Encrypted,Low
AST-0074,App-0074,Financial Reporting,API Platform Lead,DMZ,"5900,6379",Allowed,Yes,Wireless,Operational Data,No,Low,Encrypted,High
AST-0075,App-0075,Operations Support,Email Security Lead,Internal,"25,8080",Restricted,Yes,Mobile,Employee Data,Yes,Medium,Encrypted,None
AST-0076,App-0076,Payments,DevOps Lead,Internal,"22,25,1521,8080",None,Yes,Server,Health Data,Yes,Medium,Encrypted,Low
AST-0077,App-0077,Customer API Services,Network Ops Lead,Unknown,80,Restricted,Yes,Workstation,Public Data,No,Low,Not Encrypted,Low
AST-0078,App-0078,R&D,Internal Apps Lead,VPN,"80,445",Restricted,Yes,Mobile,Operational Data,No,Medium,Encrypted,Low
AST-0079,App-0079,Payments,Network Ops Lead,DMZ,"389,1433",Allowed,No,Workstation,Source Code,No,High,Unknown,None
AST-0080,App-0080,Corporate Email,Data Platform Lead,DMZ,"389,5900,6379",Allowed,No,Database,Health Data,Yes,Medium,Not Encrypted,High
AST-0081,App-0081,Corporate Email,IT Operations Lead,Internal,"389,5432",None,No,Database,Source Code,No,Low,Unknown,High
AST-0082,App-0082,Patient Records,WebOps Lead,Internal,"25,1521",Restricted,No,Network Device,Public Data,No,Low,Not Encrypted,None
AST-0083,App-0083,Online Sales,API Platform Lead,Internal,23,Restricted,No,Server,Partner Data,Yes,High,Encrypted,High
AST-0084,App-0084,Core Banking,Payments Eng Lead,VPN,"1433,3306",Restricted,No,Network Device,Financial Data,Yes,Low,Not Encrypted,Low
AST-0085,App-0085,Corporate Email,Identity Team Lead,Internal,"3306,5900",None,Yes,Server,Partner Data,No,Medium,Not Encrypted,Medium
AST-0086,App-0086,Remote Connectivity,IT Operations Lead,Internet,80,Allowed,Yes,Workstation,Customer Data,Yes,Low,Encrypted,Medium
AST-0087,App-0087,Partner Management,Network Security Lead,Internal,"22,443,8080",None,No,Server,Operational Data,No,Medium,Not Encrypted,High
AST-0088,App-0088,Remote Connectivity,API Platform Lead,Internal,9090,Restricted,Yes,Network Device,Public Data,No,High,Unknown,Low
AST-0089,App-0089,Customer API Services,Clinical IT Lead,DMZ,"3306,5432",Restricted,Yes,Network Device,Partner Data,Yes,High,Encrypted,None
AST-0090,App-0090,Financial Reporting,HR IT Lead,Internal,"25,1433,6379,9000",Restricted,Yes,Server,Health Data,Yes,Medium,Not Encrypted,Medium
AST-0091,App-0091,Operations Support,Clinical IT Lead,Internet,443,Restricted,No,Network Device,Source Code,No,Low,Encrypted,Medium
AST-0092,App-0092,Online Sales,Payments Eng Lead,Internet,"3389,6379",Restricted,Yes,Workstation,Employee Access Data,Yes,Medium,Encrypted,None
AST-0093,App-0093,Business Intelligence,Data Platform Lead,DMZ,"389,8080",Allowed,No,Mobile,Public Data,No,Medium,Unknown,None
AST-0094,App-0094,Customer API Services,HR IT Lead,Internet,8443,Restricted,Yes,Server,Operational Data,No,Medium,Unknown,None
AST-0095,App-0095,R&D,HR IT Lead,DMZ,"1433,5432",Allowed,No,Workstation,Customer Data,Yes,High,Unknown,None
AST-0096,App-0096,Business Intelligence,Platform Eng Lead,DMZ,"445,5000,6379",Restricted,No,Server,Source Code,No,Medium,Unknown,High
AST-0097,App-0097,Partner File Exchange,Payments Eng Lead,Internal,"22,9000",Restricted,No,Network Device,Partner Data,Yes,High,Unknown,Medium
AST-0098,App-0098,Customer API Services,Data Platform Lead,DMZ,"1521,3306,5000",Allowed,No,Server,Internal Data,No,Medium,Encrypted,Medium
AST-0099,App-0099,Financial Reporting,Identity Team Lead,Internal,25,Restricted,No,Workstation,Source Code,No,High,Not Encrypted,None
AST-0100,App-0100,Corporate Email,R&D Lead,Internal,443,Restricted,Yes,Mobile,Source Code,No,High,Unknown,Medium
AST-0101,App-0101,Online Sales,WebOps Lead,Internet,"3306,6379",Restricted,Yes,Server,HR Data,Yes,Low,Unknown,None
AST-0102,App-0102,Corporate Email,Network Security Lead,DMZ,"389,445",Restricted,Yes,Database,Partner Data,Yes,High,Encrypted,Low
AST-0103,App-0103,Online Sales,Clinical IT Lead,VPN,"80,1521,5000",Restricted,No,Server,Employee Data,Yes,Medium,Encrypted,Medium
AST-0104,App-0104,Online Sales,Clinical IT Lead,Internal,"23,445,8090",None,No,Server,Partner Data,Yes,High,Not Encrypted,None
AST-0105,App-0105,Knowledge Management,DBA Team Lead,Internet,9000,Allowed,Yes,Wireless,Source Code,No,Medium,Not Encrypted,Low
AST-0106,App-0106,Online Sales,Data Platform Lead,Internal,443,None,Yes,Network Device,Customer Data,Yes,Low,Encrypted,Low
AST-0107,App-0107,Customer API Services,Payments Eng Lead,DMZ,"25,3306,8443",Restricted,Yes,Server,Health Data,Yes,Medium,Encrypted,Low
AST-0108,App-0108,Partner Management,Network Ops Lead,DMZ,"1521,5000",Restricted,Yes,Wireless,HR Data,Yes,Medium,Not Encrypted,Low
AST-0109,App-0109,Field Operations,DevOps Lead,VPN,"22,5000,6379,8090",Restricted,No,Database,Source Code,No,Medium,Encrypted,Low
AST-0110,App-0110,Remote Connectivity,WebOps Lead,Internet,"25,389",Restricted,Yes,Workstation,Public Data,No,Medium,Unknown,High
AST-0111,App-0111,Email Security,Clinical IT Lead,Internal,"3389,5432,8090",Restricted,No,Server,Employee Data,Yes,High,Not Encrypted,Low
AST-0112,App-0112,Business Intelligence,HR IT Lead,VPN,"25,5000,5900",Restricted,No,Mobile,Financial Data,Yes,Medium,Unknown,None
AST-0113,App-0113,Remote Connectivity,Partner IT Lead,DMZ,"25,1521,3389",Restricted,Yes,Network Device,Employee Access Data,Yes,Medium,Unknown,None
AST-0114,App-0114,Software Delivery,R&D Lead,DMZ,"22,1521,8080",Restricted,No,Network Device,Financial Data,Yes,Medium,Encrypted,None
AST-0115,App-0115,Partner Management,Network Security Lead,Internal,"1433,6379",None,No,Workstation,Employee Access Data,Yes,Medium,Unknown,Medium
AST-0116,App-0116,R&D,Email Security Lead,Internal,443,None,Yes,Server,Operational Data,No,Low,Not Encrypted,High
AST-0117,App-0117,Core Banking,Infrastructure Lead,Internet,443,Allowed,No,Server,Source Code,No,High,Not Encrypted,None
AST-0118,App-0118,Financial Reporting,Payments Eng Lead,DMZ,"23,1433",Restricted,No,Network Device,Internal Data,No,High,Unknown,High
AST-0119,App-0119,Network Connectivity,Email Security Lead,Internal,"80,8090",Restricted,No,Server,Internal Data,No,Medium,Not Encrypted,Low
AST-0120,App-0120,Remote Connectivity,IT Operations Lead,DMZ,"443,5900",Restricted,No,Server,Financial Data,Yes,Medium,Not Encrypted,High
AST-0121,App-0121,Patient Records,Network Security Lead,VPN,"23,1433",Restricted,Yes,Server,Operational Data,No,High,Not Encrypted,Low
AST-0122,App-0122,Knowledge Management,Network Ops Lead,Internet,"23,25,80,445",Restricted,Yes,Wireless,Customer Data,Yes,High,Unknown,Medium
AST-0123,App-0123,Knowledge Management,API Platform Lead,Internal,443,None,No,Server,Payment Data,Yes,High,Unknown,None
AST-0124,App-0124,Core Banking,Internal Apps Lead,DMZ,9090,Allowed,Yes,Workstation,Operational Data,No,High,Not Encrypted,Medium
AST-0125,App-0125,Online Sales,Network Security Lead,Internal,"23,8443",Restricted,No,Database,Public Data,No,Medium,Encrypted,None
AST-0126,App-0126,Knowledge Management,Partner IT Lead,DMZ,"443,3389,5900,8443",Allowed,Yes,Network Device,Source Code,No,Low,Not Encrypted,None
AST-0127,App-0127,HR Operations,DevOps Lead,VPN,"3306,6379",Restricted,Yes,Server,HR Data,Yes,Medium,Encrypted,Low
AST-0128,App-0128,Operations Support,HR IT Lead,Internal,"23,5432",Restricted,Yes,Server,Financial Data,Yes,Medium,Encrypted,High
AST-0129,App-0129,Operations Support,HR IT Lead,DMZ,443,Restricted,No,Mobile,Employee Data,Yes,High,Encrypted,Medium
AST-0130,App-0130,R&D,API Platform Lead,Internet,"22,443,5432",Allowed,Yes,Workstation,Source Code,No,Medium,Not Encrypted,None
AST-0131,App-0131,Remote Connectivity,Partner IT Lead,Internet,80,Restricted,Yes,Server,Public Data,No,Medium,Unknown,High
AST-0132,App-0132,Software Delivery,DBA Team Lead,Internal,"80,5900",Restricted,No,Server,Payment Data,Yes,Low,Encrypted,Medium
AST-0133,App-0133,Software Delivery,Payments Eng Lead,Internal,389,Restricted,Yes,Server,Operational Data,No,Medium,Encrypted,Low
AST-0134,App-0134,Knowledge Management,WebOps Lead,Internet,"22,3389,8080",Allowed,No,Server,Partner Data,Yes,High,Not Encrypted,High
AST-0135,App-0135,HR Operations,Payments Eng Lead,Internal,443,Restricted,Yes,Database,Source Code,No,Medium,Encrypted,Medium
AST-0136,App-0136,Network Connectivity,Platform Eng Lead,Internet,"25,445,3306",Allowed,Yes,Server,Payment Data,Yes,Low,Encrypted,None
AST-0137,App-0137,HR Operations,HR IT Lead,Internet,"443,8443",Allowed,No,Mobile,Source Code,No,High,Encrypted,Medium
AST-0138,App-0138,R&D,Network Ops Lead,VPN,1521,Restricted,Yes,Workstation,HR Data,No,Low,Encrypted,Medium
AST-0139,App-0139,Partner Management,DevOps Lead,Internal,443,Restricted,No,Server,Financial Data,No,Medium,Encrypted,High
AST-0140,App-0140,R&D,Infrastructure Lead,Internal,"8443,9000",Restricted,Yes,Server,Financial Data,Yes,Medium,Unknown,Low
AST-0141,App-0141,Patient Records,HR IT Lead,DMZ,443,Restricted,No,Workstation,Employee Data,No,High,Not Encrypted,High
AST-0142,App-0142,R&D,Platform Eng Lead,VPN,25,Restricted,Yes,Server,Partner Data,No,Medium,Unknown,None
AST-0143,App-0143,Core Banking,Clinical IT Lead,Internet,"443,5000",Allowed,Yes,Server,Financial Data,No,High,Encrypted,High
AST-0144,App-0144,Payments,Network Security Lead,DMZ,"445,8443",Restricted,No,Server,Employee Access Data,Yes,Medium,Encrypted,None
AST-0145,App-0145,Corporate Email,Email Security Lead,Internal,8443,Restricted,Yes,Wireless,Partner Data,Yes,Medium,Not Encrypted,Medium
AST-0146,App-0146,Customer API Services,Partner IT Lead,Internal,"443,3389",Restricted,No,Mobile,Internal Data,No,Medium,Unknown,None
AST-0147,App-0147,Business Intelligence,Network Security Lead,Internet,"1521,9090",Allowed,No,Wireless,Financial Data,Yes,Medium,Not Encrypted,High
AST-0148,App-0148,Partner Management,Network Ops Lead,Internet,1521,Restricted,No,Server,Operational Data,No,Medium,Not Encrypted,None
AST-0149,App-0149,Network Connectivity,Payments Eng Lead,Internet,"3306,5432",Restricted,No,Server,Internal Data,No,Medium,Not Encrypted,Low
AST-0150,App-0150,Operations Support,Identity Team Lead,VPN,"22,25,443",Restricted,Yes,Mobile,HR Data,Yes,Low,Encrypted,High
AST-0151,App-0151,Email Security,Mainframe Team Lead,DMZ,25,Restricted,No,Network Device,Employee Data,Yes,High,Not Encrypted,None
AST-0152,App-0152,Field Operations,Payments Eng Lead,Internal,"443,8090",Restricted,Yes,Server,Source Code,No,High,Encrypted,Medium
AST-0153,App-0153,Payments,Email Security Lead,VPN,"80,3306,5000,6379",Restricted,No,Database,Operational Data,No,Medium,Not Encrypted,Medium
AST-0154,App-0154,Business Intelligence,Mainframe Team Lead,Internal,443,Restricted,No,Server,Health Data,Yes,Low,Encrypted,High
AST-0155,App-0155,Operations Support,Platform Eng Lead,VPN,"389,445,3306,8080",Restricted,Yes,Workstation,Source Code,No,Medium,Encrypted,None
AST-0156,App-0156,Remote Connectivity,Email Security Lead,VPN,"25,80,6379",Restricted,Yes,Database,Operational Data,No,Medium,Not Encrypted,Low
AST-0157,App-0157,Corporate Email,Clinical IT Lead,Internal,443,None,Yes,Network Device,Financial Data,Yes,Medium,Not Encrypted,Medium
AST-0158,App-0158,Identity Management,WebOps Lead,Internal,"443,445,3306,8443",Restricted,Yes,Database,Employee Access Data,Yes,High,Encrypted,Low
AST-0159,App-0159,Software Delivery,API Platform Lead,VPN,443,Restricted,Yes,Database,Source Code,No,Medium,Unknown,Low
AST-0160,App-0160,Online Sales,DBA Team Lead,Internet,"445,5900,8090",Allowed,Yes,Server,Health Data,Yes,Low,Encrypted,High
AST-0161,App-0161,Remote Connectivity,Identity Team Lead,VPN,"8443,9090",Restricted,Yes,Workstation,Source Code,No,Medium,Encrypted,High
AST-0162,App-0162,Knowledge Management,WebOps Lead,Internal,"8080,8090",Restricted,Yes,Server,Public Data,No,Medium,Encrypted,High
AST-0163,App-0163,Remote Connectivity,DBA Team Lead,DMZ,443,Restricted,Yes,Server,Operational Data,No,Medium,Not Encrypted,None
AST-0164,App-0164,HR Operations,Email Security Lead,VPN,5000,Restricted,Yes,Database,Source Code,No,High,Unknown,None
AST-0165,App-0165,Online Sales,Mainframe Team Lead,Internal,"8080,8090",None,Yes,Network Device,Public Data,No,High,Unknown,Low
AST-0166,App-0166,Business Intelligence,Platform Eng Lead,Unknown,"25,443,6379",None,No,Wireless,Internal Data,No,Medium,Encrypted,None
AST-0167,App-0167,Partner Management,Email Security Lead,Internal,"22,3389,8090",Restricted,No,Network Device,Public Data,No,High,Encrypted,None
AST-0168,App-0168,Email Security,HR IT Lead,Internal,"25,8090",None,No,Server,Public Data,No,Medium,Not Encrypted,High
AST-0169,App-0169,Remote Connectivity,Mobility Team Lead,Internal,"1433,5900",None,Yes,Database,Internal Data,No,High,Unknown,Medium
AST-0170,App-0170,Field Operations,R&D Lead,Unknown,"25,8080",Restricted,Yes,Network Device,Source Code,No,Medium,Encrypted,High
AST-0171,App-0171,Email Security,Identity Team Lead,Internal,"389,9090",Restricted,No,Database,Source Code,No,Medium,Unknown,Low
AST-0172,App-0172,Network Connectivity,R&D Lead,VPN,"22,389,5000,6379",Restricted,Yes,Wireless,Financial Data,Yes,Medium,Encrypted,Low
AST-0173,App-0173,R&D,API Platform Lead,DMZ,80,Restricted,Yes,Server,Operational Data,No,High,Encrypted,Low
AST-0174,App-0174,R&D,Partner IT Lead,VPN,"445,8443,9090",Restricted,Yes,Network Device,Health Data,Yes,Medium,Encrypted,Low
AST-0175,App-0175,Identity Management,DevOps Lead,Internal,"25,3389,5432,9090",Restricted,Yes,Server,Health Data,Yes,Medium,Encrypted,High
AST-0176,App-0176,Payments,Platform Eng Lead,Internal,"389,8090",None,Yes,Network Device,HR Data,Yes,High,Not Encrypted,Low
AST-0177,App-0177,Operations Support,WebOps Lead,Internet,"25,5432,8090",Restricted,Yes,Database,Internal Data,No,Medium,Not Encrypted,Low
AST-0178,App-0178,Field Operations,R&D Lead,Internal,443,Restricted,Yes,Server,Source Code,No,Medium,Encrypted,Medium
AST-0179,App-0179,Business Intelligence,Email Security Lead,Internet,"80,1521",Allowed,Yes,Server,Source Code,No,Medium,Unknown,None
AST-0180,App-0180,Customer API Services,R&D Lead,VPN,"22,6379,8080,9090",Restricted,Yes,Workstation,Employee Access Data,Yes,High,Unknown,Medium
AST-0181,App-0181,Customer API Services,Infrastructure Lead,Internal,6379,None,No,Server,HR Data,Yes,Low,Encrypted,Medium
AST-0182,App-0182,Network Connectivity,Clinical IT Lead,DMZ,"8080,9090",Restricted,No,Database,Payment Data,Yes,Low,Encrypted,Medium
AST-0183,App-0183,Patient Records,Email Security Lead,DMZ,3306,Allowed,Yes,Workstation,HR Data,Yes,Medium,Unknown,None
AST-0184,App-0184,Patient Records,DevOps Lead,Internet,"23,8080,9090",Restricted,No,Workstation,Source Code,No,High,Not Encrypted,None
AST-0185,App-0185,Network Connectivity,HR IT Lead,Unknown,"6379,8443",None,No,Network Device,Financial Data,Yes,Medium,Not Encrypted,High
AST-0186,App-0186,HR Operations,Internal Apps Lead,Internal,"5432,5900",Restricted,No,Mobile,Financial Data,Yes,Medium,Not Encrypted,High
AST-0187,App-0187,Identity Management,Mobility Team Lead,DMZ,"23,25,8090",Allowed,Yes,Server,Financial Data,Yes,Low,Encrypted,Medium
AST-0188,App-0188,Knowledge Management,Identity Team Lead,Internet,"445,1521,8090",Restricted,Yes,Workstation,Financial Data,Yes,High,Unknown,High
AST-0189,App-0189,Core Banking,Network Ops Lead,DMZ,"80,389,1521",Restricted,Yes,Server,Partner Data,Yes,Low,Encrypted,Medium
AST-0190,App-0190,Customer API Services,Network Ops Lead,Unknown,"1521,5000,9090",Restricted,Yes,Server,Internal Data,No,Medium,Encrypted,Low
AST-0191,App-0191,HR Operations,Mainframe Team Lead,Internal,"445,5432",Restricted,No,Server,Health Data,Yes,Low,Unknown,Low
AST-0192,App-0192,Business Intelligence,Internal Apps Lead,VPN,"443,3389,8080",Restricted,Yes,Wireless,Payment Data,Yes,High,Encrypted,Medium
AST-0193,App-0193,Email Security,Network Ops Lead,VPN,"389,1521,9090",Restricted,Yes,Database,Operational Data,No,Low,Encrypted,Medium
AST-0194,App-0194,R&D,Network Security Lead,Internet,"25,1433,1521,9000",Allowed,No,Mobile,Partner Data,Yes,High,Encrypted,High
AST-0195,App-0195,Partner Management,Data Platform Lead,Internal,8090,Restricted,Yes,Server,Operational Data,No,Low,Not Encrypted,None
AST-0196,App-0196,R&D,Network Security Lead,Internal,8443,None,No,Network Device,Health Data,Yes,High,Unknown,Low
AST-0197,App-0197,Knowledge Management,DBA Team Lead,DMZ,"25,5900",Allowed,No,Server,Payment Data,Yes,Medium,Encrypted,High
AST-0198,App-0198,Corporate Email,R&D Lead,DMZ,"8080,8090",Restricted,No,Mobile,Internal Data,No,Low,Unknown,None
AST-0199,App-0199,Core Banking,Network Ops Lead,Internal,"23,5000,5432",None,No,Server,Health Data,Yes,Medium,Encrypted,Low
AST-0200,App-0200,Financial Reporting,Network Ops Lead,DMZ,"23,8090,9000",Restricted,Yes,Server,Financial Data,Yes,High,Encrypted,None
AST-0201,App-0201,Online Sales,Platform Eng Lead,Internal,"25,8443",Restricted,Yes,Network Device,Operational Data,No,Medium,Not Encrypted,Low
AST-0202,App-0202,Software Delivery,DevOps Lead,Internal,5000,None,No,Network Device,Public Data,No,Low,Not Encrypted,None
AST-0203,App-0203,Partner Management,Platform Eng Lead,Internal,"445,8080",Restricted,Yes,Workstation,Health Data,Yes,Medium,Not Encrypted,None
AST-0204,App-0204,Core Banking,Payments Eng Lead,Internet,"445,5900,9090",Allowed,Yes,Network Device,Customer Data,Yes,Low,Encrypted,High
AST-0205,App-0205,Software Delivery,R&D Lead,Internal,"25,5000,5432,5900",Restricted,Yes,Network Device,Operational Data,No,Low,Unknown,Medium
AST-0206,App-0206,Payments,Network Ops Lead,DMZ,"25,6379",Allowed,No,Server,Financial Data,Yes,Medium,Encrypted,None
AST-0207,App-0207,Core Banking,Internal Apps Lead,DMZ,389,Allowed,No,Workstation,Partner Data,Yes,High,Unknown,Medium
AST-0208,App-0208,Online Sales,R&D Lead,Internet,"22,1433,9090",Restricted,Yes,Network Device,Employee Access Data,Yes,High,Encrypted,High
AST-0209,App-0209,Corporate Email,DevOps Lead,Internal,1433,Restricted,No,Network Device,Public Data,No,High,Not Encrypted,High
AST-0210,App-0210,R&D,IT Operations Lead,DMZ,"1433,9090",Restricted,Yes,Server,Payment Data,Yes,Medium,Not Encrypted,Medium
AST-0211,App-0211,Customer API Services,Network Security Lead,DMZ,"25,9000",Allowed,Yes,Server,Customer Data,Yes,Medium,Encrypted,Low
AST-0212,App-0212,Patient Records,Data Platform Lead,Internet,"3306,6379",Allowed,No,Server,Operational Data,No,Medium,Encrypted,High
AST-0213,App-0213,R&D,Payments Eng Lead,Internal,"389,5000",None,Yes,Network Device,Financial Data,Yes,High,Unknown,Low
AST-0214,App-0214,Identity Management,Mobility Team Lead,VPN,"80,443",Restricted,Yes,Server,Employee Access Data,Yes,High,Not Encrypted,Low
AST-0215,App-0215,Customer API Services,Platform Eng Lead,DMZ,443,Allowed,Yes,Workstation,Public Data,No,Low,Not Encrypted,High
AST-0216,App-0216,Customer API Services,DBA Team Lead,Internal,1521,Restricted,Yes,Network Device,Employee Data,Yes,High,Encrypted,High
AST-0217,App-0217,Field Operations,Mobility Team Lead,DMZ,443,Restricted,Yes,Wireless,Employee Access Data,No,Medium,Not Encrypted,Low
AST-0218,App-0218,Operations Support,R&D Lead,DMZ,"80,445,1521,8080",Allowed,No,Server,Payment Data,Yes,Medium,Encrypted,Low
AST-0219,App-0219,Partner Management,Network Ops Lead,DMZ,443,Allowed,No,Workstation,Internal Data,No,Medium,Unknown,Medium
AST-0220,App-0220,Corporate Email,Internal Apps Lead,Internal,445,Restricted,Yes,Mobile,Customer Data,Yes,Medium,Encrypted,Low
AST-0221,App-0221,Business Intelligence,Network Security Lead,Internet,"25,5900,8080",Allowed,No,Network Device,Internal Data,No,Low,Unknown,Low
AST-0222,App-0222,Partner File Exchange,Platform Eng Lead,DMZ,"443,1521,5900,9090",Allowed,Yes,Mobile,Employee Data,Yes,Medium,Unknown,Low
AST-0223,App-0223,Email Security,Identity Team Lead,Internet,443,Restricted,Yes,Workstation,Operational Data,No,High,Not Encrypted,High
AST-0224,App-0224,Software Delivery,Payments Eng Lead,Internal,"25,3389,9090",Restricted,No,Workstation,Source Code,No,High,Unknown,High
AST-0225,App-0225,Partner File Exchange,Infrastructure Lead,VPN,"25,443,5432,5900",Restricted,No,Server,Internal Data,No,Medium,Unknown,High
AST-0226,App-0226,HR Operations,R&D Lead,Internal,"1433,6379,8080",None,No,Server,Health Data,Yes,Medium,Unknown,High
AST-0227,App-0227,Operations Support,Identity Team Lead,Internal,443,Restricted,Yes,Network Device,Payment Data,Yes,Low,Encrypted,Medium
AST-0228,App-0228,HR Operations,Email Security Lead,DMZ,1521,Restricted,No,Server,Operational Data,No,Medium,Unknown,Low
AST-0229,App-0229,Business Intelligence,Infrastructure Lead,Internal,23,Restricted,Yes,Wireless,Source Code,No,Low,Unknown,Low
AST-0230,App-0230,Field Operations,HR IT Lead,Unknown,"5000,6379,9000",None,Yes,Server,Employee Access Data,No,Medium,Not Encrypted,None
AST-0231,App-0231,Payments,Data Platform Lead,Internal,9090,Restricted,Yes,Network Device,Internal Data,No,High,Not Encrypted,None
AST-0232,App-0232,Partner Management,Email Security Lead,Internet,"80,3389",Allowed,Yes,Wireless,Partner Data,Yes,Medium,Encrypted,Medium
AST-0233,App-0233,Identity Management,Infrastructure Lead,VPN,445,Restricted,Yes,Mobile,Source Code,No,Medium,Unknown,High
AST-0234,App-0234,Partner Management,API Platform Lead,Internet,"1433,8090",Restricted,No,Server,Employee Access Data,Yes,High,Unknown,Medium
AST-0235,App-0235,Corporate Email,Network Security Lead,VPN,"1521,6379",Restricted,Yes,Server,Customer Data,Yes,Low,Not Encrypted,Low
AST-9001,Test Rig,Research,R&D Lead,Internal,22,Restricted,Yes,Server,Internal Data,No,Low,Unknown,None
AST-9002,Mainframe,Core Banking,CTO,DMZ,"443,3270",Allowed,No,Server,Financial Data,Yes,High,Not Encrypted,High

~~~

---

## `data/audit_log.csv`  —  place at: `cyber-exposure-governance-platform/data/audit_log.csv`  ·  _unchanged_

~~~text
timestamp,operator,action,asset_id,cve_id,details
2026-06-20 04:26:11,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 04:26:13,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:26:13,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:26:15,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:26:15,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:26:16,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:26:16,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:27:58,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:27:58,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:28:08,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 04:28:09,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:28:09,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:29:58,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 04:35:32,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 04:35:33,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:35:33,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:36:14,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:36:15,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:36:36,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 04:36:37,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:36:37,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:38:52,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:38:52,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:42:42,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 04:42:43,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:42:43,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:46:16,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 04:46:17,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:46:17,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:47:52,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:47:52,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:48:45,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 04:48:46,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:48:46,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:53:15,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 04:53:16,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:53:16,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:54:29,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 04:54:30,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:54:30,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:54:44,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:54:44,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 04:59:44,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 04:59:44,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:04:05,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 05:04:06,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:04:06,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:13:26,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 05:13:28,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:13:28,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:14:48,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 05:14:49,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:14:49,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:15:47,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:15:47,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:15:49,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:15:49,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:15:54,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:15:54,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:18:22,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:18:22,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:20:44,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:20:45,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:20:48,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:20:48,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:25:51,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 05:25:52,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:25:52,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:26:49,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:26:49,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:26:50,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:26:50,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:29:59,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 05:30:00,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:30:01,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:32:50,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:32:50,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 05:39:17,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 05:39:18,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 05:39:19,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"
2026-06-20 06:21:47,analyst,Assessment completed,,,303 exposure rows assessed
2026-06-20 06:21:48,analyst,Simulation executed,,,Patch Top 5 Highest-Risk Exposures
2026-06-20 06:21:48,analyst,Reports prepared,,,"Detailed, executive, and ticket export reports generated"

~~~

---

## `data/fallback_epss.json`  —  place at: `cyber-exposure-governance-platform/data/fallback_epss.json`  ·  _unchanged_

~~~json
{
 "CVE-2021-5084": {
  "epss": 0.659,
  "percentile": 0.907
 },
 "CVE-2019-5041": {
  "epss": 0.625,
  "percentile": 0.75
 },
 "CVE-2019-5017": {
  "epss": 0.729,
  "percentile": 0.81
 },
 "CVE-2022-26134": {
  "epss": 0.903,
  "percentile": 0.985
 },
 "CVE-2020-5112": {
  "epss": 0.178,
  "percentile": 0.22
 },
 "CVE-2023-34362": {
  "epss": 0.962,
  "percentile": 0.997
 },
 "CVE-2025-5006": {
  "epss": 0.418,
  "percentile": 0.611
 },
 "CVE-2021-5076": {
  "epss": 0.005,
  "percentile": 0.006
 },
 "CVE-2023-5105": {
  "epss": 0.756,
  "percentile": 0.84
 },
 "CVE-2019-5069": {
  "epss": 0.662,
  "percentile": 0.931
 },
 "CVE-2022-5002": {
  "epss": 0.87,
  "percentile": 0.989
 },
 "CVE-2024-5055": {
  "epss": 0.83,
  "percentile": 0.922
 },
 "CVE-2021-5079": {
  "epss": 0.096,
  "percentile": 0.122
 },
 "CVE-2020-5056": {
  "epss": 0.277,
  "percentile": 0.305
 },
 "CVE-2022-5089": {
  "epss": 0.902,
  "percentile": 0.921
 },
 "CVE-2022-5104": {
  "epss": 0.353,
  "percentile": 0.399
 },
 "CVE-2024-5078": {
  "epss": 0.562,
  "percentile": 0.63
 },
 "CVE-2022-5003": {
  "epss": 0.773,
  "percentile": 0.859
 },
 "CVE-2025-5058": {
  "epss": 0.808,
  "percentile": 0.92
 },
 "CVE-2019-11043": {
  "epss": 0.04,
  "percentile": 0.3
 },
 "CVE-2022-5042": {
  "epss": 0.61,
  "percentile": 0.678
 },
 "CVE-2019-5022": {
  "epss": 0.617,
  "percentile": 0.9
 },
 "CVE-2024-5115": {
  "epss": 0.812,
  "percentile": 0.953
 },
 "CVE-2025-5071": {
  "epss": 0.785,
  "percentile": 0.925
 },
 "CVE-2020-5010": {
  "epss": 0.405,
  "percentile": 0.579
 },
 "CVE-2021-5101": {
  "epss": 0.669,
  "percentile": 0.954
 },
 "CVE-2020-5061": {
  "epss": 0.811,
  "percentile": 0.895
 },
 "CVE-2021-5086": {
  "epss": 0.521,
  "percentile": 0.59
 },
 "CVE-2023-44487": {
  "epss": 0.49,
  "percentile": 0.8
 },
 "CVE-2023-5114": {
  "epss": 0.323,
  "percentile": 0.429
 },
 "CVE-2019-5068": {
  "epss": 0.919,
  "percentile": 0.971
 },
 "CVE-2021-5040": {
  "epss": 0.212,
  "percentile": 0.275
 },
 "CVE-2023-27997": {
  "epss": 0.884,
  "percentile": 0.981
 },
 "CVE-2019-5077": {
  "epss": 0.366,
  "percentile": 0.546
 },
 "CVE-2022-1552": {
  "epss": 0.155,
  "percentile": 0.642
 },
 "CVE-2020-5072": {
  "epss": 0.431,
  "percentile": 0.577
 },
 "CVE-2023-23897": {
  "epss": 0.291,
  "percentile": 0.771
 },
 "CVE-2019-5021": {
  "epss": 0.691,
  "percentile": 0.811
 },
 "CVE-2022-5012": {
  "epss": 0.562,
  "percentile": 0.624
 },
 "CVE-2024-5020": {
  "epss": 0.581,
  "percentile": 0.645
 },
 "CVE-2023-5103": {
  "epss": 0.084,
  "percentile": 0.102
 },
 "CVE-2024-5111": {
  "epss": 0.215,
  "percentile": 0.325
 },
 "CVE-2021-5087": {
  "epss": 0.574,
  "percentile": 0.638
 },
 "CVE-2022-5106": {
  "epss": 0.508,
  "percentile": 0.644
 },
 "CVE-2020-5004": {
  "epss": 0.062,
  "percentile": 0.08
 },
 "CVE-2024-5038": {
  "epss": 0.087,
  "percentile": 0.102
 },
 "CVE-2022-5031": {
  "epss": 0.027,
  "percentile": 0.04
 },
 "CVE-2022-30190": {
  "epss": 0.72,
  "percentile": 0.94
 },
 "CVE-2025-5109": {
  "epss": 0.518,
  "percentile": 0.662
 },
 "CVE-2022-5093": {
  "epss": 0.797,
  "percentile": 0.905
 },
 "CVE-2018-15473": {
  "epss": 0.12,
  "percentile": 0.55
 },
 "CVE-2021-5081": {
  "epss": 0.632,
  "percentile": 0.996
 },
 "CVE-2024-21887": {
  "epss": 0.8,
  "percentile": 0.96
 },
 "CVE-2020-5090": {
  "epss": 0.69,
  "percentile": 0.767
 },
 "CVE-2019-5001": {
  "epss": 0.734,
  "percentile": 0.89
 },
 "CVE-2022-5082": {
  "epss": 0.136,
  "percentile": 0.224
 },
 "CVE-2024-5027": {
  "epss": 0.282,
  "percentile": 0.423
 },
 "CVE-2024-5118": {
  "epss": 0.215,
  "percentile": 0.309
 },
 "CVE-2025-5009": {
  "epss": 0.894,
  "percentile": 0.94
 },
 "CVE-2020-5083": {
  "epss": 0.49,
  "percentile": 0.665
 },
 "CVE-2025-5046": {
  "epss": 0.875,
  "percentile": 0.922
 },
 "CVE-2025-5014": {
  "epss": 0.624,
  "percentile": 0.636
 },
 "CVE-2019-5018": {
  "epss": 0.465,
  "percentile": 0.538
 },
 "CVE-2020-5016": {
  "epss": 0.385,
  "percentile": 0.458
 },
 "CVE-2025-5085": {
  "epss": 0.803,
  "percentile": 0.888
 },
 "CVE-2022-3786": {
  "epss": 0.06,
  "percentile": 0.38
 },
 "CVE-2023-5013": {
  "epss": 0.005,
  "percentile": 0.006
 },
 "CVE-2024-3400": {
  "epss": 0.958,
  "percentile": 0.996
 },
 "CVE-2025-5102": {
  "epss": 0.207,
  "percentile": 0.271
 },
 "CVE-2024-1086": {
  "epss": 0.3,
  "percentile": 0.74
 },
 "CVE-2022-22965": {
  "epss": 0.61,
  "percentile": 0.88
 },
 "CVE-2020-5026": {
  "epss": 0.622,
  "percentile": 0.758
 },
 "CVE-2025-5044": {
  "epss": 0.537,
  "percentile": 0.554
 },
 "CVE-2023-5097": {
  "epss": 0.309,
  "percentile": 0.367
 },
 "CVE-2023-5107": {
  "epss": 0.797,
  "percentile": 0.886
 },
 "CVE-2024-6387": {
  "epss": 0.746,
  "percentile": 0.956
 },
 "CVE-2019-5025": {
  "epss": 0.645,
  "percentile": 0.828
 },
 "CVE-2019-5002": {
  "epss": 0.807,
  "percentile": 0.986
 },
 "CVE-2022-5054": {
  "epss": 0.565,
  "percentile": 0.702
 },
 "CVE-2019-5113": {
  "epss": 0.859,
  "percentile": 0.87
 },
 "CVE-2020-5119": {
  "epss": 0.635,
  "percentile": 0.706
 },
 "CVE-2023-5073": {
  "epss": 0.703,
  "percentile": 0.846
 },
 "CVE-2021-5051": {
  "epss": 0.215,
  "percentile": 0.331
 },
 "CVE-2024-23897": {
  "epss": 0.52,
  "percentile": 0.82
 },
 "CVE-2023-5052": {
  "epss": 0.629,
  "percentile": 0.819
 },
 "CVE-2019-5047": {
  "epss": 0.732,
  "percentile": 0.988
 },
 "CVE-2023-50164": {
  "epss": 0.58,
  "percentile": 0.86
 },
 "CVE-2023-5060": {
  "epss": 0.842,
  "percentile": 0.936
 },
 "CVE-2022-5057": {
  "epss": 0.408,
  "percentile": 0.619
 },
 "CVE-2021-23017": {
  "epss": 0.401,
  "percentile": 0.822
 },
 "CVE-2023-20198": {
  "epss": 0.951,
  "percentile": 0.995
 },
 "CVE-2025-5005": {
  "epss": 0.384,
  "percentile": 0.386
 },
 "CVE-2019-5032": {
  "epss": 0.103,
  "percentile": 0.123
 },
 "CVE-2023-5015": {
  "epss": 0.337,
  "percentile": 0.42
 },
 "CVE-2019-5064": {
  "epss": 0.667,
  "percentile": 0.708
 },
 "CVE-2021-5034": {
  "epss": 0.574,
  "percentile": 0.912
 },
 "CVE-2024-5080": {
  "epss": 0.765,
  "percentile": 0.832
 },
 "CVE-2019-5036": {
  "epss": 0.296,
  "percentile": 0.351
 },
 "CVE-2025-5045": {
  "epss": 0.681,
  "percentile": 0.904
 },
 "CVE-2021-3156": {
  "epss": 0.05,
  "percentile": 0.33
 },
 "CVE-2019-5095": {
  "epss": 0.024,
  "percentile": 0.036
 },
 "CVE-2023-0286": {
  "epss": 0.09,
  "percentile": 0.45
 },
 "CVE-2019-5100": {
  "epss": 0.733,
  "percentile": 0.958
 },
 "CVE-2019-5059": {
  "epss": 0.791,
  "percentile": 0.973
 },
 "CVE-2019-5063": {
  "epss": 0.721,
  "percentile": 0.801
 },
 "CVE-2023-5096": {
  "epss": 0.866,
  "percentile": 0.984
 },
 "CVE-2020-5030": {
  "epss": 0.559,
  "percentile": 0.621
 },
 "CVE-2021-5067": {
  "epss": 0.455,
  "percentile": 0.459
 },
 "CVE-2023-38545": {
  "epss": 0.18,
  "percentile": 0.66
 },
 "CVE-2020-5116": {
  "epss": 0.338,
  "percentile": 0.435
 },
 "CVE-2022-5065": {
  "epss": 0.717,
  "percentile": 0.767
 },
 "CVE-2019-5037": {
  "epss": 0.701,
  "percentile": 0.993
 },
 "CVE-2024-5043": {
  "epss": 0.454,
  "percentile": 0.686
 },
 "CVE-2024-5053": {
  "epss": 0.54,
  "percentile": 0.749
 },
 "CVE-2020-5005": {
  "epss": 0.448,
  "percentile": 0.607
 },
 "CVE-2019-5098": {
  "epss": 0.458,
  "percentile": 0.506
 },
 "CVE-2021-5003": {
  "epss": 0.823,
  "percentile": 0.914
 },
 "CVE-2021-44228": {
  "epss": 0.975,
  "percentile": 0.999
 },
 "CVE-2023-5039": {
  "epss": 0.69,
  "percentile": 0.971
 },
 "CVE-2023-5099": {
  "epss": 0.735,
  "percentile": 0.817
 },
 "CVE-2024-5000": {
  "epss": 0.856,
  "percentile": 0.955
 },
 "CVE-2024-5024": {
  "epss": 0.334,
  "percentile": 0.336
 },
 "CVE-2025-5110": {
  "epss": 0.566,
  "percentile": 0.916
 },
 "CVE-2024-5023": {
  "epss": 0.272,
  "percentile": 0.403
 },
 "CVE-2019-5033": {
  "epss": 0.09,
  "percentile": 0.102
 },
 "CVE-2023-4966": {
  "epss": 0.81,
  "percentile": 0.962
 },
 "CVE-2021-5049": {
  "epss": 0.579,
  "percentile": 0.643
 },
 "CVE-2020-5050": {
  "epss": 0.787,
  "percentile": 0.875
 },
 "CVE-2025-5092": {
  "epss": 0.52,
  "percentile": 0.826
 },
 "CVE-2021-5004": {
  "epss": 0.155,
  "percentile": 0.189
 },
 "CVE-2021-5108": {
  "epss": 0.705,
  "percentile": 0.844
 },
 "CVE-2024-5007": {
  "epss": 0.605,
  "percentile": 0.909
 },
 "CVE-2021-26855": {
  "epss": 0.944,
  "percentile": 0.993
 },
 "CVE-2023-22515": {
  "epss": 0.86,
  "percentile": 0.972
 },
 "CVE-2022-5048": {
  "epss": 0.7,
  "percentile": 0.993
 },
 "CVE-2021-5008": {
  "epss": 0.383,
  "percentile": 0.421
 },
 "CVE-2019-5117": {
  "epss": 0.442,
  "percentile": 0.544
 },
 "CVE-2022-5028": {
  "epss": 0.561,
  "percentile": 0.795
 },
 "CVE-2023-5088": {
  "epss": 0.578,
  "percentile": 0.642
 },
 "CVE-2020-5019": {
  "epss": 0.785,
  "percentile": 0.88
 },
 "CVE-2023-5011": {
  "epss": 0.565,
  "percentile": 0.566
 },
 "CVE-2021-4034": {
  "epss": 0.46,
  "percentile": 0.78
 },
 "CVE-2019-5094": {
  "epss": 0.321,
  "percentile": 0.33
 },
 "CVE-2022-5062": {
  "epss": 0.611,
  "percentile": 0.84
 },
 "CVE-2020-1472": {
  "epss": 0.83,
  "percentile": 0.965
 },
 "CVE-2019-5075": {
  "epss": 0.328,
  "percentile": 0.397
 },
 "CVE-2023-2868": {
  "epss": 0.55,
  "percentile": 0.84
 },
 "CVE-2021-34527": {
  "epss": 0.82,
  "percentile": 0.96
 },
 "CVE-2021-5070": {
  "epss": 0.688,
  "percentile": 0.997
 },
 "CVE-2024-5066": {
  "epss": 0.462,
  "percentile": 0.582
 }
}
~~~

---

## `data/fallback_kev.json`  —  place at: `cyber-exposure-governance-platform/data/fallback_kev.json`  ·  _unchanged_

~~~json
{
 "vulnerabilities": [
  {
   "cveID": "CVE-2019-5041",
   "vendorProject": "VMware",
   "product": "vCenter",
   "vulnerabilityName": "VMware vCenter vulnerability (CVE-2019-5041)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2019-5017",
   "vendorProject": "Linux",
   "product": "Kernel",
   "vulnerabilityName": "Linux Kernel vulnerability (CVE-2019-5017)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2022-26134",
   "vendorProject": "Atlassian",
   "product": "Confluence",
   "vulnerabilityName": "Confluence OGNL Injection RCE",
   "dateAdded": "2024-01-01",
   "shortDescription": "RCE in Confluence Server and Data Center.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2023-34362",
   "vendorProject": "Progress",
   "product": "MOVEit Transfer",
   "vulnerabilityName": "MOVEit Transfer SQLi RCE",
   "dateAdded": "2024-01-01",
   "shortDescription": "SQL injection leading to RCE in MOVEit.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2025-5006",
   "vendorProject": "Atlassian",
   "product": "Jira",
   "vulnerabilityName": "Atlassian Jira vulnerability (CVE-2025-5006)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2023-5105",
   "vendorProject": "VMware",
   "product": "vCenter",
   "vulnerabilityName": "VMware vCenter vulnerability (CVE-2023-5105)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2019-5069",
   "vendorProject": "nginx",
   "product": "nginx",
   "vulnerabilityName": "nginx nginx vulnerability (CVE-2019-5069)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2022-5002",
   "vendorProject": "PHP",
   "product": "PHP",
   "vulnerabilityName": "PHP PHP vulnerability (CVE-2022-5002)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2024-5055",
   "vendorProject": "Adobe",
   "product": "ColdFusion",
   "vulnerabilityName": "Adobe ColdFusion vulnerability (CVE-2024-5055)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2024-5078",
   "vendorProject": "Atlassian",
   "product": "Jira",
   "vulnerabilityName": "Atlassian Jira vulnerability (CVE-2024-5078)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2022-5003",
   "vendorProject": "nginx",
   "product": "nginx",
   "vulnerabilityName": "nginx nginx vulnerability (CVE-2022-5003)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2022-5042",
   "vendorProject": "Citrix",
   "product": "NetScaler",
   "vulnerabilityName": "Citrix NetScaler vulnerability (CVE-2022-5042)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2023-27997",
   "vendorProject": "Fortinet",
   "product": "FortiOS",
   "vulnerabilityName": "FortiOS SSL-VPN Heap Overflow",
   "dateAdded": "2024-01-01",
   "shortDescription": "Heap overflow in FortiOS SSL-VPN.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2022-5012",
   "vendorProject": "Node.js",
   "product": "Node",
   "vulnerabilityName": "Node.js Node vulnerability (CVE-2022-5012)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2024-5020",
   "vendorProject": "Citrix",
   "product": "NetScaler",
   "vulnerabilityName": "Citrix NetScaler vulnerability (CVE-2024-5020)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2021-5087",
   "vendorProject": "Apache",
   "product": "HTTP Server",
   "vulnerabilityName": "Apache HTTP Server vulnerability (CVE-2021-5087)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2022-30190",
   "vendorProject": "Microsoft",
   "product": "MSDT",
   "vulnerabilityName": "Follina MSDT RCE",
   "dateAdded": "2024-01-01",
   "shortDescription": "RCE via MSDT (Follina).",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2025-5109",
   "vendorProject": "PHP",
   "product": "PHP",
   "vulnerabilityName": "PHP PHP vulnerability (CVE-2025-5109)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2024-21887",
   "vendorProject": "Ivanti",
   "product": "Connect Secure",
   "vulnerabilityName": "Ivanti Connect Secure Command Injection",
   "dateAdded": "2024-01-01",
   "shortDescription": "Command injection in Ivanti Connect Secure.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2020-5090",
   "vendorProject": "PostgreSQL",
   "product": "PostgreSQL",
   "vulnerabilityName": "PostgreSQL PostgreSQL vulnerability (CVE-2020-5090)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2025-5009",
   "vendorProject": "PHP",
   "product": "PHP",
   "vulnerabilityName": "PHP PHP vulnerability (CVE-2025-5009)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2025-5014",
   "vendorProject": "Atlassian",
   "product": "Jira",
   "vulnerabilityName": "Atlassian Jira vulnerability (CVE-2025-5014)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2024-3400",
   "vendorProject": "Palo Alto",
   "product": "PAN-OS",
   "vulnerabilityName": "PAN-OS GlobalProtect Command Injection",
   "dateAdded": "2024-01-01",
   "shortDescription": "Command injection in PAN-OS GlobalProtect.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2020-5026",
   "vendorProject": "Microsoft",
   "product": "Windows",
   "vulnerabilityName": "Microsoft Windows vulnerability (CVE-2020-5026)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2025-5044",
   "vendorProject": "nginx",
   "product": "nginx",
   "vulnerabilityName": "nginx nginx vulnerability (CVE-2025-5044)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2023-5107",
   "vendorProject": "nginx",
   "product": "nginx",
   "vulnerabilityName": "nginx nginx vulnerability (CVE-2023-5107)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2024-6387",
   "vendorProject": "OpenSSH",
   "product": "OpenSSH Server",
   "vulnerabilityName": "OpenSSH regreSSHion RCE",
   "dateAdded": "2024-01-01",
   "shortDescription": "Signal-handler race RCE in OpenSSH.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2020-5119",
   "vendorProject": "Jenkins",
   "product": "Jenkins",
   "vulnerabilityName": "Jenkins Jenkins vulnerability (CVE-2020-5119)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2023-5052",
   "vendorProject": "Node.js",
   "product": "Node",
   "vulnerabilityName": "Node.js Node vulnerability (CVE-2023-5052)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2023-5060",
   "vendorProject": "PostgreSQL",
   "product": "PostgreSQL",
   "vulnerabilityName": "PostgreSQL PostgreSQL vulnerability (CVE-2023-5060)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2023-20198",
   "vendorProject": "Cisco",
   "product": "IOS XE",
   "vulnerabilityName": "Cisco IOS XE Web UI Privilege Escalation",
   "dateAdded": "2024-01-01",
   "shortDescription": "Privilege escalation in IOS XE Web UI.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2019-5064",
   "vendorProject": "Kubernetes",
   "product": "kube-apiserver",
   "vulnerabilityName": "Kubernetes kube-apiserver vulnerability (CVE-2019-5064)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2019-5063",
   "vendorProject": "nginx",
   "product": "nginx",
   "vulnerabilityName": "nginx nginx vulnerability (CVE-2019-5063)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2020-5030",
   "vendorProject": "Kubernetes",
   "product": "kube-apiserver",
   "vulnerabilityName": "Kubernetes kube-apiserver vulnerability (CVE-2020-5030)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2024-5043",
   "vendorProject": "Citrix",
   "product": "NetScaler",
   "vulnerabilityName": "Citrix NetScaler vulnerability (CVE-2024-5043)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2020-5005",
   "vendorProject": "Atlassian",
   "product": "Jira",
   "vulnerabilityName": "Atlassian Jira vulnerability (CVE-2020-5005)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2019-5098",
   "vendorProject": "Atlassian",
   "product": "Jira",
   "vulnerabilityName": "Atlassian Jira vulnerability (CVE-2019-5098)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2021-5003",
   "vendorProject": "Docker",
   "product": "Engine",
   "vulnerabilityName": "Docker Engine vulnerability (CVE-2021-5003)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2021-44228",
   "vendorProject": "Apache",
   "product": "Log4j",
   "vulnerabilityName": "Apache Log4j RCE (Log4Shell)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Remote code execution in Apache Log4j.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2023-5099",
   "vendorProject": "MySQL",
   "product": "MySQL",
   "vulnerabilityName": "MySQL MySQL vulnerability (CVE-2023-5099)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2024-5000",
   "vendorProject": "Jenkins",
   "product": "Jenkins",
   "vulnerabilityName": "Jenkins Jenkins vulnerability (CVE-2024-5000)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2025-5110",
   "vendorProject": "MySQL",
   "product": "MySQL",
   "vulnerabilityName": "MySQL MySQL vulnerability (CVE-2025-5110)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2023-4966",
   "vendorProject": "Citrix",
   "product": "NetScaler ADC",
   "vulnerabilityName": "Citrix Bleed Sensitive Info Disclosure",
   "dateAdded": "2024-01-01",
   "shortDescription": "Memory disclosure in NetScaler (Citrix Bleed).",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2021-5049",
   "vendorProject": "Kubernetes",
   "product": "kube-apiserver",
   "vulnerabilityName": "Kubernetes kube-apiserver vulnerability (CVE-2021-5049)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2020-5050",
   "vendorProject": "Fortinet",
   "product": "FortiOS",
   "vulnerabilityName": "Fortinet FortiOS vulnerability (CVE-2020-5050)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2025-5092",
   "vendorProject": "Apache",
   "product": "HTTP Server",
   "vulnerabilityName": "Apache HTTP Server vulnerability (CVE-2025-5092)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2021-26855",
   "vendorProject": "Microsoft",
   "product": "Exchange Server",
   "vulnerabilityName": "Exchange SSRF (ProxyLogon)",
   "dateAdded": "2024-01-01",
   "shortDescription": "SSRF in Microsoft Exchange.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2023-22515",
   "vendorProject": "Atlassian",
   "product": "Confluence",
   "vulnerabilityName": "Confluence Broken Access Control",
   "dateAdded": "2024-01-01",
   "shortDescription": "Broken access control in Confluence.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2019-5117",
   "vendorProject": "Kubernetes",
   "product": "kube-apiserver",
   "vulnerabilityName": "Kubernetes kube-apiserver vulnerability (CVE-2019-5117)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2022-5028",
   "vendorProject": "PostgreSQL",
   "product": "PostgreSQL",
   "vulnerabilityName": "PostgreSQL PostgreSQL vulnerability (CVE-2022-5028)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2023-5088",
   "vendorProject": "Linux",
   "product": "Kernel",
   "vulnerabilityName": "Linux Kernel vulnerability (CVE-2023-5088)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2020-5019",
   "vendorProject": "Fortinet",
   "product": "FortiOS",
   "vulnerabilityName": "Fortinet FortiOS vulnerability (CVE-2020-5019)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2023-5011",
   "vendorProject": "Samba",
   "product": "Samba",
   "vulnerabilityName": "Samba Samba vulnerability (CVE-2023-5011)",
   "dateAdded": "2024-01-01",
   "shortDescription": "Synthetic test vulnerability record for dataset volume.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  },
  {
   "cveID": "CVE-2020-1472",
   "vendorProject": "Microsoft",
   "product": "Netlogon",
   "vulnerabilityName": "Zerologon Netlogon EoP",
   "dateAdded": "2024-01-01",
   "shortDescription": "Elevation of privilege in Netlogon (Zerologon).",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2023-2868",
   "vendorProject": "Barracuda",
   "product": "ESG",
   "vulnerabilityName": "Barracuda ESG Command Injection",
   "dateAdded": "2024-01-01",
   "shortDescription": "Command injection in Barracuda ESG.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Known"
  },
  {
   "cveID": "CVE-2021-34527",
   "vendorProject": "Microsoft",
   "product": "Windows Print Spooler",
   "vulnerabilityName": "PrintNightmare RCE",
   "dateAdded": "2024-01-01",
   "shortDescription": "RCE in Windows Print Spooler.",
   "requiredAction": "Apply vendor updates or mitigations.",
   "dueDate": "2024-01-15",
   "knownRansomwareCampaignUse": "Unknown"
  }
 ]
}
~~~

---

## `data/fallback_nvd.json`  —  place at: `cyber-exposure-governance-platform/data/fallback_nvd.json`  ·  _unchanged_

~~~json
{
 "CVE-2021-5084": {
  "cvss_score": 7.6,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5041": {
  "cvss_score": 3.7,
  "severity": "Low",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5017": {
  "cvss_score": 8.9,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-26134": {
  "cvss_score": 9.8,
  "severity": "Critical",
  "description": "RCE in Confluence Server and Data Center.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5112": {
  "cvss_score": 8.7,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-34362": {
  "cvss_score": 9.8,
  "severity": "Critical",
  "description": "SQL injection leading to RCE in MOVEit.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5006": {
  "cvss_score": 8.2,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5076": {
  "cvss_score": 4.2,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5105": {
  "cvss_score": 7.4,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5069": {
  "cvss_score": 7.9,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5002": {
  "cvss_score": 8.5,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5055": {
  "cvss_score": 8.2,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5079": {
  "cvss_score": 4.3,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5056": {
  "cvss_score": 9.0,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5089": {
  "cvss_score": 8.3,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5104": {
  "cvss_score": 7.1,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5078": {
  "cvss_score": 5.6,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5003": {
  "cvss_score": 9.2,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5058": {
  "cvss_score": 3.5,
  "severity": "Low",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-11043": {
  "cvss_score": 4.3,
  "severity": "Medium",
  "description": "Buffer underflow in PHP-FPM.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5042": {
  "cvss_score": 8.7,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5022": {
  "cvss_score": 2.1,
  "severity": "Low",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5115": {
  "cvss_score": 6.5,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5071": {
  "cvss_score": 9.0,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5010": {
  "cvss_score": 8.7,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5101": {
  "cvss_score": 8.4,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5061": {
  "cvss_score": 7.5,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5086": {
  "cvss_score": 4.9,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-44487": {
  "cvss_score": 7.5,
  "severity": "High",
  "description": "DoS via HTTP/2 rapid reset.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5114": {
  "cvss_score": 6.5,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5068": {
  "cvss_score": 8.3,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5040": {
  "cvss_score": 4.8,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-27997": {
  "cvss_score": 9.2,
  "severity": "Critical",
  "description": "Heap overflow in FortiOS SSL-VPN.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5077": {
  "cvss_score": 8.7,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-1552": {
  "cvss_score": 7.5,
  "severity": "High",
  "description": "Privilege escalation via extension scripts.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5072": {
  "cvss_score": 9.9,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-23897": {
  "cvss_score": 8.8,
  "severity": "High",
  "description": "Demonstration Jenkins vulnerability.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5021": {
  "cvss_score": 7.4,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5012": {
  "cvss_score": 9.1,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5103": {
  "cvss_score": 5.8,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5111": {
  "cvss_score": 8.9,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5087": {
  "cvss_score": 9.3,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5106": {
  "cvss_score": 8.3,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5004": {
  "cvss_score": 8.7,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5038": {
  "cvss_score": 8.1,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5031": {
  "cvss_score": 2.3,
  "severity": "Low",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-30190": {
  "cvss_score": 7.8,
  "severity": "High",
  "description": "RCE via MSDT (Follina).",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5109": {
  "cvss_score": 7.7,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5093": {
  "cvss_score": 7.6,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2018-15473": {
  "cvss_score": 5.3,
  "severity": "Medium",
  "description": "User enumeration in OpenSSH.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5081": {
  "cvss_score": 4.8,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-21887": {
  "cvss_score": 9.1,
  "severity": "Critical",
  "description": "Command injection in Ivanti Connect Secure.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5090": {
  "cvss_score": 5.8,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5001": {
  "cvss_score": 9.1,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5082": {
  "cvss_score": 9.5,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5027": {
  "cvss_score": 6.8,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5118": {
  "cvss_score": 9.1,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5009": {
  "cvss_score": 7.5,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5083": {
  "cvss_score": 9.7,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5046": {
  "cvss_score": 9.9,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5014": {
  "cvss_score": 4.3,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5018": {
  "cvss_score": 6.8,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5016": {
  "cvss_score": 10.0,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5085": {
  "cvss_score": 9.7,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-3786": {
  "cvss_score": 6.5,
  "severity": "Medium",
  "description": "Stack overflow in OpenSSL punycode decode.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5013": {
  "cvss_score": 8.8,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-3400": {
  "cvss_score": 10.0,
  "severity": "Critical",
  "description": "Command injection in PAN-OS GlobalProtect.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5102": {
  "cvss_score": 8.9,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-1086": {
  "cvss_score": 7.8,
  "severity": "High",
  "description": "Use-after-free in Linux netfilter.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-22965": {
  "cvss_score": 9.8,
  "severity": "Critical",
  "description": "RCE in Spring Framework (Spring4Shell).",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5026": {
  "cvss_score": 9.9,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5044": {
  "cvss_score": 4.5,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5097": {
  "cvss_score": 8.1,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5107": {
  "cvss_score": 9.6,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-6387": {
  "cvss_score": 8.1,
  "severity": "High",
  "description": "Signal-handler race RCE in OpenSSH.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5025": {
  "cvss_score": 8.6,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5002": {
  "cvss_score": 9.1,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5054": {
  "cvss_score": 4.9,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5113": {
  "cvss_score": 8.2,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5119": {
  "cvss_score": 5.3,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5073": {
  "cvss_score": 6.3,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5051": {
  "cvss_score": 3.7,
  "severity": "Low",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-23897": {
  "cvss_score": 9.8,
  "severity": "Critical",
  "description": "Arbitrary file read via Jenkins CLI.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5052": {
  "cvss_score": 7.8,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5047": {
  "cvss_score": 7.5,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-50164": {
  "cvss_score": 9.8,
  "severity": "Critical",
  "description": "Path traversal/file upload in Apache Struts.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5060": {
  "cvss_score": 5.3,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5057": {
  "cvss_score": 8.4,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-23017": {
  "cvss_score": 7.7,
  "severity": "High",
  "description": "Off-by-one in NGINX resolver.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-20198": {
  "cvss_score": 10.0,
  "severity": "Critical",
  "description": "Privilege escalation in IOS XE Web UI.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5005": {
  "cvss_score": 9.1,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5032": {
  "cvss_score": 9.1,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5015": {
  "cvss_score": 7.2,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5064": {
  "cvss_score": 8.7,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5034": {
  "cvss_score": 4.9,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5080": {
  "cvss_score": 9.9,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5036": {
  "cvss_score": 7.3,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5045": {
  "cvss_score": 4.7,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-3156": {
  "cvss_score": 3.6,
  "severity": "Low",
  "description": "Heap overflow in sudo (low-impact context).",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5095": {
  "cvss_score": 6.6,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-0286": {
  "cvss_score": 7.8,
  "severity": "High",
  "description": "Type confusion in OpenSSL GENERAL_NAME.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5100": {
  "cvss_score": 7.6,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5059": {
  "cvss_score": 2.2,
  "severity": "Low",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5063": {
  "cvss_score": 9.7,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5096": {
  "cvss_score": 7.5,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5067": {
  "cvss_score": 6.1,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-38545": {
  "cvss_score": 8.0,
  "severity": "High",
  "description": "Heap overflow in curl SOCKS5 handshake.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5116": {
  "cvss_score": 7.2,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5065": {
  "cvss_score": 2.6,
  "severity": "Low",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5037": {
  "cvss_score": 8.8,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5043": {
  "cvss_score": 6.6,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5053": {
  "cvss_score": 9.6,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5005": {
  "cvss_score": 4.3,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5098": {
  "cvss_score": 6.5,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-44228": {
  "cvss_score": 10.0,
  "severity": "Critical",
  "description": "Remote code execution in Apache Log4j.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5039": {
  "cvss_score": 3.6,
  "severity": "Low",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5099": {
  "cvss_score": 5.4,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5000": {
  "cvss_score": 4.7,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5024": {
  "cvss_score": 7.9,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5110": {
  "cvss_score": 5.7,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5023": {
  "cvss_score": 7.9,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5033": {
  "cvss_score": 8.0,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-4966": {
  "cvss_score": 7.5,
  "severity": "High",
  "description": "Memory disclosure in NetScaler (Citrix Bleed).",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5049": {
  "cvss_score": 7.7,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5050": {
  "cvss_score": 4.0,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2025-5092": {
  "cvss_score": 9.7,
  "severity": "Critical",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5004": {
  "cvss_score": 5.6,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5108": {
  "cvss_score": 8.6,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5007": {
  "cvss_score": 5.8,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-26855": {
  "cvss_score": 9.8,
  "severity": "Critical",
  "description": "SSRF in Microsoft Exchange.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-22515": {
  "cvss_score": 9.8,
  "severity": "Critical",
  "description": "Broken access control in Confluence.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5048": {
  "cvss_score": 5.0,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5008": {
  "cvss_score": 5.6,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5117": {
  "cvss_score": 4.9,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5028": {
  "cvss_score": 7.1,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5088": {
  "cvss_score": 7.6,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-5019": {
  "cvss_score": 2.8,
  "severity": "Low",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-5011": {
  "cvss_score": 8.7,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-4034": {
  "cvss_score": 7.8,
  "severity": "High",
  "description": "Local privilege escalation in polkit pkexec.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5094": {
  "cvss_score": 3.5,
  "severity": "Low",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2022-5062": {
  "cvss_score": 7.1,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2020-1472": {
  "cvss_score": 9.8,
  "severity": "Critical",
  "description": "Elevation of privilege in Netlogon (Zerologon).",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2019-5075": {
  "cvss_score": 8.3,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2023-2868": {
  "cvss_score": 9.8,
  "severity": "Critical",
  "description": "Command injection in Barracuda ESG.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-34527": {
  "cvss_score": 8.8,
  "severity": "High",
  "description": "RCE in Windows Print Spooler.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2021-5070": {
  "cvss_score": 8.4,
  "severity": "High",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 },
 "CVE-2024-5066": {
  "cvss_score": 6.6,
  "severity": "Medium",
  "description": "Synthetic test vulnerability record for dataset volume.",
  "published": "2024-01-01",
  "last_modified": "2025-01-01"
 }
}
~~~

---

## `data/ids_alerts.csv`  —  place at: `cyber-exposure-governance-platform/data/ids_alerts.csv`  ·  _unchanged_

~~~text
alert_id,asset_id,alert_type,alert_severity,source_ip,destination_ip,timestamp,signature_name,confidence
IDS-0001,AST-0054,Data Exfil Attempt,High,45.116.213.244,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Medium
IDS-0002,AST-0157,Suspicious Web Request,High,45.96.201.10,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0003,AST-0015,Port Scan,Medium,45.205.124.232,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0004,AST-0015,Web Attack,High,45.237.124.188,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Medium
IDS-0005,AST-0028,Suspicious Web Request,High,45.197.224.26,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0006,AST-0028,Web Attack,High,45.118.100.183,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0007,AST-0028,Port Scan,Critical,45.239.12.176,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Medium
IDS-0008,AST-0028,Port Scan,High,45.228.12.27,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Low
IDS-0009,AST-0147,Suspicious Web Request,Critical,45.164.229.54,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Medium
IDS-0010,AST-0187,Brute Force,High,45.137.82.198,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,Medium
IDS-0011,AST-0162,Port Scan,High,45.41.71.30,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0012,AST-0136,Port Scan,High,45.141.82.70,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Medium
IDS-0013,AST-0023,Suspicious Web Request,Medium,45.44.19.80,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0014,AST-0124,Recon,Medium,45.13.34.8,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,Low
IDS-0015,AST-0124,Data Exfil Attempt,Low,45.28.99.14,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0016,AST-0186,Exploit Attempt,High,45.158.92.80,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Low
IDS-0017,AST-0177,Brute Force,Low,45.250.237.194,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,High
IDS-0018,AST-0155,Web Attack,Critical,45.25.117.80,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Low
IDS-0019,AST-0155,Data Exfil Attempt,Medium,45.243.58.37,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0020,AST-0202,Suspicious Web Request,High,45.47.180.235,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Low
IDS-0021,AST-0202,Recon,High,45.125.8.17,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,Low
IDS-0022,AST-0202,Data Exfil Attempt,Critical,45.123.119.217,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Medium
IDS-0023,AST-0202,Web Attack,High,45.155.148.33,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Medium
IDS-0024,AST-0181,Exploit Attempt,Low,45.84.143.167,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0025,AST-0074,Suspicious Web Request,Medium,45.103.152.106,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Low
IDS-0026,AST-0110,Brute Force,Medium,45.250.124.99,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,High
IDS-0027,AST-0156,Brute Force,Low,45.201.251.112,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,Low
IDS-0028,AST-0082,Recon,Medium,45.45.170.172,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0029,AST-0082,Port Scan,Low,45.30.152.153,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Low
IDS-0030,AST-0067,Port Scan,Medium,45.79.245.104,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0031,AST-0135,Port Scan,Low,45.84.127.166,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Low
IDS-0032,AST-0148,Port Scan,High,45.228.149.232,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0033,AST-0148,Exploit Attempt,High,45.116.137.75,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0034,AST-0160,Data Exfil Attempt,High,45.175.225.82,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0035,AST-0091,Suspicious Web Request,Medium,45.254.23.150,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Medium
IDS-0036,AST-0034,Exploit Attempt,High,45.16.95.231,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Medium
IDS-0037,AST-0158,Exploit Attempt,Critical,45.29.221.73,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,Medium
IDS-0038,AST-0145,Brute Force,Medium,45.161.82.183,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,Low
IDS-0039,AST-0145,Exploit Attempt,Medium,45.112.140.55,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Low
IDS-0040,AST-0145,Web Attack,Medium,45.49.143.99,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0041,AST-0145,Recon,Medium,45.74.224.172,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0042,AST-0128,Exploit Attempt,Critical,45.37.185.227,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0043,AST-0134,Exploit Attempt,High,45.36.165.207,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0044,AST-0230,Data Exfil Attempt,Low,45.160.47.117,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Low
IDS-0045,AST-0229,Data Exfil Attempt,Medium,45.58.48.109,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Medium
IDS-0046,AST-0208,Data Exfil Attempt,Low,45.183.129.69,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0047,AST-0208,Exploit Attempt,Medium,45.9.251.10,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Medium
IDS-0048,AST-0127,Recon,Critical,45.247.177.21,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,Low
IDS-0049,AST-0127,Web Attack,Low,45.120.133.21,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Medium
IDS-0050,AST-0047,Port Scan,High,45.162.190.170,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Low
IDS-0051,AST-0234,Port Scan,Low,45.157.14.232,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Medium
IDS-0052,AST-0234,Recon,Medium,45.121.117.132,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0053,AST-0234,Data Exfil Attempt,Medium,45.108.91.246,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Medium
IDS-0054,AST-0234,Suspicious Web Request,High,45.10.178.237,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0055,AST-0060,Suspicious Web Request,Low,45.16.162.122,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Medium
IDS-0056,AST-0060,Web Attack,Medium,45.169.254.75,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0057,AST-0182,Exploit Attempt,High,45.22.33.130,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,Low
IDS-0058,AST-0182,Port Scan,High,45.34.158.72,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Medium
IDS-0059,AST-0075,Suspicious Web Request,Critical,45.155.45.233,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0060,AST-0050,Web Attack,Low,45.95.207.45,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Low
IDS-0061,AST-0050,Suspicious Web Request,Low,45.125.47.205,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0062,AST-0001,Exploit Attempt,High,45.248.38.153,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0063,AST-0031,Web Attack,Medium,45.198.99.61,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Low
IDS-0064,AST-0031,Data Exfil Attempt,Low,45.54.148.188,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0065,AST-0031,Recon,Critical,45.194.210.30,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,Medium
IDS-0066,AST-0031,Exploit Attempt,High,45.103.122.78,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,Low
IDS-0067,AST-0007,Brute Force,Medium,45.122.68.38,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,Low
IDS-0068,AST-0120,Exploit Attempt,Critical,45.238.205.115,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Medium
IDS-0069,AST-0161,Recon,Medium,45.25.235.137,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0070,AST-0195,Exploit Attempt,Medium,45.86.70.69,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Medium
IDS-0071,AST-0195,Port Scan,High,45.119.198.173,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Low
IDS-0072,AST-0189,Brute Force,Medium,45.174.177.47,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,Medium
IDS-0073,AST-0189,Recon,Medium,45.173.3.213,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0074,AST-0235,Exploit Attempt,Critical,45.176.115.90,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0075,AST-0210,Suspicious Web Request,High,45.9.7.159,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0076,AST-0107,Brute Force,Medium,45.182.246.31,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,High
IDS-0077,AST-0106,Web Attack,Medium,45.230.29.179,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0078,AST-0012,Suspicious Web Request,Medium,45.164.117.237,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0079,AST-0086,Exploit Attempt,Low,45.66.42.200,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Medium
IDS-0080,AST-0086,Port Scan,High,45.98.100.86,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0081,AST-0086,Exploit Attempt,High,45.46.113.18,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,Medium
IDS-0082,AST-0086,Data Exfil Attempt,High,45.46.166.126,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Low
IDS-0083,AST-0090,Exploit Attempt,High,45.234.114.184,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0084,AST-0144,Exploit Attempt,Critical,45.147.187.65,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0085,AST-0164,Exploit Attempt,Medium,45.168.164.1,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0086,AST-0164,Exploit Attempt,Low,45.69.39.180,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,Low
IDS-0087,AST-0055,Exploit Attempt,Medium,45.132.182.241,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0088,AST-0003,Data Exfil Attempt,Medium,45.217.187.200,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Low
IDS-0089,AST-0003,Port Scan,Medium,45.1.99.245,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0090,AST-0221,Data Exfil Attempt,Critical,45.86.175.78,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Medium
IDS-0091,AST-0221,Exploit Attempt,Critical,45.94.137.219,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0092,AST-0052,Port Scan,Medium,45.166.52.46,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Medium
IDS-0093,AST-0052,Exploit Attempt,Medium,45.77.179.100,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0094,AST-0052,Port Scan,Low,45.125.22.227,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Medium
IDS-0095,AST-0052,Data Exfil Attempt,Low,45.36.10.50,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0096,AST-0073,Brute Force,Medium,45.17.203.139,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,Low
IDS-0097,AST-0066,Data Exfil Attempt,Medium,45.248.5.10,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Low
IDS-0098,AST-0066,Recon,Critical,45.202.185.11,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,Medium
IDS-0099,AST-0018,Brute Force,Low,45.241.174.223,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,Low
IDS-0100,AST-0079,Web Attack,Low,45.237.19.10,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0101,AST-0079,Web Attack,Medium,45.121.233.236,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0102,AST-0079,Exploit Attempt,High,45.4.45.162,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0103,AST-0079,Exploit Attempt,High,45.117.157.44,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0104,AST-0077,Port Scan,Critical,45.128.153.205,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0105,AST-0077,Brute Force,Critical,45.110.87.208,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,High
IDS-0106,AST-0130,Exploit Attempt,High,45.250.176.148,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0107,AST-0130,Web Attack,High,45.196.12.152,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0108,AST-0141,Port Scan,Critical,45.37.194.107,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Medium
IDS-0109,AST-0083,Recon,Medium,45.113.63.237,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0110,AST-0002,Web Attack,Critical,45.200.41.5,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Low
IDS-0111,AST-0002,Data Exfil Attempt,Critical,45.2.46.238,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0112,AST-0030,Suspicious Web Request,Medium,45.178.33.53,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Low
IDS-0113,AST-0184,Suspicious Web Request,Medium,45.106.62.241,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Low
IDS-0114,AST-0088,Exploit Attempt,Medium,45.184.128.157,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0115,AST-0102,Suspicious Web Request,High,45.2.143.61,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Low
IDS-0116,AST-0102,Brute Force,Critical,45.159.93.221,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,High
IDS-0117,AST-0102,Brute Force,Medium,45.71.14.50,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,High
IDS-0118,AST-0102,Port Scan,High,45.128.46.41,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Low
IDS-0119,AST-0146,Exploit Attempt,Critical,45.73.54.112,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,Medium
IDS-0120,AST-0146,Suspicious Web Request,High,45.12.27.190,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Low
IDS-0121,AST-0188,Web Attack,High,45.125.132.30,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0122,AST-0008,Brute Force,Low,45.152.149.84,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,Low
IDS-0123,AST-0045,Recon,High,45.84.59.26,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0124,AST-0197,Exploit Attempt,High,45.229.57.19,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Low
IDS-0125,AST-0085,Data Exfil Attempt,Critical,45.38.56.238,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Low
IDS-0126,AST-0087,Web Attack,Medium,45.35.118.185,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Medium
IDS-0127,AST-0087,Brute Force,Low,45.250.70.52,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,Medium
IDS-0128,AST-0123,Exploit Attempt,Low,45.72.35.29,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0129,AST-0122,Data Exfil Attempt,Medium,45.195.88.57,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0130,AST-0122,Suspicious Web Request,Medium,45.203.204.164,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0131,AST-0122,Web Attack,Medium,45.23.106.220,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0132,AST-0122,Data Exfil Attempt,High,45.215.119.72,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Low
IDS-0133,AST-0010,Exploit Attempt,Low,45.64.84.112,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0134,AST-0035,Web Attack,Medium,45.107.251.12,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0135,AST-0035,Exploit Attempt,Medium,45.109.136.101,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,High
IDS-0136,AST-0226,Port Scan,Medium,45.62.22.143,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Low
IDS-0137,AST-0040,Exploit Attempt,High,45.92.76.62,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0138,AST-0040,Port Scan,Critical,45.172.79.42,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Low
IDS-0139,AST-0118,Exploit Attempt,Medium,45.198.36.224,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,Low
IDS-0140,AST-0118,Exploit Attempt,High,45.161.119.181,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Medium
IDS-0141,AST-0138,Port Scan,Medium,45.136.9.76,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Medium
IDS-0142,AST-0138,Exploit Attempt,High,45.202.176.21,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0143,AST-0166,Recon,Low,45.132.243.233,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0144,AST-0166,Recon,Critical,45.99.94.120,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0145,AST-0119,Recon,High,45.166.144.181,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0146,AST-0119,Port Scan,Medium,45.36.252.86,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0147,AST-0225,Port Scan,Low,45.189.241.193,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Low
IDS-0148,AST-0233,Brute Force,Low,45.83.91.230,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,High
IDS-0149,AST-0233,Suspicious Web Request,Medium,45.71.14.17,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Low
IDS-0150,AST-0207,Data Exfil Attempt,Medium,45.121.182.137,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0151,AST-0172,Suspicious Web Request,Medium,45.205.173.243,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Medium
IDS-0152,AST-0172,Port Scan,High,45.23.21.101,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Low
IDS-0153,AST-0081,Suspicious Web Request,Critical,45.43.71.29,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0154,AST-0081,Web Attack,Medium,45.224.53.134,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0155,AST-0081,Exploit Attempt,High,45.249.175.139,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,Low
IDS-0156,AST-0081,Web Attack,Medium,45.108.114.189,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Medium
IDS-0157,AST-0149,Suspicious Web Request,High,45.6.224.206,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0158,AST-0149,Brute Force,Medium,45.106.149.88,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,Medium
IDS-0159,AST-0005,Recon,Medium,45.118.78.146,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,Low
IDS-0160,AST-0005,Web Attack,High,45.203.67.59,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0161,AST-0190,Suspicious Web Request,Critical,45.91.73.117,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0162,AST-0205,Web Attack,Low,45.47.250.45,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Medium
IDS-0163,AST-0205,Web Attack,High,45.30.11.82,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0164,AST-0205,Web Attack,Medium,45.95.48.53,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Medium
IDS-0165,AST-0205,Exploit Attempt,Low,45.251.89.38,10.0.0.1,2026-06-20 12:00:00,Suspected RCE Exploit,Medium
IDS-0166,AST-0212,Web Attack,Medium,45.32.236.7,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Medium
IDS-0167,AST-0017,Data Exfil Attempt,High,45.238.82.40,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Low
IDS-0168,AST-0039,Recon,Low,45.122.230.75,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,Medium
IDS-0169,AST-0072,Web Attack,Medium,45.87.177.29,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Low
IDS-0170,AST-0072,Data Exfil Attempt,Critical,45.174.142.30,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0171,AST-0072,Suspicious Web Request,Critical,45.159.216.57,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Low
IDS-0172,AST-0072,Data Exfil Attempt,High,45.84.15.156,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0173,AST-0192,Brute Force,High,45.6.22.138,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,High
IDS-0174,AST-0192,Data Exfil Attempt,Low,45.250.132.101,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0175,AST-0201,Recon,Medium,45.233.171.93,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0176,AST-0097,Exploit Attempt,High,45.96.4.73,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Low
IDS-0177,AST-0043,Suspicious Web Request,Medium,45.56.187.228,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0178,AST-0100,Exploit Attempt,Medium,45.42.207.187,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Medium
IDS-0179,AST-0048,Exploit Attempt,Low,45.36.214.151,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Low
IDS-0180,AST-0048,Port Scan,High,45.78.122.254,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0181,AST-0048,Recon,Critical,45.23.2.105,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,Low
IDS-0182,AST-0048,Suspicious Web Request,Medium,45.143.119.182,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,High
IDS-0183,AST-0143,Web Attack,High,45.214.98.75,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0184,AST-0143,Data Exfil Attempt,Critical,45.214.150.78,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Medium
IDS-0185,AST-0209,Data Exfil Attempt,High,45.203.1.40,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,High
IDS-0186,AST-0111,Data Exfil Attempt,Critical,45.107.46.126,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Medium
IDS-0187,AST-0101,Brute Force,Critical,45.196.71.127,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,High
IDS-0188,AST-0101,Port Scan,Medium,45.149.124.145,10.0.0.1,2026-06-20 12:00:00,External Port Scan,Medium
IDS-0189,AST-0101,Exploit Attempt,High,45.250.178.210,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,Low
IDS-0190,AST-0101,Port Scan,High,45.217.67.42,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0191,AST-0131,Web Attack,High,45.225.178.35,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Low
IDS-0192,AST-0131,Recon,High,45.70.93.108,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,High
IDS-0193,AST-0151,Recon,Critical,45.75.136.164,10.0.0.1,2026-06-20 12:00:00,Device Fingerprinting,Medium
IDS-0194,AST-0151,Port Scan,Medium,45.197.161.47,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High
IDS-0195,AST-0137,Web Attack,Medium,45.224.81.212,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Medium
IDS-0196,AST-0137,Suspicious Web Request,High,45.25.137.149,10.0.0.1,2026-06-20 12:00:00,Malformed HTTP,Medium
IDS-0197,AST-0219,Web Attack,Critical,45.133.73.96,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,High
IDS-0198,AST-0041,Exploit Attempt,High,45.27.56.40,10.0.0.1,2026-06-20 12:00:00,Webshell Activity,High
IDS-0199,AST-0041,Brute Force,High,45.107.118.235,10.0.0.1,2026-06-20 12:00:00,SSH Brute Force,High
IDS-0200,AST-0121,Web Attack,Critical,45.90.80.177,10.0.0.1,2026-06-20 12:00:00,SQLi Pattern,Low
IDS-0201,AST-0140,Data Exfil Attempt,Medium,45.45.182.78,10.0.0.1,2026-06-20 12:00:00,Outbound Anomaly,Medium
IDS-0202,AST-0153,Port Scan,High,45.220.178.37,10.0.0.1,2026-06-20 12:00:00,External Port Scan,High

~~~

---

## `data/risk_exceptions.csv`  —  place at: `cyber-exposure-governance-platform/data/risk_exceptions.csv`  ·  _unchanged_

~~~text
asset_id,cve_id,exception_status,acceptance_reason,accepted_by,acceptance_expiry_date,compensating_control
AST-0089,CVE-2019-5032,Deferred,Compensating controls in place / patch scheduled,DBA Team Lead,2026-08-17,Network restriction and monitoring enabled
AST-0123,CVE-2020-5116,Deferred,Compensating controls in place / patch scheduled,Partner IT Lead,2026-09-25,Network restriction and monitoring enabled
AST-0048,CVE-2020-5083,Risk Accepted,Compensating controls in place / patch scheduled,WebOps Lead,2026-08-02,Network restriction and monitoring enabled
AST-0081,CVE-2019-5095,Risk Accepted,Compensating controls in place / patch scheduled,Partner IT Lead,2026-07-28,Network restriction and monitoring enabled
AST-0050,CVE-2020-5116,Deferred,Compensating controls in place / patch scheduled,Internal Apps Lead,2026-04-16,Network restriction and monitoring enabled
AST-0033,CVE-2025-5044,Deferred,Compensating controls in place / patch scheduled,Internal Apps Lead,,Network restriction and monitoring enabled
AST-0169,CVE-2021-5086,Deferred,Compensating controls in place / patch scheduled,DBA Team Lead,,Network restriction and monitoring enabled
AST-0044,CVE-2020-5004,Deferred,Compensating controls in place / patch scheduled,Internal Apps Lead,,Network restriction and monitoring enabled
AST-0032,CVE-2024-5118,Deferred,Compensating controls in place / patch scheduled,Identity Team Lead,2026-10-09,Network restriction and monitoring enabled
AST-0009,CVE-2023-5096,Deferred,Compensating controls in place / patch scheduled,DBA Team Lead,2026-10-14,Network restriction and monitoring enabled
AST-0194,CVE-2021-34527,Risk Accepted,Compensating controls in place / patch scheduled,Platform Eng Lead,2026-09-12,Network restriction and monitoring enabled
AST-0172,CVE-2019-5036,Deferred,Compensating controls in place / patch scheduled,Email Security Lead,,Network restriction and monitoring enabled
AST-0018,CVE-2021-34527,Deferred,Compensating controls in place / patch scheduled,Infrastructure Lead,,Network restriction and monitoring enabled
AST-0075,CVE-2025-5092,Risk Accepted,Compensating controls in place / patch scheduled,API Platform Lead,2026-04-13,Network restriction and monitoring enabled
AST-0042,CVE-2025-5045,Deferred,Compensating controls in place / patch scheduled,Mobility Team Lead,,Network restriction and monitoring enabled
AST-0015,CVE-2019-5064,Risk Accepted,Compensating controls in place / patch scheduled,DBA Team Lead,2026-10-15,Network restriction and monitoring enabled
AST-0207,CVE-2022-5003,Deferred,Compensating controls in place / patch scheduled,Network Ops Lead,2026-05-17,Network restriction and monitoring enabled
AST-0025,CVE-2021-5081,Risk Accepted,Compensating controls in place / patch scheduled,R&D Lead,2026-03-02,Network restriction and monitoring enabled
AST-0189,CVE-2023-22515,Deferred,Compensating controls in place / patch scheduled,Network Security Lead,,Network restriction and monitoring enabled
AST-0045,CVE-2019-5064,Deferred,Compensating controls in place / patch scheduled,Data Platform Lead,2026-03-29,Network restriction and monitoring enabled
AST-0100,CVE-2023-5096,Risk Accepted,Compensating controls in place / patch scheduled,Email Security Lead,2026-04-03,Network restriction and monitoring enabled
AST-0019,CVE-2019-5002,Risk Accepted,Compensating controls in place / patch scheduled,Identity Team Lead,2026-09-18,Network restriction and monitoring enabled

~~~

---

## `data/risk_policy.json`  —  place at: `cyber-exposure-governance-platform/data/risk_policy.json`  ·  _unchanged_

~~~json
{
  "weights": {
    "threat_intelligence": 35,
    "business_impact": 15,
    "network_exposure": 20,
    "ids_correlation": 15,
    "privacy_impact": 10,
    "sla_governance": 5
  },
  "sla_days": {
    "Critical": 7,
    "High": 15,
    "Medium": 30,
    "Low": 90
  },
  "priority_thresholds": {
    "Critical": 85,
    "High": 70,
    "Medium": 45,
    "Low": 0
  }
}

~~~

---

## `data/risk_snapshots.csv`  —  place at: `cyber-exposure-governance-platform/data/risk_snapshots.csv`  ·  _unchanged_

~~~text
timestamp,total_exposures,critical_count,high_count,medium_count,low_count,average_score,kev_count,ids_correlated_count,sla_breached_count
2026-06-20 04:26:12,303,18,59,165,61,59.94,131,156,213
2026-06-20 04:28:08,303,18,59,165,61,59.94,131,156,213
2026-06-20 04:29:58,303,18,59,165,61,59.94,131,156,213
2026-06-20 04:35:32,303,18,59,165,61,59.94,131,156,213
2026-06-20 04:36:36,303,18,59,165,61,59.94,131,156,213
2026-06-20 04:42:42,303,18,59,165,61,59.94,131,156,213
2026-06-20 04:46:16,303,18,59,165,61,59.94,131,156,213
2026-06-20 04:48:45,303,18,59,165,61,59.94,131,156,213
2026-06-20 04:53:15,303,18,59,165,61,59.94,131,156,213
2026-06-20 04:54:29,303,18,59,165,61,59.94,131,156,213
2026-06-20 05:04:05,303,18,59,165,61,59.94,131,156,213
2026-06-20 05:13:26,303,18,59,165,61,59.94,131,156,213
2026-06-20 05:14:48,303,18,59,165,61,59.94,131,156,213
2026-06-20 05:25:51,303,18,59,165,61,59.94,131,156,213
2026-06-20 05:29:59,303,18,59,165,61,59.94,131,156,213
2026-06-20 05:39:17,303,18,59,165,61,59.94,131,156,213
2026-06-20 06:21:47,303,18,59,165,61,59.94,131,156,213

~~~

---

## `data/sample_input.csv`  —  place at: `cyber-exposure-governance-platform/data/sample_input.csv`  ·  _unchanged_

~~~text
asset_id,asset_name,product,cve_id,business_criticality,internet_facing,environment,asset_owner,first_detected_date
AST-0001,Host-0001,FortiOS,CVE-2020-5019,Medium,No,Prod,R&D,2026-02-25
AST-0002,Host-0002,PostgreSQL,CVE-2022-5028,Medium,No,Prod,DevOps,2026-04-05
AST-0002,Host-0002,Software,CVE-2021-5040,Low,No,Prod,DevOps,2026-05-01
AST-0003,Host-0003,kube-apiserver,CVE-2019-5117,High,No,Prod,Data Platform,2026-02-21
AST-0004,Host-0004,FortiOS,CVE-2020-5050,Medium,No,Stage,IT Operations,2026-02-22
AST-0005,Host-0005,Software,CVE-2023-5103,Medium,Yes,Stage,Platform Eng,2026-06-03
AST-0006,Host-0006,Software,CVE-2019-5025,Low,No,Stage,R&D,2026-04-30
AST-0007,Host-0007,kube-apiserver,CVE-2019-5117,High,Yes,Prod,WebOps,2026-02-18
AST-0008,Host-0008,Software,CVE-2024-5027,High,No,Prod,Data Platform,2026-06-04
AST-0009,Host-0009,Software,CVE-2023-5096,High,No,Dev,Partner IT,2026-05-25
AST-0009,Host-0009,MySQL,CVE-2023-5099,High,No,Prod,Partner IT,2026-03-25
AST-0010,Host-0010,nginx,CVE-2019-5063,Medium,Yes,UAT,Email Security,2026-04-26
AST-0011,Host-0011,Software,CVE-2022-5089,High,No,UAT,R&D,2026-02-17
AST-0012,Host-0012,PAN-OS,CVE-2024-3400,Medium,No,Prod,Data Platform,2026-04-04
AST-0013,Host-0013,Software,CVE-2023-5103,Medium,No,UAT,R&D,2026-04-03
AST-0014,Host-0014,PAN-OS,CVE-2024-3400,Low,No,UAT,DBA Team,2026-04-16
AST-0015,Host-0015,kube-apiserver,CVE-2019-5064,Low,Yes,UAT,R&D,2026-05-13
AST-0016,Host-0016,Jira,CVE-2025-5006,Medium,No,Prod,Platform Eng,2026-04-17
AST-0016,Host-0016,Software,CVE-2024-5038,Medium,No,Prod,Platform Eng,2026-05-23
AST-0017,Host-0017,Software,CVE-2021-5108,Medium,No,Dev,API Platform,2026-02-02
AST-0018,Host-0018,Windows Print Spooler,CVE-2021-34527,Medium,No,Prod,DBA Team,2026-02-28
AST-0018,Host-0018,PHP,CVE-2025-5109,High,No,UAT,DBA Team,2026-02-02
AST-0019,Host-0019,Software,CVE-2019-5002,Medium,No,Prod,Mobility Team,2026-03-01
AST-0020,Host-0020,Software,CVE-2024-5118,High,No,Prod,Network Security,2026-06-13
AST-0021,Host-0021,Exchange Server,CVE-2021-26855,Medium,Yes,Prod,Data Platform,2026-04-17
AST-0022,Host-0022,Jira,CVE-2025-5014,Medium,Yes,Prod,Infrastructure,2026-04-07
AST-0022,Host-0022,Software,CVE-2022-22965,High,Yes,Prod,Infrastructure,2026-03-26
AST-0023,Host-0023,vCenter,CVE-2019-5041,Medium,No,Dev,Mobility Team,2026-03-12
AST-0023,Host-0023,IOS XE,CVE-2023-20198,Medium,No,UAT,Mobility Team,2026-01-31
AST-0024,Host-0024,Software,CVE-2020-5116,High,No,Prod,Infrastructure,2026-05-04
AST-0025,Host-0025,Software,CVE-2021-5081,High,Yes,Stage,Payments Eng,2026-05-11
AST-0026,Host-0026,Software,CVE-2019-5113,Low,Yes,Dev,Infrastructure,2026-03-15
AST-0027,Host-0027,Software,CVE-2022-5065,Medium,No,Stage,Platform Eng,2026-02-22
AST-0028,Host-0028,Jira,CVE-2019-5098,High,No,Dev,Mobility Team,2026-05-23
AST-0029,Host-0029,NetScaler ADC,CVE-2023-4966,High,No,Dev,API Platform,2026-05-22
AST-0029,Host-0029,Software,CVE-2019-5094,Medium,No,Prod,API Platform,2026-06-15
AST-0030,Host-0030,PostgreSQL,CVE-2022-5028,High,Yes,Prod,R&D,2026-04-25
AST-0031,Host-0031,NetScaler ADC,CVE-2023-4966,High,No,Prod,HR IT,2026-04-08
AST-0032,Host-0032,Software,CVE-2024-5118,Medium,No,Prod,Data Platform,2026-02-26
AST-0032,Host-0032,Confluence,CVE-2023-22515,Medium,No,Stage,Data Platform,2026-03-02
AST-0033,Host-0033,nginx,CVE-2025-5044,Medium,Yes,Prod,HR IT,2026-04-21
AST-0034,Host-0034,NetScaler,CVE-2022-5042,Medium,Yes,Dev,Infrastructure,2026-03-29
AST-0034,Host-0034,PHP,CVE-2022-5002,Low,Yes,Prod,Infrastructure,2026-06-13
AST-0035,Host-0035,Software,CVE-2025-5071,Medium,Yes,Prod,Network Ops,2026-03-26
AST-0035,Host-0035,Jenkins,CVE-2024-5000,Medium,Yes,Dev,Network Ops,2026-05-24
AST-0036,Host-0036,Software,CVE-2023-5096,High,Yes,UAT,Network Security,2026-03-19
AST-0036,Host-0036,Software,CVE-2020-5056,Low,Yes,Dev,Network Security,2026-02-12
AST-0037,Host-0037,Software,CVE-2021-4034,Medium,No,Prod,DBA Team,2026-04-23
AST-0038,Host-0038,PostgreSQL,CVE-2023-5060,Medium,Yes,Prod,Network Ops,2026-04-08
AST-0038,Host-0038,Software,CVE-2021-5004,Medium,Yes,Stage,Network Ops,2026-02-14
AST-0039,Host-0039,nginx,CVE-2019-5069,Low,Yes,Stage,Partner IT,2026-03-27
AST-0039,Host-0039,FortiOS,CVE-2023-27997,High,Yes,Prod,Partner IT,2026-05-25
AST-0040,Host-0040,Software,CVE-2019-5033,Low,No,Prod,Payments Eng,2026-06-02
AST-0041,Host-0041,Netlogon,CVE-2020-1472,High,No,Prod,Identity Team,2026-05-30
AST-0041,Host-0041,Software,CVE-2022-5031,Low,No,Prod,Identity Team,2026-04-19
AST-0042,Host-0042,Software,CVE-2025-5045,Medium,No,Prod,R&D,2026-04-20
AST-0043,Host-0043,PHP,CVE-2025-5009,Low,No,Prod,WebOps,2026-04-24
AST-0044,Host-0044,Software,CVE-2020-5004,High,No,UAT,IT Operations,2026-03-18
AST-0044,Host-0044,Software,CVE-2021-5081,Low,No,UAT,IT Operations,2026-04-11
AST-0045,Host-0045,kube-apiserver,CVE-2019-5064,Low,Yes,Prod,Network Security,2026-03-16
AST-0045,Host-0045,PAN-OS,CVE-2024-3400,High,Yes,Dev,Network Security,2026-04-21
AST-0046,Host-0046,Software,CVE-2020-5010,High,No,UAT,Email Security,2026-05-16
AST-0047,Host-0047,Software,CVE-2024-5053,Medium,No,Prod,DBA Team,2026-05-22
AST-0047,Host-0047,Software,CVE-2025-5046,Low,No,Stage,DBA Team,2026-03-20
AST-0048,Host-0048,Software,CVE-2020-5083,Medium,Yes,Dev,IT Operations,2026-05-13
AST-0049,Host-0049,PAN-OS,CVE-2024-3400,High,No,Prod,DBA Team,2026-03-04
AST-0050,Host-0050,Software,CVE-2020-5116,Medium,No,Dev,Internal Apps,2026-02-26
AST-0050,Host-0050,Software,CVE-2021-5086,High,No,Prod,Internal Apps,2026-03-29
AST-0051,Host-0051,Jira,CVE-2019-5098,Medium,No,Prod,Internal Apps,2026-06-14
AST-0051,Host-0051,PHP,CVE-2025-5009,Medium,No,Prod,Internal Apps,2026-05-26
AST-0052,Host-0052,Software,CVE-2023-5096,Medium,No,Dev,Network Security,2026-03-03
AST-0053,Host-0053,Software,CVE-2022-5062,High,No,Stage,Network Ops,2026-04-12
AST-0053,Host-0053,Software,CVE-2019-5094,High,No,Prod,Network Ops,2026-04-11
AST-0054,Host-0054,Software,CVE-2024-23897,Low,No,Stage,DevOps,2026-05-29
AST-0055,Host-0055,ColdFusion,CVE-2024-5055,High,Yes,Prod,Mobility Team,2026-06-05
AST-0056,Host-0056,Software,CVE-2023-0286,High,Yes,Prod,WebOps,2026-06-15
AST-0057,Host-0057,Software,CVE-2022-5048,Medium,No,Prod,Data Platform,2026-03-25
AST-0057,Host-0057,NetScaler,CVE-2022-5042,High,No,Prod,Data Platform,2026-05-07
AST-0058,Host-0058,kube-apiserver,CVE-2021-5049,Medium,Yes,Dev,DevOps,2026-02-25
AST-0059,Host-0059,Software,CVE-2025-5071,Low,No,Stage,Partner IT,2026-02-10
AST-0060,Host-0060,Software,CVE-2020-5016,Medium,No,Prod,Mainframe Team,2026-02-05
AST-0061,Host-0061,Software,CVE-2021-23017,Medium,No,Stage,Network Security,2026-03-11
AST-0062,Host-0062,Software,CVE-2022-5093,High,Yes,Prod,Mobility Team,2026-05-31
AST-0062,Host-0062,Software,CVE-2024-5118,Medium,Yes,Prod,Mobility Team,2026-02-10
AST-0063,Host-0063,nginx,CVE-2025-5044,High,No,UAT,Mainframe Team,2026-04-19
AST-0063,Host-0063,Jira,CVE-2020-5005,Medium,No,UAT,Mainframe Team,2026-05-01
AST-0064,Host-0064,Exchange Server,CVE-2021-26855,High,No,Prod,Infrastructure,2026-05-29
AST-0065,Host-0065,Software,CVE-2023-5073,High,No,Dev,Platform Eng,2026-03-26
AST-0066,Host-0066,Software,CVE-2021-5040,High,Yes,Prod,Network Security,2026-03-04
AST-0067,Host-0067,Software,CVE-2022-5048,Medium,No,Prod,Identity Team,2026-02-05
AST-0068,Host-0068,ColdFusion,CVE-2024-5055,Medium,No,UAT,Platform Eng,2026-03-25
AST-0069,Host-0069,Software,CVE-2024-5007,Medium,No,UAT,Email Security,2026-02-18
AST-0070,Host-0070,kube-apiserver,CVE-2019-5064,Medium,Yes,Prod,Platform Eng,2026-03-03
AST-0070,Host-0070,Exchange Server,CVE-2021-26855,High,Yes,Prod,Platform Eng,2026-05-04
AST-0071,Host-0071,Software,CVE-2024-5007,High,No,Prod,Infrastructure,2026-05-14
AST-0072,Host-0072,Software,CVE-2023-0286,Medium,No,Stage,Partner IT,2026-04-09
AST-0073,Host-0073,Software,CVE-2024-5115,Medium,Yes,Dev,Email Security,2026-06-03
AST-0073,Host-0073,Software,CVE-2023-5073,Low,Yes,UAT,Email Security,2026-04-06
AST-0074,Host-0074,Jira,CVE-2024-5078,Medium,Yes,Prod,API Platform,2026-02-17
AST-0075,Host-0075,HTTP Server,CVE-2025-5092,High,No,UAT,Email Security,2026-05-11
AST-0075,Host-0075,Software,CVE-2022-5089,Medium,No,Prod,Email Security,2026-05-09
AST-0076,Host-0076,ColdFusion,CVE-2024-5055,Low,No,Prod,DevOps,2026-04-27
AST-0077,Host-0077,kube-apiserver,CVE-2020-5030,Medium,No,Prod,Network Ops,2026-03-24
AST-0077,Host-0077,Software,CVE-2024-5023,Low,No,Prod,Network Ops,2026-03-31
AST-0078,Host-0078,nginx,CVE-2023-5107,Medium,No,Stage,Internal Apps,2026-03-04
AST-0079,Host-0079,Software,CVE-2021-5079,Medium,Yes,UAT,Network Ops,2026-02-19
AST-0080,Host-0080,FortiOS,CVE-2023-27997,High,Yes,Prod,Data Platform,2026-03-16
AST-0081,Host-0081,Software,CVE-2019-5095,Low,No,Dev,IT Operations,2026-04-04
AST-0082,Host-0082,Software,CVE-2021-5070,Low,No,Prod,WebOps,2026-06-06
AST-0083,Host-0083,Software,CVE-2020-5072,Low,No,Prod,API Platform,2026-03-28
AST-0084,Host-0084,NetScaler ADC,CVE-2023-4966,Medium,No,UAT,Payments Eng,2026-03-22
AST-0085,Host-0085,PostgreSQL,CVE-2022-5028,Medium,No,UAT,Identity Team,2026-04-11
AST-0086,Host-0086,Samba,CVE-2023-5011,High,Yes,Prod,IT Operations,2026-02-18
AST-0087,Host-0087,MSDT,CVE-2022-30190,High,No,Prod,Network Security,2026-04-04
AST-0087,Host-0087,nginx,CVE-2023-5107,Low,No,Stage,Network Security,2026-05-23
AST-0088,Host-0088,OpenSSH Server,CVE-2024-6387,Low,No,Dev,API Platform,2026-05-01
AST-0089,Host-0089,Software,CVE-2019-5032,High,Yes,Prod,Clinical IT,2026-05-20
AST-0090,Host-0090,Software,CVE-2022-5048,Medium,No,UAT,HR IT,2026-03-19
AST-0091,Host-0091,Software,CVE-2021-5108,Medium,Yes,Prod,Clinical IT,2026-02-23
AST-0092,Host-0092,Jenkins,CVE-2024-5000,High,Yes,Prod,Payments Eng,2026-03-07
AST-0093,Host-0093,Software,CVE-2024-5038,Low,Yes,Prod,Data Platform,2026-02-04
AST-0094,Host-0094,Software,CVE-2021-5067,Low,Yes,Dev,HR IT,2026-06-15
AST-0095,Host-0095,Software,CVE-2019-5002,High,Yes,Stage,HR IT,2026-02-06
AST-0096,Host-0096,Software,CVE-2024-5118,Medium,Yes,Dev,Platform Eng,2026-05-14
AST-0097,Host-0097,PHP,CVE-2022-5002,High,No,Dev,Payments Eng,2026-04-25
AST-0097,Host-0097,Software,CVE-2025-5058,Medium,No,Prod,Payments Eng,2026-03-26
AST-0098,Host-0098,MySQL,CVE-2023-5099,Medium,Yes,Dev,Data Platform,2026-03-30
AST-0098,Host-0098,Software,CVE-2021-5101,High,Yes,Prod,Data Platform,2026-03-31
AST-0099,Host-0099,Software,CVE-2022-3786,Medium,No,Dev,Identity Team,2026-02-14
AST-0100,Host-0100,Software,CVE-2023-5096,High,No,Stage,R&D,2026-04-21
AST-0101,Host-0101,Software,CVE-2024-5038,High,Yes,UAT,WebOps,2026-05-12
AST-0101,Host-0101,Software,CVE-2021-5086,High,Yes,Prod,WebOps,2026-02-05
AST-0102,Host-0102,Software,CVE-2019-5037,Low,Yes,Prod,Network Security,2026-02-04
AST-0102,Host-0102,Node,CVE-2023-5052,High,Yes,Prod,Network Security,2026-04-26
AST-0103,Host-0103,Software,CVE-2025-5045,High,No,Dev,Clinical IT,2026-05-30
AST-0104,Host-0104,OpenSSH Server,CVE-2024-6387,High,No,Dev,Clinical IT,2026-06-01
AST-0105,Host-0105,Software,CVE-2024-5115,High,Yes,Prod,DBA Team,2026-02-25
AST-0106,Host-0106,Software,CVE-2019-5036,High,No,Prod,Data Platform,2026-04-12
AST-0107,Host-0107,Software,CVE-2019-5047,Medium,Yes,Prod,Payments Eng,2026-03-26
AST-0107,Host-0107,Software,CVE-2019-5036,Medium,Yes,Stage,Payments Eng,2026-05-16
AST-0108,Host-0108,Software,CVE-2023-5039,High,Yes,Prod,Network Ops,2026-04-06
AST-0109,Host-0109,Software,CVE-2021-5086,High,No,Stage,DevOps,2026-03-21
AST-0110,Host-0110,Software,CVE-2021-5034,Medium,Yes,Dev,WebOps,2026-02-11
AST-0110,Host-0110,Software,CVE-2019-5095,High,Yes,Prod,WebOps,2026-06-13
AST-0111,Host-0111,Software,CVE-2023-5114,High,No,Prod,Clinical IT,2026-05-23
AST-0112,Host-0112,vCenter,CVE-2019-5041,High,No,Prod,HR IT,2026-06-03
AST-0112,Host-0112,Software,CVE-2019-5001,Low,No,Prod,HR IT,2026-02-02
AST-0113,Host-0113,Software,CVE-2019-5068,High,Yes,Prod,Partner IT,2026-05-21
AST-0114,Host-0114,Software,CVE-2019-5033,High,Yes,Prod,R&D,2026-03-13
AST-0115,Host-0115,Log4j,CVE-2021-44228,Low,No,Dev,Network Security,2026-06-07
AST-0116,Host-0116,vCenter,CVE-2023-5105,Medium,No,Prod,Email Security,2026-03-22
AST-0117,Host-0117,PostgreSQL,CVE-2022-5028,High,Yes,Prod,Infrastructure,2026-04-06
AST-0118,Host-0118,Windows Print Spooler,CVE-2021-34527,Medium,No,Stage,Payments Eng,2026-03-05
AST-0119,Host-0119,kube-apiserver,CVE-2019-5117,Medium,No,Prod,Email Security,2026-03-02
AST-0120,Host-0120,Software,CVE-2020-5116,High,Yes,Dev,IT Operations,2026-05-17
AST-0121,Host-0121,Software,CVE-2021-5084,High,No,UAT,Network Security,2026-05-31
AST-0122,Host-0122,nginx,CVE-2022-5003,Low,Yes,UAT,Network Ops,2026-06-17
AST-0123,Host-0123,Software,CVE-2020-5116,Medium,No,Prod,API Platform,2026-04-17
AST-0124,Host-0124,Software,CVE-2025-5045,High,Yes,UAT,Internal Apps,2026-06-01
AST-0124,Host-0124,Software,CVE-2023-44487,Low,Yes,Prod,Internal Apps,2026-03-19
AST-0125,Host-0125,Software,CVE-2023-38545,High,No,Stage,Network Security,2026-02-02
AST-0125,Host-0125,Software,CVE-2019-5100,Low,No,Stage,Network Security,2026-05-11
AST-0126,Host-0126,Software,CVE-2020-5004,High,Yes,Prod,Partner IT,2026-05-15
AST-0127,Host-0127,Windows Print Spooler,CVE-2021-34527,High,No,UAT,DevOps,2026-02-23
AST-0128,Host-0128,nginx,CVE-2019-5069,Low,No,Dev,HR IT,2026-03-04
AST-0129,Host-0129,Software,CVE-2024-23897,High,Yes,UAT,HR IT,2026-02-23
AST-0130,Host-0130,Software,CVE-2022-5054,High,Yes,UAT,API Platform,2026-04-20
AST-0130,Host-0130,Software,CVE-2020-5061,Medium,Yes,UAT,API Platform,2026-06-04
AST-0131,Host-0131,Software,CVE-2019-5077,Medium,Yes,Prod,Partner IT,2026-03-31
AST-0131,Host-0131,Software,CVE-2025-5046,Medium,Yes,Dev,Partner IT,2026-03-28
AST-0132,Host-0132,PAN-OS,CVE-2024-3400,High,No,Prod,DBA Team,2026-04-03
AST-0132,Host-0132,Software,CVE-2019-5068,Low,No,Prod,DBA Team,2026-04-25
AST-0133,Host-0133,Software,CVE-2023-5039,High,No,Prod,Payments Eng,2026-05-19
AST-0134,Host-0134,Software,CVE-2022-5106,Low,Yes,Prod,WebOps,2026-03-10
AST-0135,Host-0135,FortiOS,CVE-2020-5050,Medium,No,UAT,Payments Eng,2026-02-17
AST-0136,Host-0136,Software,CVE-2024-5027,High,Yes,Dev,Platform Eng,2026-04-09
AST-0137,Host-0137,Software,CVE-2020-5004,High,Yes,Prod,HR IT,2026-03-30
AST-0138,Host-0138,Software,CVE-2022-5048,Medium,No,Prod,Network Ops,2026-03-27
AST-0139,Host-0139,Software,CVE-2021-5034,Medium,No,Stage,DevOps,2026-05-25
AST-0140,Host-0140,Software,CVE-2022-5054,High,No,Prod,Infrastructure,2026-06-19
AST-0140,Host-0140,OpenSSH Server,CVE-2024-6387,Low,No,Prod,Infrastructure,2026-06-11
AST-0141,Host-0141,Kernel,CVE-2019-5017,High,No,Prod,HR IT,2026-06-02
AST-0141,Host-0141,PAN-OS,CVE-2024-3400,Medium,No,Prod,HR IT,2026-05-23
AST-0142,Host-0142,Jira,CVE-2019-5098,High,No,Prod,Platform Eng,2026-04-05
AST-0143,Host-0143,Software,CVE-2023-5103,High,Yes,Prod,Clinical IT,2026-04-28
AST-0143,Host-0143,Software,CVE-2020-5056,High,Yes,Prod,Clinical IT,2026-02-01
AST-0144,Host-0144,Software,CVE-2024-5024,High,Yes,Prod,Network Security,2026-03-10
AST-0145,Host-0145,Software,CVE-2020-5010,High,No,Dev,Email Security,2026-03-23
AST-0146,Host-0146,HTTP Server,CVE-2021-5087,High,No,Prod,Partner IT,2026-05-18
AST-0147,Host-0147,kube-apiserver,CVE-2020-5030,High,Yes,Prod,Network Security,2026-05-25
AST-0148,Host-0148,Software,CVE-2023-0286,Medium,Yes,Dev,Network Ops,2026-04-20
AST-0149,Host-0149,PHP,CVE-2025-5109,Medium,Yes,Prod,Payments Eng,2026-03-07
AST-0150,Host-0150,Engine,CVE-2021-5003,High,No,Prod,Identity Team,2026-04-30
AST-0151,Host-0151,Software,CVE-2023-5013,High,Yes,Prod,Mainframe Team,2026-06-12
AST-0152,Host-0152,Software,CVE-2024-5118,Medium,No,Stage,Payments Eng,2026-04-02
AST-0153,Host-0153,Software,CVE-2024-5023,High,No,Prod,Email Security,2026-04-10
AST-0154,Host-0154,Software,CVE-2023-5013,Medium,No,Prod,Mainframe Team,2026-03-12
AST-0155,Host-0155,Software,CVE-2024-5115,High,No,Prod,Platform Eng,2026-04-23
AST-0156,Host-0156,Software,CVE-2021-5008,Medium,No,Prod,Email Security,2026-05-12
AST-0156,Host-0156,Software,CVE-2019-5025,High,No,Prod,Email Security,2026-03-24
AST-0157,Host-0157,NetScaler ADC,CVE-2023-4966,High,No,Prod,Clinical IT,2026-02-28
AST-0158,Host-0158,HTTP Server,CVE-2025-5092,High,No,Prod,WebOps,2026-06-08
AST-0158,Host-0158,Software,CVE-2022-5054,Medium,No,Prod,WebOps,2026-02-23
AST-0159,Host-0159,MOVEit Transfer,CVE-2023-34362,Low,No,UAT,API Platform,2026-05-07
AST-0160,Host-0160,Software,CVE-2019-5002,Medium,Yes,Stage,DBA Team,2026-05-25
AST-0161,Host-0161,nginx,CVE-2019-5063,Medium,No,Prod,Identity Team,2026-06-09
AST-0162,Host-0162,Software,CVE-2022-3786,High,No,Prod,WebOps,2026-04-05
AST-0163,Host-0163,Software,CVE-2025-5005,Medium,Yes,Stage,DBA Team,2026-04-12
AST-0164,Host-0164,Software,CVE-2019-5077,High,No,Prod,Email Security,2026-05-24
AST-0165,Host-0165,NetScaler,CVE-2024-5043,High,No,Prod,Mainframe Team,2026-03-31
AST-0165,Host-0165,ColdFusion,CVE-2024-5055,High,No,Dev,Mainframe Team,2026-02-05
AST-0166,Host-0166,HTTP Server,CVE-2021-5087,Medium,No,Prod,Platform Eng,2026-04-19
AST-0166,Host-0166,Software,CVE-2019-11043,Medium,No,Prod,Platform Eng,2026-06-07
AST-0167,Host-0167,nginx,CVE-2019-5069,Low,No,Prod,Email Security,2026-05-27
AST-0167,Host-0167,Software,CVE-2019-5094,Low,No,Stage,Email Security,2026-04-03
AST-0168,Host-0168,Software,CVE-2023-5114,High,No,Prod,HR IT,2026-03-24
AST-0168,Host-0168,Software,CVE-2020-5010,Medium,No,Stage,HR IT,2026-04-06
AST-0169,Host-0169,Software,CVE-2021-5086,Medium,No,Prod,Mobility Team,2026-05-19
AST-0170,Host-0170,Software,CVE-2021-3156,Low,No,Stage,R&D,2026-06-08
AST-0171,Host-0171,Software,CVE-2021-5081,High,No,Stage,Identity Team,2026-04-06
AST-0172,Host-0172,Software,CVE-2019-5036,High,No,Prod,R&D,2026-06-05
AST-0173,Host-0173,Software,CVE-2025-5046,Medium,Yes,Dev,API Platform,2026-06-07
AST-0173,Host-0173,Software,CVE-2021-5108,Medium,Yes,Prod,API Platform,2026-03-05
AST-0174,Host-0174,Software,CVE-2024-5080,High,No,Prod,Partner IT,2026-04-09
AST-0175,Host-0175,Confluence,CVE-2023-22515,High,No,UAT,DevOps,2026-05-10
AST-0176,Host-0176,Software,CVE-2022-5057,Medium,No,Prod,Platform Eng,2026-04-18
AST-0177,Host-0177,HTTP Server,CVE-2021-5087,Low,Yes,UAT,WebOps,2026-06-18
AST-0178,Host-0178,Log4j,CVE-2021-44228,Medium,No,Prod,R&D,2026-05-28
AST-0179,Host-0179,Software,CVE-2025-5005,Low,Yes,Prod,Email Security,2026-04-06
AST-0180,Host-0180,PHP,CVE-2022-5002,High,No,UAT,R&D,2026-03-11
AST-0181,Host-0181,nginx,CVE-2023-5107,High,No,Prod,Infrastructure,2026-05-25
AST-0182,Host-0182,Software,CVE-2020-5116,High,No,Prod,Clinical IT,2026-03-31
AST-0183,Host-0183,PAN-OS,CVE-2024-3400,High,Yes,Dev,Email Security,2026-05-31
AST-0184,Host-0184,Jira,CVE-2025-5014,Low,Yes,Dev,DevOps,2026-05-08
AST-0185,Host-0185,Jenkins,CVE-2024-5000,High,No,Prod,HR IT,2026-03-29
AST-0185,Host-0185,Engine,CVE-2021-5003,High,No,Dev,HR IT,2026-02-06
AST-0186,Host-0186,HTTP Server,CVE-2025-5092,High,No,Prod,Internal Apps,2026-05-08
AST-0187,Host-0187,ColdFusion,CVE-2024-5055,High,Yes,UAT,Mobility Team,2026-05-09
AST-0188,Host-0188,HTTP Server,CVE-2021-5087,Medium,Yes,Prod,Identity Team,2026-06-02
AST-0189,Host-0189,Confluence,CVE-2023-22515,Medium,Yes,Prod,Network Ops,2026-02-04
AST-0189,Host-0189,Software,CVE-2021-5067,Medium,Yes,Prod,Network Ops,2026-02-16
AST-0190,Host-0190,Software,CVE-2024-5080,High,No,Dev,Network Ops,2026-05-23
AST-0191,Host-0191,Software,CVE-2022-5054,Low,No,Prod,Mainframe Team,2026-03-10
AST-0192,Host-0192,Software,CVE-2019-5037,High,No,Prod,Internal Apps,2026-04-24
AST-0192,Host-0192,Software,CVE-2024-5115,Medium,No,Prod,Internal Apps,2026-06-10
AST-0193,Host-0193,Software,CVE-2019-5032,High,No,Stage,Network Ops,2026-06-19
AST-0194,Host-0194,Windows Print Spooler,CVE-2021-34527,Medium,Yes,Prod,Network Security,2026-03-07
AST-0194,Host-0194,vCenter,CVE-2019-5041,Low,Yes,Prod,Network Security,2026-06-01
AST-0195,Host-0195,Software,CVE-2023-5114,High,No,Prod,Data Platform,2026-04-24
AST-0195,Host-0195,Software,CVE-2023-5013,High,No,Prod,Data Platform,2026-03-06
AST-0196,Host-0196,PHP,CVE-2025-5109,Medium,No,Dev,Network Security,2026-04-29
AST-0197,Host-0197,kube-apiserver,CVE-2021-5049,Low,No,Prod,DBA Team,2026-02-14
AST-0198,Host-0198,Kernel,CVE-2019-5017,High,Yes,Dev,R&D,2026-04-27
AST-0199,Host-0199,Software,CVE-2022-5031,High,No,UAT,Network Ops,2026-04-22
AST-0199,Host-0199,ESG,CVE-2023-2868,High,No,Dev,Network Ops,2026-04-11
AST-0200,Host-0200,Software,CVE-2022-5104,High,No,Prod,Network Ops,2026-02-18
AST-0201,Host-0201,IOS XE,CVE-2023-20198,Medium,No,Dev,Platform Eng,2026-02-09
AST-0202,Host-0202,NetScaler,CVE-2022-5042,High,No,Prod,DevOps,2026-04-22
AST-0203,Host-0203,NetScaler,CVE-2022-5042,High,No,Prod,Platform Eng,2026-03-10
AST-0204,Host-0204,Software,CVE-2021-5076,High,Yes,Stage,Payments Eng,2026-03-20
AST-0205,Host-0205,Software,CVE-2024-5053,Medium,No,Prod,R&D,2026-03-06
AST-0206,Host-0206,Software,CVE-2023-5096,Low,Yes,Prod,Network Ops,2026-03-10
AST-0207,Host-0207,nginx,CVE-2022-5003,High,Yes,Prod,Internal Apps,2026-04-06
AST-0208,Host-0208,Confluence,CVE-2022-26134,Medium,Yes,Prod,R&D,2026-03-24
AST-0209,Host-0209,Confluence,CVE-2022-26134,High,No,Prod,DevOps,2026-02-26
AST-0209,Host-0209,Software,CVE-2021-5040,High,No,Dev,DevOps,2026-06-11
AST-0210,Host-0210,Software,CVE-2019-5037,Medium,Yes,Prod,IT Operations,2026-05-08
AST-0211,Host-0211,Software,CVE-2025-5005,High,Yes,Dev,Network Security,2026-02-02
AST-0212,Host-0212,Software,CVE-2019-5075,High,Yes,UAT,Data Platform,2026-03-22
AST-0213,Host-0213,Jira,CVE-2025-5014,Medium,No,Dev,Payments Eng,2026-06-03
AST-0214,Host-0214,vCenter,CVE-2023-5105,High,No,Prod,Mobility Team,2026-02-15
AST-0215,Host-0215,NetScaler,CVE-2022-5042,High,Yes,Prod,Platform Eng,2026-03-05
AST-0215,Host-0215,MySQL,CVE-2023-5099,Medium,Yes,Dev,Platform Eng,2026-06-05
AST-0216,Host-0216,Software,CVE-2021-5086,Medium,No,Dev,DBA Team,2026-02-22
AST-0216,Host-0216,Windows Print Spooler,CVE-2021-34527,Medium,No,Prod,DBA Team,2026-05-08
AST-0217,Host-0217,Samba,CVE-2023-5011,Medium,Yes,Prod,Mobility Team,2026-02-25
AST-0217,Host-0217,Software,CVE-2022-3786,Medium,Yes,Prod,Mobility Team,2026-06-11
AST-0218,Host-0218,Software,CVE-2024-5066,High,Yes,Prod,R&D,2026-04-15
AST-0219,Host-0219,Software,CVE-2022-5089,Medium,Yes,Prod,Network Ops,2026-02-28
AST-0220,Host-0220,Jira,CVE-2020-5005,Low,No,Prod,Internal Apps,2026-04-24
AST-0220,Host-0220,Windows Print Spooler,CVE-2021-34527,Medium,No,Prod,Internal Apps,2026-03-11
AST-0221,Host-0221,Software,CVE-2022-5062,Low,Yes,Dev,Network Security,2026-06-08
AST-0222,Host-0222,ColdFusion,CVE-2024-5055,High,Yes,Dev,Platform Eng,2026-03-16
AST-0222,Host-0222,Software,CVE-2020-5083,High,Yes,Dev,Platform Eng,2026-05-29
AST-0223,Host-0223,FortiOS,CVE-2020-5019,Low,Yes,Dev,Identity Team,2026-04-14
AST-0224,Host-0224,Software,CVE-2019-5032,High,No,Prod,Payments Eng,2026-04-06
AST-0225,Host-0225,Software,CVE-2020-5112,Medium,No,Dev,Infrastructure,2026-03-21
AST-0226,Host-0226,ESG,CVE-2023-2868,High,No,Prod,R&D,2026-04-01
AST-0227,Host-0227,nginx,CVE-2022-5003,Low,No,UAT,Identity Team,2026-05-20
AST-0228,Host-0228,Software,CVE-2020-5083,High,Yes,Dev,Email Security,2026-06-13
AST-0229,Host-0229,Software,CVE-2023-5096,High,No,Dev,Infrastructure,2026-04-29
AST-0230,Host-0230,Engine,CVE-2021-5003,High,No,UAT,HR IT,2026-02-02
AST-0230,Host-0230,PHP,CVE-2022-5002,Medium,No,Dev,HR IT,2026-06-09
AST-0231,Host-0231,Software,CVE-2023-5039,Medium,No,Prod,Data Platform,2026-02-11
AST-0232,Host-0232,Jira,CVE-2019-5098,Medium,Yes,Prod,Email Security,2026-02-05
AST-0233,Host-0233,Software,CVE-2022-5054,Medium,No,Prod,Infrastructure,2026-05-04
AST-0233,Host-0233,Software,CVE-2019-5113,High,No,Prod,Infrastructure,2026-04-29
AST-0234,Host-0234,Software,CVE-2021-5079,High,Yes,Prod,API Platform,2026-06-05
AST-0235,Host-0235,Software,CVE-2021-5070,High,No,Prod,Network Security,2026-04-04
AST-0235,Host-0235,Software,CVE-2019-5032,Medium,No,Prod,Network Security,2026-03-14
AST-0001,Host-0001,FortiOS,CVE-2020-5019,Medium,No,Prod,R&D,2026-02-25
AST-9001,Quantum Test Rig,Experimental,CVE-2024-NOTREAL,Medium,No,Dev,R&D,2026-06-15
AST-9002,Tier0 Mainframe,Legacy Core,CVE-2022-26134,Critical,Yes,Prod,Mainframe Team,2026-04-26

~~~

---

## `docs/CEGP_Project_Report.docx`  —  place at: `cyber-exposure-governance-platform/docs/CEGP_Project_Report.docx`  ·  _unchanged_

_Binary Word document — included in the ZIP, not printable here._

---

## `docs/demo_script.md`  —  place at: `cyber-exposure-governance-platform/docs/demo_script.md`  ·  _unchanged_

~~~markdown
# Demo Script — Cyber Exposure Governance Platform

## 1. Opening

This project is a lightweight cyber exposure governance platform. It does not replace vulnerability scanners. It consumes scanner-style vulnerability data and helps organizations decide what to fix first, who owns it, when it is due, and what risk reduction can be achieved.

## 2. Problem Statement

Organizations often have many vulnerabilities, but limited remediation capacity. CVSS alone is not enough because it does not fully include active exploitation, asset criticality, network exposure, IDS/IPS activity, privacy impact, or SLA governance.

## 3. Demo Flow

1. Open the Streamlit application.
2. Keep bundled sample files enabled.
3. Click **Run Cyber Exposure Assessment**.
4. Show executive summary cards.
5. Explain that CVEs are enriched using KEV, EPSS, and NVD.
6. Show the Analyst View.
7. Show Network Exposure tab.
8. Show IDS/IPS Correlation tab.
9. Show Privacy Impact tab.
10. Show Remediation Governance tab.
11. Show What-If Simulation.
12. Export reports.
13. Show SHA-256 report integrity hash.
14. Show Audit Log.

## 4. Key Message

The platform converts raw vulnerability data into business-aligned cyber exposure decisions by correlating vulnerability intelligence, network exposure, IDS/IPS signals, privacy impact, remediation SLA, exception handling, and control mapping.

## 5. Closing

This tool can be productized for small and mid-sized organizations as a lightweight layer between vulnerability scanners and remediation teams.

~~~

---

## `docs/gcp_deployment_guide.md`  —  place at: `cyber-exposure-governance-platform/docs/gcp_deployment_guide.md`  ·  _UPDATED this session_

~~~markdown
# Cyber Exposure Governance Platform (CEGP)
### Future Scope — Deploying the Application on Google Cloud Platform (GCP)

> A complete, **beginner-proof**, step-by-step guide to take CEGP from a local Streamlit app to a **secure, internet-accessible, authenticated web service** running on Google Cloud — so a whole team (or auditors) can use it from anywhere, with no one able to reach it without logging in.
>
> This guide assumes **no prior cloud experience**. Every command is explained, every step has a "how to check it worked", and nothing is left as an exercise for the reader.

**Authors:** Dwaipayan Mojumder · Deblina Das · M.Sc. Cyber Security (4th Sem) · Guidance: Prof. Sanjay Pal

---

## How to Use This Guide

- **Follow the parts in order.** Each one builds on the previous.
- **Anything in `monospace`** is either a command you type or a value you replace.
- **`UPPER_CASE` placeholders** (like `YOUR_PROJECT_ID`) must be replaced with your own values. To make this painless, [Step 0.5](#05--set-your-variables-once) sets them once as shell variables so you can copy-paste the rest verbatim.
- **Every step ends with a ✅ "Check it worked" box.** If the check fails, jump to [Troubleshooting](#troubleshooting) before continuing.
- **Boxes marked ⚠️ are important** — read them.

> 💡 **Validated:** The container start-up command, the Streamlit launch flags, the dependency versions, and the integrity-key generation in this guide were test-run before publishing. The health endpoint Cloud Run checks (`/_stcore/health`) returns HTTP 200 with this exact configuration.

---

## A Plain-English Glossary

You do **not** need to memorise these — refer back as needed.

| Term | What it means in one line |
|---|---|
| **Terminal / shell** | The text window where you type commands (Command Prompt / PowerShell on Windows, Terminal on Mac/Linux). |
| **`gcloud`** | Google Cloud's command-line tool — how you control GCP by typing instead of clicking. |
| **Project** | Your isolated workspace on GCP. Everything (services, bills, permissions) lives inside one project, identified by a **Project ID**. |
| **Region** | The physical location your app runs in, e.g. `asia-south1` (Mumbai) or `us-central1` (Iowa). Pick one close to your users and reuse it everywhere. |
| **Container / image** | A self-contained, portable bundle of your app plus everything it needs to run. The bundle is the *image*; a running copy is a *container*. |
| **Dockerfile** | The recipe that tells GCP how to build your image. |
| **Artifact Registry** | Google's storage shelf for your container images. |
| **Cloud Build** | Google's service that builds your image in the cloud (so you don't need Docker on your laptop). |
| **Cloud Run** | The service that *runs* your container, gives it an HTTPS web address, and auto-scales it. |
| **Secret Manager** | A secure vault for passwords and keys, so they never sit in your code. |
| **IAP (Identity-Aware Proxy)** | A Google login gate placed in front of your app — only people you approve can get in. |
| **Service account** | A non-human "robot" identity that GCP services use to talk to each other. |
| **IAM** | Identity and Access Management — GCP's system of *who is allowed to do what*. |

---

## Table of Contents

1. [What We Are Building](#1-what-we-are-building)
2. [Deployment Options Compared](#2-deployment-options-compared)
3. [Part 0 — Get Your Machine Ready (Prerequisites)](#part-0--get-your-machine-ready-prerequisites)
4. [Part 1 — Prepare the App for the Cloud](#part-1--prepare-the-app-for-the-cloud)
5. [Part 2 — Set Up Your GCP Project](#part-2--set-up-your-gcp-project)
6. [Part 3 — Create an Image Repository](#part-3--create-an-image-repository)
7. [Part 4 — Build & Push the Container](#part-4--build--push-the-container)
8. [Part 5 — Deploy to Cloud Run](#part-5--deploy-to-cloud-run)
9. [Part 6 — Protect the Integrity Key with Secret Manager](#part-6--protect-the-integrity-key-with-secret-manager)
10. [Part 7 — Lock It Down with Authentication (IAP)](#part-7--lock-it-down-with-authentication-iap)
11. [Part 8 — Custom Domain & HTTPS](#part-8--custom-domain--https)
12. [Part 9 — Continuous Deployment (Optional)](#part-9--continuous-deployment-optional)
13. [Part 10 — Operate: Logs, Scaling & Updates](#part-10--operate-logs-scaling--updates)
14. [Part 11 — Make Data Survive Restarts (Persistence)](#part-11--make-data-survive-restarts-persistence)
15. [Cost Considerations](#cost-considerations)
16. [Security Checklist](#security-checklist)
17. [Tearing Everything Down](#tearing-everything-down)
18. [Troubleshooting](#troubleshooting)
19. [Quick Command Reference (Cheat Sheet)](#quick-command-reference-cheat-sheet)
20. [References](#references)
21. [Appendix — How This Document Is Wired Into the App](#appendix--how-this-document-is-wired-into-the-app)

---

## 1. What We Are Building

We will package CEGP into a **container**, store it in Google's registry, and run it on **Cloud Run** — a fully managed service that runs containers, scales automatically, gives you an HTTPS URL out of the box, and only charges while it is actually handling requests.

Then we will:

- Store the report-signing key safely in **Secret Manager** (never in code).
- Put **Identity-Aware Proxy (IAP)** in front so that **only people you authorise can reach the app** — everyone else is stopped at a Google login.
- Optionally attach a **custom domain** and set up **automatic re-deployment** when the code changes.

**The journey, at a glance:**

```
Your code  ──►  Container image  ──►  Artifact Registry  ──►  Cloud Run (live HTTPS URL)
                                                                     │
                                              Secret Manager (signing key)
                                                                     │
                                                  IAP login gate (authorised users only)
```

The end result is a professional, secure, always-on deployment.

---

## 2. Deployment Options Compared

GCP offers several ways to host the app. This guide focuses on **Cloud Run**, which is the best fit for a Streamlit application.

| Option | What it is | Best for | This guide |
|---|---|---|---|
| **Cloud Run** | Managed containers, auto-scaling, pay-per-use, HTTPS included | Web apps like this one | ✅ Recommended |
| **App Engine (Flexible)** | Managed app hosting on containers | Similar to Cloud Run, less flexible | Alternative |
| **Compute Engine (VM)** | A virtual machine you manage yourself | Full control, always-on, more upkeep | Alternative |
| **GKE (Kubernetes)** | Container orchestration at scale | Large, complex, multi-service systems | Overkill here |

> **Why Cloud Run?** No servers to manage; it scales to zero when idle (so it is cheap); it provides a free HTTPS endpoint; it integrates cleanly with Secret Manager and IAP; and it supports the WebSocket connections Streamlit relies on.

---

# Part 0 — Get Your Machine Ready (Prerequisites)

Do these one-time setup steps before anything else.

### 0.1 A GCP account with billing enabled

You already have one. If billing is not yet linked: in the [Cloud Console](https://console.cloud.google.com) go to **Billing → Link a billing account**. New accounts include free credits, and this design stays at or near the free tier for light use.

### 0.2 Install the `gcloud` CLI

`gcloud` is the tool you will type all the commands into.

- **Windows:** Download the installer from the [Cloud SDK page](https://cloud.google.com/sdk/docs/install) and run it. When it finishes, tick "Start Google Cloud SDK Shell" — that is your terminal for this guide.
- **macOS / Linux:** Follow the same [install page](https://cloud.google.com/sdk/docs/install); it walks you through a short download-and-extract, then asks you to run `./google-cloud-sdk/install.sh`.

> ✅ **Check it worked** — open a terminal and run:
> ```bash
> gcloud version
> ```
> You should see version numbers (no "command not found"). If it says "command not found", close and reopen the terminal, or re-run the installer.

### 0.3 Open a terminal

- **Windows:** open **Google Cloud SDK Shell** (installed in step 0.2) — recommended, as it is pre-wired for `gcloud`.
- **macOS:** open the **Terminal** app (Applications → Utilities → Terminal).
- **Linux:** open your usual terminal.

### 0.4 Have the project files ready

You need the CEGP project folder on your machine — the folder that contains `app.py`, `requirements.txt`, `core/`, `services/`, and `data/`. In the terminal, move into it:

```bash
cd path/to/your/CEGP-folder
```

> ✅ **Check it worked** — run `ls` (Mac/Linux) or `dir` (Windows). You should see `app.py` in the list.

### 0.5 Set your variables once

To avoid typos later, set these once. **Replace the values** with your own, then paste the block into your terminal. Every later command reuses them.

**macOS / Linux (and the Windows Cloud SDK Shell):**

```bash
export PROJECT_ID="your-project-id"      # e.g. cegp-prod-2026
export REGION="asia-south1"              # e.g. asia-south1 (Mumbai) or us-central1
export SERVICE="cegp"                    # the Cloud Run service name
export REPO="cegp-repo"                  # the Artifact Registry repo name
```

**Windows PowerShell (if you are not using the Cloud SDK Shell):**

```powershell
$PROJECT_ID="your-project-id"
$REGION="asia-south1"
$SERVICE="cegp"
$REPO="cegp-repo"
```

> ⚠️ **Important:** Variables only last for the current terminal window. If you close it, re-paste this block before continuing.
>
> 📝 **Note on examples:** The commands below use the Linux/Mac `$PROJECT_ID` style. On Windows PowerShell, the same variables are written `$PROJECT_ID` too, so the commands work as-is. (In the Cloud SDK Shell on Windows, the Linux style works.)

---

# Part 1 — Prepare the App for the Cloud

A container needs a few small files in the project root. **None of them change how the app runs locally.**

### 1.1 Create a `Dockerfile`

This is the recipe that builds the container. Create a file named exactly `Dockerfile` (no file extension) in the project root, and paste in:

```dockerfile
# Use a small, official Python base image (matches local Python 3.12)
FROM python:3.12-slim

# Keep Python output unbuffered so logs appear immediately in Cloud Run
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Install dependencies first — this layer is cached, so rebuilds are faster
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application into the image
COPY . .

# Cloud Run tells the app which port to listen on via the PORT variable (default 8080)
ENV PORT=8080
EXPOSE 8080

# Start Streamlit, bound to all network interfaces on the Cloud Run port
CMD streamlit run app.py \
    --server.port=${PORT} \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --server.enableCORS=false \
    --server.enableXsrfProtection=false
```

> **Why these flags?** Cloud Run injects the port number as `PORT` and expects the app to listen on `0.0.0.0` (all interfaces). `headless=true` stops Streamlit trying to open a browser inside the container. Disabling CORS/XSRF avoids WebSocket and file-upload issues behind Cloud Run's proxy. **This is safe** because, after Part 7, IAP is the real security gate in front of the app.

### 1.2 Create a `.dockerignore`

This keeps junk and secrets out of the image (smaller, safer builds). Create `.dockerignore` in the project root:

```
.venv/
venv/
__pycache__/
*.pyc
.git/
.gitignore
.streamlit/secrets.toml
data/.integrity_key
*.md
.DS_Store
```

> **Why exclude `data/.integrity_key`?** The signing key must come from Secret Manager in the cloud (Part 6), never baked into the image.

### 1.3 Pin `requirements.txt`

Make sure your `requirements.txt` lists everything the app needs, **with upper bounds** so a future breaking release cannot silently break your build:

```
streamlit>=1.36,<2.0
pandas>=2.0,<3.0
plotly>=5.20,<7.0
requests>=2.31,<3.0
openpyxl>=3.1.0,<4.0
xlrd>=2.0.1,<3.0
```

> ⚠️ **Audit note:** An unbounded `pandas>=2.0` will install **pandas 3.x**, which has breaking changes versus the 2.x series the app was written against. The `<3.0` cap above prevents that. Apply the same upper-bound discipline to any other library your app imports.

### 1.4 (Recommended) Add a `.streamlit/config.toml`

Putting server settings in a config file is cleaner than long command-line flags and keeps behaviour consistent. Create `.streamlit/config.toml`:

```toml
[server]
headless = true
enableCORS = false
enableXsrfProtection = false

[browser]
gatherUsageStats = false
```

> This is optional — the `Dockerfile` flags already cover it — but it documents intent and helps local runs behave like the cloud.

### 1.5 Read the integrity key from the environment

The app signs reports with `REPORT_INTEGRITY_KEY`. In the cloud we supply this via Secret Manager (Part 6) as an environment variable. The app **already reads this environment variable** if present, so **no code change is required**. (We will confirm this end-to-end in Part 6.)

> ✅ **Check it worked** — your project root now contains: `Dockerfile`, `.dockerignore`, `requirements.txt` (with upper bounds), and optionally `.streamlit/config.toml`. Run `ls -a` (Mac/Linux) or `dir /a` (Windows) to confirm.

---

# Part 2 — Set Up Your GCP Project

Run these once. (Make sure you have set your variables — [Step 0.5](#05--set-your-variables-once).)

### 2.1 Sign in and select your project

```bash
gcloud auth login
gcloud config set project $PROJECT_ID
gcloud config set run/region $REGION
```

`gcloud auth login` opens a browser for you to sign in to your Google account. The other two lines make `gcloud` use your project and region by default.

If you need a **fresh** project instead:

```bash
gcloud projects create $PROJECT_ID --name="CEGP"
gcloud config set project $PROJECT_ID
# Then link a billing account: Console → Billing → Link a billing account
```

> ✅ **Check it worked:**
> ```bash
> gcloud config list
> ```
> Confirm `project = your-project-id` and `region = your-region` are shown.

### 2.2 Enable the required APIs

APIs are the individual GCP services; they are off by default and must be switched on:

```bash
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  iap.googleapis.com \
  compute.googleapis.com
```

This can take a minute or two.

> ✅ **Check it worked:**
> ```bash
> gcloud services list --enabled --filter="config.name:(run.googleapis.com OR iap.googleapis.com)"
> ```
> Both `run.googleapis.com` and `iap.googleapis.com` should appear.

### 2.3 Note your project number (used later)

Some commands need your **project number** (a long digit string, different from the Project ID). Capture it now:

```bash
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
echo "Project number: $PROJECT_NUMBER"
```

> ✅ **Check it worked** — `echo` prints a long number. If it is blank, re-check `$PROJECT_ID`.

---

# Part 3 — Create an Image Repository

Artifact Registry is the shelf where your container image is stored. Create one repository (once):

```bash
gcloud artifacts repositories create $REPO \
  --repository-format=docker \
  --location=$REGION \
  --description="CEGP container images"
```

> ✅ **Check it worked:**
> ```bash
> gcloud artifacts repositories list --location=$REGION
> ```
> You should see `cegp-repo` (or your `$REPO` name) listed as a `DOCKER` repository.

---

# Part 4 — Build & Push the Container

From inside the project folder (where the `Dockerfile` lives), let **Cloud Build** build the image and store it — **no local Docker needed**:

```bash
gcloud builds submit \
  --tag $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest
```

This uploads your code, builds the image in the cloud, and pushes it to Artifact Registry. The first build takes a few minutes (it downloads the Python base image and installs dependencies). When it finishes you will see the image path ending in `:latest` and a green `SUCCESS`.

> ✅ **Check it worked:**
> ```bash
> gcloud artifacts docker images list \
>   $REGION-docker.pkg.dev/$PROJECT_ID/$REPO
> ```
> Your `cegp` image should be listed with a recent timestamp.

> 🛠️ **If the build fails** on a Python package, a dependency is missing from `requirements.txt`, or it needs a system library. See the [Troubleshooting](#troubleshooting) table.

---

# Part 5 — Deploy to Cloud Run

Now run the image as a live service. **For this first deploy we keep it public** so you can confirm it works; we lock it down in Part 7.

```bash
gcloud run deploy $SERVICE \
  --image $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest \
  --region $REGION \
  --platform managed \
  --port 8080 \
  --memory 1Gi \
  --cpu 1 \
  --cpu-boost \
  --min-instances 0 \
  --max-instances 4 \
  --timeout 3600 \
  --allow-unauthenticated
```

A few notes on the options:

- `--memory 1Gi` is comfortable for pandas/plotly; raise to `2Gi` for very large uploads.
- `--cpu-boost` gives extra CPU during start-up, which noticeably reduces Streamlit's cold-start time.
- `--min-instances 0` lets it scale to zero (cheapest); set to `1` to avoid cold-start delay.
- `--max-instances 4` caps how many copies can run at once (cost ceiling).
- `--timeout 3600` keeps long-lived Streamlit WebSocket sessions alive (max is 3600 seconds = 60 minutes).
- `--allow-unauthenticated` makes it reachable **for now**. **We remove this in Part 7.**

When the command finishes it prints a **Service URL** like `https://cegp-xxxxxxxx-uc.a.run.app`.

> ✅ **Check it worked** — open the printed Service URL in your browser. The CEGP app should load over HTTPS. You can also confirm from the terminal:
> ```bash
> gcloud run services describe $SERVICE --region $REGION --format='value(status.url)'
> curl -s -o /dev/null -w "%{http_code}\n" "$(gcloud run services describe $SERVICE --region $REGION --format='value(status.url)')/_stcore/health"
> ```
> The health check should print `200`.

> ⚠️ **The app is publicly reachable at this point. Do not load real or sensitive data until you have completed Part 7.**

---

# Part 6 — Protect the Integrity Key with Secret Manager

Reports are signed with a secret key. Store it in the vault instead of in the container.

### 6.1 Create the secret

```bash
# Generate a strong random key and store it as a secret named cegp-integrity-key
openssl rand -hex 32 | gcloud secrets create cegp-integrity-key \
  --data-file=- \
  --replication-policy=automatic
```

> `openssl rand -hex 32` produces a 64-character random key. The `|` pipes it straight into the secret, so the key is never written to disk or shown on screen.

> ✅ **Check it worked:**
> ```bash
> gcloud secrets describe cegp-integrity-key --format='value(name)'
> ```
> It prints the secret's full resource name.

### 6.2 Let Cloud Run read it

Grant the Cloud Run runtime service account permission to read the secret, then attach the secret as an environment variable:

```bash
# The default Cloud Run runtime identity is the Compute Engine default service account
gcloud secrets add-iam-policy-binding cegp-integrity-key \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Attach the secret to the service as the REPORT_INTEGRITY_KEY environment variable
gcloud run services update $SERVICE \
  --region $REGION \
  --update-secrets REPORT_INTEGRITY_KEY=cegp-integrity-key:latest
```

The app now signs and verifies reports using the managed key, and the key never appears in your code or image.

> 🔒 **Best-practice upgrade (optional):** For production, create a **dedicated** service account for the service instead of using the default Compute SA, and grant only that account the `secretAccessor` role. This follows least-privilege. For a project deliverable, the default account is acceptable.

> ✅ **Check it worked:**
> ```bash
> gcloud run services describe $SERVICE --region $REGION \
>   --format='value(spec.template.spec.containers[0].env)'
> ```
> You should see `REPORT_INTEGRITY_KEY` referencing the secret. Then reload the app and generate/verify a report — signing should succeed.

---

# Part 7 — Lock It Down with Authentication (IAP)

This is the most important step: making sure **no one can open the app without signing in** and being authorised. We use **Identity-Aware Proxy (IAP)**, which puts a Google login in front of the app and only lets through users you approve.

> ✨ **What changed (and why this guide is simpler than older ones):** As of 2025–2026, Google supports enabling **IAP directly on a Cloud Run service** — a single `--iap` flag, **no load balancer required, and no load-balancer cost**. This is now the recommended approach and is what we use below. (The older load-balancer method still exists and is summarised at the end of this part for completeness.)

### 7.1 First-time setup: the OAuth consent screen (Console — once per project)

IAP shows users a Google sign-in / consent screen, which must be configured once. In a personal or student project (one **without** a Google Workspace organisation), the OAuth client **cannot be created from the command line** — so do this first time in the Console:

1. In the Cloud Console, open **APIs & Services → OAuth consent screen** (or **Google Auth Platform → Branding**).
2. Click **Get started**, fill in the **App name** (e.g. "CEGP") and your support email.
3. For **Audience**, choose **External** (this lets you add specific Google accounts as test/allowed users), then **Create**.
4. The simplest path: open **Cloud Run → your `cegp` service → Security tab → Require authentication → select Identity-Aware Proxy (IAP) → Save**. When you enable IAP from the Console the first time, Google **auto-generates the OAuth client for you** and grants IAP permission to invoke the service automatically.

> 💡 **Recommendation:** Enable IAP for the **first time** via the Console (step 4 above) so the OAuth client is auto-created. After that, you can manage everything else — including adding users — from the command line below.

### 7.2 Enable IAP and remove public access (command line)

If you prefer the CLI (after the one-time consent screen exists), enable IAP and stop anonymous access in one update:

```bash
gcloud run services update $SERVICE \
  --region $REGION \
  --no-allow-unauthenticated \
  --iap
```

Then grant the **IAP service agent** permission to invoke your service (so IAP can forward authenticated traffic to it):

```bash
gcloud run services add-iam-policy-binding $SERVICE \
  --region $REGION \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com" \
  --role="roles/run.invoker"
```

> ⚠️ If you see a warning like *"Deploying services with IAP enabled in a project without an organization may require initial setup via the Cloud Console"*, it means the OAuth client does not exist yet — go back and do [Step 7.1](#71-first-time-setup-the-oauth-consent-screen-console--once-per-project) in the Console first, then re-run this command.

> ✅ **Check IAP is on:**
> ```bash
> gcloud run services describe $SERVICE --region $REGION | grep -i "iap"
> ```
> The output should include `Iap Enabled: true`.

### 7.3 Grant access to specific people

By default, **no one** can get in yet — not even you. Grant each authorised user the **IAP-secured Web App User** role (`roles/iap.httpsResourceAccessor`):

```bash
gcloud iap web add-iam-policy-binding \
  --member="user:someone@example.com" \
  --role="roles/iap.httpsResourceAccessor" \
  --region=$REGION \
  --resource-type=cloud-run \
  --service=$SERVICE
```

Repeat for each person (or use `group:team@example.com` for a Google Group). To **see** who currently has access:

```bash
gcloud iap web get-iam-policy \
  --region=$REGION \
  --resource-type=cloud-run \
  --service=$SERVICE
```

To **remove** someone, use the same command with `remove-iam-policy-binding`.

> ✅ **Check it worked** — open the Service URL in a private/incognito browser window. You should be redirected to a **Google sign-in**. Sign in with an **authorised** account → the app loads. Sign in with an **un-authorised** account → access is refused. This is the "nobody gets in without authentication" behaviour described in the project documentation.

### 7.4 Role-based access *inside* the app (future scope)

IAP controls **who can reach** the app. To control **what each person can do** (Viewer / Analyst / Approver / Admin, as described in the project documentation), IAP passes the signed-in user's identity to the app in a request header (`X-Goog-Authenticated-User-Email`). A future version of CEGP can read that header to apply in-app roles without managing its own passwords.

### 7.5 Advanced alternative (load balancer + IAP)

If you ever need a multi-region setup, Cloud Armor (WAF) rules, or central access management across many backends, you can instead front Cloud Run with an **external HTTPS load balancer** and enable IAP on the backend service. This is more complex and incurs an always-on load-balancer cost. It is **not needed** for CEGP. Reference: [Enabling IAP for Cloud Run (load balancer)](https://cloud.google.com/iap/docs/enabling-cloud-run).

---

# Part 8 — Custom Domain & HTTPS

- **Cloud Run URL:** already HTTPS by default — nothing to do.
- **Your own domain (e.g. `cegp.yourcompany.com`):** use Cloud Run **domain mappings**:
  1. In the Console, go to **Cloud Run → Manage custom domains → Add mapping**.
  2. Select the `cegp` service and enter your domain.
  3. Google shows you DNS records (usually a `CNAME`); add them at your domain registrar.
  4. Wait for DNS to propagate — Google then issues and renews a **managed TLS certificate** automatically, so HTTPS just works.

> 📝 Domain mappings availability varies by region. If it is unavailable in your region, either map the domain in a supported region or use the load-balancer approach from [Step 7.5](#75-advanced-alternative-load-balancer--iap), which supports custom domains everywhere.

---

# Part 9 — Continuous Deployment (Optional)

To redeploy automatically whenever you push code to GitHub, so you never run build commands by hand again.

### 9.1 Add a `cloudbuild.yaml`

Create `cloudbuild.yaml` in the project root. It defines build → push → deploy:

```yaml
steps:
  # 1. Build the container image
  - name: gcr.io/cloud-builders/docker
    args:
      - build
      - -t
      - ${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPO}/${_SERVICE}:$COMMIT_SHA
      - .

  # 2. Push the image to Artifact Registry
  - name: gcr.io/cloud-builders/docker
    args:
      - push
      - ${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPO}/${_SERVICE}:$COMMIT_SHA

  # 3. Deploy the new image to Cloud Run
  - name: gcr.io/google.com/cloudsdktool/cloud-sdk
    entrypoint: gcloud
    args:
      - run
      - deploy
      - ${_SERVICE}
      - --image=${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPO}/${_SERVICE}:$COMMIT_SHA
      - --region=${_REGION}
      - --platform=managed

images:
  - ${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPO}/${_SERVICE}:$COMMIT_SHA

substitutions:
  _REGION: asia-south1
  _REPO: cegp-repo
  _SERVICE: cegp

options:
  logging: CLOUD_LOGGING_ONLY
```

> Change the three `substitutions` values if yours differ. `$COMMIT_SHA` tags each image with the exact Git commit, so you always know what is running.

### 9.2 Create the trigger

1. Push the project to a GitHub repository.
2. In the Console, open **Cloud Build → Triggers → Create trigger**.
3. Connect your GitHub repo and choose the branch (e.g. `main`).
4. Set **Configuration** to **Cloud Build configuration file** and point it at `cloudbuild.yaml`.
5. Save.

> ✅ **Check it worked** — push a small change to `main`, then watch **Cloud Build → History**. A build should start automatically and end in `SUCCESS`, after which the new revision is live. IAP and your secret settings **persist** across deploys.

---

# Part 10 — Operate: Logs, Scaling & Updates

- **View logs:**
  ```bash
  gcloud run services logs read $SERVICE --region $REGION --limit 100
  ```
  or open **Cloud Run → cegp → Logs** in the Console.

- **Redeploy after code changes** (manual, if not using CD):
  ```bash
  gcloud builds submit --tag $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest
  gcloud run deploy $SERVICE --image $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest --region $REGION
  ```

- **Roll back** to a previous version if something breaks:
  ```bash
  gcloud run revisions list --service $SERVICE --region $REGION
  gcloud run services update-traffic $SERVICE --region $REGION --to-revisions REVISION_NAME=100
  ```

- **Scaling:** adjust `--min-instances` (responsiveness vs cost) and `--max-instances` (ceiling) on the deploy command.

- **Monitoring & alerts:** use **Cloud Monitoring** to watch request count, latency, and errors, and to set alerts.

---

# Part 11 — Make Data Survive Restarts (Persistence)

> ⚠️ **Read this if CEGP stores anything it must not lose** (audit log, snapshots, history).

Cloud Run instances are **stateless**: the container's local disk is **wiped every time the instance restarts, scales to zero, or scales out to a new copy**. Whether that matters to CEGP depends entirely on **where the app currently writes its data**. So first decide which case you are in, then follow only that case.

### 11.0 First — which case are you in?

Look at how CEGP reads and writes its audit log, snapshots, and any saved history. Search the code for file paths such as `open(...)`, `to_csv(...)`, `to_json(...)`, `Path("data/...")`, or `sqlite3.connect("...db")`.

| What you find in the code | Your case |
|---|---|
| It writes to a **local path** inside the project (e.g. `data/audit.log`, `data/snapshots/`, a local `*.db` SQLite file) | **Case A — Local disk** → follow [11.A](#11a--case-a-the-app-writes-to-local-disk) |
| It already writes to a **managed backend** (Cloud SQL / a `postgresql://` or `mysql://` connection, a Cloud Storage bucket / `gs://` path, or Firestore) | **Case B — Managed backend** → follow [11.B](#11b--case-b-the-app-already-uses-a-database-or-bucket) |

> 💡 Not sure? If the app saves anything that should still be there after a redeploy and you have **not** set up a database or bucket, assume **Case A**.

---

### 11.A — Case A: the app writes to local disk

**Then this data will be lost on every restart**, and you must move it to a managed backend before relying on the cloud deployment. Pick the option that matches the kind of data:

- **Cloud Storage bucket** — best for files: exported reports, PDF/Excel artifacts, and snapshot dumps.
  ```bash
  # Create a bucket (bucket names are globally unique — prefix with your project)
  gcloud storage buckets create gs://${PROJECT_ID}-cegp-data --location=$REGION

  # Let the Cloud Run service account read/write objects in it
  gcloud storage buckets add-iam-policy-binding gs://${PROJECT_ID}-cegp-data \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/storage.objectAdmin"
  ```
  Then either (a) change the app to read/write objects via the `google-cloud-storage` client, or (b) **mount the bucket as a volume** so existing file paths keep working unchanged:
  ```bash
  gcloud run services update $SERVICE --region $REGION \
    --add-volume=name=cegp-data,type=cloud-storage,bucket=${PROJECT_ID}-cegp-data \
    --add-volume-mount=volume=cegp-data,mount-path=/app/data
  ```
  > The volume-mount route (b) is the smallest code change — the app still writes to `data/`, but `data/` now lives in the bucket.

  > 🟢 **Built-in option (no volume mount): the Assessment History archive can write directly to a bucket.** CEGP's history module already supports Cloud Storage natively — it switches on automatically when the `CEGP_GCS_BUCKET` environment variable is set, and otherwise falls back to local disk with no change in behaviour. To enable it:
  > 1. Add `google-cloud-storage` to `requirements.txt` and rebuild the image (Part 4), so the package is in the container.
  > 2. Grant the bucket access (the `add-iam-policy-binding` command above already does this).
  > 3. Point the service at the bucket via environment variables:
  >    ```bash
  >    gcloud run services update $SERVICE --region $REGION \
  >      --set-env-vars CEGP_GCS_BUCKET=${PROJECT_ID}-cegp-data,CEGP_GCS_PREFIX=cegp
  >    ```
  > The **Assessment History** tab then shows *"Currently persisting to: Cloud Storage bucket"*, and every run's archive and registry are stored under `gs://${PROJECT_ID}-cegp-data/cegp/runs/…`, surviving restarts. `CEGP_GCS_PREFIX` is optional (a folder prefix inside the bucket). If the variable is unset or the package/bucket is unavailable, the app silently uses local disk — nothing breaks.

- **Cloud SQL (PostgreSQL/MySQL)** — best for the **structured audit trail** you will want to query and report on. This matches the "database backend" item on the project roadmap. Create an instance, then connect the service:
  ```bash
  gcloud run services update $SERVICE --region $REGION \
    --add-cloudsql-instances=$PROJECT_ID:$REGION:cegp-sql \
    --set-env-vars=DB_CONNECTION="..."   # your app's connection string
  ```

- **Firestore** — a serverless NoSQL option, good for simple document-style records with the least setup; no instance to size or run.

> ✅ **Check it worked** — write a record (e.g. add an audit entry), then force a new revision (`gcloud run deploy ...` again, or set `--min-instances 0` and wait for scale-to-zero). Reload the app: the record should **still be there**.

---

### 11.B — Case B: the app already uses a database or bucket

**Then local-disk loss does not apply** — your data already lives outside the container, so it survives restarts. You only need to confirm the cloud service can **reach** that backend and is **authorised** to use it:

1. **Connectivity & credentials are supplied via the service, not the image.** Pass the connection string / credentials as environment variables or secrets at deploy time, never baked into the container:
   ```bash
   gcloud run services update $SERVICE --region $REGION \
     --set-env-vars=DB_CONNECTION="your-connection-string"
   # or, for a secret value:
   gcloud run services update $SERVICE --region $REGION \
     --update-secrets DB_PASSWORD=cegp-db-password:latest
   ```
2. **Grant the Cloud Run service account the right role** on the backend:
   - Cloud Storage → `roles/storage.objectAdmin` (or `objectViewer` if read-only).
   - Firestore → `roles/datastore.user`.
   - Cloud SQL → `roles/cloudsql.client`, and attach the instance with `--add-cloudsql-instances=$PROJECT_ID:$REGION:INSTANCE`.
3. **If the backend is a private/Cloud SQL instance**, use the built-in connector (the `--add-cloudsql-instances` flag above) rather than exposing a public IP.

> ✅ **Check it worked** — open the app and trigger a read **and** a write against the backend. Both should succeed, and the data should appear directly in the database/bucket (verify in the Console).

> Because your data is already external, you can leave `--min-instances 0` (cheapest) without any risk of losing history.

---

> 📝 **For the current project submission:** demonstrating local/in-memory behaviour is fine to show the app working. This section documents the production-grade path for **both** cases so the work is complete and holds up under questioning.

---

## Cost Considerations

- **Cloud Run** bills per request and per resource-second, and **scales to zero** — when no one is using it, you pay almost nothing. Light, intermittent use typically falls within or near the free tier.
- **Artifact Registry** charges a small amount for stored image size; delete old image versions to keep it minimal.
- **Secret Manager** is effectively free at this scale.
- **IAP (direct on Cloud Run)** adds **no extra cost** and **no load balancer** — this is the main reason to prefer it over the older approach.
- **Cloud Build** has a generous free daily tier; CD builds for a project this size are typically free.
- Set a **budget alert** (**Billing → Budgets & alerts**) so you are notified before any unexpected spend.

---

## Security Checklist

Run through this before treating the deployment as "done":

- [ ] `--allow-unauthenticated` has been removed; `Iap Enabled: true` is confirmed.
- [ ] Only intended users/groups appear in `gcloud iap web get-iam-policy`.
- [ ] The integrity key lives **only** in Secret Manager (not in code, not in the image, not in `.streamlit/secrets.toml`).
- [ ] `.dockerignore` excludes `.git/`, secrets, and the local key file.
- [ ] An incognito test with an **un-authorised** account is correctly **refused**.
- [ ] A budget alert is configured.
- [ ] (Production) A dedicated least-privilege service account is used.
- [ ] (Production) Persistent storage is configured (Part 11) so audit data is not lost.

---

## Tearing Everything Down

To remove the app and stop charges:

```bash
gcloud run services delete $SERVICE --region $REGION
gcloud artifacts repositories delete $REPO --location $REGION
gcloud secrets delete cegp-integrity-key
```

To remove **absolutely everything**, delete the whole project (this is irreversible):

```bash
gcloud projects delete $PROJECT_ID
```

> 📝 If you used the advanced load-balancer approach, also delete the load balancer components and the reserved static IP from the Console, or they keep billing.

---

## Troubleshooting

| Symptom | Likely cause & fix |
|---|---|
| **`gcloud: command not found`** | The CLI is not installed or the terminal was opened before install. Reinstall (Part 0.2) and reopen the terminal. |
| **`PERMISSION_DENIED` on a command** | Your account lacks the IAM role for that action, or the relevant API is not enabled. Re-run Part 2.2 and confirm you are the project owner. |
| **Build fails on a Python package** | A dependency is missing from `requirements.txt`, or it needs a system library. Add the package, or add the library to the `Dockerfile` with `RUN apt-get update && apt-get install -y <lib>`. |
| **Build pulls pandas 3.x and the app errors** | `requirements.txt` lacks upper bounds. Use the pinned versions in Part 1.3 (`pandas>=2.0,<3.0`). |
| **App won't start / "container failed to listen on PORT"** | Streamlit not bound to `0.0.0.0:$PORT`. Confirm the `CMD` flags in the `Dockerfile` exactly match Part 1.1. |
| **Blank page or constant reconnecting** | WebSocket blocked. Ensure `--server.enableCORS=false` and `--server.enableXsrfProtection=false`, and that `--timeout` is high (e.g. 3600). |
| **Slow first load** | Cold start (scaled to zero). Add `--cpu-boost` and/or set `--min-instances 1` to keep one warm. |
| **IAP warning: "project without an organization"** | The OAuth client does not exist yet. Enable IAP **once via the Console** (Part 7.1) so it is auto-created, then use the CLI. |
| **403 after enabling IAP — even for you** | The signed-in user lacks `roles/iap.httpsResourceAccessor`. Grant it (Part 7.3). Also confirm the IAP service agent has `run.invoker` (Part 7.2). |
| **Out-of-org user can't sign in** | The OAuth consent screen audience is set to **Internal**. Change it to **External** under OAuth consent screen / Audience. |
| **Reports fail to sign** | `REPORT_INTEGRITY_KEY` not attached, or the service account lacks `secretAccessor`. Re-run Part 6. |
| **Audit log / snapshots disappear** | Cloud Run is stateless. Move storage to Cloud Storage / Cloud SQL / Firestore (Part 11). |

---

## Quick Command Reference (Cheat Sheet)

```bash
# --- Variables (set once per terminal) ---
export PROJECT_ID="your-project-id"
export REGION="asia-south1"
export SERVICE="cegp"
export REPO="cegp-repo"
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')

# --- One-time project setup ---
gcloud auth login
gcloud config set project $PROJECT_ID
gcloud services enable run.googleapis.com artifactregistry.googleapis.com \
  cloudbuild.googleapis.com secretmanager.googleapis.com iap.googleapis.com compute.googleapis.com
gcloud artifacts repositories create $REPO --repository-format=docker --location=$REGION

# --- Build & deploy ---
gcloud builds submit --tag $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest
gcloud run deploy $SERVICE \
  --image $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest \
  --region $REGION --port 8080 --memory 1Gi --cpu 1 --cpu-boost \
  --min-instances 0 --max-instances 4 --timeout 3600 --allow-unauthenticated

# --- Secret ---
openssl rand -hex 32 | gcloud secrets create cegp-integrity-key --data-file=- --replication-policy=automatic
gcloud secrets add-iam-policy-binding cegp-integrity-key \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
gcloud run services update $SERVICE --region $REGION \
  --update-secrets REPORT_INTEGRITY_KEY=cegp-integrity-key:latest

# --- Lock down with IAP (enable in Console once, then) ---
gcloud run services update $SERVICE --region $REGION --no-allow-unauthenticated --iap
gcloud run services add-iam-policy-binding $SERVICE --region $REGION \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com" \
  --role="roles/run.invoker"
gcloud iap web add-iam-policy-binding \
  --member="user:someone@example.com" --role="roles/iap.httpsResourceAccessor" \
  --region=$REGION --resource-type=cloud-run --service=$SERVICE

# --- Verify ---
gcloud run services describe $SERVICE --region $REGION | grep -i iap
gcloud run services logs read $SERVICE --region $REGION --limit 50
```

---

## References

- Cloud Run — https://cloud.google.com/run/docs
- Deploy a Streamlit service to Cloud Run — https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-streamlit-service
- Deploying container images to Cloud Run — https://cloud.google.com/run/docs/deploying
- Artifact Registry — https://cloud.google.com/artifact-registry/docs
- Cloud Build — https://cloud.google.com/build/docs
- Secret Manager — https://cloud.google.com/secret-manager/docs
- **Configure IAP directly on Cloud Run (recommended)** — https://cloud.google.com/run/docs/securing/identity-aware-proxy-cloud-run
- Enabling IAP for Cloud Run via load balancer (advanced) — https://cloud.google.com/iap/docs/enabling-cloud-run
- Cloud Run custom domains — https://cloud.google.com/run/docs/mapping-custom-domains
- Cloud Run min/max instances & cold starts — https://cloud.google.com/run/docs/configuring/min-instances
- Cloud SQL — https://cloud.google.com/sql/docs · Firestore — https://cloud.google.com/firestore/docs · Cloud Storage — https://cloud.google.com/storage/docs
- Google Cloud SDK install — https://cloud.google.com/sdk/docs/install

---

## Appendix — How This Document Is Wired Into the App

This file is opened from the CEGP UI by the **"Future Scope → Implementation using GCP"** button, exactly like the existing project documentation. Place this file in the project's `docs/` folder (e.g. `docs/gcp_deployment_guide.md`); the button reads and renders it with `st.markdown(...)`. No further wiring is needed — replacing this file updates what the button shows.

---

*Cyber Exposure Governance Platform — an M.Sc. Cyber Security project by Dwaipayan Mojumder and Deblina Das, under the guidance of Prof. Sanjay Pal.*

~~~

---

## `docs/project_documentation.md`  —  place at: `cyber-exposure-governance-platform/docs/project_documentation.md`  ·  _unchanged_

~~~markdown
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

~~~

---

## `docs/project_report_outline.md`  —  place at: `cyber-exposure-governance-platform/docs/project_report_outline.md`  ·  _unchanged_

~~~markdown
# Project Report Outline

## 1. Introduction
Explain cyber exposure management, vulnerability overload, and need for risk-based prioritization.

## 2. Problem Statement
Traditional vulnerability reports contain too many CVEs. Security teams need a business-aligned prioritization method.

## 3. Objectives
- Ingest vulnerability exposure data.
- Enrich CVEs using public threat intelligence.
- Correlate asset, network, IDS/IPS, and privacy context.
- Calculate final cyber exposure score.
- Assign SLA and remediation ownership.
- Generate remediation playbooks and reports.
- Verify report integrity using SHA-256.

## 4. Scope
Included: CSV ingestion, threat enrichment, scoring, dashboards, governance, simulation, audit reporting.
Excluded: live network scanning, agent installation, full SIEM integration, full RBAC.

## 5. System Architecture
Import → Normalize → Enrich → Correlate → Prioritize → Govern → Simulate → Report → Audit.

## 6. Data Sources
- CISA KEV
- FIRST EPSS
- NVD CVE API
- Asset inventory
- IDS/IPS alerts
- Risk exceptions

## 7. Methodology
Explain scoring dimensions:
- Threat intelligence
- Business impact
- Network exposure
- IDS correlation
- Privacy impact
- SLA governance

## 8. Algorithm
Describe scoring weights from `risk_policy.json`.

## 9. Implementation
Explain Python, Streamlit, pandas, services, and core engines.

## 10. Testing
Reference `test_cases.md`.

## 11. Results
Include screenshots of executive dashboard, analyst queue, simulation, and report integrity.

## 12. Syllabus Mapping
Reference `syllabus_mapping.md`.

## 13. Limitations
- Does not perform live scanning.
- IDS/IPS data is CSV-based for demo.
- Some external feeds may be unavailable; fallback data is used.
- Risk scoring is explainable and configurable but not a certified quantitative risk model.

## 14. Future Enhancements
- Nessus/Qualys/OpenVAS API connectors.
- SIEM integration.
- ServiceNow/Jira API ticket creation.
- Database backend.
- SSO/RBAC.
- Docker/Kubernetes deployment.
- ML-assisted remediation prediction.

## 15. Conclusion
The project demonstrates a practical cyber exposure governance workflow that can help organizations prioritize remediation based on risk, not just severity.

~~~

---

## `docs/syllabus_mapping.md`  —  place at: `cyber-exposure-governance-platform/docs/syllabus_mapping.md`  ·  _unchanged_

~~~markdown
# Mapping to M.Sc. Cybersecurity Curriculum

| Subject / Chapter Area | How the Project Covers It |
|---|---|
| Information Security Risk Management | Risk score, remediation SLA, risk acceptance, governance dashboard |
| Network Security | Network zones, internet exposure, firewall status, VPN requirement, risky ports |
| Firewalls and VPNs | Firewall allowed/restricted logic and VPN-required exposure logic |
| IDS/IPS | IDS alert correlation, exploit-attempt escalation, alert severity logic |
| Data Privacy | PII, sensitive data type, encryption status, regulatory impact scoring |
| Cryptography | SHA-256 report integrity and verification |
| Computer Networks | IP context, open ports, network zones, exposed services |
| Operating Systems | OS/product CVE exposure and patch remediation context |
| Linux Security | Server vulnerability and patch/hardening context; can be extended to Linux audit scripts |
| Algorithms | Weighted scoring, normalization, prioritization, classification, sorting |
| Pattern Recognition / ML Concepts | Rule-based classification and simulation; future scope can add Decision Tree/Naive Bayes |
| Python Programming Lab | Modular Python implementation using Streamlit, pandas, requests, Plotly |
| Wireless/Mobile Security | Asset type supports wireless/mobile/network devices as exposure categories |
| Biometric Security | Not forced into scope; intentionally excluded because it is not a natural fit |

~~~

---

## `docs/test_cases.md`  —  place at: `cyber-exposure-governance-platform/docs/test_cases.md`  ·  _unchanged_

~~~markdown
# Test Cases

| Test No. | Test Scenario | Expected Result |
|---:|---|---|
| 1 | Run with bundled sample files | Assessment completes successfully |
| 2 | Missing `cve_id` column | Validation error is shown |
| 3 | Invalid CVE format | Warning is shown |
| 4 | Internet-facing asset with risky ports | Network exposure score increases |
| 5 | Asset with IDS exploit alert | IDS correlation score increases |
| 6 | PII + high data sensitivity | Privacy impact increases |
| 7 | KEV + internet + IDS alert | Priority becomes Critical or High |
| 8 | Old first detected date | SLA breach or due-soon status appears |
| 9 | Risk exception CSV provided | Exception fields are merged |
| 10 | What-if simulation | Before/after risk reduction appears |
| 11 | Detailed report export | CSV downloads successfully |
| 12 | Ticket export | Jira/ServiceNow-style CSV downloads |
| 13 | SHA-256 hash generation | Hash appears for each report |
| 14 | Hash verification with correct file | Verified status appears |
| 15 | Hash verification with modified file | Tampered/mismatch warning appears |

~~~

---

## `docs/ui_preview.html`  —  place at: `cyber-exposure-governance-platform/docs/ui_preview.html`  ·  _unchanged_

~~~html
<!DOCTYPE html><html><head><meta charset="utf-8"><title>UI Preview - HPE accent</title>
<style>
body{font-family:'Segoe UI',Roboto,sans-serif;background:#fff;color:#1F2937;margin:0;padding:22px;max-width:1180px}
.header{background:linear-gradient(115deg,#1D1F27 0%,#23262F 52%,#015E48 88%,#01A982 122%);border-radius:14px;padding:20px 26px;color:#fff;box-shadow:0 6px 18px rgba(1,169,130,.20)}
.hrow{display:flex;align-items:center;gap:16px} .logo{font-size:2.1rem;display:flex;align-items:center}.auth{font-size:.82rem;color:#EAF6F1;font-weight:600;margin-top:3px}.chip{cursor:help} .title{font-size:1.5rem;font-weight:800} .tag{font-size:.9rem;opacity:.92;margin-top:2px}
.badge{margin-left:auto;background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.4);padding:4px 12px;border-radius:999px;font-size:.78rem;font-weight:700}
.chips{margin-top:12px;display:flex;flex-wrap:wrap;gap:8px}
.chip{background:rgba(255,255,255,.13);border:1px solid rgba(255,255,255,.3);padding:3px 11px;border-radius:999px;font-size:.74rem;font-weight:600}
.section{padding:7px 0 7px 12px;margin:18px 0 10px;font-size:1.05rem;font-weight:700;color:#1D1F27;background:#F4F8F6;border-radius:0 8px 8px 0;border-left:4px solid #1D1F27}
.sgreen{border-left-color:#01A982;color:#017A5E}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.kpi{background:#fff;border:1px solid #E3E8EF;border-radius:12px;padding:13px 16px;box-shadow:0 1px 3px rgba(20,49,92,.06)}
.kl{font-size:.70rem;letter-spacing:.05em;text-transform:uppercase;color:#5B6675;font-weight:700} .kv{font-size:1.85rem;font-weight:800;margin-top:6px}
table{border-collapse:collapse;width:100%;border:1px solid #E3E8EF;border-radius:10px;overflow:hidden;font-size:.86rem}
th{background:#E6F6F1;color:#015E48;text-align:left;padding:9px 12px;font-size:.74rem;text-transform:uppercase;letter-spacing:.03em}
td{padding:8px 12px;border-top:1px solid #EDF1F6} tr:nth-child(even) td{background:#FBFCFE}
.btn{display:inline-block;background:#01A982;color:#fff;font-weight:600;padding:7px 16px;border-radius:8px;font-size:.85rem;margin-top:12px}
.note{font-size:.78rem;color:#8A94A6;margin-top:10px}
</style></head><body>
<div class="header"><div class="hrow"><span class="logo"><svg width="46" height="46" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"><path d="M32 3 L56 12 V30 C56 46 46 56 32 61 C18 56 8 46 8 30 V12 Z" fill="#01A982" stroke="#fff" stroke-width="2.5" stroke-linejoin="round"/><rect x="22" y="29" width="20" height="16" rx="2.5" fill="#15315C" stroke="#fff" stroke-width="2"/><path d="M26 29 V24 a6 6 0 0 1 12 0 V29" fill="none" stroke="#fff" stroke-width="2.5"/><circle cx="32" cy="36" r="2.4" fill="#fff"/><rect x="31" y="37" width="2" height="5" rx="1" fill="#fff"/></svg></span>
<div><div class="title">Cyber Exposure Governance Platform</div>
<div class="auth">Dwaipayan Mojumder &middot; Deblina Das &nbsp;|&nbsp; M.Sc. Cyber Security (4th Sem) &nbsp;|&nbsp; Under the guidance of Prof. Sanjay Pal</div><div class="tag">Risk-based vulnerability prioritization &middot; remediation governance &middot; audit-ready evidence</div></div>
<span class="badge">v1</span></div>
</div>
<div class="section">Cyber Exposure Posture</div>
<div class="kpis"><div class="kpi" style="border-top:4px solid #01A982"><div class="kl">Total Exposures</div><div class="kv" style="color:#017A5E">8</div></div><div class="kpi" style="border-top:4px solid #B23A3A"><div class="kl">Critical</div><div class="kv" style="color:#B23A3A">3</div></div><div class="kpi" style="border-top:4px solid #C9A227"><div class="kl">CISA KEV</div><div class="kv" style="color:#8A6D0E">5</div></div><div class="kpi" style="border-top:4px solid #01A982"><div class="kl">Avg Risk Score</div><div class="kv" style="color:#017A5E">71.24</div></div></div>
<div class="section sgreen">Top Business-Critical Exposures</div>
<table><thead><tr><th>Asset</th><th>Business Process</th><th>CVE</th><th>Priority</th><th>Score</th><th>KEV</th><th>IDS</th><th>SLA</th></tr></thead><tbody><tr><td>Customer Portal Server</td><td>Online Sales</td><td>CVE-2021-44228</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Critical</span></td><td style='text-align:right'>100.0</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Yes</span></td><td>2</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Breached</span></td></tr><tr><td>VPN Gateway</td><td>Remote Connectivity</td><td>CVE-2023-27997</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Critical</span></td><td style='text-align:right'>100.0</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Yes</span></td><td>1</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Breached</span></td></tr><tr><td>Mail Server</td><td>Corporate Email</td><td>CVE-2021-26855</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Critical</span></td><td style='text-align:right'>97.9</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Yes</span></td><td>1</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Breached</span></td></tr><tr><td>File Transfer Server</td><td>Partner File Exchange</td><td>CVE-2024-6387</td><td><span style="background:#F6ECC9;color:#7A5E10;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">High</span></td><td style='text-align:right'>83.4</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Yes</span></td><td>1</td><td><span style="background:#D6EAE0;color:#1C5740;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Within SLA</span></td></tr><tr><td>Customer API Gateway</td><td>Customer API Services</td><td>CVE-2021-23017</td><td><span style="background:#DCE6F6;color:#163A6B;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Medium</span></td><td style='text-align:right'>62.8</td><td><span style="background:#EEF1F5;color:#5B6675;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">No</span></td><td>1</td><td><span style="background:#D6EAE0;color:#1C5740;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Within SLA</span></td></tr><tr><td>Internal Wiki</td><td>Knowledge Management</td><td>CVE-2022-26134</td><td><span style="background:#DCE6F6;color:#163A6B;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Medium</span></td><td style='text-align:right'>52.3</td><td><span style="background:#F4D7D7;color:#8E2A2A;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Yes</span></td><td>0</td><td><span style="background:#D6EAE0;color:#1C5740;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Within SLA</span></td></tr><tr><td>Finance Database</td><td>Financial Reporting</td><td>CVE-2022-1552</td><td><span style="background:#DCE6F6;color:#163A6B;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Medium</span></td><td style='text-align:right'>47.1</td><td><span style="background:#EEF1F5;color:#5B6675;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">No</span></td><td>0</td><td><span style="background:#D6EAE0;color:#1C5740;font-weight:600;padding:2px 9px;border-radius:6px;font-size:.8rem">Within SLA</span></td></tr></tbody></table>
<span class="btn">Run Cyber Exposure Assessment</span>
<div class="section sgreen">Executive dashboard — the running app adds a Prioritisation Matrix (EPSS×CVSS), priority donut, KEV split, EPSS distribution, risk-by-environment, top assets, and per-tab charts</div><div style="background:#F4F8F6;border:1px solid #CDE8DF;border-left:4px solid #01A982;border-radius:8px;padding:10px 14px;font-size:.85rem;color:#15315C;margin-bottom:8px"><b>Exposure Score</b> &mdash; weighted 0–100 score combining threat intel (35), network (20), business (15), IDS (15), privacy (10), SLA (5).</div><div class="note">Static preview of the real app theme &mdash; HPE green accent + charcoal on the existing layout (rendered from app.py CSS + live sample-data assessment). Priority/SLA colour-coding is kept functional (Critical red, High amber, Medium blue, Low/OK green). No HPE logo or wordmark used.</div>
</body></html>
~~~

---

## `docs/windows_c_drive_setup.md`  —  place at: `cyber-exposure-governance-platform/docs/windows_c_drive_setup.md`  ·  _unchanged_

~~~markdown
# Windows C Drive Setup

## Recommended Path

```powershell
C:\cyber-exposure-governance-platform-product
```

## Fastest Method

1. Extract the ZIP directly to `C:\`.
2. Confirm this folder exists:

```powershell
C:\cyber-exposure-governance-platform-product
```

3. Double-click:

```text
run_app_windows.bat
```

## Manual Method

```powershell
cd C:\cyber-exposure-governance-platform-product
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Open App

```text
http://localhost:8501
```

~~~

---
