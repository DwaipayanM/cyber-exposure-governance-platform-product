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


def render_header() -> None:
    st.markdown(
        f"""
        <div class="cegp-header">
          <div class="cegp-header-row">
            <span class="cegp-logo">{CYBER_LOGO_SVG}</span>
            <div>
              <div class="cegp-title">Cyber Exposure Governance Platform</div>
              <div class="cegp-authors">Dwaipayan Mojumder &middot; Deblina Das &nbsp;|&nbsp; M.Sc. Cyber Security (4th Sem) &nbsp;|&nbsp; Under the guidance of Prof. Sanjay Pal</div>
              <div class="cegp-tag">Risk-based vulnerability prioritization &middot; remediation governance &middot; audit-ready evidence</div>
            </div>
            <span class="cegp-badge">v1</span>
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
        choice = st.selectbox(
            "View a concept", ["\u2014 select \u2014"] + DIAGRAM_CONCEPTS,
            index=0, key="concept_pick", label_visibility="collapsed",
        )
        if choice and choice != "\u2014 select \u2014":
            st.markdown(
                f'<div class="cegp-conceptcard"><b>{choice}</b> &mdash; {CONCEPTS[choice]}</div>',
                unsafe_allow_html=True,
            )
            st.markdown(_diagram_svg(choice), unsafe_allow_html=True)
        else:
            for k, v in CONCEPTS.items():
                st.markdown(f"**{k}** \u2014 {v.split(' \u2014 ', 1)[-1]}")


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
        "Privacy Impact", "Remediation Governance", "Simulation", "Reports & Integrity", "Audit Log",
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
    cols = ["asset_name", "business_process", "cve_id", "priority", "final_score", "kev_status",
            "ids_alert_count", "privacy_impact_level", "sla_status", "primary_action"]
    render_table(df[cols].head(10))

with tabs[1]:
    section("Security Analyst Exposure Queue", NAVY)
    analyst_cols = [
        "asset_id", "asset_name", "application_name", "cve_id", "severity", "cvss_score",
        "epss_score", "epss_percentile", "kev_status", "network_exposure_level",
        "ids_alert_count", "privacy_impact_level", "final_score", "priority",
        "score_drivers", "primary_action", "temporary_mitigation", "control_area",
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
        cols = ["asset_name", "cve_id", "kev_status", "ids_alert_count", "highest_alert_severity",
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

with tabs[7]:
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

with tabs[8]:
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
