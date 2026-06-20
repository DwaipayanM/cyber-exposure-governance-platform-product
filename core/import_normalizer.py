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
