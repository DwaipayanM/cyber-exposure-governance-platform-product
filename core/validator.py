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
