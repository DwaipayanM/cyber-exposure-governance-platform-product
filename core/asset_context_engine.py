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
