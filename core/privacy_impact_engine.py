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
