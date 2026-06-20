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
