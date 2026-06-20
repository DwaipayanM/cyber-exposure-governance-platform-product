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
