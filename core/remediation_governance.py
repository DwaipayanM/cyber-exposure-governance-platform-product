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
