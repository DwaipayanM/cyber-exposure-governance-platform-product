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
