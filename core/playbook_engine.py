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
