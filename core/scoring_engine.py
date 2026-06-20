"""Final cyber exposure scoring engine."""
from __future__ import annotations

import pandas as pd

from core.policy_engine import classify_priority, get_weight


def _norm(raw: float, raw_max: float, target_max: float) -> float:
    raw = float(raw or 0)
    if raw_max <= 0:
        return 0.0
    return min((raw / raw_max) * target_max, target_max)


def calculate_threat_intelligence_score(df: pd.DataFrame, policy: dict) -> pd.DataFrame:
    df = df.copy()
    target = get_weight(policy, "threat_intelligence")

    def compute(row):
        raw = 0
        reasons = []
        kev = str(row.get("kev_status", "")).lower()
        epss_percentile = float(row.get("epss_percentile", 0) or 0)
        severity = str(row.get("severity", "")).lower()
        cvss = float(row.get("cvss_score", 0) or 0)

        if kev == "yes":
            raw += 40
            reasons.append("CISA KEV known exploited")
        if epss_percentile >= 0.95:
            raw += 25
            reasons.append("very high EPSS percentile")
        elif epss_percentile >= 0.80:
            raw += 18
            reasons.append("high EPSS percentile")
        elif epss_percentile >= 0.50:
            raw += 10
            reasons.append("medium EPSS percentile")
        else:
            raw += 3

        if severity == "critical" or cvss >= 9:
            raw += 15
            reasons.append("critical CVSS severity")
        elif severity == "high" or cvss >= 7:
            raw += 10
            reasons.append("high CVSS severity")
        elif severity == "medium" or cvss >= 4:
            raw += 5
            reasons.append("medium CVSS severity")
        elif cvss > 0:
            raw += 2

        return _norm(raw, 80, target), "; ".join(reasons)

    values = df.apply(compute, axis=1, result_type="expand")
    df["threat_intelligence_score"] = values[0].astype(float).round(2)
    df["threat_intelligence_reason"] = values[1]
    return df


def calculate_final_score(df: pd.DataFrame, policy: dict, include_sla_score: bool = False) -> pd.DataFrame:
    df = df.copy()

    if "threat_intelligence_score" not in df.columns:
        df = calculate_threat_intelligence_score(df, policy)

    network_target = get_weight(policy, "network_exposure")
    ids_target = get_weight(policy, "ids_correlation")
    privacy_target = get_weight(policy, "privacy_impact")

    df["network_exposure_score"] = df.get("network_exposure_score_raw", 0).apply(lambda x: _norm(x, 30, network_target))
    df["ids_correlation_score"] = df.get("ids_correlation_score_raw", 0).apply(lambda x: _norm(x, 35, ids_target))
    df["privacy_impact_score"] = df.get("privacy_impact_score_raw", 0).apply(lambda x: _norm(x, 30, privacy_target))

    for col in ["business_impact_score", "threat_intelligence_score", "network_exposure_score", "ids_correlation_score", "privacy_impact_score"]:
        if col not in df.columns:
            df[col] = 0.0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    if include_sla_score:
        sla_target = get_weight(policy, "sla_governance")
        df["sla_governance_score"] = df.get("sla_status", "").apply(lambda s: sla_target if str(s).lower() == "breached" else 0)
    else:
        df["sla_governance_score"] = 0.0

    df["final_score"] = (
        df["threat_intelligence_score"]
        + df["business_impact_score"]
        + df["network_exposure_score"]
        + df["ids_correlation_score"]
        + df["privacy_impact_score"]
        + df["sla_governance_score"]
    ).clip(0, 100).round(2)

    df["priority"] = df["final_score"].apply(lambda x: classify_priority(x, policy))
    return df


def summarize_score_drivers(row: pd.Series) -> str:
    drivers = []
    for label, col in [
        ("Threat intelligence", "threat_intelligence_score"),
        ("Business impact", "business_impact_score"),
        ("Network exposure", "network_exposure_score"),
        ("IDS correlation", "ids_correlation_score"),
        ("Privacy impact", "privacy_impact_score"),
        ("SLA governance", "sla_governance_score"),
    ]:
        try:
            value = float(row.get(col, 0) or 0)
        except Exception:
            value = 0
        if value > 0:
            drivers.append(f"{label}: {value:.1f}")
    return " | ".join(drivers)
