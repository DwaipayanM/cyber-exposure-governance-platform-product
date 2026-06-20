"""IDS/IPS alert correlation engine."""
from __future__ import annotations

import pandas as pd


def correlate_ids_alerts(exposure_df: pd.DataFrame, ids_df: pd.DataFrame | None) -> pd.DataFrame:
    df = exposure_df.copy()

    if ids_df is None or ids_df.empty:
        df["ids_alert_count"] = 0
        df["highest_alert_severity"] = "None"
        df["exploit_attempt_detected"] = "No"
        df["ids_correlation_score_raw"] = 0.0
        df["ids_correlation_reason"] = "No IDS/IPS alerts provided"
        return df

    alerts = ids_df.copy()
    alerts.columns = [c.strip().lower() for c in alerts.columns]

    def severity_rank(value: str) -> int:
        value = str(value).lower()
        if value == "critical":
            return 4
        if value == "high":
            return 3
        if value == "medium":
            return 2
        if value == "low":
            return 1
        return 0

    alerts["sev_rank"] = alerts["alert_severity"].apply(severity_rank)
    alerts["is_exploit"] = alerts["alert_type"].str.lower().str.contains("exploit", na=False)
    alerts["high_confidence"] = alerts["confidence"].str.lower().eq("high")

    grouped = alerts.groupby("asset_id").agg(
        ids_alert_count=("alert_id", "count"),
        max_sev_rank=("sev_rank", "max"),
        exploit_attempt_detected_bool=("is_exploit", "max"),
        high_confidence_count=("high_confidence", "sum"),
        signatures=("signature_name", lambda x: "; ".join(sorted(set([str(v) for v in x if str(v).strip()]))[:5])),
    ).reset_index()

    rank_to_sev = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "None"}
    grouped["highest_alert_severity"] = grouped["max_sev_rank"].map(rank_to_sev).fillna("None")
    grouped["exploit_attempt_detected"] = grouped["exploit_attempt_detected_bool"].map({True: "Yes", False: "No"})

    def score(row):
        points = 0
        reasons = []
        alert_count = int(row.get("ids_alert_count", 0))
        max_rank = int(row.get("max_sev_rank", 0))
        exploit = bool(row.get("exploit_attempt_detected_bool", False))
        high_conf = int(row.get("high_confidence_count", 0))

        if alert_count > 0:
            points += 5
            reasons.append(f"{alert_count} IDS/IPS alert(s)")
        if max_rank >= 3:
            points += 15
            reasons.append("high/critical alert severity")
        elif max_rank == 2:
            points += 8
            reasons.append("medium alert severity")
        if exploit:
            points += 20
            reasons.append("exploit attempt detected")
        if high_conf > 0:
            points += 10
            reasons.append("high-confidence alert")
        if alert_count > 3:
            points += 10
            reasons.append("multiple alerts on same asset")

        return min(points, 35), "; ".join(reasons)

    values = grouped.apply(score, axis=1, result_type="expand")
    grouped["ids_correlation_score_raw"] = values[0].astype(float)
    grouped["ids_correlation_reason"] = values[1]

    merged = df.merge(
        grouped[
            [
                "asset_id",
                "ids_alert_count",
                "highest_alert_severity",
                "exploit_attempt_detected",
                "ids_correlation_score_raw",
                "ids_correlation_reason",
                "signatures",
            ]
        ],
        on="asset_id",
        how="left",
    )

    merged["ids_alert_count"] = merged["ids_alert_count"].fillna(0).astype(int)
    merged["highest_alert_severity"] = merged["highest_alert_severity"].fillna("None")
    merged["exploit_attempt_detected"] = merged["exploit_attempt_detected"].fillna("No")
    merged["ids_correlation_score_raw"] = merged["ids_correlation_score_raw"].fillna(0.0)
    merged["ids_correlation_reason"] = merged["ids_correlation_reason"].fillna("No IDS/IPS alerts correlated")
    merged["signatures"] = merged["signatures"].fillna("")
    return merged
