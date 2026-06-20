"""What-if risk reduction simulation engine."""
from __future__ import annotations

import pandas as pd

from core.policy_engine import classify_priority


def _metrics(df: pd.DataFrame, score_col: str = "final_score") -> dict:
    if df.empty:
        return {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Average Score": 0.0, "Total Risk": 0.0}
    counts = df["priority"].value_counts().to_dict() if "priority" in df else {}
    return {
        "Critical": int(counts.get("Critical", 0)),
        "High": int(counts.get("High", 0)),
        "Medium": int(counts.get("Medium", 0)),
        "Low": int(counts.get("Low", 0)),
        "Average Score": round(float(df[score_col].mean()), 2),
        "Total Risk": round(float(df[score_col].sum()), 2),
    }


def run_simulation(df: pd.DataFrame, scenario: str, policy: dict) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return summary dataframe and simulated dataframe."""
    before_df = df.copy()
    after_df = df.copy()
    after_df["simulated_score"] = after_df["final_score"].astype(float)

    if scenario == "Patch Top 5 Highest-Risk Exposures":
        idx = after_df.sort_values("final_score", ascending=False).head(5).index
        after_df.loc[idx, "simulated_score"] = (after_df.loc[idx, "simulated_score"] * 0.15).round(2)
    elif scenario == "Patch All CISA KEV Exposures":
        mask = after_df["kev_status"].eq("Yes")
        after_df.loc[mask, "simulated_score"] = (after_df.loc[mask, "simulated_score"] - after_df.loc[mask, "threat_intelligence_score"] * 0.75).clip(lower=0).round(2)
    elif scenario == "Isolate Internet-Facing Critical Assets":
        mask = (after_df["internet_facing"].eq("Yes") | after_df["network_zone"].str.lower().eq("internet")) & after_df["priority"].isin(["Critical", "High"])
        after_df.loc[mask, "simulated_score"] = (after_df.loc[mask, "simulated_score"] - after_df.loc[mask, "network_exposure_score"] * 0.8).clip(lower=0).round(2)
    elif scenario == "Fix IDS-Correlated Exposures":
        mask = after_df["ids_alert_count"].fillna(0).astype(int) > 0
        after_df.loc[mask, "simulated_score"] = (after_df.loc[mask, "simulated_score"] - after_df.loc[mask, "ids_correlation_score"]).clip(lower=0).round(2)
    elif scenario == "Encrypt Sensitive Unencrypted/Unknown Assets":
        mask = after_df["encryption_status"].str.lower().isin(["unknown", "not encrypted"]) & after_df["privacy_impact_level"].isin(["Critical", "High", "Medium"])
        after_df.loc[mask, "simulated_score"] = (after_df.loc[mask, "simulated_score"] - after_df.loc[mask, "privacy_impact_score"] * 0.8).clip(lower=0).round(2)

    after_df["priority"] = after_df["simulated_score"].apply(lambda x: classify_priority(x, policy))
    before = _metrics(before_df, "final_score")
    after = _metrics(after_df, "simulated_score")

    rows = []
    for metric in ["Critical", "High", "Medium", "Low", "Average Score", "Total Risk"]:
        b = before[metric]
        a = after[metric]
        if isinstance(b, (int, float)) and b:
            improvement = round(((b - a) / b) * 100, 2)
        else:
            improvement = 0.0
        rows.append({"Metric": metric, "Before": b, "After": a, "Improvement %": improvement})

    return pd.DataFrame(rows), after_df
