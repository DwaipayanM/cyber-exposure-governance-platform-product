"""Risk trend snapshot engine."""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

import pandas as pd


def save_risk_snapshot(df: pd.DataFrame, path: str = "data/risk_snapshots.csv") -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    exists = p.exists()

    counts = df.get("priority", pd.Series(dtype=str)).value_counts().to_dict()
    row = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_exposures": len(df),
        "critical_count": int(counts.get("Critical", 0)),
        "high_count": int(counts.get("High", 0)),
        "medium_count": int(counts.get("Medium", 0)),
        "low_count": int(counts.get("Low", 0)),
        "average_score": round(float(df.get("final_score", pd.Series([0])).mean()), 2) if len(df) else 0,
        "kev_count": int((df.get("kev_status", pd.Series(dtype=str)) == "Yes").sum()),
        "ids_correlated_count": int((df.get("ids_alert_count", pd.Series(dtype=int)).fillna(0).astype(int) > 0).sum()) if "ids_alert_count" in df else 0,
        "sla_breached_count": int((df.get("sla_status", pd.Series(dtype=str)) == "Breached").sum()),
    }

    with p.open("a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not exists or p.stat().st_size == 0:
            writer.writeheader()
        writer.writerow(row)


def read_risk_snapshots(path: str = "data/risk_snapshots.csv") -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        return pd.DataFrame()
    return pd.read_csv(p)
