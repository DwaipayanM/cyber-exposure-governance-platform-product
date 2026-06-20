"""Simple CSV audit logger with operator attribution.

Every logged action records who performed it (operator) and when, so the audit
trail can answer "who accepted this risk / ran this assessment", not just that
something happened. The operator is captured in the UI session and passed in on
each call; it defaults to "system" for automated events.
"""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

FIELDNAMES = ["timestamp", "operator", "action", "asset_id", "cve_id", "details"]


def log_event(
    action: str,
    asset_id: str = "",
    cve_id: str = "",
    details: str = "",
    operator: str = "system",
    log_path: str = "data/audit_log.csv",
) -> None:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists()
    operator = (str(operator).strip() or "system")
    with path.open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not exists or path.stat().st_size == 0:
            writer.writerow(FIELDNAMES)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            operator,
            action,
            asset_id,
            cve_id,
            details,
        ])


def read_audit_log(log_path: str = "data/audit_log.csv"):
    import pandas as pd
    path = Path(log_path)
    if not path.exists():
        return pd.DataFrame(columns=FIELDNAMES)
    df = pd.read_csv(path)
    # Backward-compatibility: older logs may not have an operator column.
    if "operator" not in df.columns:
        df["operator"] = "system"
        df = df[[c for c in FIELDNAMES if c in df.columns]]
    return df
