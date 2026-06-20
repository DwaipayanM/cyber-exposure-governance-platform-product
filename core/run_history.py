"""Per-run assessment history.

Each completed assessment is archived so the UI can reopen a past run in full
detail, regenerate its Action Plan / reports, and prove which input data
produced it (via input fingerprints).

Storage goes through a pluggable backend (``core.storage_backend``): the local
filesystem by default, or Google Cloud Storage when ``CEGP_GCS_BUCKET`` is set
(see the GCP guide, Part 11). Local behaviour is unchanged; cloud persistence is
purely opt-in and falls back to local automatically if anything is unavailable.
"""
from __future__ import annotations

import hashlib
import io
from datetime import datetime
from pathlib import Path

import pandas as pd

from core.storage_backend import get_backend, active_backend_name

REGISTRY_COLUMNS = [
    "run_id", "timestamp", "operator",
    "total_exposures", "critical", "high", "medium", "low",
    "kev_count", "sla_breached", "average_score",
    "vuln_rows", "asset_rows", "ids_rows",
    "vuln_fingerprint", "asset_fingerprint", "ids_fingerprint",
    "data_file", "notes",
]

_REGISTRY_KEY = "runs/runs_index.csv"


def _run_key(data_file: str) -> str:
    return f"runs/{data_file}"


def runs_dir(data_dir: str | Path = "data") -> Path:
    """Local runs directory (created on demand). Informational for local mode."""
    p = Path(data_dir) / "runs"
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return p


def storage_mode(data_dir: str | Path = "data") -> str:
    """Return 'gcs' or 'local' so the UI can show where history is persisted."""
    return active_backend_name(data_dir)


def _short_hash(text: str, n: int = 12) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def fingerprint_df(df: pd.DataFrame | None) -> str:
    """Stable short fingerprint of a dataframe's content (proves which data was used)."""
    if df is None:
        return ""
    try:
        return _short_hash(df.to_csv(index=False))
    except Exception:
        return ""


def list_runs(data_dir: str | Path = "data") -> pd.DataFrame:
    """Return the run registry, newest first (empty frame if none)."""
    be = get_backend(data_dir)
    text = be.read_text(_REGISTRY_KEY)
    if not text:
        return pd.DataFrame(columns=REGISTRY_COLUMNS)
    try:
        df = pd.read_csv(io.StringIO(text), dtype=str).fillna("")
        for c in REGISTRY_COLUMNS:
            if c not in df.columns:
                df[c] = ""
        return df[REGISTRY_COLUMNS].sort_values("run_id", ascending=False).reset_index(drop=True)
    except Exception:
        return pd.DataFrame(columns=REGISTRY_COLUMNS)


def save_run(result_df: pd.DataFrame, *, operator: str = "system",
             data_dir: str | Path = "data", inputs: dict | None = None,
             notes: str = "") -> str:
    """Archive a full assessment result and append a registry row. Returns the run_id."""
    inputs = inputs or {}
    be = get_backend(data_dir)
    now = datetime.now()
    run_id = f"{now:%Y%m%d-%H%M%S}-{now.microsecond // 1000:03d}"
    data_file = f"run_{run_id}.csv"

    # Persist the full result frame (all columns) so the run can be reopened exactly.
    be.write_text(_run_key(data_file), result_df.to_csv(index=False))

    def _cnt(col: str, value: str) -> int:
        try:
            return int((result_df[col].astype(str) == value).sum())
        except Exception:
            return 0

    avg = 0.0
    if "final_score" in result_df.columns and len(result_df):
        try:
            avg = round(float(pd.to_numeric(result_df["final_score"], errors="coerce").mean()), 2)
        except Exception:
            avg = 0.0

    row = {
        "run_id": run_id,
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "operator": operator or "system",
        "total_exposures": len(result_df),
        "critical": _cnt("priority", "Critical"),
        "high": _cnt("priority", "High"),
        "medium": _cnt("priority", "Medium"),
        "low": _cnt("priority", "Low"),
        "kev_count": _cnt("kev_status", "Yes"),
        "sla_breached": _cnt("sla_status", "Breached"),
        "average_score": avg,
        "vuln_rows": inputs.get("vuln_rows", ""),
        "asset_rows": inputs.get("asset_rows", ""),
        "ids_rows": inputs.get("ids_rows", ""),
        "vuln_fingerprint": inputs.get("vuln_fingerprint", ""),
        "asset_fingerprint": inputs.get("asset_fingerprint", ""),
        "ids_fingerprint": inputs.get("ids_fingerprint", ""),
        "data_file": data_file,
        "notes": notes,
    }

    # Read-modify-write the registry (works identically on local and GCS backends).
    existing = list_runs(data_dir)
    new_row = pd.DataFrame([row], columns=REGISTRY_COLUMNS)
    registry = new_row if existing.empty else pd.concat([existing, new_row], ignore_index=True)
    be.write_text(_REGISTRY_KEY, registry[REGISTRY_COLUMNS].to_csv(index=False))
    return run_id


def load_run(run_id: str, data_dir: str | Path = "data") -> pd.DataFrame | None:
    """Reload a previously archived run's full result frame (or None if missing)."""
    be = get_backend(data_dir)
    data_file = f"run_{run_id}.csv"
    runs = list_runs(data_dir)
    if not runs.empty:
        match = runs[runs["run_id"].astype(str) == str(run_id)]
        if not match.empty and str(match.iloc[0].get("data_file", "")).strip():
            data_file = str(match.iloc[0]["data_file"])
    text = be.read_text(_run_key(data_file))
    if text is None:
        return None
    try:
        return pd.read_csv(io.StringIO(text))
    except Exception:
        return None


def delete_run(run_id: str, data_dir: str | Path = "data") -> bool:
    """Remove a run's archived data file and its registry row."""
    be = get_backend(data_dir)
    runs = list_runs(data_dir)
    if runs.empty:
        return False
    match = runs[runs["run_id"].astype(str) == str(run_id)]
    if not match.empty:
        be.delete(_run_key(str(match.iloc[0].get("data_file", f"run_{run_id}.csv"))))
    remaining = runs[runs["run_id"].astype(str) != str(run_id)]
    try:
        be.write_text(_REGISTRY_KEY, remaining[REGISTRY_COLUMNS].to_csv(index=False))
    except Exception:
        return False
    return True
