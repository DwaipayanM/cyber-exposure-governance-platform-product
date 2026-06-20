"""FIRST EPSS enrichment service."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import pandas as pd
import requests

EPSS_URL = "https://api.first.org/data/v1/epss"


def _load_fallback(path: str = "data/fallback_epss.json") -> dict:
    try:
        with Path(path).open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _fetch_live_epss(cves: list[str]) -> dict:
    if not cves:
        return {}
    # FIRST supports comma-separated CVEs. Keep chunks moderate for demo stability.
    out = {}
    for i in range(0, len(cves), 50):
        chunk = cves[i:i+50]
        try:
            response = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=15)
            response.raise_for_status()
            payload = response.json()
            for item in payload.get("data", []):
                out[str(item.get("cve", "")).upper()] = {
                    "epss": float(item.get("epss", 0) or 0),
                    "percentile": float(item.get("percentile", 0) or 0),
                }
        except Exception:
            continue
    return out


def enrich_with_epss(df: pd.DataFrame, use_live: bool = True) -> pd.DataFrame:
    result = df.copy()
    cves = sorted(set(result["cve_id"].dropna().astype(str).str.upper()))
    data = _fetch_live_epss(cves) if use_live else {}
    fallback = _load_fallback()

    rows = []
    for cve in cves:
        item = data.get(cve) or fallback.get(cve) or {"epss": 0.0, "percentile": 0.0}
        rows.append({"cve_id": cve, "epss_score": float(item.get("epss", 0)), "epss_percentile": float(item.get("percentile", 0))})

    epss_df = pd.DataFrame(rows)
    result = result.merge(epss_df, on="cve_id", how="left")
    result["epss_score"] = result["epss_score"].fillna(0.0)
    result["epss_percentile"] = result["epss_percentile"].fillna(0.0)

    def category(p):
        if p >= 0.95:
            return "Very High"
        if p >= 0.80:
            return "High"
        if p >= 0.50:
            return "Medium"
        return "Low"

    result["epss_category"] = result["epss_percentile"].apply(category)
    return result
