"""CISA Known Exploited Vulnerabilities enrichment service."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import pandas as pd
import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _load_json(path: str | Path) -> dict:
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def load_kev_catalog(use_live: bool = True, fallback_path: str = "data/fallback_kev.json", cache_path: str = "data/cache/kev_cache.json") -> pd.DataFrame:
    data = None
    if use_live:
        try:
            response = requests.get(CISA_KEV_URL, timeout=15)
            response.raise_for_status()
            data = response.json()
            Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
            with Path(cache_path).open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            data = None

    if data is None:
        for path in [cache_path, fallback_path]:
            try:
                if Path(path).exists():
                    data = _load_json(path)
                    break
            except Exception:
                data = None

    vulnerabilities = (data or {}).get("vulnerabilities", [])
    rows = []
    for item in vulnerabilities:
        rows.append(
            {
                "cve_id": str(item.get("cveID", "")).upper(),
                "kev_status": "Yes",
                "kev_vendor": item.get("vendorProject", ""),
                "kev_product": item.get("product", ""),
                "kev_vulnerability_name": item.get("vulnerabilityName", ""),
                "kev_date_added": item.get("dateAdded", ""),
                "kev_required_action": item.get("requiredAction", ""),
                "kev_due_date": item.get("dueDate", ""),
                "kev_ransomware_use": item.get("knownRansomwareCampaignUse", ""),
            }
        )
    return pd.DataFrame(rows)


def enrich_with_kev(df: pd.DataFrame, use_live: bool = True) -> pd.DataFrame:
    result = df.copy()
    kev_df = load_kev_catalog(use_live=use_live)
    if kev_df.empty:
        result["kev_status"] = "No"
        return result

    result = result.merge(kev_df, on="cve_id", how="left")
    result["kev_status"] = result["kev_status"].fillna("No")
    for col in ["kev_vendor", "kev_product", "kev_vulnerability_name", "kev_date_added", "kev_required_action", "kev_due_date", "kev_ransomware_use"]:
        if col in result.columns:
            result[col] = result[col].fillna("")
    return result
