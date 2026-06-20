"""NVD CVE enrichment service with fallback data."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _load_fallback(path: str = "data/fallback_nvd.json") -> dict:
    try:
        with Path(path).open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _extract_cvss(metrics: dict) -> tuple[float, str]:
    """Extract CVSS score/severity across CVSS v4/v3/v2 shapes."""
    candidates = [
        ("cvssMetricV40", "cvssData"),
        ("cvssMetricV31", "cvssData"),
        ("cvssMetricV30", "cvssData"),
        ("cvssMetricV2", "cvssData"),
    ]
    for metric_key, data_key in candidates:
        if metric_key in metrics and metrics[metric_key]:
            first = metrics[metric_key][0]
            cvss_data = first.get(data_key, {})
            score = cvss_data.get("baseScore", 0) or first.get("impactScore", 0) or 0
            severity = first.get("baseSeverity") or cvss_data.get("baseSeverity") or ""
            return float(score or 0), str(severity).title() if severity else _severity_from_score(float(score or 0))
    return 0.0, "Unknown"


def _severity_from_score(score: float) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def _fetch_nvd_single(cve: str, api_key: str | None = None) -> dict | None:
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = requests.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=15)
        response.raise_for_status()
        payload = response.json()
        vulns = payload.get("vulnerabilities", [])
        if not vulns:
            return None
        cve_obj = vulns[0].get("cve", {})
        descriptions = cve_obj.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        score, severity = _extract_cvss(cve_obj.get("metrics", {}))
        return {
            "cvss_score": score,
            "severity": severity,
            "description": description,
            "published": cve_obj.get("published", ""),
            "last_modified": cve_obj.get("lastModified", ""),
        }
    except Exception:
        return None


def enrich_with_nvd(df: pd.DataFrame, use_live: bool = True, api_key: str | None = None) -> pd.DataFrame:
    result = df.copy()
    cves = sorted(set(result["cve_id"].dropna().astype(str).str.upper()))
    fallback = _load_fallback()
    rows = []

    for cve in cves:
        item = _fetch_nvd_single(cve, api_key=api_key) if use_live else None
        item = item or fallback.get(cve) or {
            "cvss_score": 0.0,
            "severity": "Unknown",
            "description": "No CVE description available from live or fallback data.",
            "published": "",
            "last_modified": "",
        }
        rows.append(
            {
                "cve_id": cve,
                "cvss_score": float(item.get("cvss_score", 0) or 0),
                "severity": str(item.get("severity", "Unknown")).title(),
                "cve_description": item.get("description", ""),
                "cve_published": item.get("published", ""),
                "cve_last_modified": item.get("last_modified", ""),
            }
        )

    nvd_df = pd.DataFrame(rows)
    result = result.merge(nvd_df, on="cve_id", how="left")
    result["cvss_score"] = result["cvss_score"].fillna(0.0)
    result["severity"] = result["severity"].fillna("Unknown")
    return result
