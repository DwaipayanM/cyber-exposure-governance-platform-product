"""Risk policy loader for configurable scoring, SLA, and priority thresholds."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_POLICY = {
    "weights": {
        "threat_intelligence": 35,
        "business_impact": 15,
        "network_exposure": 20,
        "ids_correlation": 15,
        "privacy_impact": 10,
        "sla_governance": 5,
    },
    "sla_days": {"Critical": 7, "High": 15, "Medium": 30, "Low": 90},
    "priority_thresholds": {"Critical": 85, "High": 70, "Medium": 45, "Low": 0},
}


def load_risk_policy(policy_path: str | Path = "data/risk_policy.json") -> Dict[str, Any]:
    path = Path(policy_path)
    if not path.exists():
        return DEFAULT_POLICY.copy()

    try:
        with path.open("r", encoding="utf-8") as f:
            policy = json.load(f)
        # Defensive merge with defaults
        merged = DEFAULT_POLICY.copy()
        merged["weights"] = {**DEFAULT_POLICY["weights"], **policy.get("weights", {})}
        merged["sla_days"] = {**DEFAULT_POLICY["sla_days"], **policy.get("sla_days", {})}
        merged["priority_thresholds"] = {
            **DEFAULT_POLICY["priority_thresholds"],
            **policy.get("priority_thresholds", {}),
        }
        return merged
    except Exception:
        return DEFAULT_POLICY.copy()


def get_weight(policy: Dict[str, Any], section_name: str) -> float:
    return float(policy.get("weights", {}).get(section_name, DEFAULT_POLICY["weights"].get(section_name, 0)))


def get_sla_days(policy: Dict[str, Any], priority: str) -> int:
    return int(policy.get("sla_days", {}).get(priority, DEFAULT_POLICY["sla_days"].get(priority, 90)))


def get_priority_thresholds(policy: Dict[str, Any]) -> Dict[str, float]:
    return policy.get("priority_thresholds", DEFAULT_POLICY["priority_thresholds"]).copy()


def classify_priority(score: float, policy: Dict[str, Any] | None = None) -> str:
    policy = policy or DEFAULT_POLICY
    thresholds = get_priority_thresholds(policy)
    score = float(score or 0)
    if score >= float(thresholds.get("Critical", 85)):
        return "Critical"
    if score >= float(thresholds.get("High", 70)):
        return "High"
    if score >= float(thresholds.get("Medium", 45)):
        return "Medium"
    return "Low"
