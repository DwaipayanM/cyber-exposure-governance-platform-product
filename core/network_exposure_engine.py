"""Network exposure scoring engine."""
from __future__ import annotations

import re

import pandas as pd

DANGEROUS_PORTS = {"22", "23", "3389", "445", "5900", "5985", "5986", "1433", "1521", "3306", "5432", "6379"}


def _parse_ports(value) -> set[str]:
    text = "" if value is None or pd.isna(value) else str(value)
    return set(re.findall(r"\d+", text))


def add_network_exposure(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    def compute(row):
        points = 0
        reasons = []

        zone = str(row.get("network_zone", "")).strip().lower()
        firewall = str(row.get("firewall_status", "")).strip().lower()
        vpn_required = str(row.get("vpn_required", "")).strip().lower()
        asset_type = str(row.get("asset_type", "")).strip().lower()
        ports = _parse_ports(row.get("open_ports", ""))

        if zone == "internet":
            points += 20
            reasons.append("internet-facing network zone")
        elif zone == "dmz":
            points += 15
            reasons.append("DMZ exposure")
        elif zone == "vpn":
            points += 8
            reasons.append("VPN zone")
        elif zone == "internal":
            points += 5
            reasons.append("internal network zone")
        else:
            points += 5
            reasons.append("unknown network zone")

        if firewall == "allowed":
            points += 10
            reasons.append("firewall allows access")
        elif firewall == "restricted":
            points += 5
            reasons.append("restricted firewall access")

        risky_ports = sorted(ports & DANGEROUS_PORTS)
        if risky_ports:
            points += 10
            reasons.append(f"risky open ports: {', '.join(risky_ports)}")

        if vpn_required == "no":
            points += 5
            reasons.append("VPN not required")

        if asset_type in {"wireless", "mobile", "network device"}:
            points += 5
            reasons.append(f"{asset_type} exposure")

        raw_score = min(points, 30)
        if raw_score >= 25:
            level = "Critical"
        elif raw_score >= 18:
            level = "High"
        elif raw_score >= 10:
            level = "Medium"
        else:
            level = "Low"

        return raw_score, level, "; ".join(reasons)

    values = df.apply(compute, axis=1, result_type="expand")
    df["network_exposure_score_raw"] = values[0].astype(float)
    df["network_exposure_level"] = values[1]
    df["network_exposure_reason"] = values[2]
    return df
