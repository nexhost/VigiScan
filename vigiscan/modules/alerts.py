"""Normalized defensive alerts for VigiScan web analysis modules."""

from __future__ import annotations

from typing import Literal, TypedDict


AlertLevel = Literal["Critical", "High", "Medium", "Low", "Informational"]


class Alert(TypedDict):
    """One normalized defensive alert."""

    title: str
    severity: AlertLevel
    description: str
    evidence: str
    recommendation: str
    owasp_category: str | None
    source: str


SEVERITY_ORDER: dict[AlertLevel, int] = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
}


def create_alert(
    *,
    title: str,
    severity: AlertLevel,
    description: str,
    evidence: str,
    recommendation: str,
    source: str,
    owasp_category: str | None = None,
) -> Alert:
    """Build a normalized alert dictionary."""
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "owasp_category": owasp_category,
        "source": source,
    }


def severity_counts(alerts: list[Alert]) -> dict[AlertLevel, int]:
    """Count alerts by severity."""
    counts: dict[AlertLevel, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }
    for alert in alerts:
        counts[alert["severity"]] += 1
    return counts


def highest_severity(alerts: list[Alert]) -> AlertLevel | None:
    """Return the highest alert severity in a list."""
    if not alerts:
        return None
    return max(alerts, key=lambda item: SEVERITY_ORDER[item["severity"]])["severity"]
