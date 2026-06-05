from __future__ import annotations

from vigiscan.modules.alerts import create_alert, highest_severity, severity_counts


def test_alert_helpers_count_and_rank_severity():
    alerts = [
        create_alert(
            title="One",
            severity="Low",
            description="Low alert.",
            evidence="-",
            recommendation="Review.",
            source="test",
        ),
        create_alert(
            title="Two",
            severity="Critical",
            description="Critical alert.",
            evidence="-",
            recommendation="Fix.",
            source="test",
        ),
    ]

    assert severity_counts(alerts)["Critical"] == 1
    assert severity_counts(alerts)["Low"] == 1
    assert highest_severity(alerts) == "Critical"
