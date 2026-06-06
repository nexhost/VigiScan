from __future__ import annotations

from vigiscan.web.i18n import TRANSLATIONS


def test_i18n_contains_required_es_en_keys():
    for language in ("es", "en"):
        for key in (
            "dashboard",
            "reports",
            "assets",
            "threat_intelligence",
            "settings",
            "new_scan",
            "uptime_monitor",
            "infrastructure_monitor",
            "ioc_center",
        ):
            assert TRANSLATIONS[language][key]

    assert TRANSLATIONS["es"]["dashboard"] == "Panel de control"
    assert TRANSLATIONS["en"]["dashboard"] == "Dashboard"
