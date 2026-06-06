from __future__ import annotations

from vigiscan.modules.infra_monitor import human_uptime


def test_human_uptime_formats_compact_labels():
    assert human_uptime(59) == "0m"
    assert human_uptime(3661) == "1h 1m"
    assert human_uptime(90000) == "1d 1h"
