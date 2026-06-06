"""Infrastructure metrics collection for the VigiScan web host."""

from __future__ import annotations

from datetime import UTC, datetime
import time
from typing import Any

try:
    import psutil
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    psutil = None  # type: ignore[assignment]

_LAST_NET_SAMPLE: dict[str, float] | None = None


def collect_metrics() -> dict[str, Any]:
    """Collect a normalized snapshot of host CPU, memory, disk and network state."""
    global _LAST_NET_SAMPLE

    if psutil is None:
        return _empty_metrics()

    now = time.monotonic()
    cpu_percent = _safe_float(psutil.cpu_percent(interval=None))
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    network = psutil.net_io_counters()
    boot_time = psutil.boot_time()

    upload_rate = 0.0
    download_rate = 0.0
    if _LAST_NET_SAMPLE:
        elapsed = max(now - _LAST_NET_SAMPLE["sampled_at"], 1.0)
        upload_rate = max(network.bytes_sent - _LAST_NET_SAMPLE["bytes_sent"], 0) / elapsed
        download_rate = max(network.bytes_recv - _LAST_NET_SAMPLE["bytes_recv"], 0) / elapsed

    _LAST_NET_SAMPLE = {
        "sampled_at": now,
        "bytes_sent": float(network.bytes_sent),
        "bytes_recv": float(network.bytes_recv),
    }

    return {
        "cpu_percent": round(cpu_percent, 1),
        "memory_percent": round(_safe_float(memory.percent), 1),
        "memory_used": round(_bytes_to_gb(memory.used), 2),
        "memory_total": round(_bytes_to_gb(memory.total), 2),
        "disk_percent": round(_safe_float(disk.percent), 1),
        "disk_used": round(_bytes_to_gb(disk.used), 2),
        "disk_total": round(_bytes_to_gb(disk.total), 2),
        "net_bytes_sent": int(network.bytes_sent),
        "net_bytes_recv": int(network.bytes_recv),
        "net_upload_rate": round(_bytes_to_mb(upload_rate), 2),
        "net_download_rate": round(_bytes_to_mb(download_rate), 2),
        "active_processes": _process_count(),
        "server_uptime": round(max(datetime.now(UTC).timestamp() - boot_time, 0), 0),
    }


def human_uptime(seconds: float | int | None) -> str:
    """Return a compact uptime label from seconds."""
    total_seconds = int(seconds or 0)
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _seconds = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _process_count() -> int:
    if psutil is None:
        return 0
    try:
        return len(psutil.pids())
    except psutil.Error:
        return 0


def _bytes_to_gb(value: float | int) -> float:
    return float(value) / 1024 / 1024 / 1024


def _bytes_to_mb(value: float | int) -> float:
    return float(value) / 1024 / 1024


def _safe_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _empty_metrics() -> dict[str, Any]:
    return {
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "memory_used": 0.0,
        "memory_total": 0.0,
        "disk_percent": 0.0,
        "disk_used": 0.0,
        "disk_total": 0.0,
        "net_bytes_sent": 0,
        "net_bytes_recv": 0,
        "net_upload_rate": 0.0,
        "net_download_rate": 0.0,
        "active_processes": 0,
        "server_uptime": 0.0,
    }
