"""Uptime monitoring primitives for VigiScan."""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Protocol, TypedDict
from urllib.parse import urlparse

import requests
from requests import Response
from requests.exceptions import RequestException, SSLError


class UptimeResult(TypedDict):
    """Normalized uptime check result."""

    url: str
    up: bool
    status_code: int | None
    response_time_ms: int | None
    ssl_enabled: bool
    ssl_valid: bool
    error: str | None


class HTTPRequester(Protocol):
    """HTTP callable interface for tests."""

    def __call__(self, **kwargs: object) -> Response:
        """Execute an HTTP request."""


@dataclass(frozen=True, slots=True)
class UptimeConfig:
    """Runtime controls for uptime checks."""

    timeout_seconds: float = 8.0
    user_agent: str = "VigiScan-Uptime/0.1.0"


def check_url(
    url: str,
    *,
    config: UptimeConfig | None = None,
    requester: HTTPRequester | None = None,
) -> UptimeResult:
    """Check availability, HTTPS usage and response time for one URL."""
    settings = config or UptimeConfig()
    request = requester or requests.get
    parsed = urlparse(url)
    ssl_enabled = parsed.scheme.lower() == "https"
    start = perf_counter()
    try:
        response = request(
            url=url,
            headers={"User-Agent": settings.user_agent, "Accept": "*/*"},
            timeout=settings.timeout_seconds,
            allow_redirects=False,
            verify=True,
        )
        elapsed_ms = int((perf_counter() - start) * 1000)
        status_code = response.status_code
        up = 200 <= status_code < 400
        response.close()
        return {
            "url": url,
            "up": up,
            "status_code": status_code,
            "response_time_ms": elapsed_ms,
            "ssl_enabled": ssl_enabled,
            "ssl_valid": ssl_enabled,
            "error": None,
        }
    except SSLError as exc:
        elapsed_ms = int((perf_counter() - start) * 1000)
        return {
            "url": url,
            "up": False,
            "status_code": None,
            "response_time_ms": elapsed_ms,
            "ssl_enabled": ssl_enabled,
            "ssl_valid": False,
            "error": str(exc),
        }
    except RequestException as exc:
        elapsed_ms = int((perf_counter() - start) * 1000)
        return {
            "url": url,
            "up": False,
            "status_code": None,
            "response_time_ms": elapsed_ms,
            "ssl_enabled": ssl_enabled,
            "ssl_valid": False,
            "error": str(exc),
        }


def summarize_checks(results: list[UptimeResult]) -> dict[str, float | int]:
    """Return aggregate uptime metrics for a group of check results."""
    total = len(results)
    up = sum(1 for result in results if result["up"])
    response_times = [
        int(result["response_time_ms"])
        for result in results
        if result["response_time_ms"] is not None
    ]
    return {
        "total": total,
        "up": up,
        "down": total - up,
        "uptime_percentage": round((up / total) * 100, 2) if total else 0.0,
        "avg_response_time": round(sum(response_times) / len(response_times), 1)
        if response_times
        else 0.0,
    }
