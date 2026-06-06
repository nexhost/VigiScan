"""Passive SSL/TLS analyzer."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import requests


def analyze_tls(url: str, *, requester: Any = requests.head) -> dict[str, Any]:
    """Analyze certificate metadata and HTTP to HTTPS redirect behavior."""
    parsed = urlparse(url)
    host = parsed.hostname
    https_available = parsed.scheme == "https"
    cert = None
    error = None
    if host:
        try:
            cert = fetch_certificate(host)
            https_available = True
        except OSError as exc:
            error = str(exc)
    redirect = check_http_redirect(host, requester=requester) if host else False
    result = certificate_summary(cert)
    result.update(
        {
            "module": "tls_analyzer",
            "ok": error is None,
            "https_available": https_available,
            "http_to_https_redirect": redirect,
            "error": error,
        }
    )
    result["score"] = ssl_score(result)
    return result


def fetch_certificate(host: str, *, port: int = 443, timeout: float = 4.0) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            return tls_sock.getpeercert()


def certificate_summary(cert: dict[str, Any] | None) -> dict[str, Any]:
    if not cert:
        return {"issuer": "-", "subject": "-", "sans": [], "expires_at": None, "days_remaining": 0, "expired": True, "expires_soon": False}
    expires_raw = cert.get("notAfter")
    expires_at = datetime.strptime(expires_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC) if expires_raw else None
    days_remaining = (expires_at - datetime.now(UTC)).days if expires_at else 0
    return {
        "issuer": _rdn(cert.get("issuer")),
        "subject": _rdn(cert.get("subject")),
        "sans": [value for key, value in cert.get("subjectAltName", []) if key == "DNS"],
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_remaining": days_remaining,
        "expired": days_remaining < 0,
        "expires_soon": 0 <= days_remaining <= 30,
    }


def check_http_redirect(host: str, *, requester: Any = requests.head) -> bool:
    try:
        response = requester(f"http://{host}", timeout=4, allow_redirects=False)
        return str(response.headers.get("Location", "")).lower().startswith("https://")
    except requests.RequestException:
        return False


def ssl_score(result: dict[str, Any]) -> str:
    if not result.get("https_available") or result.get("expired"):
        return "F"
    if result.get("expires_soon"):
        return "C"
    if not result.get("http_to_https_redirect"):
        return "B"
    return "A"


def _rdn(value: Any) -> str:
    if not value:
        return "-"
    return ", ".join("=".join(item) for group in value for item in group)
