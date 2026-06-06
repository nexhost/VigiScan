"""Passive API security checks."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

import requests


API_PATHS = ["/swagger.json", "/openapi.json", "/api-docs", "/graphql"]


def analyze_api_security(
    url: str,
    scan_result: dict[str, Any] | None = None,
    *,
    requester: Any = requests.get,
    options_requester: Any = requests.options,
) -> dict[str, Any]:
    """Run safe API exposure checks without payloads."""
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(_finding("API sin HTTPS", "High", "Public API traffic should use HTTPS."))
    findings.extend(_check_common_api_paths(url, requester=requester))
    findings.extend(_check_headers(scan_result or {}, url, options_requester=options_requester))
    return {"module": "api_security", "ok": True, "findings": findings}


def _check_common_api_paths(url: str, *, requester: Any) -> list[dict[str, str]]:
    findings = []
    for path in API_PATHS:
        try:
            response = requester(urljoin(url, path), timeout=4, allow_redirects=False)
        except requests.RequestException:
            continue
        if response.status_code in {200, 401, 403}:
            title = "GraphQL endpoint expuesto" if path == "/graphql" else "Swagger/OpenAPI expuesto"
            findings.append(_finding(title, "Medium", f"Endpoint detectable: {path}"))
    return findings


def _check_headers(
    scan_result: dict[str, Any],
    url: str,
    *,
    options_requester: Any,
) -> list[dict[str, str]]:
    findings = []
    response = scan_result.get("response", {}) if isinstance(scan_result, dict) else {}
    headers = response.get("headers", {}) if isinstance(response, dict) else {}
    cors = str(headers.get("Access-Control-Allow-Origin", ""))
    content_type = str(headers.get("Content-Type", ""))
    if cors == "*":
        findings.append(_finding("CORS permisivo", "Medium", "Access-Control-Allow-Origin permite cualquier origen."))
    if content_type and "json" not in content_type.lower() and "/api" in url:
        findings.append(_finding("Content-Type incorrecto", "Low", f"Content-Type observado: {content_type}"))
    try:
        response_options = options_requester(url, timeout=4, allow_redirects=False)
        allow = str(response_options.headers.get("Allow", ""))
        if any(method in allow.upper() for method in ["PUT", "DELETE", "TRACE"]):
            findings.append(_finding("Metodos HTTP sensibles", "Medium", allow))
    except requests.RequestException:
        pass
    return findings


def _finding(title: str, severity: str, evidence: str) -> dict[str, str]:
    return {"title": title, "severity": severity, "evidence": evidence}
