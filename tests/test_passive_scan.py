from __future__ import annotations

from typing import cast

from scanner import ScanResult
from vigiscan.modules.passive_scan import analyze_passive


def sample_scan_result(body: str, headers: dict[str, str] | None = None) -> ScanResult:
    return cast(
        ScanResult,
        {
            "ok": True,
            "target": {
                "url": "http://example.com",
                "scheme": "http",
                "hostname": "example.com",
                "port": None,
                "path": "/",
            },
            "request": {
                "method": "GET",
                "timeout_seconds": 10,
                "max_body_bytes": 1024,
                "allow_redirects": False,
            },
            "response": {
                "status_code": 200,
                "reason": "OK",
                "final_url": "http://example.com",
                "elapsed_ms": 12,
                "headers": headers or {},
                "body_sample": body,
                "body_truncated": False,
            },
            "error": None,
        },
    )


def test_passive_scan_detects_cookies_forms_comments_versions_and_errors():
    report = analyze_passive(
        sample_scan_result(
            "<!-- TODO debug admin -->"
            "<meta name='generator' content='ExampleCMS 1.0'>"
            "<form><input type='password' name='password'></form>"
            "Traceback (most recent call last)",
            headers={
                "Set-Cookie": "session=abc",
                "Server": "Apache/2.4.49",
            },
        )
    )
    titles = {alert["title"] for alert in report["alerts"]}

    assert "Cookie sin HttpOnly" in titles
    assert "Cookie sin Secure" in titles
    assert "Cookie sin SameSite" in titles
    assert "Formulario sin CSRF visible" in titles
    assert "Formulario login sin HTTPS" in titles
    assert "Comentario HTML sospechoso" in titles
    assert "Version expuesta" in titles
    assert "Version o generador expuesto en HTML" in titles
    assert "Error tecnico visible" in titles


def test_passive_scan_imports_header_and_directory_findings():
    report = analyze_passive(
        sample_scan_result(""),
        headers_report={
            "findings": [
                {
                    "header": "Content-Security-Policy",
                    "status": "Ausente",
                    "severity": "Alto",
                    "recommendation": "Definir CSP.",
                }
            ]
        },
        directories_report={
            "findings": [
                {
                    "path": ".env",
                    "exposed": True,
                }
            ]
        },
    )

    assert any("Header Content-Security-Policy" in alert["title"] for alert in report["alerts"])
    assert any(alert["title"] == "Directorio o archivo comun expuesto" for alert in report["alerts"])
