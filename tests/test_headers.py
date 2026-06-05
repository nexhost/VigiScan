from __future__ import annotations

from io import StringIO
from typing import cast

from rich.console import Console

from modules.headers import analyze_headers, render_headers_report
from scanner import ScanResult


def make_scan_result(headers: dict[str, str]) -> ScanResult:
    return cast(
        ScanResult,
        {
            "ok": True,
            "target": {
                "url": "https://example.com",
                "scheme": "https",
                "hostname": "example.com",
                "port": None,
                "path": "/",
            },
            "request": {
                "method": "GET",
                "timeout_seconds": 10.0,
                "max_body_bytes": 65536,
                "allow_redirects": False,
            },
            "response": {
                "status_code": 200,
                "reason": "OK",
                "final_url": "https://example.com",
                "elapsed_ms": 10,
                "headers": headers,
                "body_sample": "",
                "body_truncated": False,
            },
            "error": None,
        },
    )


def test_analyze_headers_detects_all_expected_headers():
    result = make_scan_result(
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        },
    )

    report = analyze_headers(result)

    assert report["ok"] is True
    assert report["overall_severity"] == "Bajo"
    assert {finding["header"] for finding in report["findings"]} == {
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
    }
    assert all(finding["present"] for finding in report["findings"])


def test_analyze_headers_classifies_missing_headers():
    report = analyze_headers(make_scan_result({}))
    findings = {finding["header"]: finding for finding in report["findings"]}

    assert report["overall_severity"] == "Alto"
    assert findings["Content-Security-Policy"]["severity"] == "Alto"
    assert findings["Strict-Transport-Security"]["severity"] == "Alto"
    assert findings["X-Frame-Options"]["severity"] == "Medio"
    assert findings["X-Content-Type-Options"]["severity"] == "Medio"
    assert findings["Permissions-Policy"]["severity"] == "Medio"
    assert findings["Referrer-Policy"]["severity"] == "Bajo"
    assert all(finding["status"] == "Ausente" for finding in findings.values())


def test_analyze_headers_is_case_insensitive_and_marks_weak_values():
    report = analyze_headers(
        make_scan_result(
            {
                "x-frame-options": "ALLOWALL",
                "X-Content-Type-Options": "none",
                "strict-transport-security": "includeSubDomains",
            },
        ),
    )
    findings = {finding["header"]: finding for finding in report["findings"]}

    assert findings["X-Frame-Options"]["present"] is True
    assert findings["X-Frame-Options"]["status"] == "Debil"
    assert findings["X-Content-Type-Options"]["status"] == "Debil"
    assert findings["Strict-Transport-Security"]["status"] == "Debil"


def test_render_headers_report_outputs_rich_table():
    report = analyze_headers(
        make_scan_result({"Content-Security-Policy": "default-src 'self'"}),
    )
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=140)

    render_headers_report(report, console=console)

    rendered = output.getvalue()
    assert "VigiScan - HTTP Security Headers" in rendered
    assert "Content-Security-Policy" in rendered
    assert "Strict-Transport-Security" in rendered
