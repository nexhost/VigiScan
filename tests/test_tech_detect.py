from __future__ import annotations

from typing import cast

from modules.tech_detect import analyze_technologies
from scanner import ScanResult


def make_scan_result(
    headers: dict[str, str],
    html: str = "",
) -> ScanResult:
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
                "body_sample": html,
                "body_truncated": False,
            },
            "error": None,
        },
    )


def by_name(report):
    return {item["name"]: item for item in report["technologies"]}


def test_detects_server_header_technologies_with_versions():
    report = analyze_technologies(
        make_scan_result(
            {
                "Server": "Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13",
                "X-Powered-By": "PHP/8.2.12",
            },
        ),
    )
    technologies = by_name(report)

    assert technologies["Apache"]["version"] == "2.4.58"
    assert technologies["Apache"]["confidence_level"] == "Alto"
    assert technologies["OpenSSL"]["version"] == "3.0.13"
    assert technologies["PHP"]["version"] == "8.2.12"


def test_detects_nginx_from_server_header_case_insensitive():
    report = analyze_technologies(make_scan_result({"server": "nginx/1.24.0"}))
    technologies = by_name(report)

    assert technologies["Nginx"]["version"] == "1.24.0"
    assert technologies["Nginx"]["confidence"] == 95


def test_detects_wordpress_from_meta_and_html():
    html = """
    <html>
      <head><meta name="generator" content="WordPress 6.4.3"></head>
      <body><script src="/wp-content/themes/app/main.js"></script></body>
    </html>
    """

    report = analyze_technologies(make_scan_result({}, html))
    technologies = by_name(report)

    assert technologies["WordPress"]["version"] == "6.4.3"
    assert technologies["WordPress"]["confidence_level"] == "Alto"
    assert len(technologies["WordPress"]["evidence"]) == 2


def test_detects_laravel_and_php_from_cookies():
    report = analyze_technologies(
        make_scan_result({"Set-Cookie": "laravel_session=abc; PHPSESSID=def"}),
    )
    technologies = by_name(report)

    assert technologies["Laravel"]["version"] is None
    assert technologies["Laravel"]["confidence_level"] == "Alto"
    assert technologies["PHP"]["confidence_level"] == "Medio"


def test_returns_empty_list_without_evidence():
    report = analyze_technologies(make_scan_result({"Server": "unknown"}))

    assert report["module"] == "tech_detect"
    assert report["target_url"] == "https://example.com"
    assert report["technologies"] == []
