from __future__ import annotations

from typing import cast

import requests

from vigiscan.modules.directories import analyze_directories, load_wordlist
from vigiscan.scanner import ScanResult


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False

    def close(self) -> None:
        self.closed = True


def make_scan_result(url: str = "https://example.com/app/index.html") -> ScanResult:
    return cast(
        ScanResult,
        {
            "ok": True,
            "target": {
                "url": url,
                "scheme": "https",
                "hostname": "example.com",
                "port": None,
                "path": "/app/index.html",
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
                "final_url": url,
                "elapsed_ms": 10,
                "headers": {},
                "body_sample": "",
                "body_truncated": False,
            },
            "error": None,
        },
    )


def test_load_wordlist_contains_only_common_paths():
    assert load_wordlist() == (
        ".env",
        ".git/",
        "backup.zip",
        "config.php",
        "phpinfo.php",
        "admin/",
        "login/",
        "backup/",
    )


def test_analyze_directories_checks_only_given_paths():
    requested_urls: list[str] = []

    def fake_request(**kwargs):
        requested_urls.append(cast(str, kwargs["url"]))
        return FakeResponse(404)

    report = analyze_directories(
        make_scan_result(),
        paths=(".env", "admin/"),
        requester=fake_request,
    )

    assert requested_urls == [
        "https://example.com/.env",
        "https://example.com/admin/",
    ]
    assert report["wordlist_size"] == 2
    assert report["exposed_count"] == 0


def test_analyze_directories_marks_2xx_as_exposed():
    def fake_request(**kwargs):
        if kwargs["url"].endswith("/.env"):
            return FakeResponse(
                200,
                {"Content-Type": "text/plain", "Content-Length": "128"},
            )
        return FakeResponse(403)

    report = analyze_directories(
        make_scan_result(),
        paths=(".env", ".git/"),
        requester=fake_request,
    )
    findings = {finding["path"]: finding for finding in report["findings"]}

    assert report["exposed_count"] == 1
    assert findings[".env"]["status"] == "Expuesto"
    assert findings[".env"]["content_length"] == 128
    assert findings[".git/"]["status"] == "No expuesto"


def test_analyze_directories_handles_request_errors():
    def fake_request(**kwargs):
        raise requests.Timeout("request timed out")

    report = analyze_directories(
        make_scan_result(),
        paths=("backup.zip",),
        requester=fake_request,
    )
    finding = report["findings"][0]

    assert finding["path"] == "backup.zip"
    assert finding["status"] == "Error"
    assert finding["exposed"] is False
    assert finding["error"] == "request timed out"


def test_analyze_directories_without_target_does_not_request():
    called = False

    def fake_request(**kwargs):
        nonlocal called
        called = True
        return FakeResponse(200)

    result = make_scan_result()
    result["target"] = None

    report = analyze_directories(
        result,
        paths=(".env",),
        requester=fake_request,
    )

    assert called is False
    assert report["ok"] is False
    assert report["findings"] == []
