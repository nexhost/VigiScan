from __future__ import annotations

import requests

from scanner import ScanRequest, Scanner, ScannerConfig


class FakeResponse:
    status_code = 200
    reason = "OK"
    url = "https://example.com"
    headers = {"Content-Type": "text/plain", "Content-Length": "5"}
    encoding = "utf-8"

    def iter_content(self, chunk_size: int):
        yield b"hello"

    def close(self) -> None:
        return None


def test_scan_returns_normalized_success(monkeypatch):
    def fake_get(**kwargs):
        assert kwargs["url"] == "https://example.com"
        assert kwargs["timeout"] == 3.0
        assert kwargs["allow_redirects"] is False
        assert kwargs["stream"] is True
        assert kwargs["verify"] is True
        return FakeResponse()

    monkeypatch.setattr(requests, "get", fake_get)

    scanner = Scanner(ScannerConfig(timeout_seconds=3.0))
    result = scanner.scan(ScanRequest(url="https://example.com"))

    assert result["ok"] is True
    assert result["target"]["hostname"] == "example.com"
    assert result["request"]["method"] == "GET"
    assert result["response"]["status_code"] == 200
    assert result["response"]["body_sample"] == "hello"
    assert result["error"] is None


def test_scan_rejects_invalid_scheme():
    scanner = Scanner()
    result = scanner.scan(ScanRequest(url="ftp://example.com"))

    assert result["ok"] is False
    assert result["target"] is None
    assert result["response"] is None
    assert result["error"]["type"] == "ScannerError"


def test_scan_normalizes_request_exception(monkeypatch):
    def fake_get(**kwargs):
        raise requests.Timeout("request timed out")

    monkeypatch.setattr(requests, "get", fake_get)

    scanner = Scanner()
    result = scanner.scan(ScanRequest(url="https://example.com"))

    assert result["ok"] is False
    assert result["target"]["hostname"] == "example.com"
    assert result["response"] is None
    assert result["error"]["type"] == "Timeout"
