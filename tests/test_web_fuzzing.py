from __future__ import annotations

from requests import Response
from requests.exceptions import ConnectionError

from modules.web_fuzzing import (
    WebFuzzingConfig,
    analyze_web_fuzzing,
    load_hidden_path_wordlist,
    load_subdomain_wordlist,
)


def make_response(status_code: int, headers: dict[str, str] | None = None) -> Response:
    response = Response()
    response.status_code = status_code
    response._content = b""
    response._content_consumed = True
    response.headers.update(headers or {})
    return response


def test_load_web_fuzzing_wordlists():
    assert "admin" in load_subdomain_wordlist()
    assert ".env" in load_hidden_path_wordlist()


def test_analyze_web_fuzzing_discovers_subdomains_and_hidden_paths():
    requested_urls: list[str] = []

    def resolver(host: str) -> list[str]:
        if host == "api.example.com":
            return ["203.0.113.10"]
        raise OSError("not found")

    def requester(**kwargs: object) -> Response:
        url = str(kwargs["url"])
        requested_urls.append(url)
        if url == "https://api.example.com/":
            return make_response(200)
        if url == "https://example.com/.env":
            return make_response(403, {"Content-Type": "text/plain", "Content-Length": "12"})
        return make_response(404)

    report = analyze_web_fuzzing(
        {"target": {"url": "https://example.com/app"}},
        config=WebFuzzingConfig(max_subdomains=2, max_paths=2),
        subdomains=("api", "dev"),
        paths=(".env", "missing/"),
        requester=requester,
        resolver=resolver,
    )

    assert report["ok"] is True
    assert report["discovered_subdomains"] == 1
    assert report["discovered_paths"] == 1
    assert report["subdomains"][0]["host"] == "api.example.com"
    assert report["hidden_paths"][0]["path"] == ".env"
    assert "https://example.com/.env" in requested_urls


def test_analyze_web_fuzzing_handles_request_errors():
    def requester(**kwargs: object) -> Response:
        raise ConnectionError("timeout")

    report = analyze_web_fuzzing(
        {"target": {"url": "https://example.com"}},
        subdomains=("api",),
        paths=(".env",),
        requester=requester,
        resolver=lambda host: ["203.0.113.10"],
    )

    assert report["subdomains"][0]["resolved"] is True
    assert report["subdomains"][0]["error"] == "timeout"
    assert report["hidden_paths"][0]["discovered"] is False
    assert report["hidden_paths"][0]["error"] == "timeout"


def test_analyze_web_fuzzing_without_target_does_not_request():
    def requester(**kwargs: object) -> Response:
        raise AssertionError("requester should not be called")

    report = analyze_web_fuzzing(
        {},
        subdomains=("api",),
        paths=(".env",),
        requester=requester,
        resolver=lambda host: ["203.0.113.10"],
    )

    assert report["ok"] is False
    assert report["target_url"] is None
