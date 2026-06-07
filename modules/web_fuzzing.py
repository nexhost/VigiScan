"""Controlled web fuzzing checks for subdomains and hidden paths."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from importlib import resources
from typing import Protocol, TypedDict
from urllib.parse import urljoin, urlparse

import requests
from requests import Response
from requests.exceptions import RequestException

from scanner import ScanResult

DEFAULT_TIMEOUT_SECONDS = 4.0
DEFAULT_USER_AGENT = "VigiScan/0.1.0 WebFuzzer"
WORDLIST_PACKAGE = "modules.wordlists"
SUBDOMAIN_WORDLIST = "subdomains.txt"
HIDDEN_PATH_WORDLIST = "hidden_paths.txt"


class HTTPRequester(Protocol):
    def __call__(self, **kwargs: object) -> Response:
        """Execute an HTTP request."""


class DNSResolver(Protocol):
    def __call__(self, host: str) -> list[str]:
        """Resolve a hostname to one or more IP addresses."""


class SubdomainFinding(TypedDict):
    host: str
    url: str
    resolved: bool
    ips: list[str]
    status_code: int | None
    status: str
    error: str | None


class HiddenPathFinding(TypedDict):
    path: str
    url: str
    discovered: bool
    status_code: int | None
    content_type: str | None
    content_length: int | None
    evidence: str
    error: str | None


class WebFuzzingReport(TypedDict):
    module: str
    ok: bool
    target_url: str | None
    base_domain: str | None
    subdomain_wordlist_size: int
    hidden_path_wordlist_size: int
    discovered_subdomains: int
    discovered_paths: int
    subdomains: list[SubdomainFinding]
    hidden_paths: list[HiddenPathFinding]


@dataclass(frozen=True, slots=True)
class WebFuzzingConfig:
    """Runtime controls for safe web fuzzing."""

    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_subdomains: int = 10
    max_paths: int = 12
    allow_redirects: bool = False
    user_agent: str = DEFAULT_USER_AGENT

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")
        if self.max_subdomains <= 0:
            raise ValueError("max_subdomains must be greater than zero.")
        if self.max_paths <= 0:
            raise ValueError("max_paths must be greater than zero.")


def analyze_web_fuzzing(
    scan_result: ScanResult,
    *,
    config: WebFuzzingConfig | None = None,
    subdomains: tuple[str, ...] | None = None,
    paths: tuple[str, ...] | None = None,
    requester: HTTPRequester | None = None,
    resolver: DNSResolver | None = None,
) -> WebFuzzingReport:
    """Run controlled subdomain and hidden-path discovery."""
    target_url = _extract_target_url(scan_result)
    settings = config or WebFuzzingConfig()
    subdomain_words = (subdomains or load_subdomain_wordlist())[: settings.max_subdomains]
    hidden_paths = (paths or load_hidden_path_wordlist())[: settings.max_paths]
    if target_url is None:
        return {
            "module": "web_fuzzing",
            "ok": False,
            "target_url": None,
            "base_domain": None,
            "subdomain_wordlist_size": len(subdomain_words),
            "hidden_path_wordlist_size": len(hidden_paths),
            "discovered_subdomains": 0,
            "discovered_paths": 0,
            "subdomains": [],
            "hidden_paths": [],
        }

    parsed = urlparse(target_url)
    base_domain = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    request = requester or requests.get
    resolve = resolver or _resolve_host
    subdomain_findings = [
        _check_subdomain(
            scheme=scheme,
            base_domain=base_domain,
            label=label,
            config=settings,
            requester=request,
            resolver=resolve,
        )
        for label in subdomain_words
    ]
    origin_url = f"{scheme}://{base_domain}"
    path_findings = [
        _check_hidden_path(path, origin_url, settings, request)
        for path in hidden_paths
    ]
    return {
        "module": "web_fuzzing",
        "ok": True,
        "target_url": target_url,
        "base_domain": base_domain,
        "subdomain_wordlist_size": len(subdomain_words),
        "hidden_path_wordlist_size": len(hidden_paths),
        "discovered_subdomains": sum(1 for item in subdomain_findings if item["resolved"]),
        "discovered_paths": sum(1 for item in path_findings if item["discovered"]),
        "subdomains": subdomain_findings,
        "hidden_paths": path_findings,
    }


def load_subdomain_wordlist() -> tuple[str, ...]:
    return _load_wordlist(SUBDOMAIN_WORDLIST)


def load_hidden_path_wordlist() -> tuple[str, ...]:
    return _load_wordlist(HIDDEN_PATH_WORDLIST)


def _load_wordlist(name: str) -> tuple[str, ...]:
    wordlist = resources.files(WORDLIST_PACKAGE).joinpath(name).read_text(encoding="utf-8")
    return tuple(
        line.strip()
        for line in wordlist.splitlines()
        if line.strip() and not line.startswith("#")
    )


def _check_subdomain(
    *,
    scheme: str,
    base_domain: str,
    label: str,
    config: WebFuzzingConfig,
    requester: HTTPRequester,
    resolver: DNSResolver,
) -> SubdomainFinding:
    host = f"{label}.{base_domain}".lower()
    url = f"{scheme}://{host}/"
    try:
        ips = resolver(host)
    except OSError as exc:
        return {
            "host": host,
            "url": url,
            "resolved": False,
            "ips": [],
            "status_code": None,
            "status": "No resuelto",
            "error": str(exc),
        }
    status_code: int | None = None
    error: str | None = None
    try:
        response = requester(
            url=url,
            headers={"User-Agent": config.user_agent, "Accept": "*/*"},
            timeout=config.timeout_seconds,
            allow_redirects=config.allow_redirects,
            stream=True,
            verify=True,
        )
        status_code = response.status_code
        response.close()
    except RequestException as exc:
        error = str(exc)
    return {
        "host": host,
        "url": url,
        "resolved": True,
        "ips": ips,
        "status_code": status_code,
        "status": "Resuelto",
        "error": error,
    }


def _check_hidden_path(
    path: str,
    origin_url: str,
    config: WebFuzzingConfig,
    requester: HTTPRequester,
) -> HiddenPathFinding:
    url = urljoin(f"{origin_url}/", path)
    try:
        response = requester(
            url=url,
            headers={"User-Agent": config.user_agent, "Accept": "*/*"},
            timeout=config.timeout_seconds,
            allow_redirects=config.allow_redirects,
            stream=True,
            verify=True,
        )
    except RequestException as exc:
        return {
            "path": path,
            "url": url,
            "discovered": False,
            "status_code": None,
            "content_type": None,
            "content_length": None,
            "evidence": "La ruta no pudo verificarse por un error HTTP.",
            "error": str(exc),
        }
    try:
        status_code = response.status_code
        discovered = status_code in {200, 204, 206, 301, 302, 307, 308, 401, 403}
        return {
            "path": path,
            "url": url,
            "discovered": discovered,
            "status_code": status_code,
            "content_type": response.headers.get("Content-Type"),
            "content_length": _parse_content_length(response.headers.get("Content-Length")),
            "evidence": _path_evidence(status_code, discovered),
            "error": None,
        }
    finally:
        response.close()


def _resolve_host(host: str) -> list[str]:
    return sorted(set(socket.gethostbyname_ex(host)[2]))


def _path_evidence(status_code: int, discovered: bool) -> str:
    if discovered:
        return f"La ruta respondio con HTTP {status_code}."
    return f"La ruta respondio con HTTP {status_code}; no se marca descubierta."


def _parse_content_length(value: str | None) -> int | None:
    if value is None or not value.isdigit():
        return None
    return int(value)


def _extract_target_url(scan_result: ScanResult) -> str | None:
    target = scan_result.get("target")
    if target is None:
        return None
    value = target.get("url")
    return value if isinstance(value, str) else None
