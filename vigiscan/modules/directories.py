"""Common sensitive path exposure checks for VigiScan.

The module uses a small local wordlist of well-known sensitive paths and checks
only those routes. It does not generate mutations, recurse into discovered
directories, or perform brute-force enumeration.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from typing import Literal, Protocol, TypedDict
from urllib.parse import urljoin, urlparse

import requests
from requests import Response
from requests.exceptions import RequestException

from vigiscan.scanner import ScanResult

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_USER_AGENT = "VigiScan/0.1.0"
WORDLIST_PACKAGE = "vigiscan.modules.wordlists"
WORDLIST_NAME = "common_paths.txt"

ExposureStatus = Literal["Expuesto", "No expuesto", "Error"]


class DirectoryFinding(TypedDict):
    """Normalized result for one common path check."""

    path: str
    url: str
    exposed: bool
    status: ExposureStatus
    status_code: int | None
    content_type: str | None
    content_length: int | None
    evidence: str
    error: str | None


class DirectoriesReport(TypedDict):
    """Normalized report returned by the directories module."""

    module: str
    ok: bool
    target_url: str | None
    wordlist_size: int
    exposed_count: int
    findings: list[DirectoryFinding]


class HTTPRequester(Protocol):
    """Callable interface used to perform HTTP requests."""

    def __call__(self, **kwargs: object) -> Response:
        """Execute an HTTP request and return a response."""


@dataclass(frozen=True, slots=True)
class DirectoryCheckConfig:
    """Runtime controls for common path checks."""

    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    allow_redirects: bool = False
    user_agent: str = DEFAULT_USER_AGENT

    def __post_init__(self) -> None:
        """Validate common path check configuration."""
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")


def analyze_directories(
    scan_result: ScanResult,
    *,
    config: DirectoryCheckConfig | None = None,
    paths: tuple[str, ...] | None = None,
    requester: HTTPRequester | None = None,
) -> DirectoriesReport:
    """Check common sensitive paths from a local wordlist.

    Args:
        scan_result: JSON-compatible result returned by ``Scanner.scan``.
        config: Optional request safety settings.
        paths: Optional explicit paths for tests or controlled custom runs.
        requester: Optional HTTP callable, usually injected by unit tests.

    Returns:
        A normalized report with one finding per wordlist entry.
    """
    target_url = _extract_target_url(scan_result)
    wordlist = paths or load_wordlist()
    settings = config or DirectoryCheckConfig()

    if target_url is None:
        return {
            "module": "directories",
            "ok": False,
            "target_url": None,
            "wordlist_size": len(wordlist),
            "exposed_count": 0,
            "findings": [],
        }

    request = requester or requests.get
    base_url = _origin_url(target_url)
    findings = [
        _check_path(
            path=path,
            url=urljoin(f"{base_url}/", path),
            config=settings,
            requester=request,
        )
        for path in wordlist
    ]

    return {
        "module": "directories",
        "ok": True,
        "target_url": target_url,
        "wordlist_size": len(wordlist),
        "exposed_count": sum(1 for finding in findings if finding["exposed"]),
        "findings": findings,
    }


def load_wordlist() -> tuple[str, ...]:
    """Load the local common paths wordlist bundled with the package."""
    wordlist = (
        resources.files(WORDLIST_PACKAGE)
        .joinpath(WORDLIST_NAME)
        .read_text(encoding="utf-8")
    )
    paths: list[str] = []
    for line in wordlist.splitlines():
        path = line.strip()
        if path and not path.startswith("#"):
            paths.append(path)
    return tuple(paths)


def _check_path(
    *,
    path: str,
    url: str,
    config: DirectoryCheckConfig,
    requester: HTTPRequester,
) -> DirectoryFinding:
    """Check one path and normalize the result."""
    try:
        response = requester(
            url=url,
            headers={
                "User-Agent": config.user_agent,
                "Accept": "*/*",
            },
            timeout=config.timeout_seconds,
            allow_redirects=config.allow_redirects,
            stream=True,
            verify=True,
        )
    except RequestException as exc:
        return _error_finding(path=path, url=url, error=str(exc))

    try:
        return _response_finding(path=path, url=url, response=response)
    finally:
        response.close()


def _response_finding(path: str, url: str, response: Response) -> DirectoryFinding:
    """Build a finding from an HTTP response."""
    status_code = response.status_code
    exposed = _is_exposed(status_code)
    content_length = _parse_content_length(response.headers.get("Content-Length"))
    content_type = response.headers.get("Content-Type")
    status: ExposureStatus = "Expuesto" if exposed else "No expuesto"

    return {
        "path": path,
        "url": url,
        "exposed": exposed,
        "status": status,
        "status_code": status_code,
        "content_type": content_type,
        "content_length": content_length,
        "evidence": _evidence(status_code, exposed),
        "error": None,
    }


def _error_finding(path: str, url: str, error: str) -> DirectoryFinding:
    """Build a finding for a request failure."""
    return {
        "path": path,
        "url": url,
        "exposed": False,
        "status": "Error",
        "status_code": None,
        "content_type": None,
        "content_length": None,
        "evidence": "La ruta no pudo verificarse por un error HTTP.",
        "error": error,
    }


def _is_exposed(status_code: int) -> bool:
    """Return whether a status code indicates direct exposure."""
    return 200 <= status_code < 300


def _evidence(status_code: int, exposed: bool) -> str:
    """Create a concise evidence message."""
    if exposed:
        return f"La ruta respondio con HTTP {status_code}."
    return f"La ruta respondio con HTTP {status_code}; no se marca expuesta."


def _parse_content_length(value: str | None) -> int | None:
    """Parse a Content-Length header when present."""
    if value is None or not value.isdigit():
        return None
    return int(value)


def _origin_url(url: str) -> str:
    """Return the scheme and authority for a target URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _extract_target_url(scan_result: ScanResult) -> str | None:
    """Extract the target URL without assuming a successful scan."""
    target = scan_result.get("target")
    if target is None:
        return None
    return target["url"]
