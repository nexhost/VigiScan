"""HTTP scanner primitives for VigiScan.

This module owns the first network boundary of the application. It validates a
target URL, performs a bounded HTTP request, and returns a JSON-serializable
payload that future scanner modules can consume without depending on
``requests`` internals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter
from typing import NotRequired, TypedDict
from urllib.parse import ParseResult, urlparse

import requests
from requests import Response
from requests.exceptions import RequestException

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_BODY_BYTES = 64 * 1024
DEFAULT_USER_AGENT = "VigiScan/0.1.0"


class ScannerError(ValueError):
    """Raised when scanner input cannot be processed safely."""


class TargetInfo(TypedDict):
    """Normalized target metadata derived from a validated URL."""

    url: str
    scheme: str
    hostname: str
    port: int | None
    path: str


class RequestInfo(TypedDict):
    """Normalized outbound HTTP request metadata."""

    method: str
    timeout_seconds: float
    max_body_bytes: int
    allow_redirects: bool


class ResponseInfo(TypedDict):
    """Normalized inbound HTTP response metadata."""

    status_code: int
    reason: str
    final_url: str
    elapsed_ms: int
    headers: dict[str, str]
    body_sample: str
    body_truncated: bool
    content_length: NotRequired[int]


class ErrorInfo(TypedDict):
    """Normalized error metadata for validation and request failures."""

    type: str
    message: str


class ScanResult(TypedDict):
    """JSON-serializable contract returned to future scanner modules."""

    ok: bool
    target: TargetInfo | None
    request: RequestInfo
    response: ResponseInfo | None
    error: ErrorInfo | None


@dataclass(frozen=True, slots=True)
class ScanRequest:
    """Input data required to perform an initial HTTP scan.

    Attributes:
        url: Absolute HTTP or HTTPS URL to request.
    """

    url: str


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    """Runtime controls for outbound HTTP requests.

    Attributes:
        timeout_seconds: Maximum time ``requests`` may spend connecting and
            reading the response.
        max_body_bytes: Maximum number of response bytes captured in
            ``body_sample``.
        allow_redirects: Whether the initial request should follow redirects.
        user_agent: User-Agent header sent by VigiScan.
    """

    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    allow_redirects: bool = False
    user_agent: str = DEFAULT_USER_AGENT
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate scanner safety limits when configuration is created."""
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")
        if self.max_body_bytes < 0:
            raise ValueError("max_body_bytes must be zero or greater.")


class Scanner:
    """Coordinates HTTP scan workflows as modules are added."""

    def __init__(self, config: ScannerConfig | None = None) -> None:
        """Initialize a scanner with explicit request safety controls."""
        self._config = config or ScannerConfig()

    def scan(self, request: ScanRequest) -> ScanResult:
        """Validate a URL, perform a bounded GET request, and normalize output.

        The method never raises for validation or network failures. Instead, it
        returns a stable JSON-compatible structure with ``ok=False`` and an
        ``error`` object, allowing future modules to handle failures uniformly.
        """
        request_info = self._build_request_info()

        try:
            target = self._validate_url(request.url)
        except ScannerError as exc:
            return self._failure_result(
                request_info=request_info,
                error_type=exc.__class__.__name__,
                message=str(exc),
            )

        try:
            response, elapsed_ms = self._request(target["url"])
            response_info = self._normalize_response(response, elapsed_ms)
        except RequestException as exc:
            return self._failure_result(
                request_info=request_info,
                error_type=exc.__class__.__name__,
                message=str(exc),
                target=target,
            )

        return {
            "ok": True,
            "target": target,
            "request": request_info,
            "response": response_info,
            "error": None,
        }

    def prepare(self, request: ScanRequest) -> ScanResult:
        """Backward-compatible alias for the initial scan workflow."""
        return self.scan(request)

    def _request(self, url: str) -> tuple[Response, int]:
        """Execute a safe, bounded HTTP GET request."""
        headers = {
            "User-Agent": self._config.user_agent,
            "Accept": "*/*",
            **self._config.headers,
        }
        start = perf_counter()
        response = requests.get(
            url=url,
            headers=headers,
            timeout=self._config.timeout_seconds,
            allow_redirects=self._config.allow_redirects,
            stream=True,
            verify=True,
        )
        elapsed_ms = int((perf_counter() - start) * 1000)
        return response, elapsed_ms

    def _normalize_response(self, response: Response, elapsed_ms: int) -> ResponseInfo:
        """Convert a ``requests.Response`` into JSON-safe metadata."""
        body_bytes, body_truncated = self._read_limited_body(response)
        content_length = response.headers.get("Content-Length")
        normalized: ResponseInfo = {
            "status_code": response.status_code,
            "reason": response.reason,
            "final_url": response.url,
            "elapsed_ms": elapsed_ms,
            "headers": dict(response.headers),
            "body_sample": body_bytes.decode(response.encoding or "utf-8", "replace"),
            "body_truncated": body_truncated,
        }
        if content_length is not None and content_length.isdigit():
            normalized["content_length"] = int(content_length)
            normalized["body_truncated"] = (
                body_truncated or int(content_length) > self._config.max_body_bytes
            )
        return normalized

    def _read_limited_body(self, response: Response) -> tuple[bytes, bool]:
        """Read at most the configured number of response bytes."""
        chunks: list[bytes] = []
        total_bytes = 0
        truncated = False
        try:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                remaining = self._config.max_body_bytes - total_bytes
                if remaining <= 0:
                    truncated = True
                    break
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    truncated = True
                    break
                chunks.append(chunk)
                total_bytes += len(chunk)
        finally:
            response.close()
        return b"".join(chunks), truncated

    def _validate_url(self, raw_url: str) -> TargetInfo:
        """Validate and normalize a user-provided HTTP target URL."""
        parsed = urlparse(raw_url.strip())
        self._assert_valid_url(parsed)

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        return {
            "url": parsed.geturl(),
            "scheme": parsed.scheme.lower(),
            "hostname": parsed.hostname or "",
            "port": parsed.port,
            "path": path,
        }

    def _assert_valid_url(self, parsed: ParseResult) -> None:
        """Raise ``ScannerError`` if the parsed URL is not requestable."""
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ScannerError("URL scheme must be http or https.")
        if not parsed.netloc or not parsed.hostname:
            raise ScannerError("URL must include a hostname.")
        if parsed.username or parsed.password:
            raise ScannerError("URL credentials are not allowed.")
        if parsed.fragment:
            raise ScannerError("URL fragments are not sent in HTTP requests.")
        try:
            parsed.port
        except ValueError as exc:
            raise ScannerError("URL port is invalid.") from exc

    def _build_request_info(self) -> RequestInfo:
        """Build normalized outbound request metadata."""
        return {
            "method": "GET",
            "timeout_seconds": self._config.timeout_seconds,
            "max_body_bytes": self._config.max_body_bytes,
            "allow_redirects": self._config.allow_redirects,
        }

    def _failure_result(
        self,
        *,
        request_info: RequestInfo,
        error_type: str,
        message: str,
        target: TargetInfo | None = None,
    ) -> ScanResult:
        """Build a normalized failure result."""
        return {
            "ok": False,
            "target": target,
            "request": request_info,
            "response": None,
            "error": {
                "type": error_type,
                "message": message,
            },
        }


def create_scanner(config: ScannerConfig | None = None) -> Scanner:
    """Create the scanner orchestration service."""
    return Scanner(config=config)
