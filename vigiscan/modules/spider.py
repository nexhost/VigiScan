"""Safe same-origin spider for authorized defensive discovery."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Protocol, TypedDict
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from requests import Response
from requests.exceptions import RequestException


DEFAULT_MAX_DEPTH = 1
DEFAULT_MAX_URLS = 20
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_USER_AGENT = "VigiScan/0.1.0"


class SpiderPage(TypedDict):
    """One discovered page."""

    url: str
    depth: int
    status_code: int | None
    content_type: str | None
    links: list[str]
    error: str | None


class SpiderReport(TypedDict):
    """Normalized spider output."""

    module: str
    ok: bool
    start_url: str
    max_depth: int
    max_urls: int
    discovered_count: int
    pages: list[SpiderPage]


class HTTPRequester(Protocol):
    """Minimal request callable used for tests."""

    def __call__(self, **kwargs: object) -> Response:
        """Execute an HTTP request."""


@dataclass(frozen=True, slots=True)
class SpiderConfig:
    """Safety limits for spider execution."""

    max_depth: int = DEFAULT_MAX_DEPTH
    max_urls: int = DEFAULT_MAX_URLS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    user_agent: str = DEFAULT_USER_AGENT

    def __post_init__(self) -> None:
        if self.max_depth < 0:
            raise ValueError("max_depth must be zero or greater.")
        if self.max_urls <= 0:
            raise ValueError("max_urls must be greater than zero.")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")


def crawl_site(
    start_url: str,
    *,
    config: SpiderConfig | None = None,
    requester: HTTPRequester | None = None,
) -> SpiderReport:
    """Discover same-origin links without submitting forms or brute forcing."""
    settings = config or SpiderConfig()
    request = requester or requests.get
    origin = _origin(start_url)
    queue: deque[tuple[str, int]] = deque([(_normalize_url(start_url), 0)])
    queued = {_normalize_url(start_url)}
    visited: set[str] = set()
    pages: list[SpiderPage] = []

    while queue and len(pages) < settings.max_urls:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        page = _fetch_page(url, depth, settings, request)
        pages.append(page)

        if depth >= settings.max_depth or page["error"] is not None:
            continue
        for link in page["links"]:
            if len(queued) >= settings.max_urls:
                break
            normalized = _normalize_url(link)
            if normalized in queued or _origin(normalized) != origin:
                continue
            queued.add(normalized)
            queue.append((normalized, depth + 1))

    return {
        "module": "spider",
        "ok": True,
        "start_url": start_url,
        "max_depth": settings.max_depth,
        "max_urls": settings.max_urls,
        "discovered_count": len(pages),
        "pages": pages,
    }


def _fetch_page(
    url: str,
    depth: int,
    config: SpiderConfig,
    requester: HTTPRequester,
) -> SpiderPage:
    try:
        response = requester(
            url=url,
            headers={"User-Agent": config.user_agent, "Accept": "text/html,*/*"},
            timeout=config.timeout_seconds,
            allow_redirects=False,
            stream=False,
            verify=True,
        )
    except RequestException as exc:
        return {
            "url": url,
            "depth": depth,
            "status_code": None,
            "content_type": None,
            "links": [],
            "error": str(exc),
        }

    content_type = response.headers.get("Content-Type")
    body = response.text if _is_html(content_type) else ""
    links = _extract_links(url, body)
    return {
        "url": url,
        "depth": depth,
        "status_code": response.status_code,
        "content_type": content_type,
        "links": links,
        "error": None,
    }


def _extract_links(base_url: str, body: str) -> list[str]:
    parser = _LinkParser(base_url)
    parser.feed(body)
    return sorted(parser.links)


class _LinkParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self._base_url = base_url
        self.links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if not href:
            return
        absolute = _normalize_url(urljoin(self._base_url, href))
        if absolute.startswith(("http://", "https://")):
            self.links.add(absolute)


def _is_html(content_type: str | None) -> bool:
    return content_type is None or "html" in content_type.lower()


def _normalize_url(url: str) -> str:
    without_fragment, _fragment = urldefrag(url.strip())
    return without_fragment.rstrip("/") or without_fragment


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
