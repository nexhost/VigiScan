"""Technology detection module for VigiScan.

This module consumes the normalized ``ScanResult`` from ``scanner``
and infers common web technologies from HTTP headers, cookies, meta tags, and
HTML content. Findings include a name, optional version, numeric confidence,
and a human-readable confidence level.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, TypedDict

from scanner import ScanResult

ConfidenceLevel = Literal["Alto", "Medio", "Bajo"]


class TechnologyFinding(TypedDict):
    """Normalized technology finding for downstream modules."""

    name: str
    version: str | None
    confidence: int
    confidence_level: ConfidenceLevel
    evidence: list[str]


class TechDetectReport(TypedDict):
    """Normalized technology detection report."""

    module: str
    ok: bool
    target_url: str | None
    technologies: list[TechnologyFinding]


@dataclass(slots=True)
class TechnologyCandidate:
    """Internal detection candidate before findings are merged."""

    name: str
    confidence: int
    evidence: str
    version: str | None = None


@dataclass(slots=True)
class TechnologyAccumulator:
    """Merged technology evidence."""

    name: str
    version: str | None = None
    confidence: int = 0
    evidence: list[str] = field(default_factory=list)

    def add(self, candidate: TechnologyCandidate) -> None:
        """Merge one candidate into the accumulated finding."""
        should_replace_version = (
            candidate.version
            and (not self.version or candidate.confidence >= self.confidence)
        )
        if should_replace_version:
            self.version = candidate.version
        self.confidence = min(100, max(self.confidence, candidate.confidence))
        if candidate.evidence not in self.evidence:
            self.evidence.append(candidate.evidence)


def analyze_technologies(scan_result: ScanResult) -> TechDetectReport:
    """Detect technologies from a normalized scanner result.

    Args:
        scan_result: JSON-compatible result returned by ``Scanner.scan``.

    Returns:
        A normalized report containing detected technology names, versions,
        confidence scores, confidence levels, and evidence strings.
    """
    response = scan_result.get("response")
    headers = _normalize_headers(response["headers"] if response is not None else {})
    html = response["body_sample"] if response is not None else ""
    cookies = _extract_cookies(headers)

    candidates: list[TechnologyCandidate] = []
    candidates.extend(_detect_from_headers(headers))
    candidates.extend(_detect_from_cookies(cookies))
    candidates.extend(_detect_from_meta_tags(html))
    candidates.extend(_detect_from_html(html))

    return {
        "module": "tech_detect",
        "ok": scan_result["ok"],
        "target_url": _extract_target_url(scan_result),
        "technologies": _merge_candidates(candidates),
    }


def _detect_from_headers(headers: dict[str, str]) -> list[TechnologyCandidate]:
    """Detect technologies exposed by HTTP headers."""
    candidates: list[TechnologyCandidate] = []
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    pingback = headers.get("x-pingback", "")

    apache_version = _extract_product_version("Apache", server)
    if apache_version or _contains_word("Apache", server):
        candidates.append(
            TechnologyCandidate(
                name="Apache",
                version=apache_version,
                confidence=95 if apache_version else 85,
                evidence="Header Server contiene Apache.",
            ),
        )

    nginx_version = _extract_product_version("nginx", server)
    if nginx_version or _contains_word("nginx", server):
        candidates.append(
            TechnologyCandidate(
                name="Nginx",
                version=nginx_version,
                confidence=95 if nginx_version else 85,
                evidence="Header Server contiene nginx.",
            ),
        )

    openssl_version = _extract_product_version("OpenSSL", server)
    if openssl_version or _contains_word("OpenSSL", server):
        candidates.append(
            TechnologyCandidate(
                name="OpenSSL",
                version=openssl_version,
                confidence=90 if openssl_version else 80,
                evidence="Header Server contiene OpenSSL.",
            ),
        )

    php_version = _extract_product_version("PHP", powered_by)
    if php_version or _contains_word("PHP", powered_by):
        candidates.append(
            TechnologyCandidate(
                name="PHP",
                version=php_version,
                confidence=95 if php_version else 85,
                evidence="Header X-Powered-By contiene PHP.",
            ),
        )

    if _contains_word("Laravel", powered_by):
        candidates.append(
            TechnologyCandidate(
                name="Laravel",
                version=_extract_product_version("Laravel", powered_by),
                confidence=90,
                evidence="Header X-Powered-By contiene Laravel.",
            ),
        )

    if "wp-" in pingback.lower() or "xmlrpc.php" in pingback.lower():
        candidates.append(
            TechnologyCandidate(
                name="WordPress",
                version=None,
                confidence=80,
                evidence="Header X-Pingback apunta a endpoints de WordPress.",
            ),
        )

    return candidates


def _detect_from_cookies(cookie_header: str) -> list[TechnologyCandidate]:
    """Detect technologies exposed by cookies."""
    lower_cookies = cookie_header.lower()
    candidates: list[TechnologyCandidate] = []

    if "phpsessid" in lower_cookies:
        candidates.append(
            TechnologyCandidate(
                name="PHP",
                version=None,
                confidence=75,
                evidence="Cookie PHPSESSID detectada.",
            ),
        )

    if "wordpress_" in lower_cookies or "wp-settings-" in lower_cookies:
        candidates.append(
            TechnologyCandidate(
                name="WordPress",
                version=None,
                confidence=80,
                evidence="Cookie de WordPress detectada.",
            ),
        )

    if "laravel_session" in lower_cookies or "xsrf-token" in lower_cookies:
        candidates.append(
            TechnologyCandidate(
                name="Laravel",
                version=None,
                confidence=85,
                evidence="Cookie de Laravel detectada.",
            ),
        )

    return candidates


def _detect_from_meta_tags(html: str) -> list[TechnologyCandidate]:
    """Detect technologies from HTML meta tags."""
    candidates: list[TechnologyCandidate] = []
    generator = _extract_meta_generator(html)
    if not generator:
        return candidates

    wordpress_version = _extract_wordpress_version(generator)
    if wordpress_version or _contains_word("WordPress", generator):
        candidates.append(
            TechnologyCandidate(
                name="WordPress",
                version=wordpress_version,
                confidence=95 if wordpress_version else 90,
                evidence="Meta generator contiene WordPress.",
            ),
        )

    return candidates


def _detect_from_html(html: str) -> list[TechnologyCandidate]:
    """Detect technologies from generic HTML content."""
    lower_html = html.lower()
    candidates: list[TechnologyCandidate] = []

    if "wp-content/" in lower_html or "wp-includes/" in lower_html:
        candidates.append(
            TechnologyCandidate(
                name="WordPress",
                version=None,
                confidence=85,
                evidence="HTML referencia rutas wp-content o wp-includes.",
            ),
        )

    if re.search(r"\bname\s*=\s*['\"]csrf-token['\"]", html, re.IGNORECASE):
        if "laravel" in lower_html:
            candidates.append(
                TechnologyCandidate(
                    name="Laravel",
                    version=None,
                    confidence=70,
                    evidence="HTML contiene csrf-token y referencias a Laravel.",
                ),
            )

    if re.search(r"\.php(?:[?'\"]|$)", html, re.IGNORECASE):
        candidates.append(
            TechnologyCandidate(
                name="PHP",
                version=None,
                confidence=55,
                evidence="HTML referencia rutas con extension .php.",
            ),
        )

    return candidates


def _merge_candidates(
    candidates: list[TechnologyCandidate],
) -> list[TechnologyFinding]:
    """Merge duplicate candidates into final technology findings."""
    merged: dict[str, TechnologyAccumulator] = {}
    for candidate in candidates:
        accumulator = merged.setdefault(
            candidate.name,
            TechnologyAccumulator(name=candidate.name),
        )
        accumulator.add(candidate)

    findings: list[TechnologyFinding] = [
        {
            "name": item.name,
            "version": item.version,
            "confidence": item.confidence,
            "confidence_level": _confidence_level(item.confidence),
            "evidence": item.evidence,
        }
        for item in merged.values()
    ]
    return sorted(findings, key=lambda item: (-item["confidence"], item["name"]))


def _extract_product_version(product: str, value: str) -> str | None:
    """Extract a product version from strings like ``Apache/2.4.58``."""
    pattern = rf"\b{re.escape(product)}\s*/\s*([A-Za-z0-9][A-Za-z0-9._+-]*)"
    match = re.search(pattern, value, flags=re.IGNORECASE)
    if match is None:
        return None
    return match.group(1)


def _extract_wordpress_version(value: str) -> str | None:
    """Extract WordPress versions from generator values."""
    slash_version = _extract_product_version("WordPress", value)
    if slash_version:
        return slash_version

    match = re.search(
        r"\bWordPress\s+([0-9][A-Za-z0-9._+-]*)",
        value,
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    return match.group(1)


def _extract_meta_generator(html: str) -> str | None:
    """Extract a generator meta tag content value from HTML."""
    for match in re.finditer(r"<meta\b[^>]*>", html, flags=re.IGNORECASE):
        tag = match.group(0)
        if not re.search(
            r"\bname\s*=\s*['\"]generator['\"]",
            tag,
            flags=re.IGNORECASE,
        ):
            continue
        content_match = re.search(
            r"\bcontent\s*=\s*['\"]([^'\"]+)['\"]",
            tag,
            flags=re.IGNORECASE,
        )
        if content_match is not None:
            return content_match.group(1)
    return None


def _extract_cookies(headers: dict[str, str]) -> str:
    """Extract cookie values from normalized response headers."""
    cookie_values = [
        value
        for name, value in headers.items()
        if name in {"set-cookie", "cookie"}
    ]
    return "\n".join(cookie_values)


def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Normalize HTTP header names to lower case."""
    return {name.lower(): value for name, value in headers.items()}


def _contains_word(word: str, value: str) -> bool:
    """Return whether a product-like token exists in a value."""
    return re.search(rf"\b{re.escape(word)}\b", value, re.IGNORECASE) is not None


def _confidence_level(confidence: int) -> ConfidenceLevel:
    """Translate a numeric confidence score to a level."""
    if confidence >= 85:
        return "Alto"
    if confidence >= 60:
        return "Medio"
    return "Bajo"


def _extract_target_url(scan_result: ScanResult) -> str | None:
    """Extract the target URL without assuming a successful scan."""
    target = scan_result.get("target")
    if target is None:
        return None
    return target["url"]
