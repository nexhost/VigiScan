"""Local CVE lookup module for VigiScan.

The checker uses a bundled JSON data set and performs deterministic local
searches. It does not call external vulnerability feeds, so results are only as
complete as ``data/cve_local.json``.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import NotRequired, TypedDict

from modules.tech_detect import TechDetectReport, TechnologyFinding

DATA_PACKAGE = "data"
DATA_FILE = "cve_local.json"


class CVERecord(TypedDict):
    """One local CVE record."""

    product: str
    version: str | None
    affected_version: NotRequired[str | None]
    cve: str
    cve_id: NotRequired[str]
    severity: str
    cvss: NotRequired[float | None]
    cwe: NotRequired[str | None]
    description: str
    impact: NotRequired[str]
    recommendation: NotRequired[str]
    references: NotRequired[list[str]]


class CVEMatch(TypedDict):
    """Normalized CVE match returned by the checker."""

    product: str
    detected_version: str | None
    matched_version: str | None
    affected_version: str | None
    cve: str
    cve_id: str
    severity: str
    cvss: float | None
    cwe: str | None
    description: str
    impact: str
    recommendation: str
    references: list[str]
    match_type: str


class CVECheckReport(TypedDict):
    """Normalized CVE check report."""

    module: str
    ok: bool
    source: str
    matches: list[CVEMatch]
    checked: NotRequired[list[dict[str, str | None]]]


def load_cve_database() -> tuple[CVERecord, ...]:
    """Load the bundled local CVE database."""
    content = (
        resources.files(DATA_PACKAGE)
        .joinpath(DATA_FILE)
        .read_text(encoding="utf-8")
    )
    records = json.loads(content)
    return tuple(_normalize_record(record) for record in records)


def search_cves(
    product: str,
    version: str | None = None,
    *,
    database: tuple[CVERecord, ...] | None = None,
) -> list[CVEMatch]:
    """Search local CVEs by product and optional version.

    Args:
        product: Product name to search, for example ``Apache``.
        version: Optional detected product version.
        database: Optional in-memory database for tests.

    Returns:
        CVE matches for the product. When ``version`` is provided, exact version
        matches and generic product records are returned.
    """
    records = database if database is not None else load_cve_database()
    normalized_product = _normalize_product(product)
    normalized_version = _normalize_version(version)
    matches: list[CVEMatch] = []

    for record in records:
        if _normalize_product(record["product"]) != normalized_product:
            continue
        match_type = _match_type(record["version"], normalized_version)
        if match_type is None:
            continue
        matches.append(_build_match(record, version, match_type))

    return sorted(matches, key=lambda item: (item["product"], item["cve"]))


def check_technologies(
    technologies: list[TechnologyFinding],
    *,
    database: tuple[CVERecord, ...] | None = None,
) -> CVECheckReport:
    """Search local CVEs for technology detection findings."""
    records = database if database is not None else load_cve_database()
    matches: list[CVEMatch] = []
    checked: list[dict[str, str | None]] = []

    for technology in technologies:
        product = technology["name"]
        version = technology["version"]
        checked.append({"product": product, "version": version})
        matches.extend(search_cves(product, version, database=records))

    return {
        "module": "cve_checker",
        "ok": True,
        "source": f"{DATA_PACKAGE}.{DATA_FILE}",
        "checked": checked,
        "matches": _deduplicate_matches(matches),
    }


def check_tech_report(
    report: TechDetectReport,
    *,
    database: tuple[CVERecord, ...] | None = None,
) -> CVECheckReport:
    """Search local CVEs from a full technology detection report."""
    return check_technologies(report["technologies"], database=database)


def _normalize_record(record: object) -> CVERecord:
    """Validate and normalize one JSON record."""
    if not isinstance(record, dict):
        raise ValueError("CVE database entries must be objects.")

    required_fields = {"product", "cve", "severity", "description"}
    missing = required_fields - record.keys()
    if missing:
        raise ValueError(f"CVE database entry missing fields: {sorted(missing)}")

    version = record.get("version")
    if version is not None and not isinstance(version, str):
        raise ValueError("CVE database version must be a string or null.")

    return {
        "product": str(record["product"]),
        "version": version,
        "affected_version": _optional_string(record.get("affected_version")),
        "cve": str(record["cve"]),
        "cve_id": str(record.get("cve_id", record["cve"])),
        "severity": str(record["severity"]),
        "cvss": _optional_float(record.get("cvss")),
        "cwe": _optional_string(record.get("cwe")),
        "description": str(record["description"]),
        "impact": str(record.get("impact", "Impacto no documentado en la base local.")),
        "recommendation": str(
            record.get(
                "recommendation",
                "Revisar el componente afectado, aplicar parches disponibles "
                "y validar controles compensatorios.",
            )
        ),
        "references": _string_list(record.get("references")),
    }


def _build_match(
    record: CVERecord,
    detected_version: str | None,
    match_type: str,
) -> CVEMatch:
    """Build one normalized match."""
    return {
        "product": record["product"],
        "detected_version": detected_version,
        "matched_version": record["version"],
        "affected_version": record.get("affected_version") or record["version"],
        "cve": record["cve"],
        "cve_id": record.get("cve_id", record["cve"]),
        "severity": record["severity"],
        "cvss": record.get("cvss"),
        "cwe": record.get("cwe"),
        "description": record["description"],
        "impact": record.get("impact", "Impacto no documentado en la base local."),
        "recommendation": record.get(
            "recommendation",
            "Revisar el componente afectado, aplicar parches disponibles "
            "y validar controles compensatorios.",
        ),
        "references": record.get("references", []),
        "match_type": match_type,
    }


def _match_type(
    record_version: str | None,
    detected_version: str | None,
) -> str | None:
    """Return the type of version match or ``None`` when it does not match."""
    if record_version is None:
        return "product"
    if detected_version is None:
        return None
    if _normalize_version(record_version) == detected_version:
        return "exact_version"
    return None


def _deduplicate_matches(matches: list[CVEMatch]) -> list[CVEMatch]:
    """Remove duplicate matches while preserving deterministic ordering."""
    seen: set[tuple[str, str, str | None]] = set()
    unique: list[CVEMatch] = []
    for match in sorted(matches, key=lambda item: (item["product"], item["cve"])):
        key = (match["product"].lower(), match["cve"], match["matched_version"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(match)
    return unique


def _normalize_product(product: str) -> str:
    """Normalize a product name for local comparisons."""
    return product.strip().lower()


def _normalize_version(version: str | None) -> str | None:
    """Normalize a version value for local comparisons."""
    if version is None:
        return None
    return version.strip().lower()


def _optional_string(value: object) -> str | None:
    """Return a stripped string or ``None`` for empty local metadata."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_float(value: object) -> float | None:
    """Return a float CVSS value when available."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("CVE database cvss must be numeric or null.") from exc


def _string_list(value: object) -> list[str]:
    """Normalize a references value into a list of strings."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("CVE database references must be a list of strings.")
    return [str(item) for item in value]
