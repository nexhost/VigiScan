"""HTTP security header analysis module.

The module consumes the normalized ``ScanResult`` produced by
``vigiscan.scanner``. It detects common browser security headers, classifies
missing or weak values as ``Alto``, ``Medio`` or ``Bajo``, and can render the
results as a Rich table for the command line interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypedDict

from rich.console import Console
from rich.table import Table
from rich.text import Text

from vigiscan.scanner import ScanResult

Severity = Literal["Alto", "Medio", "Bajo"]
HeaderStatus = Literal["Presente", "Ausente", "Debil"]


class HeaderFinding(TypedDict):
    """Normalized finding for one expected HTTP security header."""

    header: str
    present: bool
    status: HeaderStatus
    severity: Severity
    value: str | None
    recommendation: str


class HeadersReport(TypedDict):
    """Normalized report returned by the headers module."""

    module: str
    ok: bool
    target_url: str | None
    overall_severity: Severity
    findings: list[HeaderFinding]


@dataclass(frozen=True, slots=True)
class HeaderRule:
    """Detection and classification rule for one security header."""

    name: str
    missing_severity: Severity
    missing_recommendation: str


HEADER_RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        name="Content-Security-Policy",
        missing_severity="Alto",
        missing_recommendation="Definir una politica CSP para reducir XSS e inyeccion.",
    ),
    HeaderRule(
        name="X-Frame-Options",
        missing_severity="Medio",
        missing_recommendation="Usar DENY o SAMEORIGIN para mitigar clickjacking.",
    ),
    HeaderRule(
        name="X-Content-Type-Options",
        missing_severity="Medio",
        missing_recommendation=(
            "Usar nosniff para evitar interpretacion de tipos insegura."
        ),
    ),
    HeaderRule(
        name="Strict-Transport-Security",
        missing_severity="Alto",
        missing_recommendation="Configurar HSTS con max-age para forzar HTTPS.",
    ),
    HeaderRule(
        name="Referrer-Policy",
        missing_severity="Bajo",
        missing_recommendation="Definir una politica de referrer explicita.",
    ),
    HeaderRule(
        name="Permissions-Policy",
        missing_severity="Medio",
        missing_recommendation="Restringir APIs del navegador no requeridas.",
    ),
)

SEVERITY_RANK: dict[Severity, int] = {
    "Bajo": 1,
    "Medio": 2,
    "Alto": 3,
}

SEVERITY_STYLE: dict[Severity, str] = {
    "Alto": "bold red",
    "Medio": "yellow",
    "Bajo": "green",
}

STATUS_STYLE: dict[HeaderStatus, str] = {
    "Presente": "green",
    "Ausente": "bold red",
    "Debil": "yellow",
}


def analyze_headers(scan_result: ScanResult) -> HeadersReport:
    """Analyze security headers from a normalized scan result.

    Args:
        scan_result: JSON-compatible result returned by ``Scanner.scan``.

    Returns:
        A normalized headers report suitable for future modules, JSON output,
        or Rich rendering.
    """
    target_url = _extract_target_url(scan_result)
    response = scan_result.get("response")
    raw_headers = response["headers"] if response is not None else {}
    headers = _normalize_header_names(raw_headers)

    findings = [_build_finding(rule, headers) for rule in HEADER_RULES]
    return {
        "module": "headers",
        "ok": scan_result["ok"],
        "target_url": target_url,
        "overall_severity": _overall_severity(findings),
        "findings": findings,
    }


def render_headers_report(
    report: HeadersReport,
    *,
    console: Console | None = None,
) -> None:
    """Render a headers report using Rich."""
    output = console or Console()
    title = "VigiScan - HTTP Security Headers"
    if report["target_url"]:
        title = f"{title} - {report['target_url']}"

    table = Table(title=title, show_lines=True)
    table.add_column("Header", style="bold")
    table.add_column("Estado", justify="center")
    table.add_column("Riesgo", justify="center")
    table.add_column("Valor", overflow="fold")
    table.add_column("Recomendacion", overflow="fold")

    for finding in report["findings"]:
        table.add_row(
            finding["header"],
            Text(finding["status"], style=STATUS_STYLE[finding["status"]]),
            Text(finding["severity"], style=SEVERITY_STYLE[finding["severity"]]),
            Text(finding["value"] or "-"),
            finding["recommendation"],
        )

    output.print(table)


def _build_finding(
    rule: HeaderRule,
    headers: dict[str, str],
) -> HeaderFinding:
    """Build one normalized header finding."""
    value = headers.get(rule.name.lower())
    if value is None:
        return {
            "header": rule.name,
            "present": False,
            "status": "Ausente",
            "severity": rule.missing_severity,
            "value": None,
            "recommendation": rule.missing_recommendation,
        }

    status, severity, recommendation = _evaluate_header_value(rule.name, value)
    return {
        "header": rule.name,
        "present": True,
        "status": status,
        "severity": severity,
        "value": value,
        "recommendation": recommendation,
    }


def _evaluate_header_value(
    header_name: str,
    value: str,
) -> tuple[HeaderStatus, Severity, str]:
    """Classify present header values that are empty or weak."""
    normalized_value = value.strip().lower()
    if not normalized_value:
        return "Debil", "Medio", "El header existe, pero su valor esta vacio."

    match header_name:
        case "X-Frame-Options":
            if normalized_value not in {"deny", "sameorigin"}:
                return "Debil", "Medio", "Usar DENY o SAMEORIGIN."
        case "X-Content-Type-Options":
            if normalized_value != "nosniff":
                return "Debil", "Medio", "Usar el valor nosniff."
        case "Strict-Transport-Security":
            if "max-age=" not in normalized_value:
                return "Debil", "Medio", "Incluir max-age en la politica HSTS."
        case "Referrer-Policy":
            if normalized_value == "unsafe-url":
                return "Debil", "Bajo", "Evitar unsafe-url para reducir filtrado."

    return "Presente", "Bajo", "Sin accion inmediata."


def _normalize_header_names(headers: dict[str, str]) -> dict[str, str]:
    """Normalize header names to lower case for case-insensitive matching."""
    return {name.lower(): value for name, value in headers.items()}


def _overall_severity(findings: list[HeaderFinding]) -> Severity:
    """Return the highest risk level among findings."""
    return max(findings, key=lambda item: SEVERITY_RANK[item["severity"]])["severity"]


def _extract_target_url(scan_result: ScanResult) -> str | None:
    """Extract the target URL without assuming a successful scan."""
    target = scan_result.get("target")
    if target is None:
        return None
    return target["url"]
