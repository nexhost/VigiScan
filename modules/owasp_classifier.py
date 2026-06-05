"""OWASP Top 10 2025 classification helpers for VigiScan findings."""

from __future__ import annotations

import re
from typing import Any, TypedDict

from scanner import ScanResult


class OWASPFinding(TypedDict):
    """Normalized OWASP classification shown in web reports."""

    finding: str
    severity: str
    category_id: str
    category: str
    recommendation: str
    source: str


OWASP_CATEGORIES: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Logging & Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}


def owasp_category_label(category_id: str) -> str:
    """Return a display label for an OWASP category id."""
    return f"{category_id}: {OWASP_CATEGORIES[category_id]}"


def analyze_surface_signals(scan_result: ScanResult) -> dict[str, Any]:
    """Extract passive page signals used by OWASP classification.

    This only analyzes metadata and the bounded body sample already collected by
    the scanner. It does not submit forms or send additional payloads.
    """
    findings: list[dict[str, str]] = []
    target = scan_result.get("target")
    response = scan_result.get("response")

    if target and target.get("scheme") == "http":
        findings.append(
            {
                "type": "no_tls",
                "finding": "Objetivo accesible por HTTP sin TLS.",
                "severity": "Alto",
                "recommendation": "Forzar HTTPS, redirigir HTTP a HTTPS y validar certificados TLS vigentes.",
            }
        )

    body_sample = response.get("body_sample", "") if response else ""
    if _has_form_without_basic_token(body_sample):
        findings.append(
            {
                "type": "form_without_basic_protection",
                "finding": "Formulario HTML sin token anti-CSRF visible en la respuesta inicial.",
                "severity": "Medio",
                "recommendation": "Agregar proteccion anti-CSRF, cookies seguras y validacion del lado servidor para formularios sensibles.",
            }
        )

    if _has_visible_error(body_sample):
        findings.append(
            {
                "type": "visible_error",
                "finding": "Errores tecnicos o stack traces visibles en la respuesta.",
                "severity": "Medio",
                "recommendation": "Usar manejo centralizado de errores, registrar detalles internamente y mostrar mensajes genericos al usuario.",
            }
        )

    return {
        "module": "surface",
        "ok": scan_result["ok"],
        "target_url": target["url"] if target else None,
        "findings": findings,
    }


def classify_owasp_findings(
    target_url: str | None,
    modules: dict[str, Any],
) -> list[OWASPFinding]:
    """Classify known VigiScan findings against OWASP Top 10 2025."""
    findings: list[OWASPFinding] = []
    findings.extend(_classify_headers(modules.get("headers")))
    findings.extend(_classify_directories(modules.get("directories")))
    findings.extend(_classify_cves(modules.get("cve_checker")))
    findings.extend(_classify_surface(modules.get("surface"), target_url))
    return _deduplicate(findings)


def available_owasp_filters() -> list[dict[str, str]]:
    """Return category options for dashboard/report filters."""
    return [
        {"id": category_id, "label": owasp_category_label(category_id)}
        for category_id in OWASP_CATEGORIES
    ]


def _classify_headers(report: Any) -> list[OWASPFinding]:
    if not isinstance(report, dict):
        return []
    output: list[OWASPFinding] = []
    for item in _dicts(report.get("findings")):
        if item.get("status") == "Presente":
            continue
        header = str(item.get("header") or "Header desconocido")
        output.append(
            _finding(
                finding=f"Header faltante o debil: {header}.",
                severity=str(item.get("severity") or "Medio"),
                category_id="A02",
                recommendation=str(
                    item.get("recommendation")
                    or "Revisar la configuracion de headers de seguridad."
                ),
                source="headers",
            )
        )
    return output


def _classify_directories(report: Any) -> list[OWASPFinding]:
    if not isinstance(report, dict):
        return []
    output: list[OWASPFinding] = []
    for item in _dicts(report.get("findings")):
        if item.get("exposed") is not True:
            continue
        path = str(item.get("path") or "ruta desconocida").strip()
        normalized = path.strip("/").lower()
        if normalized == ".git":
            output.append(
                _finding(
                    finding="Repositorio .git expuesto.",
                    severity="Alto",
                    category_id="A08",
                    recommendation="Bloquear acceso publico a .git, remover artefactos internos expuestos y revisar integridad del despliegue.",
                    source="directories",
                )
            )
        elif normalized == ".env":
            output.append(
                _finding(
                    finding="Archivo .env expuesto.",
                    severity="Alto",
                    category_id="A02",
                    recommendation="Retirar secretos del webroot, rotar credenciales expuestas y bloquear archivos de configuracion.",
                    source="directories",
                )
            )
        else:
            output.append(
                _finding(
                    finding=f"Ruta sensible expuesta: {path}.",
                    severity="Medio",
                    category_id="A02",
                    recommendation="Restringir rutas internas y publicar solo archivos requeridos por la aplicacion.",
                    source="directories",
                )
            )
    return output


def _classify_cves(report: Any) -> list[OWASPFinding]:
    if not isinstance(report, dict):
        return []
    output: list[OWASPFinding] = []
    for item in _dicts(report.get("matches")):
        cve_id = item.get("cve_id") or item.get("cve") or "CVE desconocida"
        product = item.get("product") or "producto desconocido"
        output.append(
            _finding(
                finding=f"Tecnologia vulnerable por CVE: {cve_id} en {product}.",
                severity=str(item.get("severity") or "Medio"),
                category_id="A03",
                recommendation=str(
                    item.get("recommendation")
                    or "Actualizar el componente afectado y revisar dependencias."
                ),
                source="cve_checker",
            )
        )
    return output


def _classify_surface(report: Any, target_url: str | None) -> list[OWASPFinding]:
    output: list[OWASPFinding] = []
    if target_url and target_url.lower().startswith("http://"):
        output.append(
            _finding(
                finding="HTTPS debil o sin TLS: el objetivo usa HTTP.",
                severity="Alto",
                category_id="A04",
                recommendation="Forzar HTTPS, redirigir HTTP a HTTPS y revisar configuracion TLS.",
                source="surface",
            )
        )
    if not isinstance(report, dict):
        return output
    for item in _dicts(report.get("findings")):
        signal_type = item.get("type")
        if signal_type == "no_tls":
            continue
        if signal_type == "form_without_basic_protection":
            output.append(
                _finding(
                    finding=str(item.get("finding")),
                    severity=str(item.get("severity") or "Medio"),
                    category_id="A07",
                    recommendation=str(item.get("recommendation")),
                    source="surface",
                )
            )
        elif signal_type == "visible_error":
            output.append(
                _finding(
                    finding=str(item.get("finding")),
                    severity=str(item.get("severity") or "Medio"),
                    category_id="A10",
                    recommendation=str(item.get("recommendation")),
                    source="surface",
                )
            )
        elif signal_type == "logging_alerting_missing":
            output.append(
                _finding(
                    finding=str(item.get("finding")),
                    severity=str(item.get("severity") or "Medio"),
                    category_id="A09",
                    recommendation=str(item.get("recommendation")),
                    source="surface",
                )
            )
    return output


def _finding(
    *,
    finding: str,
    severity: str,
    category_id: str,
    recommendation: str,
    source: str,
) -> OWASPFinding:
    return {
        "finding": finding,
        "severity": severity,
        "category_id": category_id,
        "category": owasp_category_label(category_id),
        "recommendation": recommendation,
        "source": source,
    }


def _deduplicate(findings: list[OWASPFinding]) -> list[OWASPFinding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[OWASPFinding] = []
    for finding in findings:
        key = (
            finding["category_id"],
            finding["source"],
            finding["finding"].lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _has_form_without_basic_token(body_sample: str) -> bool:
    if "<form" not in body_sample.lower():
        return False
    token_pattern = re.compile(
        r'name=["\']?(csrf|csrf_token|_csrf|authenticity_token|token)["\']?',
        re.IGNORECASE,
    )
    return token_pattern.search(body_sample) is None


def _has_visible_error(body_sample: str) -> bool:
    patterns = (
        r"Traceback \(most recent call last\)",
        r"\bStack trace\b",
        r"\bFatal error\b",
        r"\bUnhandled exception\b",
        r"\bNullReferenceException\b",
        r"\bSQLException\b",
        r"\bWarning:\s",
        r"\bNotice:\s",
    )
    return any(re.search(pattern, body_sample, re.IGNORECASE) for pattern in patterns)


def _dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
