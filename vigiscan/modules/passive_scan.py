"""Passive defensive analysis for HTTP responses and scan module output."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, TypedDict
from urllib.parse import urlparse

from scanner import ScanResult
from vigiscan.modules.alerts import Alert, create_alert, severity_counts


class PassiveScanReport(TypedDict):
    """Normalized passive scan report."""

    module: str
    ok: bool
    target_url: str | None
    alerts: list[Alert]
    severity_counts: dict[str, int]


def analyze_passive(
    scan_result: ScanResult,
    *,
    headers_report: dict[str, Any] | None = None,
    directories_report: dict[str, Any] | None = None,
) -> PassiveScanReport:
    """Analyze passive evidence without sending payloads or submitting forms."""
    target = scan_result.get("target")
    response = scan_result.get("response")
    target_url = target["url"] if target else None
    headers = response.get("headers", {}) if response else {}
    body = response.get("body_sample", "") if response else ""
    alerts: list[Alert] = []

    alerts.extend(_alerts_from_headers(headers_report))
    alerts.extend(_alerts_from_cookies(headers))
    alerts.extend(_alerts_from_html(body, target_url))
    alerts.extend(_alerts_from_versions(headers, body))
    alerts.extend(_alerts_from_visible_errors(body))
    alerts.extend(_alerts_from_directories(directories_report))

    return {
        "module": "passive_scan",
        "ok": scan_result["ok"],
        "target_url": target_url,
        "alerts": alerts,
        "severity_counts": dict(severity_counts(alerts)),
    }


def _alerts_from_headers(headers_report: dict[str, Any] | None) -> list[Alert]:
    if not isinstance(headers_report, dict):
        return []
    alerts: list[Alert] = []
    for finding in _dicts(headers_report.get("findings")):
        if finding.get("status") == "Presente":
            continue
        severity = "High" if finding.get("severity") == "Alto" else "Medium"
        alerts.append(
            create_alert(
                title=f"Header {finding.get('header')} faltante o debil",
                severity=severity,
                description="La respuesta no aplica una cabecera defensiva esperada.",
                evidence=str(finding.get("status") or "No disponible"),
                recommendation=str(
                    finding.get("recommendation")
                    or "Configurar headers de seguridad apropiados."
                ),
                source="passive_scan",
                owasp_category="A02: Security Misconfiguration",
            )
        )
    return alerts


def _alerts_from_cookies(headers: dict[str, str]) -> list[Alert]:
    raw = _header_value(headers, "Set-Cookie")
    if not raw:
        return []
    alerts: list[Alert] = []
    for cookie in _split_cookies(raw):
        lower = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        if "httponly" not in lower:
            alerts.append(_cookie_alert(name, "HttpOnly"))
        if "secure" not in lower:
            alerts.append(_cookie_alert(name, "Secure"))
        if "samesite" not in lower:
            alerts.append(_cookie_alert(name, "SameSite"))
    return alerts


def _alerts_from_html(body: str, target_url: str | None) -> list[Alert]:
    parser = _PassiveHTMLParser()
    parser.feed(body)
    alerts: list[Alert] = []
    if parser.forms and not parser.has_csrf_token:
        alerts.append(
            create_alert(
                title="Formulario sin CSRF visible",
                severity="Medium",
                description="Se encontro un formulario sin token anti-CSRF visible en el HTML inicial.",
                evidence=f"{parser.forms} formulario(s) detectado(s).",
                recommendation="Agregar proteccion anti-CSRF y validacion del lado servidor para formularios sensibles.",
                source="passive_scan",
                owasp_category="A07: Authentication Failures",
            )
        )
    if parser.has_password_input and target_url and urlparse(target_url).scheme == "http":
        alerts.append(
            create_alert(
                title="Formulario login sin HTTPS",
                severity="High",
                description="Se detecto un input de password en una pagina servida por HTTP.",
                evidence=target_url,
                recommendation="Forzar HTTPS antes de presentar formularios de autenticacion.",
                source="passive_scan",
                owasp_category="A04: Cryptographic Failures",
            )
        )
    for sensitive_name in sorted(parser.sensitive_inputs):
        alerts.append(
            create_alert(
                title="Input sensible detectado",
                severity="Informational",
                description="El HTML contiene un campo con nombre sensible que requiere protecciones adecuadas.",
                evidence=sensitive_name,
                recommendation="Verificar que el campo use HTTPS, controles anti-CSRF y manejo seguro del lado servidor.",
                source="passive_scan",
                owasp_category="A07: Authentication Failures",
            )
        )
    for comment in parser.suspicious_comments:
        alerts.append(
            create_alert(
                title="Comentario HTML sospechoso",
                severity="Low",
                description="Un comentario HTML contiene palabras que pueden revelar deuda tecnica o rutas internas.",
                evidence=comment[:160],
                recommendation="Evitar publicar comentarios con informacion interna, secretos o notas de seguridad.",
                source="passive_scan",
                owasp_category="A02: Security Misconfiguration",
            )
        )
    return alerts


def _alerts_from_versions(headers: dict[str, str], body: str) -> list[Alert]:
    alerts: list[Alert] = []
    for name in ("Server", "X-Powered-By"):
        value = _header_value(headers, name)
        if value and re.search(r"\d+(?:\.\d+)+", value):
            alerts.append(
                create_alert(
                    title="Version expuesta",
                    severity="Low",
                    description="La respuesta revela una tecnologia o version.",
                    evidence=f"{name}: {value}",
                    recommendation="Reducir banners de version cuando no sean necesarios y mantener componentes actualizados.",
                    source="passive_scan",
                    owasp_category="A02: Security Misconfiguration",
                )
            )
    if re.search(r'<meta[^>]+name=["\']generator["\']', body, re.IGNORECASE):
        alerts.append(
            create_alert(
                title="Version o generador expuesto en HTML",
                severity="Low",
                description="El HTML contiene metadata de generador que puede revelar tecnologia.",
                evidence="meta generator",
                recommendation="Evitar publicar versiones exactas cuando no sean necesarias.",
                source="passive_scan",
                owasp_category="A02: Security Misconfiguration",
            )
        )
    return alerts


def _alerts_from_visible_errors(body: str) -> list[Alert]:
    error_patterns = (
        "Traceback (most recent call last)",
        "Stack trace",
        "Fatal error",
        "Unhandled exception",
        "SQLException",
        "NullReferenceException",
    )
    for pattern in error_patterns:
        if pattern.lower() in body.lower():
            return [
                create_alert(
                    title="Error tecnico visible",
                    severity="Medium",
                    description="La respuesta contiene texto compatible con errores o stack traces visibles.",
                    evidence=pattern,
                    recommendation="Mostrar mensajes genericos al usuario y registrar detalles solo en logs internos.",
                    source="passive_scan",
                    owasp_category="A10: Mishandling of Exceptional Conditions",
                )
            ]
    return []


def _alerts_from_directories(report: dict[str, Any] | None) -> list[Alert]:
    if not isinstance(report, dict):
        return []
    alerts: list[Alert] = []
    for finding in _dicts(report.get("findings")):
        if finding.get("exposed") is not True:
            continue
        path = str(finding.get("path") or "ruta desconocida")
        severity = "Critical" if path.strip("/").lower() in {".env", ".git"} else "High"
        alerts.append(
            create_alert(
                title="Directorio o archivo comun expuesto",
                severity=severity,
                description="Una ruta comun sensible respondio como accesible.",
                evidence=path,
                recommendation="Bloquear acceso publico a rutas internas, backups y archivos de configuracion.",
                source="passive_scan",
                owasp_category="A02: Security Misconfiguration",
            )
        )
    return alerts


def _cookie_alert(cookie_name: str, attribute: str) -> Alert:
    return create_alert(
        title=f"Cookie sin {attribute}",
        severity="Medium",
        description=f"La cookie no declara el atributo defensivo {attribute}.",
        evidence=cookie_name or "cookie sin nombre",
        recommendation="Configurar cookies de sesion con HttpOnly, Secure y SameSite segun corresponda.",
        source="passive_scan",
        owasp_category="A02: Security Misconfiguration",
    )


def _header_value(headers: dict[str, str], name: str) -> str | None:
    for header_name, value in headers.items():
        if header_name.lower() == name.lower():
            return value
    return None


def _split_cookies(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if "=" in part]


class _PassiveHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms = 0
        self.has_csrf_token = False
        self.has_password_input = False
        self.sensitive_inputs: set[str] = set()
        self.suspicious_comments: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "form":
            self.forms += 1
        if tag.lower() != "input":
            return
        input_type = attributes.get("type", "").lower()
        input_name = attributes.get("name", "").lower()
        if input_type == "password":
            self.has_password_input = True
        if input_name in {"csrf", "csrf_token", "_csrf", "authenticity_token", "token"}:
            self.has_csrf_token = True
        if any(word in input_name for word in ("password", "secret", "token", "key")):
            self.sensitive_inputs.add(input_name)

    def handle_comment(self, data: str) -> None:
        if re.search(r"\b(todo|fixme|password|secret|debug|admin)\b", data, re.I):
            self.suspicious_comments.append(data.strip())


def _dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
