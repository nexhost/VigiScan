"""Small ES/EN translation helpers for the VigiScan web UI."""

from __future__ import annotations

from flask import session
from flask_login import current_user

SUPPORTED_LANGUAGES = {"es", "en"}
DEFAULT_LANGUAGE = "es"

TRANSLATIONS: dict[str, dict[str, str]] = {
    "es": {
        "dashboard": "Panel de control",
        "reports": "Reportes",
        "assets": "Activos",
        "threat_intelligence": "Inteligencia de amenazas",
        "settings": "Configuracion",
        "new_scan": "Nuevo escaneo",
        "uptime_monitor": "Monitor de disponibilidad",
        "infrastructure_monitor": "Monitor de infraestructura",
        "dns_domains": "DNS / Dominios",
        "virustotal": "VirusTotal",
        "ioc_center": "Indicadores de compromiso",
        "owasp_top_10": "OWASP Top 10",
        "security_score": "Puntuacion de seguridad",
        "findings": "Hallazgos",
        "risk": "Riesgo",
        "logout": "Salir",
        "language": "Idioma",
        "spanish": "Espanol",
        "english": "English",
        "view_report": "Ver reporte",
        "download_html": "Descargar HTML",
        "download_json": "Descargar JSON",
        "download_pdf": "Descargar PDF",
        "generating": "Generando...",
    },
    "en": {
        "dashboard": "Dashboard",
        "reports": "Reports",
        "assets": "Assets",
        "threat_intelligence": "Threat Intelligence",
        "settings": "Settings",
        "new_scan": "New scan",
        "uptime_monitor": "Uptime Monitor",
        "infrastructure_monitor": "Infrastructure Monitor",
        "dns_domains": "DNS / Domains",
        "virustotal": "VirusTotal",
        "ioc_center": "IOC Center",
        "owasp_top_10": "OWASP Top 10",
        "security_score": "Security Score",
        "findings": "Findings",
        "risk": "Risk",
        "logout": "Logout",
        "language": "Language",
        "spanish": "Espanol",
        "english": "English",
        "view_report": "View report",
        "download_html": "Download HTML",
        "download_json": "Download JSON",
        "download_pdf": "Download PDF",
        "generating": "Generating...",
    },
}


def get_locale() -> str:
    """Return the active UI locale."""
    language = session.get("language")
    if isinstance(language, str) and language in SUPPORTED_LANGUAGES:
        return language
    if current_user.is_authenticated:
        preferred = getattr(current_user, "language_preference", None)
        if preferred in SUPPORTED_LANGUAGES:
            session["language"] = preferred
            return preferred
    return DEFAULT_LANGUAGE


def translate(key: str) -> str:
    """Translate a UI key using the active locale."""
    language = get_locale()
    return TRANSLATIONS.get(language, TRANSLATIONS[DEFAULT_LANGUAGE]).get(
        key,
        TRANSLATIONS[DEFAULT_LANGUAGE].get(key, key),
    )
