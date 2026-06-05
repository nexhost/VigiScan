from __future__ import annotations

from typing import cast

from modules.owasp_classifier import (
    analyze_surface_signals,
    classify_owasp_findings,
)
from scanner import ScanResult


def test_classifies_headers_env_git_and_cves():
    findings = classify_owasp_findings(
        "https://example.com",
        {
            "headers": {
                "findings": [
                    {
                        "header": "Content-Security-Policy",
                        "status": "Ausente",
                        "severity": "Alto",
                        "recommendation": "Definir CSP.",
                    }
                ]
            },
            "directories": {
                "findings": [
                    {"path": ".env", "exposed": True},
                    {"path": ".git/", "exposed": True},
                ]
            },
            "cve_checker": {
                "matches": [
                    {
                        "cve_id": "CVE-2099-0001",
                        "product": "ExampleCMS",
                        "severity": "High",
                        "recommendation": "Actualizar ExampleCMS.",
                    }
                ]
            },
        },
    )

    categories = {item["category_id"] for item in findings}

    assert "A02" in categories
    assert "A03" in categories
    assert "A08" in categories
    assert any("Header faltante" in item["finding"] for item in findings)
    assert any(".env" in item["finding"] for item in findings)
    assert any(".git" in item["finding"] for item in findings)


def test_classifies_http_forms_visible_errors_and_logging_signal():
    findings = classify_owasp_findings(
        "http://example.com",
        {
            "surface": {
                "findings": [
                    {
                        "type": "form_without_basic_protection",
                        "finding": "Formulario HTML sin token anti-CSRF visible.",
                        "severity": "Medio",
                        "recommendation": "Agregar proteccion anti-CSRF.",
                    },
                    {
                        "type": "visible_error",
                        "finding": "Stack trace visible.",
                        "severity": "Medio",
                        "recommendation": "Ocultar detalles tecnicos.",
                    },
                    {
                        "type": "logging_alerting_missing",
                        "finding": "Falta de logs o alertas configuradas.",
                        "severity": "Medio",
                        "recommendation": "Configurar logging y alertas.",
                    },
                ]
            }
        },
    )

    categories = {item["category_id"] for item in findings}

    assert {"A04", "A07", "A09", "A10"}.issubset(categories)


def test_analyze_surface_signals_is_passive():
    scan_result = cast(
        ScanResult,
        {
            "ok": True,
            "target": {
                "url": "http://example.com",
                "scheme": "http",
                "hostname": "example.com",
                "port": None,
                "path": "/",
            },
            "request": {
                "method": "GET",
                "timeout_seconds": 10,
                "max_body_bytes": 1024,
                "allow_redirects": False,
            },
            "response": {
                "status_code": 200,
                "reason": "OK",
                "final_url": "http://example.com",
                "elapsed_ms": 10,
                "headers": {},
                "body_sample": "<form><input name='email'></form> Traceback (most recent call last)",
                "body_truncated": False,
            },
            "error": None,
        },
    )

    report = analyze_surface_signals(scan_result)
    signal_types = {finding["type"] for finding in report["findings"]}

    assert "no_tls" in signal_types
    assert "form_without_basic_protection" in signal_types
    assert "visible_error" in signal_types
