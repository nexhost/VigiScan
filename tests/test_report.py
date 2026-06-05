from __future__ import annotations

import json
from datetime import UTC, datetime

from report import build_report, render_html, save_reports


def sample_modules():
    return {
        "headers": {
            "module": "headers",
            "ok": True,
            "target_url": "https://example.com",
            "overall_severity": "Alto",
            "findings": [
                {
                    "header": "Content-Security-Policy",
                    "present": False,
                    "status": "Ausente",
                    "severity": "Alto",
                    "value": None,
                    "recommendation": "Definir CSP.",
                },
                {
                    "header": "Referrer-Policy",
                    "present": True,
                    "status": "Presente",
                    "severity": "Bajo",
                    "value": "no-referrer",
                    "recommendation": "Sin accion inmediata.",
                },
            ],
        },
        "directories": {
            "module": "directories",
            "ok": True,
            "target_url": "https://example.com",
            "wordlist_size": 8,
            "exposed_count": 1,
            "findings": [
                {
                    "path": ".env",
                    "url": "https://example.com/.env",
                    "exposed": True,
                    "status": "Expuesto",
                    "status_code": 200,
                    "content_type": "text/plain",
                    "content_length": 128,
                    "evidence": "La ruta respondio con HTTP 200.",
                    "error": None,
                },
            ],
        },
        "cve_checker": {
            "module": "cve_checker",
            "ok": True,
            "source": "data.cve_local.json",
            "matches": [
                {
                    "product": "Apache",
                    "detected_version": "2.4.49",
                    "matched_version": "2.4.49",
                    "affected_version": "Apache HTTP Server 2.4.49",
                    "cve": "CVE-2021-41773",
                    "cve_id": "CVE-2021-41773",
                    "severity": "Critical",
                    "cvss": 7.5,
                    "cwe": "CWE-22",
                    "description": "Path traversal.",
                    "impact": "File disclosure risk.",
                    "recommendation": "Update Apache and review access controls.",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                    "match_type": "exact_version",
                },
            ],
        },
    }


def test_build_report_adds_executive_summary_and_risk_score():
    report = build_report(
        target_url="https://example.com",
        modules=sample_modules(),
        generated_at=datetime(2026, 6, 4, tzinfo=UTC),
    )
    report["owasp_findings"] = [
        {
            "finding": "Tecnologia vulnerable por CVE: CVE-2021-41773 en Apache.",
            "severity": "Critical",
            "category_id": "A03",
            "category": "A03: Software Supply Chain Failures",
            "recommendation": "Update Apache and review access controls.",
            "source": "cve_checker",
        }
    ]

    assert report["target_url"] == "https://example.com"
    assert report["risk"]["score"] == 73
    assert report["risk"]["level"] == "Alto"
    assert "puntuacion de riesgo" in report["executive_summary"]["text"]
    assert report["executive_summary"]["highlights"]


def test_save_reports_writes_txt_json_and_html(tmp_path):
    report = build_report(
        target_url="https://example.com",
        modules=sample_modules(),
        generated_at=datetime(2026, 6, 4, tzinfo=UTC),
    )
    report["owasp_findings"] = [
        {
            "finding": "Tecnologia vulnerable por CVE: CVE-2021-41773 en Apache.",
            "severity": "Critical",
            "category_id": "A03",
            "category": "A03: Software Supply Chain Failures",
            "recommendation": "Update Apache and review access controls.",
            "source": "cve_checker",
        }
    ]

    paths = save_reports(report, output_dir=tmp_path, basename="sample")

    assert paths.txt.read_text(encoding="utf-8").startswith("VigiScan")
    json_report = json.loads(paths.json.read_text(encoding="utf-8"))
    assert json_report["risk"]["level"] == "Alto"
    html = paths.html.read_text(encoding="utf-8")
    assert "<html lang=\"es\">" in html
    assert "Resumen Ejecutivo" in html
    assert "Puntuacion de Riesgo" in html
    assert "CVE-2021-41773" in html
    assert "CVSS" in html
    assert "CWE-22" in html
    assert "File disclosure risk." in html
    assert "Update Apache and review access controls." in html
    assert "Clasificacion OWASP Top 10 2025" in html
    assert "A03: Software Supply Chain Failures" in html


def test_render_html_escapes_untrusted_values():
    report = build_report(
        target_url="<script>alert(1)</script>",
        modules={"headers": {"findings": []}},
        generated_at=datetime(2026, 6, 4, tzinfo=UTC),
    )

    html = render_html(report)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
