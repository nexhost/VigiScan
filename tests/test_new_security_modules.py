from __future__ import annotations

from pathlib import Path

from vigiscan.modules.api_security import analyze_api_security
from vigiscan.modules.dependency_scanner import extract_dependencies, scan_dependency_file
from vigiscan.modules.secret_scanner import mask_secret, scan_text
from vigiscan.modules.tls_analyzer import certificate_summary, ssl_score
from vigiscan.modules.waf_detect import detect_waf


def test_secret_scanner_masks_detected_values():
    result = scan_text("const key = 'AKIA1234567890ABCDEF'; password='secret123';")

    assert result["findings"]
    assert "AKIA1234567890ABCDEF" not in str(result["findings"])
    assert mask_secret("AKIA1234567890ABCDEF").startswith("AKIA")


def test_dependency_scanner_extracts_requirements(tmp_path: Path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("Flask==3.0.0\nrequests>=2.32\n", encoding="utf-8")

    result = scan_dependency_file(manifest)

    assert {"name": "Flask", "version": "3.0.0"} in result["dependencies"]
    assert {"name": "requests", "version": "2.32"} in result["dependencies"]


def test_dependency_scanner_extracts_pyproject(tmp_path: Path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "[project]\ndependencies = ['Flask>=3.0']\n",
        encoding="utf-8",
    )

    dependencies = extract_dependencies(manifest)

    assert dependencies[0]["name"] == "Flask"


def test_tls_summary_scores_certificate_states():
    expired = {"https_available": True, "expired": True}
    healthy = {
        "https_available": True,
        "expired": False,
        "expires_soon": False,
        "http_to_https_redirect": True,
    }

    assert certificate_summary(None)["expired"] is True
    assert ssl_score(expired) == "F"
    assert ssl_score(healthy) == "A"


def test_waf_detection_uses_passive_headers():
    result = detect_waf(
        {
            "response": {
                "headers": {"CF-Ray": "abc", "Server": "cloudflare"},
                "cookies": {},
            }
        }
    )

    assert result["detections"][0]["waf"] == "Cloudflare"


def test_api_security_detects_passive_cors_and_http():
    result = analyze_api_security(
        "http://example.com/api",
        {"response": {"headers": {"Access-Control-Allow-Origin": "*"}}},
        requester=lambda *args, **kwargs: type("R", (), {"status_code": 404})(),
        options_requester=lambda *args, **kwargs: type(
            "R",
            (),
            {"headers": {"Allow": "GET, DELETE"}},
        )(),
    )

    titles = {finding["title"] for finding in result["findings"]}
    assert "API sin HTTPS" in titles
    assert "CORS permisivo" in titles
    assert "Metodos HTTP sensibles" in titles
