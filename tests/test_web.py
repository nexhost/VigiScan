from __future__ import annotations

from pathlib import Path

import pytest

from vigiscan.modules.screenshot import ScreenshotResult
from vigiscan.web.app import create_app
from vigiscan.web.models import Asset, MonitoredSite, Scan, User, db


@pytest.fixture()
def app(tmp_path):
    database_path = tmp_path / "vigiscan-test.sqlite3"
    report_dir = tmp_path / "reports"
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
            "WTF_CSRF_ENABLED": False,
            "VIGISCAN_ADMIN_USERNAME": "admin",
            "VIGISCAN_ADMIN_PASSWORD": "admin",
            "VIGISCAN_REPORT_DIR": str(report_dir),
        }
    )
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client):
    return client.post(
        "/login",
        data={"username": "admin", "password": "admin"},
        follow_redirects=True,
    )


def create_completed_scan(client, monkeypatch):
    monkeypatch.setattr("vigiscan.web.routes.execute_scan", fake_report)
    monkeypatch.setattr("vigiscan.web.routes.capture_site_screenshot", fake_capture)
    login(client)
    response = client.post(
        "/scans/new",
        data={"target_url": "https://example.com"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    return response


def fake_capture(target_url: str, output_dir: Path | str, *, basename: str | None = None):
    screenshot_dir = Path(output_dir)
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    path = screenshot_dir / f"{basename or 'scan'}.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n")
    return ScreenshotResult(
        ok=True,
        path=str(path),
        message="captura disponible",
        engine="playwright",
    )


def fake_unavailable_capture(
    target_url: str,
    output_dir: Path | str,
    *,
    basename: str | None = None,
):
    return ScreenshotResult(
        ok=False,
        path=None,
        message="captura no disponible",
        engine=None,
    )


def fake_report(target_url: str, **kwargs):
    return {
        "generated_at": "2026-06-04T20:00:00+00:00",
        "target_url": target_url,
        "executive_summary": {
            "text": "VigiScan evaluo el objetivo de prueba.",
            "highlights": ["1 cabeceras requieren revision."],
        },
        "risk": {
            "score": 73,
            "level": "Alto",
            "factors": ["Header Content-Security-Policy ausente."],
        },
        "modules": {
            "headers": {
                "findings": [
                    {
                        "header": "Content-Security-Policy",
                        "status": "Ausente",
                        "severity": "Alto",
                    },
                    {
                        "header": "Referrer-Policy",
                        "status": "Presente",
                        "severity": "Bajo",
                    },
                ],
            },
            "tech_detect": {
                "technologies": [
                    {
                        "name": "Apache",
                        "version": "2.4.49",
                        "confidence_level": "Alto",
                    }
                ],
            },
            "directories": {
                "findings": [
                    {
                        "path": ".env",
                        "url": "https://example.com/.env",
                        "status_code": 200,
                        "exposed": True,
                    }
                ],
            },
            "cve_checker": {
                "matches": [
                    {
                        "cve": "CVE-2021-41773",
                        "cve_id": "CVE-2021-41773",
                        "product": "Apache",
                        "affected_version": "Apache HTTP Server 2.4.49",
                        "matched_version": "2.4.49",
                        "severity": "Critical",
                        "cvss": 7.5,
                        "cwe": "CWE-22",
                        "description": "Path traversal and file disclosure.",
                        "impact": "Sensitive file disclosure risk.",
                        "recommendation": "Update Apache and review access controls.",
                        "references": [
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
                        ],
                    }
                ],
            },
        },
    }


def test_initial_admin_user_is_created(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()

    assert admin.is_admin is True
    assert admin.check_password("admin") is True


def test_dashboard_requires_login(client):
    response = client.get("/")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_admin_can_login_and_view_dashboard(client):
    response = login(client)

    assert response.status_code == 200
    assert b"Dashboard" in response.data
    assert b"Nuevo Escaneo" in response.data
    assert b"Reportes" in response.data
    assert b"Uptime Monitor" in response.data
    assert b"Assets" in response.data
    assert b"IOC Center" in response.data
    assert b"Threat Intelligence / VirusTotal" in response.data
    assert b"OWASP Top 10" in response.data
    assert b"Settings" in response.data


def test_requested_web_routes_are_available(client):
    login(client)
    expected_ok = [
        "/dashboard",
        "/scan/new",
        "/reports",
        "/uptime",
        "/assets",
        "/iocs",
        "/threat-intel/virustotal",
        "/owasp",
        "/settings",
    ]

    for path in expected_ok:
        response = client.get(path)
        assert response.status_code == 200, path


def test_login_updates_last_access(client, app):
    login(client)

    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        assert admin.last_login_at is not None


def test_user_can_update_profile_settings(client, app):
    login(client)
    response = client.post(
        "/settings",
        data={
            "profile-email": "admin@example.com",
            "profile-display_name": "SOC Admin",
            "profile-submit_profile": "Guardar perfil",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Perfil actualizado correctamente." in response.data
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        assert admin.email == "admin@example.com"
        assert admin.display_name == "SOC Admin"


def test_user_can_change_password(client, app):
    login(client)
    response = client.post(
        "/settings",
        data={
            "password-current_password": "admin",
            "password-new_password": "new-admin-pass",
            "password-confirm_password": "new-admin-pass",
            "password-submit_password": "Cambiar contrasena",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Contrasena actualizada correctamente." in response.data
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        assert admin.check_password("new-admin-pass") is True


def test_settings_rejects_invalid_email_and_wrong_current_password(client):
    login(client)
    email_response = client.post(
        "/settings",
        data={
            "profile-email": "not-an-email",
            "profile-display_name": "Admin",
            "profile-submit_profile": "Guardar perfil",
        },
        follow_redirects=True,
    )
    password_response = client.post(
        "/settings",
        data={
            "password-current_password": "wrong",
            "password-new_password": "new-admin-pass",
            "password-confirm_password": "new-admin-pass",
            "password-submit_password": "Cambiar contrasena",
        },
        follow_redirects=True,
    )

    assert b"Ingresa un correo valido." in email_response.data
    assert b"La contrasena actual no es correcta." in password_response.data


def test_logged_in_user_can_create_scan(client, app, monkeypatch):
    response = create_completed_scan(client, monkeypatch)

    assert response.status_code == 200
    assert b"https://example.com" in response.data
    assert b"73" in response.data
    assert b"Content-Security-Policy" in response.data
    assert b"Apache" in response.data
    assert b".env" in response.data
    assert b"CVE-2021-41773" in response.data
    assert b"CVSS" in response.data
    assert b"CWE-22" in response.data
    assert b"Sensitive file disclosure risk." in response.data
    assert b"Update Apache and review access controls." in response.data
    assert b"Captura visual" in response.data
    assert b"Clasificacion OWASP Top 10 2025" in response.data
    assert b"A02: Security Misconfiguration" in response.data
    assert b"A03: Software Supply Chain Failures" in response.data
    with app.app_context():
        scan = Scan.query.one()
        assert scan.target_url == "https://example.com"
        assert scan.status == "Completado"
        assert scan.score == 73
        assert scan.risk_level == "Alto"
        assert scan.report_path is not None
        assert scan.report_data is not None
        assert scan.report_data["screenshot"]["ok"] is True
        assert scan.report_data["owasp_findings"]


def test_dashboard_shows_soc_summary_charts_and_actions(client, monkeypatch):
    create_completed_scan(client, monkeypatch)
    response = client.get("/")

    assert response.status_code == 200
    assert b"Centro de Operaciones VigiScan" in response.data
    assert b"Total Assets" in response.data
    assert b"Total IOCs" in response.data
    assert b"VirusTotal Enabled" in response.data
    assert b"Uptime Sites" in response.data
    assert b"WAF Detected" in response.data
    assert b"SSL Health" in response.data
    assert b"OWASP Findings" in response.data
    assert b"CVE Count" in response.data
    assert b"Total de escaneos" in response.data
    assert b"Riesgo alto" in response.data
    assert b"severityChart" in response.data
    assert b"technologyChart" in response.data
    assert b"Ver detalle" in response.data
    assert b"HTML" in response.data
    assert b"JSON" in response.data
    assert b"Eliminar" in response.data
    assert b"Filtrar por OWASP" in response.data
    assert b"A02" in response.data


def test_reports_show_detailed_cve_metadata(client, monkeypatch):
    create_completed_scan(client, monkeypatch)
    response = client.get("/reports")

    assert response.status_code == 200
    assert b"CVE locales" in response.data
    assert b"Captura" in response.data
    assert b"OWASP" in response.data
    assert b"CVE-2021-41773" in response.data
    assert b"Apache HTTP Server 2.4.49" in response.data
    assert b"CVSS" in response.data
    assert b"CWE-22" in response.data
    assert b"Sensitive file disclosure risk." in response.data


def test_dashboard_and_reports_filter_by_owasp_category(client, monkeypatch):
    create_completed_scan(client, monkeypatch)

    dashboard_response = client.get("/?owasp=A03")
    assert dashboard_response.status_code == 200
    assert b"https://example.com" in dashboard_response.data
    assert b"A03" in dashboard_response.data

    empty_dashboard = client.get("/?owasp=A04")
    assert empty_dashboard.status_code == 200
    assert b"Sin escaneos registrados." in empty_dashboard.data

    reports_response = client.get("/reports?owasp=A02")
    assert reports_response.status_code == 200
    assert b"https://example.com" in reports_response.data
    assert b"A02" in reports_response.data


def test_scan_shows_unavailable_screenshot_message(client, monkeypatch):
    monkeypatch.setattr("vigiscan.web.routes.execute_scan", fake_report)
    monkeypatch.setattr(
        "vigiscan.web.routes.capture_site_screenshot",
        fake_unavailable_capture,
    )
    login(client)

    response = client.post(
        "/scans/new",
        data={"target_url": "https://example.com"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"captura no disponible" in response.data


def test_scan_downloads_and_delete_work(client, app, monkeypatch):
    create_completed_scan(client, monkeypatch)

    html_response = client.get("/scans/1/download/html")
    assert html_response.status_code == 200
    assert "attachment" in html_response.headers["Content-Disposition"]
    assert b"VigiScan Security Report" in html_response.data
    assert b"Captura visual" in html_response.data
    assert b"Clasificacion OWASP Top 10 2025" in html_response.data
    assert b"A03: Software Supply Chain Failures" in html_response.data

    screenshot_response = client.get("/scans/1/screenshot")
    assert screenshot_response.status_code == 200
    assert screenshot_response.mimetype == "image/png"

    json_response = client.get("/scans/1/download/json")
    assert json_response.status_code == 200
    assert json_response.mimetype == "application/json"
    assert b"Content-Security-Policy" in json_response.data

    csv_response = client.get("/scans/1/download/csv")
    assert csv_response.status_code == 200
    assert csv_response.mimetype == "text/csv"
    assert b"CVE-2021-41773" in csv_response.data

    delete_response = client.post("/scans/1/delete", follow_redirects=True)
    assert delete_response.status_code == 200
    with app.app_context():
        assert Scan.query.count() == 0


def test_scan_form_rejects_non_http_urls(client):
    login(client)
    response = client.post(
        "/scans/new",
        data={"target_url": "ftp://example.com"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"http://" in response.data


def test_owasp_module_requires_login_and_shows_categories(client):
    response = client.get("/owasp")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

    login(client)
    response = client.get("/owasp")

    assert response.status_code == 200
    assert b"OWASP Top 10 2025" in response.data
    assert b"A01" in response.data
    assert b"Broken Access Control" in response.data
    assert b"Mishandling of Exceptional Conditions" in response.data
    assert b"Headers, tecnologias, CVE y rutas" in response.data


def test_user_can_register_asset(client, app):
    login(client)
    response = client.post(
        "/assets",
        data={
            "name": "Portal clientes",
            "asset_type": "Dominio",
            "value": "example.com",
            "owner": "SOC",
            "environment": "Produccion",
            "submit_asset": "Guardar activo",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Activo registrado." in response.data
    assert b"Portal clientes" in response.data
    with app.app_context():
        asset = Asset.query.one()
        assert asset.value == "example.com"
        assert asset.environment == "Produccion"


def test_user_can_add_uptime_site_and_run_manual_check(client, app, monkeypatch):
    def fake_check_url(url):
        return {
            "url": url,
            "up": True,
            "status_code": 200,
            "response_time_ms": 123,
            "ssl_enabled": True,
            "ssl_valid": True,
            "error": None,
        }

    monkeypatch.setattr("vigiscan.web.routes.check_url", fake_check_url)
    login(client)
    response = client.post(
        "/uptime",
        data={
            "name": "Portal",
            "url": "https://example.com",
            "active": "y",
            "submit_site": "Guardar sitio",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Sitio agregado al monitoreo." in response.data
    assert b"En linea" in response.data
    assert b"123.0 ms" in response.data

    manual_response = client.post("/uptime/1/check", follow_redirects=True)
    assert manual_response.status_code == 200
    assert b"Chequeo uptime ejecutado." in manual_response.data
    with app.app_context():
        site = MonitoredSite.query.one()
        assert site.uptime_percentage == 100.0
        assert len(site.checks) == 2


def test_user_can_configure_virustotal_and_query_reputation(
    client,
    app,
    monkeypatch,
):
    def fake_query(target, api_key, *, kind):
        assert api_key == "vt-secret"
        return {
            "enabled": True,
            "ok": True,
            "kind": kind,
            "target": target,
            "malicious": 1,
            "suspicious": 0,
            "harmless": 10,
            "undetected": 2,
            "stats": {
                "malicious": 1,
                "suspicious": 0,
                "harmless": 10,
                "undetected": 2,
            },
            "permalink": "https://www.virustotal.com/gui/domain/example.com",
            "message": "Consulta completada.",
        }

    monkeypatch.setattr("vigiscan.web.routes.query_reputation", fake_query)
    login(client)
    settings_response = client.post(
        "/settings",
        data={
            "vt-api_key": "vt-secret",
            "vt-enabled": "y",
            "vt-submit_vt_settings": "Guardar VirusTotal",
        },
        follow_redirects=True,
    )

    assert settings_response.status_code == 200
    assert b"Configuracion de VirusTotal actualizada." in settings_response.data
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        assert admin.virustotal_enabled is True
        assert admin.virustotal_api_key_encrypted != "vt-secret"

    response = client.post(
        "/threat-intelligence/virustotal",
        data={
            "target": "example.com",
            "submit_lookup": "Consultar reputacion",
        },
    )

    assert response.status_code == 200
    assert b"VirusTotal Reputation" in response.data
    assert b"example.com" in response.data
    assert b"detecciones" in response.data
