from __future__ import annotations

import pytest

from vigiscan.web.app import create_app
from vigiscan.web.models import Scan, User, db


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
    login(client)
    response = client.post(
        "/scans/new",
        data={"target_url": "https://example.com"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    return response


def fake_report(target_url: str):
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
                        "product": "Apache",
                        "matched_version": "2.4.49",
                        "severity": "Critical",
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


def test_logged_in_user_can_create_scan(client, app, monkeypatch):
    response = create_completed_scan(client, monkeypatch)

    assert response.status_code == 200
    assert b"https://example.com" in response.data
    assert b"73" in response.data
    assert b"Content-Security-Policy" in response.data
    assert b"Apache" in response.data
    assert b".env" in response.data
    assert b"CVE-2021-41773" in response.data
    with app.app_context():
        scan = Scan.query.one()
        assert scan.target_url == "https://example.com"
        assert scan.status == "Completado"
        assert scan.score == 73
        assert scan.risk_level == "Alto"
        assert scan.report_path is not None
        assert scan.report_data is not None


def test_dashboard_shows_soc_summary_charts_and_actions(client, monkeypatch):
    create_completed_scan(client, monkeypatch)
    response = client.get("/")

    assert response.status_code == 200
    assert b"Centro de Operaciones VigiScan" in response.data
    assert b"Total de escaneos" in response.data
    assert b"Riesgo alto" in response.data
    assert b"severityChart" in response.data
    assert b"technologyChart" in response.data
    assert b"Ver detalle" in response.data
    assert b"HTML" in response.data
    assert b"JSON" in response.data
    assert b"Eliminar" in response.data


def test_scan_downloads_and_delete_work(client, app, monkeypatch):
    create_completed_scan(client, monkeypatch)

    html_response = client.get("/scans/1/download/html")
    assert html_response.status_code == 200
    assert "attachment" in html_response.headers["Content-Disposition"]
    assert b"VigiScan Security Report" in html_response.data

    json_response = client.get("/scans/1/download/json")
    assert json_response.status_code == 200
    assert json_response.mimetype == "application/json"
    assert b"Content-Security-Policy" in json_response.data

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
