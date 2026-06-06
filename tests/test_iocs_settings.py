from __future__ import annotations

import pytest

from tests.test_web import login
from vigiscan.web.app import create_app
from vigiscan.web.models import Indicator, SystemSettings, VirusTotalResult, db


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


def test_regional_settings_can_be_updated(client, app):
    login(client)
    response = client.post(
        "/settings",
        data={
            "regional-country": "Republica Dominicana",
            "regional-country_code": "DO",
            "regional-timezone": "UTC",
            "regional-language": "es",
            "regional-currency": "DOP",
            "regional-date_format": "%d/%m/%Y %H:%M",
            "regional-organization_name": "SOC Demo",
            "regional-organization_sector": "Finanzas",
            "regional-organization_criticality": "Alta",
            "regional-submit_regional_settings": "Guardar configuracion regional",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Configuracion regional actualizada." in response.data
    with app.app_context():
        settings = SystemSettings.query.one()
        assert settings.country_code == "DO"
        assert settings.organization_name == "SOC Demo"


def test_ioc_center_create_filter_export_and_delete(client, app):
    login(client)
    response = client.post(
        "/iocs",
        data={
            "indicator_type": "IP",
            "value": "203.0.113.10",
            "severity": "High",
            "source": "Analyst",
            "tlp": "TLP:AMBER",
            "related_country": "DO",
            "status": "Active",
            "submit_indicator": "Guardar IOC",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"IOC registrado." in response.data
    assert b"203.0.113.10" in response.data
    assert b"203.0.113.10" in client.get("/iocs?type=IP&severity=High").data
    assert b"203.0.113.10" in client.get("/iocs/export.csv").data
    assert b"203.0.113.10" in client.get("/iocs/export.json").data

    with app.app_context():
        indicator = Indicator.query.one()
        indicator_id = indicator.id

    detail = client.get(f"/iocs/{indicator_id}")
    assert b"IOC #" in detail.data

    delete = client.post(f"/iocs/{indicator_id}/delete", follow_redirects=True)
    assert b"IOC eliminado." in delete.data
    with app.app_context():
        assert Indicator.query.count() == 0


def test_virustotal_cache_is_used(client, app):
    login(client)
    with app.app_context():
        cached = VirusTotalResult(
            observable_type="domain",
            observable_value="cached.example",
            malicious=1,
            suspicious=0,
            harmless=8,
            undetected=2,
            reputation=-5,
            categories={"test": "malware"},
            raw_json={"cached": True},
            expires_at=SystemSettings.query.one().updated_at.replace(year=2099),
        )
        db.session.add(cached)
        db.session.commit()

    response = client.post(
        "/threat-intel/virustotal",
        data={"target": "cached.example", "submit_lookup": "Consultar reputacion"},
    )

    assert response.status_code == 200
    assert b"cached.example" in response.data
    assert b"Cache" in response.data
