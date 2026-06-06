"""Flask application factory and web command for VigiScan."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from flask import Flask, current_app
from sqlalchemy import inspect, text

from vigiscan.web.auth import init_login_manager
from vigiscan.web.forms import csrf
from vigiscan.web.models import User, db
from vigiscan.web.routes import bp


def create_app(config: dict[str, Any] | None = None) -> Flask:
    """Create and configure the VigiScan web application."""
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder="templates",
        static_folder="static",
    )
    database_path = Path(app.instance_path) / "vigiscan.sqlite3"
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("VIGISCAN_SECRET_KEY", "dev-change-me"),
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{database_path}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        VIGISCAN_ADMIN_USERNAME=os.environ.get("VIGISCAN_ADMIN_USERNAME", "admin"),
        VIGISCAN_ADMIN_PASSWORD=os.environ.get("VIGISCAN_ADMIN_PASSWORD", "admin"),
        VIGISCAN_REPORT_DIR=os.environ.get("VIGISCAN_REPORT_DIR", "reports"),
        VIGISCAN_UPTIME_SCHEDULER=True,
        WTF_CSRF_TIME_LIMIT=None,
    )
    if config:
        app.config.update(config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    csrf.init_app(app)
    init_login_manager(app)
    app.register_blueprint(bp)

    if app.config.get("VIGISCAN_INIT_DB", True):
        with app.app_context():
            init_database()

    start_uptime_scheduler(app)
    return app


def start_uptime_scheduler(app: Flask) -> None:
    """Start the optional uptime scheduler for production-like runs."""
    if app.config.get("TESTING") or not app.config.get("VIGISCAN_UPTIME_SCHEDULER"):
        return
    if getattr(app, "_vigiscan_uptime_scheduler_started", False):
        return
    app._vigiscan_uptime_scheduler_started = True  # type: ignore[attr-defined]

    def worker() -> None:
        stop = threading.Event()
        while not stop.wait(300):
            with app.app_context():
                try:
                    from vigiscan.web.routes import run_due_uptime_checks

                    run_due_uptime_checks()
                except Exception:
                    app.logger.exception("Uptime scheduler failed")

    thread = threading.Thread(
        target=worker,
        name="vigiscan-uptime-scheduler",
        daemon=True,
    )
    thread.start()


def init_database() -> None:
    """Create database tables and ensure the initial administrator exists."""
    db.create_all()
    _ensure_user_profile_columns()
    _ensure_scan_asset_column()
    username = str(current_app.config["VIGISCAN_ADMIN_USERNAME"])
    password = str(current_app.config["VIGISCAN_ADMIN_PASSWORD"])
    admin = User.query.filter_by(username=username).first()
    if admin is None:
        admin = User(username=username, is_admin=True)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()


def _ensure_user_profile_columns() -> None:
    """Add lightweight profile columns for existing SQLite installations."""
    inspector = inspect(db.engine)
    if "users" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("users")}
    migrations = {
        "email": "ALTER TABLE users ADD COLUMN email VARCHAR(255)",
        "display_name": "ALTER TABLE users ADD COLUMN display_name VARCHAR(120)",
        "last_login_at": "ALTER TABLE users ADD COLUMN last_login_at DATETIME",
        "virustotal_api_key_encrypted": (
            "ALTER TABLE users ADD COLUMN virustotal_api_key_encrypted TEXT"
        ),
        "virustotal_enabled": (
            "ALTER TABLE users ADD COLUMN virustotal_enabled BOOLEAN DEFAULT 0 NOT NULL"
        ),
    }
    for column, statement in migrations.items():
        if column not in existing:
            db.session.execute(text(statement))
    db.session.commit()


def _ensure_scan_asset_column() -> None:
    """Add nullable scan-to-asset relation for existing SQLite installations."""
    inspector = inspect(db.engine)
    if "scans" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("scans")}
    if "asset_id" not in existing:
        db.session.execute(text("ALTER TABLE scans ADD COLUMN asset_id INTEGER"))
        db.session.commit()


def main() -> None:
    """Run the VigiScan web dashboard."""
    app = create_app()
    host = os.environ.get("VIGISCAN_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("VIGISCAN_WEB_PORT", "5000"))
    debug = os.environ.get("VIGISCAN_WEB_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
