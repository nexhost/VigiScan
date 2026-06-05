"""Flask application factory and web command for VigiScan."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from flask import Flask, current_app

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

    return app


def init_database() -> None:
    """Create database tables and ensure the initial administrator exists."""
    db.create_all()
    username = str(current_app.config["VIGISCAN_ADMIN_USERNAME"])
    password = str(current_app.config["VIGISCAN_ADMIN_PASSWORD"])
    admin = User.query.filter_by(username=username).first()
    if admin is None:
        admin = User(username=username, is_admin=True)
        admin.set_password(password)
        db.session.add(admin)
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
