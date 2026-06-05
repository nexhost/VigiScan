"""Authentication setup for the VigiScan web dashboard."""

from __future__ import annotations

from flask import Flask
from flask_login import LoginManager

from vigiscan.web.models import User, db

login_manager = LoginManager()
login_manager.login_view = "main.login"
login_manager.login_message = "Inicia sesion para acceder al dashboard."


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    """Load users for Flask-Login sessions."""
    if not user_id.isdigit():
        return None
    return db.session.get(User, int(user_id))


def init_login_manager(app: Flask) -> None:
    """Attach Flask-Login to an application."""
    login_manager.init_app(app)
