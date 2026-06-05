"""Flask-WTF forms for the VigiScan web dashboard."""

from __future__ import annotations

from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import PasswordField, StringField, SubmitField, URLField
from wtforms.validators import DataRequired, Length, URL, ValidationError

csrf = CSRFProtect()


class LoginForm(FlaskForm):
    """Authenticate a dashboard user."""

    username = StringField("Usuario", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Contrasena", validators=[DataRequired()])
    submit = SubmitField("Entrar")


class ScanForm(FlaskForm):
    """Create a new scan record."""

    target_url = URLField(
        "URL objetivo",
        validators=[DataRequired(), URL(require_tld=False), Length(max=2048)],
    )
    submit = SubmitField("Crear escaneo")

    def validate_target_url(self, field: URLField) -> None:
        """Require dashboard scans to use HTTP or HTTPS targets."""
        value = field.data or ""
        if not value.lower().startswith(("http://", "https://")):
            raise ValidationError("La URL debe comenzar con http:// o https://.")
