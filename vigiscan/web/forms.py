"""Flask-WTF forms for the VigiScan web dashboard."""

from __future__ import annotations

import re

from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import BooleanField, IntegerField, PasswordField, StringField, SubmitField, URLField
from wtforms.validators import DataRequired, Length, NumberRange, Optional, URL, ValidationError

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
    spider_depth = IntegerField(
        "Profundidad del spider",
        default=1,
        validators=[Optional(), NumberRange(min=0, max=3)],
    )
    enable_passive_scan = BooleanField("Passive scan", default=True)
    enable_screenshot = BooleanField("Screenshot", default=True)
    enable_owasp_mapping = BooleanField("OWASP mapping", default=True)
    enable_cve_lookup = BooleanField("CVE lookup", default=True)
    submit = SubmitField("Iniciar escaneo")

    def validate_target_url(self, field: URLField) -> None:
        """Require dashboard scans to use HTTP or HTTPS targets."""
        value = field.data or ""
        if not value.lower().startswith(("http://", "https://")):
            raise ValidationError("La URL debe comenzar con http:// o https://.")


class ProfileForm(FlaskForm):
    """Update account profile fields."""

    email = StringField("Correo", validators=[Optional(), Length(max=255)])
    display_name = StringField("Nombre visible", validators=[Optional(), Length(max=120)])
    submit_profile = SubmitField("Guardar perfil")

    def validate_email(self, field: StringField) -> None:
        value = (field.data or "").strip()
        if value and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
            raise ValidationError("Ingresa un correo valido.")


class PasswordChangeForm(FlaskForm):
    """Change account password."""

    current_password = PasswordField("Contrasena actual", validators=[DataRequired()])
    new_password = PasswordField(
        "Nueva contrasena",
        validators=[DataRequired(), Length(min=8, max=128)],
    )
    confirm_password = PasswordField(
        "Confirmar nueva contrasena",
        validators=[DataRequired(), Length(min=8, max=128)],
    )
    submit_password = SubmitField("Cambiar contrasena")

    def validate_confirm_password(self, field: PasswordField) -> None:
        if field.data != self.new_password.data:
            raise ValidationError("La confirmacion no coincide.")
