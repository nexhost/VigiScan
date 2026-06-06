"""Flask-WTF forms for the VigiScan web dashboard."""

from __future__ import annotations

import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import BooleanField, DateTimeLocalField, IntegerField, PasswordField, SelectField, StringField, SubmitField, TextAreaField, URLField
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


class MonitoredSiteForm(FlaskForm):
    """Create or update an uptime monitored site."""

    name = StringField("Nombre aplicacion", validators=[DataRequired(), Length(max=120)])
    url = URLField(
        "URL",
        validators=[DataRequired(), URL(require_tld=False), Length(max=2048)],
    )
    environment = SelectField(
        "Ambiente",
        choices=[
            ("Produccion", "Produccion"),
            ("Staging", "Staging"),
            ("Desarrollo", "Desarrollo"),
            ("QA", "QA"),
            ("Otro", "Otro"),
        ],
        default="Produccion",
    )
    responsible = StringField("Responsable", validators=[Optional(), Length(max=160)])
    country = StringField("Pais", validators=[Optional(), Length(max=120)])
    criticality = SelectField(
        "Criticidad",
        choices=[
            ("Critica", "Critica"),
            ("Alta", "Alta"),
            ("Media", "Media"),
            ("Baja", "Baja"),
        ],
        default="Media",
    )
    monitor_interval_minutes = IntegerField(
        "Intervalo monitoreo (min)",
        default=5,
        validators=[Optional(), NumberRange(min=1, max=1440)],
    )
    notes = TextAreaField("Notas", validators=[Optional(), Length(max=4000)])
    active = BooleanField("Activo", default=True)
    submit_site = SubmitField("Guardar sitio")

    def validate_url(self, field: URLField) -> None:
        value = field.data or ""
        if not value.lower().startswith(("http://", "https://")):
            raise ValidationError("La URL debe comenzar con http:// o https://.")


class AssetForm(FlaskForm):
    """Create an asset inventory entry."""

    name = StringField("Nombre", validators=[DataRequired(), Length(max=160)])
    asset_type = SelectField(
        "Tipo",
        choices=[
            ("Web App", "Web App"),
            ("API", "API"),
            ("Domain", "Domain"),
            ("Server", "Server"),
            ("Cloud Service", "Cloud Service"),
            ("Database", "Database"),
            ("Mail Server", "Mail Server"),
            ("Dominio", "Dominio"),
            ("IP", "IP"),
            ("Aplicacion", "Aplicacion"),
            ("Servidor", "Servidor"),
        ],
    )
    value = StringField("Valor principal", validators=[Optional(), Length(max=2048)])
    domain = StringField("Dominio", validators=[Optional(), Length(max=255)])
    ip_address = StringField("IP", validators=[Optional(), Length(max=80)])
    url = URLField("URL", validators=[Optional(), URL(require_tld=False), Length(max=2048)])
    owner = StringField("Responsable", validators=[Optional(), Length(max=160)])
    country = StringField("Pais", validators=[Optional(), Length(max=120)])
    criticality = SelectField(
        "Criticidad",
        choices=[
            ("Critica", "Critica"),
            ("Alta", "Alta"),
            ("Media", "Media"),
            ("Baja", "Baja"),
        ],
        default="Media",
    )
    status = SelectField(
        "Estado",
        choices=[
            ("Activo", "Activo"),
            ("En observacion", "En observacion"),
            ("Retirado", "Retirado"),
        ],
        default="Activo",
    )
    technology = StringField("Tecnologia principal", validators=[Optional(), Length(max=160)])
    environment = SelectField(
        "Ambiente",
        choices=[
            ("Produccion", "Produccion"),
            ("Staging", "Staging"),
            ("Desarrollo", "Desarrollo"),
            ("Otro", "Otro"),
        ],
    )
    notes = TextAreaField("Notas", validators=[Optional(), Length(max=4000)])
    submit_asset = SubmitField("Guardar activo")

    def validate_value(self, field: StringField) -> None:
        if not any(
            (
                (field.data or "").strip(),
                (self.domain.data or "").strip(),
                (self.ip_address.data or "").strip(),
                (self.url.data or "").strip(),
            )
        ):
            raise ValidationError("Ingresa al menos un valor, dominio, IP o URL.")


class VirusTotalSettingsForm(FlaskForm):
    """Update VirusTotal integration settings."""

    api_key = PasswordField("VirusTotal API Key", validators=[Optional(), Length(max=255)])
    enabled = BooleanField("Activar integracion")
    rate_limit_per_minute = IntegerField(
        "Limite de consultas por minuto",
        default=4,
        validators=[Optional(), NumberRange(min=1, max=60)],
    )
    cache_enabled = BooleanField("Modo cache", default=True)
    submit_vt_settings = SubmitField("Guardar VirusTotal")


class VirusTotalLookupForm(FlaskForm):
    """Run a VirusTotal reputation lookup."""

    target = StringField("URL, dominio, IP o hash", validators=[DataRequired(), Length(max=2048)])
    submit_lookup = SubmitField("Consultar reputacion")


class DomainLookupForm(FlaskForm):
    """Run a DNS/domain reconnaissance lookup."""

    target = StringField(
        "Dominio, URL o IP",
        validators=[DataRequired(), Length(max=2048)],
    )
    submit_lookup = SubmitField("Consultar DNS")


class RegionalSettingsForm(FlaskForm):
    """Update global regional settings."""

    country = StringField("Pais", validators=[DataRequired(), Length(max=120)])
    country_code = StringField("Codigo de pais", validators=[DataRequired(), Length(max=8)])
    timezone = StringField("Zona horaria", validators=[DataRequired(), Length(max=80)])
    language = StringField("Idioma", validators=[DataRequired(), Length(max=16)])
    currency = StringField("Moneda", validators=[DataRequired(), Length(max=12)])
    date_format = SelectField(
        "Formato de fecha",
        choices=[
            ("%Y-%m-%d %H:%M", "YYYY-MM-DD HH:mm"),
            ("%d/%m/%Y %H:%M", "DD/MM/YYYY HH:mm"),
            ("%m/%d/%Y %I:%M %p", "MM/DD/YYYY hh:mm AM/PM"),
        ],
    )
    organization_name = StringField(
        "Nombre de la organizacion",
        validators=[Optional(), Length(max=180)],
    )
    organization_sector = StringField("Sector", validators=[Optional(), Length(max=120)])
    organization_criticality = SelectField(
        "Nivel de criticidad",
        choices=[
            ("Critica", "Critica"),
            ("Alta", "Alta"),
            ("Media", "Media"),
            ("Baja", "Baja"),
        ],
        default="Media",
    )
    submit_regional_settings = SubmitField("Guardar configuracion regional")

    def validate_timezone(self, field: StringField) -> None:
        if (field.data or "").strip().upper() == "UTC":
            return
        try:
            ZoneInfo((field.data or "").strip())
        except ZoneInfoNotFoundError as exc:
            raise ValidationError("Zona horaria no valida para zoneinfo.") from exc


class IndicatorForm(FlaskForm):
    """Create or edit an indicator of compromise."""

    indicator_type = SelectField(
        "Tipo",
        choices=[
            ("IP", "IP"),
            ("Dominio", "Dominio"),
            ("URL", "URL"),
            ("Hash MD5", "Hash MD5"),
            ("Hash SHA1", "Hash SHA1"),
            ("Hash SHA256", "Hash SHA256"),
            ("Email", "Email"),
            ("CVE", "CVE"),
            ("User-Agent", "User-Agent"),
            ("File Name", "File Name"),
            ("Registry Key", "Registry Key"),
            ("Mutex", "Mutex"),
        ],
    )
    value = StringField("Valor", validators=[DataRequired(), Length(max=2048)])
    description = TextAreaField("Descripcion", validators=[Optional(), Length(max=4000)])
    severity = SelectField(
        "Severidad",
        choices=[
            ("Critical", "Critical"),
            ("High", "High"),
            ("Medium", "Medium"),
            ("Low", "Low"),
            ("Informational", "Informational"),
        ],
        default="Medium",
    )
    source = StringField("Fuente", validators=[Optional(), Length(max=160)])
    campaign = StringField("Campana", validators=[Optional(), Length(max=160)])
    threat_actor = StringField("Actor de amenaza", validators=[Optional(), Length(max=160)])
    tlp = SelectField(
        "TLP",
        choices=[
            ("TLP:CLEAR", "TLP:CLEAR"),
            ("TLP:GREEN", "TLP:GREEN"),
            ("TLP:AMBER", "TLP:AMBER"),
            ("TLP:RED", "TLP:RED"),
        ],
        default="TLP:AMBER",
    )
    tags = StringField("Etiquetas", validators=[Optional(), Length(max=512)])
    related_country = StringField("Pais relacionado", validators=[Optional(), Length(max=120)])
    first_seen = DateTimeLocalField("Primera observacion", validators=[Optional()], format="%Y-%m-%dT%H:%M")
    last_seen = DateTimeLocalField("Ultima observacion", validators=[Optional()], format="%Y-%m-%dT%H:%M")
    status = SelectField(
        "Estado",
        choices=[
            ("Active", "Active"),
            ("Monitoring", "Monitoring"),
            ("False Positive", "False Positive"),
            ("Expired", "Expired"),
        ],
        default="Active",
    )
    notes = TextAreaField("Notas", validators=[Optional(), Length(max=4000)])
    submit_indicator = SubmitField("Guardar IOC")
