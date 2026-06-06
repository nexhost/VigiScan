"""Database models for the VigiScan web dashboard."""

from __future__ import annotations

from datetime import UTC, datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Float, JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """Dashboard user account."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    language_preference: Mapped[str] = mapped_column(
        String(8),
        default="es",
        nullable=False,
    )
    virustotal_api_key_encrypted: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    virustotal_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    virustotal_rate_limit_per_minute: Mapped[int] = mapped_column(
        Integer,
        default=4,
        nullable=False,
    )
    virustotal_cache_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    scans: Mapped[list["Scan"]] = relationship(back_populates="user")

    def set_password(self, password: str) -> None:
        """Store a secure password hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Check a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    """Scan metadata stored for the dashboard."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="Pendiente", nullable=False)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(40), nullable=True)
    report_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    report_data: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    user: Mapped[User] = relationship(back_populates="scans")
    asset: Mapped["Asset | None"] = relationship(back_populates="scans")


class MonitoredSite(db.Model):
    """Website monitored for uptime and availability."""

    __tablename__ = "monitored_sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    environment: Mapped[str] = mapped_column(String(80), default="Produccion", nullable=False)
    responsible: Mapped[str | None] = mapped_column(String(160))
    country: Mapped[str | None] = mapped_column(String(120))
    criticality: Mapped[str] = mapped_column(String(40), default="Media", nullable=False)
    monitor_interval_minutes: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ssl_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    uptime_percentage: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    avg_response_time: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    last_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    checks: Mapped[list["UptimeCheck"]] = relationship(
        back_populates="site",
        cascade="all, delete-orphan",
        order_by="UptimeCheck.checked_at",
    )


class InfrastructureMetric(db.Model):
    """Server infrastructure metrics captured from the VigiScan host."""

    __tablename__ = "infrastructure_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    memory_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    memory_used: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    memory_total: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    disk_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    disk_used: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    disk_total: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    net_bytes_sent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    net_bytes_recv: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    net_upload_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    net_download_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    active_processes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    server_uptime: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class UptimeCheck(db.Model):
    """One uptime check result."""

    __tablename__ = "uptime_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("monitored_sites.id"), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    up: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    response_time_ms: Mapped[int | None] = mapped_column(Integer)
    ssl_valid: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    site: Mapped[MonitoredSite] = relationship(back_populates="checks")


class Asset(db.Model):
    """Attack surface asset inventory entry."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(40), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(80))
    url: Mapped[str | None] = mapped_column(String(2048))
    owner: Mapped[str | None] = mapped_column(String(160))
    country: Mapped[str | None] = mapped_column(String(120))
    criticality: Mapped[str | None] = mapped_column(String(40), default="Media")
    status: Mapped[str | None] = mapped_column(String(40), default="Activo")
    technology: Mapped[str | None] = mapped_column(String(160))
    environment: Mapped[str | None] = mapped_column(String(80))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    scans: Mapped[list[Scan]] = relationship(back_populates="asset")


class SystemSettings(db.Model):
    """Global regional and organization preferences."""

    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    country: Mapped[str] = mapped_column(String(120), default="Republica Dominicana", nullable=False)
    country_code: Mapped[str] = mapped_column(String(8), default="DO", nullable=False)
    timezone: Mapped[str] = mapped_column(String(80), default="America/Santo_Domingo", nullable=False)
    language: Mapped[str] = mapped_column(String(16), default="es", nullable=False)
    currency: Mapped[str] = mapped_column(String(12), default="DOP", nullable=False)
    date_format: Mapped[str] = mapped_column(String(40), default="%Y-%m-%d %H:%M", nullable=False)
    organization_name: Mapped[str | None] = mapped_column(String(180))
    organization_sector: Mapped[str | None] = mapped_column(String(120))
    organization_criticality: Mapped[str] = mapped_column(String(40), default="Media", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


class Indicator(db.Model):
    """Indicator of compromise registered by an analyst."""

    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_type: Mapped[str] = mapped_column(String(40), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(40), default="Medium", nullable=False)
    source: Mapped[str | None] = mapped_column(String(160))
    campaign: Mapped[str | None] = mapped_column(String(160))
    threat_actor: Mapped[str | None] = mapped_column(String(160))
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER", nullable=False)
    tags: Mapped[str | None] = mapped_column(String(512))
    related_country: Mapped[str | None] = mapped_column(String(120))
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(40), default="Active", nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


class VirusTotalResult(db.Model):
    """Cached VirusTotal observable reputation result."""

    __tablename__ = "virustotal_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    observable_type: Mapped[str] = mapped_column(String(40), nullable=False)
    observable_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    malicious: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    suspicious: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    harmless: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    undetected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    reputation: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    categories: Mapped[dict[str, object] | None] = mapped_column(JSON)
    raw_json: Mapped[dict[str, object] | None] = mapped_column(JSON)
    queried_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
