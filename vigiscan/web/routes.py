"""Routes for the VigiScan web interface."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    request,
    redirect,
    render_template,
    send_file,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import or_

from modules.cve_checker import check_tech_report
from modules.directories import DirectoryCheckConfig, analyze_directories
from modules.headers import analyze_headers
from modules.owasp_classifier import (
    analyze_surface_signals,
    available_owasp_filters,
    classify_owasp_findings,
)
from modules.tech_detect import analyze_technologies
from report import ReportDocument, build_report, save_report
from scanner import ScanRequest, ScannerConfig, create_scanner
from vigiscan.modules.api_security import analyze_api_security
from vigiscan.modules.passive_scan import analyze_passive
from vigiscan.modules.screenshot import capture_site_screenshot
from vigiscan.modules.secret_scanner import scan_text as scan_secrets_in_text
from vigiscan.modules.spider import SpiderConfig, crawl_site
from vigiscan.modules.tls_analyzer import analyze_tls
from vigiscan.modules.uptime import check_url
from vigiscan.modules.virustotal import (
    decrypt_api_key,
    detect_kind,
    encrypt_api_key,
    query_reputation,
)
from vigiscan.modules.waf_detect import detect_waf
from vigiscan.web.forms import (
    AssetForm,
    IndicatorForm,
    LoginForm,
    MonitoredSiteForm,
    PasswordChangeForm,
    ProfileForm,
    RegionalSettingsForm,
    ScanForm,
    VirusTotalLookupForm,
    VirusTotalSettingsForm,
)
from vigiscan.web.models import (
    Asset,
    Indicator,
    MonitoredSite,
    Scan,
    SystemSettings,
    UptimeCheck,
    User,
    VirusTotalResult,
    db,
)

bp = Blueprint("main", __name__)


@bp.get("/")
@login_required
def dashboard():
    selected_owasp = request.args.get("owasp", "").strip()
    all_scans = Scan.query.order_by(Scan.created_at.desc()).all()
    filtered_scans = filter_scans_by_owasp(all_scans, selected_owasp)
    scans = filtered_scans[:10]
    total_scans = Scan.query.count()
    risk_counts = {
        "Alto": Scan.query.filter_by(risk_level="Alto").count(),
        "Medio": Scan.query.filter_by(risk_level="Medio").count(),
        "Bajo": Scan.query.filter_by(risk_level="Bajo").count(),
    }
    top_technologies = detected_technology_counts(limit=10)
    dashboard_stats = build_dashboard_stats(all_scans)
    monitored_sites = MonitoredSite.query.order_by(MonitoredSite.created_at.desc()).all()
    vt_latest = VirusTotalResult.query.order_by(
        VirusTotalResult.queried_at.desc()
    ).first()
    return render_template(
        "dashboard.html",
        scans=scans,
        total_scans=total_scans,
        risk_counts=risk_counts,
        dashboard_stats=dashboard_stats,
        platform_stats=build_platform_stats(monitored_sites),
        regional_settings=get_system_settings(),
        recent_iocs=Indicator.query.order_by(Indicator.created_at.desc()).limit(5).all(),
        vt_summary={
            "cached_results": VirusTotalResult.query.count(),
            "latest_reputation": vt_latest.reputation if vt_latest else 0,
            "latest_target": vt_latest.observable_value if vt_latest else "-",
        },
        severity_chart={
            "labels": list(risk_counts.keys()),
            "values": list(risk_counts.values()),
        },
        technology_chart={
            "labels": [item["name"] for item in top_technologies],
            "values": [item["count"] for item in top_technologies],
        },
        scans_by_day_chart=dashboard_stats["scans_by_day"],
        findings_severity_chart=dashboard_stats["findings_by_severity"],
        weekly_risk_chart=dashboard_stats["weekly_risk"],
        owasp_chart=dashboard_stats["owasp_top"],
        cve_severity_chart=dashboard_stats["cve_by_severity"],
        high_risk_trend_chart=dashboard_stats["high_risk_trend"],
        top_risk_sites=dashboard_stats["top_risk_sites"],
        owasp_filters=available_owasp_filters(),
        selected_owasp=selected_owasp,
        scan_owasp_categories={
            scan.id: scan_owasp_categories(scan)
            for scan in scans
        },
    )


@bp.route("/login", methods=("GET", "POST"))
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            user.last_login_at = datetime.now(UTC)
            db.session.commit()
            login_user(user)
            return redirect(url_for("main.dashboard"))
        flash("Credenciales invalidas.", "danger")
    return render_template("login.html", form=form)


@bp.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.login"))


@bp.route("/scans/new", methods=("GET", "POST"))
@login_required
def scan_new():
    form = ScanForm()
    if form.validate_on_submit():
        options = scan_options_from_form(form)
        scan = Scan(
            target_url=form.target_url.data.strip(),
            status="En ejecucion",
            user_id=current_user.id,
        )
        scan.asset = match_asset_for_url(scan.target_url)
        db.session.add(scan)
        db.session.commit()

        run_vigiscan_scan(scan, options=options)
        db.session.commit()

        if scan.status == "Completado":
            flash("Escaneo completado correctamente.", "success")
        else:
            flash("El escaneo no pudo completarse. Revisa el detalle.", "danger")
        return redirect(url_for("main.scan_detail", scan_id=scan.id))
    return render_template("scan_new.html", form=form)


@bp.route("/settings", methods=("GET", "POST"))
@login_required
def settings():
    profile_form = ProfileForm(prefix="profile")
    password_form = PasswordChangeForm(prefix="password")
    vt_form = VirusTotalSettingsForm(prefix="vt")
    regional_form = RegionalSettingsForm(prefix="regional")
    settings_record = get_system_settings()

    if request.method == "GET":
        profile_form.email.data = current_user.email or ""
        profile_form.display_name.data = current_user.display_name or ""
        vt_form.enabled.data = bool(current_user.virustotal_enabled)
        vt_form.rate_limit_per_minute.data = current_user.virustotal_rate_limit_per_minute
        vt_form.cache_enabled.data = bool(current_user.virustotal_cache_enabled)
        regional_form.country.data = settings_record.country
        regional_form.country_code.data = settings_record.country_code
        regional_form.timezone.data = settings_record.timezone
        regional_form.language.data = settings_record.language
        regional_form.currency.data = settings_record.currency
        regional_form.date_format.data = settings_record.date_format
        regional_form.organization_name.data = settings_record.organization_name or ""
        regional_form.organization_sector.data = settings_record.organization_sector or ""
        regional_form.organization_criticality.data = (
            settings_record.organization_criticality
        )

    if profile_form.submit_profile.data and profile_form.validate_on_submit():
        current_user.email = (profile_form.email.data or "").strip() or None
        current_user.display_name = (
            (profile_form.display_name.data or "").strip() or None
        )
        db.session.commit()
        flash("Perfil actualizado correctamente.", "success")
        return redirect(url_for("main.settings"))

    if password_form.submit_password.data and password_form.validate_on_submit():
        if not current_user.check_password(password_form.current_password.data):
            flash("La contrasena actual no es correcta.", "danger")
        else:
            current_user.set_password(password_form.new_password.data)
            db.session.commit()
            flash("Contrasena actualizada correctamente.", "success")
            return redirect(url_for("main.settings"))

    if vt_form.submit_vt_settings.data and vt_form.validate_on_submit():
        api_key = (vt_form.api_key.data or "").strip()
        if api_key:
            current_user.virustotal_api_key_encrypted = encrypt_api_key(
                api_key,
                current_app.config["SECRET_KEY"],
            )
        current_user.virustotal_enabled = bool(vt_form.enabled.data)
        current_user.virustotal_rate_limit_per_minute = (
            vt_form.rate_limit_per_minute.data or 4
        )
        current_user.virustotal_cache_enabled = bool(vt_form.cache_enabled.data)
        db.session.commit()
        flash("Configuracion de VirusTotal actualizada.", "success")
        return redirect(url_for("main.settings"))

    if (
        regional_form.submit_regional_settings.data
        and regional_form.validate_on_submit()
    ):
        settings_record.country = regional_form.country.data.strip()
        settings_record.country_code = regional_form.country_code.data.strip().upper()
        settings_record.timezone = regional_form.timezone.data.strip()
        settings_record.language = regional_form.language.data.strip()
        settings_record.currency = regional_form.currency.data.strip().upper()
        settings_record.date_format = regional_form.date_format.data
        settings_record.organization_name = (
            (regional_form.organization_name.data or "").strip() or None
        )
        settings_record.organization_sector = (
            (regional_form.organization_sector.data or "").strip() or None
        )
        settings_record.organization_criticality = (
            regional_form.organization_criticality.data
        )
        settings_record.updated_at = datetime.now(UTC)
        db.session.commit()
        flash("Configuracion regional actualizada.", "success")
        return redirect(url_for("main.settings"))

    return render_template(
        "settings.html",
        profile_form=profile_form,
        password_form=password_form,
        vt_form=vt_form,
        regional_form=regional_form,
        system_settings=settings_record,
        vt_key_hint=masked_api_key(
            decrypt_api_key(
                current_user.virustotal_api_key_encrypted,
                current_app.config["SECRET_KEY"],
            )
        ),
    )


@bp.get("/scans/<int:scan_id>")
@login_required
def scan_detail(scan_id: int):
    scan = db.get_or_404(Scan, scan_id)
    findings = scan_findings(scan)
    return render_template(
        "scan_detail.html",
        scan=scan,
        findings=findings,
        screenshot=scan_screenshot_metadata(scan),
    )


@bp.get("/scans/<int:scan_id>/download/html")
@login_required
def scan_download_html(scan_id: int):
    scan = db.get_or_404(Scan, scan_id)
    path = stored_report_path(scan)
    if path is None:
        flash("El archivo de reporte HTML no existe en disco.", "danger")
        return redirect(url_for("main.scan_detail", scan_id=scan.id))

    return send_file(path, as_attachment=True, download_name=f"vigiscan-{scan.id}.html")


@bp.get("/scans/<int:scan_id>/download/json")
@login_required
def scan_download_json(scan_id: int):
    scan = db.get_or_404(Scan, scan_id)
    payload = scan.report_data or {
        "target_url": scan.target_url,
        "status": scan.status,
        "error": scan.error_message,
    }
    content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    return Response(
        content,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=vigiscan-{scan.id}.json"
        },
    )


@bp.get("/scans/<int:scan_id>/download/csv")
@login_required
def scan_download_csv(scan_id: int):
    scan = db.get_or_404(Scan, scan_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["category", "name", "severity", "detail"])
    findings = scan_findings(scan)
    for header in findings["missing_headers"]:
        writer.writerow([
            "header",
            header.get("header"),
            header.get("severity"),
            header.get("status"),
        ])
    for directory in findings["exposed_directories"]:
        writer.writerow([
            "directory",
            directory.get("path"),
            "Medium",
            directory.get("url"),
        ])
    for cve in findings["cves"]:
        writer.writerow([
            "cve",
            cve.get("cve_id") or cve.get("cve"),
            cve.get("severity"),
            cve.get("description"),
        ])
    for owasp in findings["owasp"]:
        writer.writerow([
            "owasp",
            owasp.get("category_id") or owasp.get("category"),
            owasp.get("severity"),
            owasp.get("finding"),
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=vigiscan-{scan.id}.csv"
        },
    )


@bp.get("/scans/<int:scan_id>/screenshot")
@login_required
def scan_screenshot(scan_id: int):
    scan = db.get_or_404(Scan, scan_id)
    path = stored_screenshot_path(scan)
    if path is None:
        flash("captura no disponible", "warning")
        return redirect(url_for("main.scan_detail", scan_id=scan.id))
    return send_file(path, mimetype="image/png")


@bp.post("/scans/<int:scan_id>/delete")
@login_required
def scan_delete(scan_id: int):
    scan = db.get_or_404(Scan, scan_id)
    path = stored_report_path(scan)
    screenshot_path = stored_screenshot_path(scan)
    db.session.delete(scan)
    db.session.commit()
    if path is not None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    if screenshot_path is not None:
        try:
            screenshot_path.unlink(missing_ok=True)
        except OSError:
            pass
    flash("Escaneo eliminado.", "success")
    return redirect(url_for("main.dashboard"))


@bp.get("/reports")
@login_required
def reports():
    selected_owasp = request.args.get("owasp", "").strip()
    all_scans = Scan.query.order_by(Scan.created_at.desc()).all()
    scans = filter_scans_by_owasp(all_scans, selected_owasp)
    screenshots = {scan.id: scan_screenshot_metadata(scan) for scan in scans}
    return render_template(
        "reports.html",
        scans=scans,
        screenshots=screenshots,
        owasp_filters=available_owasp_filters(),
        selected_owasp=selected_owasp,
        scan_owasp_categories={
            scan.id: scan_owasp_categories(scan)
            for scan in scans
        },
    )


@bp.get("/owasp")
@login_required
def owasp():
    return render_template("owasp.html")


@bp.route("/uptime", methods=("GET", "POST"))
@login_required
def uptime():
    form = MonitoredSiteForm()
    if form.validate_on_submit():
        site = MonitoredSite(
            name=form.name.data.strip(),
            url=form.url.data.strip(),
            active=bool(form.active.data),
        )
        db.session.add(site)
        db.session.commit()
        run_uptime_check(site)
        db.session.commit()
        flash("Sitio agregado al monitoreo.", "success")
        return redirect(url_for("main.uptime"))

    sites = MonitoredSite.query.order_by(MonitoredSite.created_at.desc()).all()
    stats = uptime_dashboard_stats(sites)
    return render_template(
        "uptime.html",
        form=form,
        sites=sites,
        stats=stats,
        charts=uptime_chart_data(sites),
        rows=uptime_table_rows(sites),
    )


@bp.post("/uptime/<int:site_id>/check")
@login_required
def uptime_check(site_id: int):
    site = db.get_or_404(MonitoredSite, site_id)
    run_uptime_check(site)
    db.session.commit()
    flash("Chequeo uptime ejecutado.", "success")
    return redirect(url_for("main.uptime"))


@bp.route("/assets", methods=("GET", "POST"))
@login_required
def assets():
    form = AssetForm()
    if form.validate_on_submit():
        asset = Asset()
        populate_asset_from_form(asset, form)
        db.session.add(asset)
        db.session.commit()
        flash("Activo registrado.", "success")
        return redirect(url_for("main.assets"))
    return render_template(
        "assets.html",
        form=form,
        assets=Asset.query.order_by(Asset.created_at.desc()).all(),
    )


@bp.route("/assets/new", methods=("GET", "POST"))
@login_required
def asset_new():
    form = AssetForm()
    if form.validate_on_submit():
        asset = Asset()
        populate_asset_from_form(asset, form)
        db.session.add(asset)
        db.session.commit()
        flash("Activo registrado.", "success")
        return redirect(url_for("main.asset_detail", asset_id=asset.id))
    return render_template("asset_form.html", form=form, asset=None)


@bp.route("/assets/<int:asset_id>")
@login_required
def asset_detail(asset_id: int):
    asset = db.get_or_404(Asset, asset_id)
    related_sites = [
        site for site in MonitoredSite.query.all()
        if asset_matches_value(asset, site.url)
    ]
    related_cves = [
        cve
        for scan in asset.scans
        for cve in scan_findings(scan)["cves"]
    ]
    return render_template(
        "asset_detail.html",
        asset=asset,
        related_sites=related_sites,
        related_cves=related_cves,
        risk_history=asset_risk_history(asset),
    )


@bp.route("/assets/<int:asset_id>/edit", methods=("GET", "POST"))
@login_required
def asset_edit(asset_id: int):
    asset = db.get_or_404(Asset, asset_id)
    form = AssetForm(obj=asset)
    if request.method == "GET":
        form.ip_address.data = asset.ip_address
    if form.validate_on_submit():
        populate_asset_from_form(asset, form)
        db.session.commit()
        flash("Activo actualizado.", "success")
        return redirect(url_for("main.asset_detail", asset_id=asset.id))
    return render_template("asset_form.html", form=form, asset=asset)


@bp.post("/assets/<int:asset_id>/delete")
@login_required
def asset_delete(asset_id: int):
    asset = db.get_or_404(Asset, asset_id)
    db.session.delete(asset)
    db.session.commit()
    flash("Activo eliminado.", "success")
    return redirect(url_for("main.assets"))


@bp.route("/iocs", methods=("GET", "POST"))
@login_required
def iocs():
    form = IndicatorForm()
    if form.validate_on_submit():
        indicator = Indicator()
        populate_indicator_from_form(indicator, form)
        db.session.add(indicator)
        db.session.commit()
        flash("IOC registrado.", "success")
        return redirect(url_for("main.iocs"))

    query = filtered_indicator_query()
    return render_template(
        "iocs.html",
        form=form,
        indicators=query.order_by(Indicator.created_at.desc()).all(),
        filters={
            "q": request.args.get("q", ""),
            "type": request.args.get("type", ""),
            "severity": request.args.get("severity", ""),
            "country": request.args.get("country", ""),
            "tlp": request.args.get("tlp", ""),
        },
    )


@bp.route("/iocs/new", methods=("GET", "POST"))
@login_required
def ioc_new():
    form = IndicatorForm()
    if form.validate_on_submit():
        indicator = Indicator()
        populate_indicator_from_form(indicator, form)
        db.session.add(indicator)
        db.session.commit()
        flash("IOC registrado.", "success")
        return redirect(url_for("main.ioc_detail", indicator_id=indicator.id))
    return render_template("ioc_form.html", form=form, indicator=None)


@bp.get("/iocs/export.csv")
@login_required
def ioc_export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id",
        "type",
        "value",
        "severity",
        "source",
        "campaign",
        "threat_actor",
        "tlp",
        "tags",
        "related_country",
        "status",
    ])
    for indicator in filtered_indicator_query().order_by(Indicator.created_at.desc()):
        writer.writerow([
            indicator.id,
            indicator.indicator_type,
            indicator.value,
            indicator.severity,
            indicator.source or "",
            indicator.campaign or "",
            indicator.threat_actor or "",
            indicator.tlp,
            indicator.tags or "",
            indicator.related_country or "",
            indicator.status,
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=vigiscan-iocs.csv"},
    )


@bp.get("/iocs/export.json")
@login_required
def ioc_export_json():
    payload = [
        indicator_to_dict(indicator)
        for indicator in filtered_indicator_query().order_by(Indicator.created_at.desc())
    ]
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=vigiscan-iocs.json"},
    )


@bp.get("/iocs/<int:indicator_id>")
@login_required
def ioc_detail(indicator_id: int):
    indicator = db.get_or_404(Indicator, indicator_id)
    return render_template("ioc_detail.html", indicator=indicator)


@bp.route("/iocs/<int:indicator_id>/edit", methods=("GET", "POST"))
@login_required
def ioc_edit(indicator_id: int):
    indicator = db.get_or_404(Indicator, indicator_id)
    form = IndicatorForm(obj=indicator)
    if form.validate_on_submit():
        populate_indicator_from_form(indicator, form)
        db.session.commit()
        flash("IOC actualizado.", "success")
        return redirect(url_for("main.ioc_detail", indicator_id=indicator.id))
    return render_template("ioc_form.html", form=form, indicator=indicator)


@bp.post("/iocs/<int:indicator_id>/delete")
@login_required
def ioc_delete(indicator_id: int):
    indicator = db.get_or_404(Indicator, indicator_id)
    db.session.delete(indicator)
    db.session.commit()
    flash("IOC eliminado.", "success")
    return redirect(url_for("main.iocs"))


@bp.route("/threat-intel/virustotal", methods=("GET", "POST"))
@bp.route("/threat-intelligence/virustotal", methods=("GET", "POST"))
@login_required
def virustotal():
    form = VirusTotalLookupForm()
    result = None
    cached = False
    if form.validate_on_submit():
        api_key = (
            decrypt_api_key(
                current_user.virustotal_api_key_encrypted,
                current_app.config["SECRET_KEY"],
            )
            if current_user.virustotal_enabled
            else None
        )
        kind = detect_kind(form.target.data.strip())
        result, cached = query_virustotal_with_cache(
            form.target.data.strip(),
            api_key,
            kind=kind,
            cache_enabled=bool(current_user.virustotal_cache_enabled),
        )
    return render_template(
        "virustotal.html",
        form=form,
        result=result,
        cached=cached,
        enabled=bool(current_user.virustotal_enabled),
        vt_key_hint=masked_api_key(
            decrypt_api_key(
                current_user.virustotal_api_key_encrypted,
                current_app.config["SECRET_KEY"],
            )
        ),
    )


def get_system_settings() -> SystemSettings:
    """Return the singleton regional settings row."""
    settings_record = SystemSettings.query.first()
    if settings_record is None:
        settings_record = SystemSettings()
        db.session.add(settings_record)
        db.session.commit()
    return settings_record


def local_datetime(value: datetime | None) -> str:
    """Format a datetime using configured local timezone and format."""
    if value is None:
        return "-"
    settings_record = get_system_settings()
    try:
        timezone = ZoneInfo(settings_record.timezone)
    except ZoneInfoNotFoundError:
        timezone = UTC
    aware = _aware_datetime(value).astimezone(timezone)
    return aware.strftime(settings_record.date_format)


def masked_api_key(api_key: str | None) -> str:
    """Show only the last four API key characters."""
    if not api_key:
        return "No configurada"
    tail = api_key[-4:] if len(api_key) >= 4 else api_key
    return f"********{tail}"


def populate_asset_from_form(asset: Asset, form: AssetForm) -> None:
    """Persist asset fields from a submitted form."""
    value = (form.value.data or "").strip()
    domain = (form.domain.data or "").strip()
    ip_address = (form.ip_address.data or "").strip()
    url = (form.url.data or "").strip()
    asset.name = form.name.data.strip()
    asset.asset_type = form.asset_type.data
    asset.value = value or domain or ip_address or url
    asset.domain = domain or None
    asset.ip_address = ip_address or None
    asset.url = url or None
    asset.owner = (form.owner.data or "").strip() or None
    asset.country = (form.country.data or "").strip() or None
    asset.criticality = form.criticality.data
    asset.status = form.status.data
    asset.technology = (form.technology.data or "").strip() or None
    asset.environment = form.environment.data
    asset.notes = (form.notes.data or "").strip() or None


def asset_matches_value(asset: Asset, candidate: str | None) -> bool:
    """Check whether an asset field appears in a candidate URL/value."""
    if not candidate:
        return False
    normalized = candidate.lower()
    values = [
        asset.value,
        asset.domain,
        asset.ip_address,
        asset.url,
    ]
    return any(value and str(value).lower() in normalized for value in values)


def asset_risk_history(asset: Asset) -> dict[str, list[Any]]:
    """Build a compact risk history chart for an asset."""
    scans = sorted(asset.scans, key=lambda item: item.created_at)[-12:]
    return {
        "labels": [local_datetime(scan.created_at) for scan in scans],
        "values": [scan.score or 0 for scan in scans],
    }


def populate_indicator_from_form(indicator: Indicator, form: IndicatorForm) -> None:
    """Persist IOC fields from a submitted form."""
    indicator.indicator_type = form.indicator_type.data
    indicator.value = form.value.data.strip()
    indicator.description = (form.description.data or "").strip() or None
    indicator.severity = form.severity.data
    indicator.source = (form.source.data or "").strip() or None
    indicator.campaign = (form.campaign.data or "").strip() or None
    indicator.threat_actor = (form.threat_actor.data or "").strip() or None
    indicator.tlp = form.tlp.data
    indicator.tags = (form.tags.data or "").strip() or None
    indicator.related_country = (form.related_country.data or "").strip() or None
    indicator.first_seen = form.first_seen.data
    indicator.last_seen = form.last_seen.data
    indicator.status = form.status.data
    indicator.notes = (form.notes.data or "").strip() or None
    indicator.updated_at = datetime.now(UTC)


def filtered_indicator_query():
    """Apply IOC search and filter parameters."""
    query = Indicator.query
    search = request.args.get("q", "").strip()
    indicator_type = request.args.get("type", "").strip()
    severity = request.args.get("severity", "").strip()
    country = request.args.get("country", "").strip()
    tlp = request.args.get("tlp", "").strip()
    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                Indicator.value.ilike(like),
                Indicator.description.ilike(like),
                Indicator.tags.ilike(like),
                Indicator.source.ilike(like),
            )
        )
    if indicator_type:
        query = query.filter(Indicator.indicator_type == indicator_type)
    if severity:
        query = query.filter(Indicator.severity == severity)
    if country:
        query = query.filter(Indicator.related_country.ilike(f"%{country}%"))
    if tlp:
        query = query.filter(Indicator.tlp == tlp)
    return query


def indicator_to_dict(indicator: Indicator) -> dict[str, Any]:
    """Serialize one IOC for JSON export."""
    return {
        "id": indicator.id,
        "indicator_type": indicator.indicator_type,
        "value": indicator.value,
        "description": indicator.description,
        "severity": indicator.severity,
        "source": indicator.source,
        "campaign": indicator.campaign,
        "threat_actor": indicator.threat_actor,
        "tlp": indicator.tlp,
        "tags": indicator.tags,
        "related_country": indicator.related_country,
        "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
        "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
        "status": indicator.status,
        "notes": indicator.notes,
        "created_at": indicator.created_at.isoformat(),
        "updated_at": indicator.updated_at.isoformat(),
    }


def query_virustotal_with_cache(
    target: str,
    api_key: str | None,
    *,
    kind: str,
    cache_enabled: bool,
) -> tuple[dict[str, Any], bool]:
    """Query VT with local cache and clear disabled-key behavior."""
    now = datetime.now(UTC)
    cached = (
        VirusTotalResult.query.filter_by(
            observable_type=kind,
            observable_value=target,
        )
        .order_by(VirusTotalResult.queried_at.desc())
        .first()
    )
    if cache_enabled and cached and _aware_datetime(cached.expires_at) > now:
        return virustotal_cache_to_result(cached), True

    result = query_reputation(target, api_key, kind=kind)  # type: ignore[arg-type]
    if result.get("ok"):
        raw_json = result.get("raw_json")
        stats = result.get("stats", {})
        reputation = int(result.get("reputation", 0))
        cached_result = VirusTotalResult(
            observable_type=kind,
            observable_value=target,
            malicious=int(stats.get("malicious", result.get("malicious", 0))),
            suspicious=int(stats.get("suspicious", result.get("suspicious", 0))),
            harmless=int(stats.get("harmless", result.get("harmless", 0))),
            undetected=int(stats.get("undetected", result.get("undetected", 0))),
            reputation=reputation,
            categories=result.get("categories") if isinstance(result.get("categories"), dict) else {},
            raw_json=raw_json if isinstance(raw_json, dict) else result,
            queried_at=now,
            expires_at=now + timedelta(hours=24),
        )
        db.session.add(cached_result)
        db.session.commit()
    return result, False


def virustotal_cache_to_result(cached: VirusTotalResult) -> dict[str, Any]:
    """Convert a cached VT row to the template result shape."""
    return {
        "enabled": True,
        "ok": True,
        "kind": cached.observable_type,
        "target": cached.observable_value,
        "malicious": cached.malicious,
        "suspicious": cached.suspicious,
        "harmless": cached.harmless,
        "undetected": cached.undetected,
        "reputation": cached.reputation,
        "categories": cached.categories or {},
        "raw_json": cached.raw_json or {},
        "last_analysis_date": local_datetime(cached.queried_at),
        "stats": {
            "malicious": cached.malicious,
            "suspicious": cached.suspicious,
            "harmless": cached.harmless,
            "undetected": cached.undetected,
        },
        "message": "Resultado servido desde cache local.",
    }


def run_vigiscan_scan(scan: Scan, *, options: dict[str, Any] | None = None) -> None:
    """Run the existing VigiScan engine and persist report metadata."""
    scan_options = options or default_scan_options()
    try:
        report_doc = execute_scan(scan.target_url, options=scan_options)
        report_dir = Path(str(current_app.config["VIGISCAN_REPORT_DIR"]))
        report_doc["scan_options"] = scan_options
        settings_record = get_system_settings()
        report_doc["regional_settings"] = {
            "country": settings_record.country,
            "country_code": settings_record.country_code,
            "timezone": settings_record.timezone,
            "language": settings_record.language,
            "currency": settings_record.currency,
            "date_format": settings_record.date_format,
            "organization_name": settings_record.organization_name,
            "organization_sector": settings_record.organization_sector,
            "organization_criticality": settings_record.organization_criticality,
            "generated_at_local": local_datetime(datetime.now(UTC)),
        }
        if scan_options["screenshot"]:
            screenshot_result = capture_site_screenshot(
                scan.target_url,
                report_dir / "screenshots",
                basename=f"scan-{scan.id}",
            )
            screenshot_data = screenshot_result.to_dict()
            if screenshot_result.path:
                screenshot_path = Path(screenshot_result.path)
                try:
                    screenshot_data["relative_path"] = str(
                        screenshot_path.relative_to(report_dir)
                    ).replace("\\", "/")
                except ValueError:
                    screenshot_data["relative_path"] = screenshot_path.name
            report_doc["screenshot"] = screenshot_data
        else:
            report_doc["screenshot"] = {
                "ok": False,
                "path": None,
                "message": "captura no disponible",
                "engine": None,
            }
        if scan_options["owasp_mapping"]:
            report_doc["owasp_findings"] = classify_owasp_findings(
                report_doc["target_url"],
                report_doc["modules"],
            )
        else:
            report_doc["owasp_findings"] = []
        report_path = save_report(report_doc, "html", output_dir=report_dir)
    except Exception as exc:
        scan.status = "Fallido"
        scan.completed_at = datetime.now(UTC)
        scan.error_message = str(exc)
        scan.summary = "El escaneo no pudo completarse."
        return

    scan.status = "Completado"
    scan.score = report_doc["risk"]["score"]
    scan.risk_level = report_doc["risk"]["level"]
    scan.report_path = str(report_path)
    scan.report_data = dict(report_doc)
    scan.summary = report_doc["executive_summary"]["text"]
    scan.completed_at = datetime.now(UTC)
    scan.error_message = None


def safe_module_call(factory):
    """Run optional defensive module without aborting the whole scan."""
    try:
        return factory()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def execute_scan(
    target_url: str,
    *,
    options: dict[str, Any] | None = None,
) -> ReportDocument:
    """Execute scanner, analysis modules, CVE lookup, and report building."""
    scan_options = options or default_scan_options()
    scanner_config = ScannerConfig()
    directory_config = DirectoryCheckConfig()
    scan_result = create_scanner(scanner_config).scan(ScanRequest(url=target_url))
    if not scan_result["ok"]:
        error = scan_result["error"] or {"message": "Error desconocido"}
        raise RuntimeError(str(error["message"]))

    headers_report = analyze_headers(scan_result)
    technologies_report = analyze_technologies(scan_result)
    cve_report = (
        check_tech_report(technologies_report)
        if scan_options["cve_lookup"]
        else {
            "module": "cve_checker",
            "ok": True,
            "source": "disabled",
            "checked": [],
            "matches": [],
        }
    )
    directories_report = analyze_directories(scan_result, config=directory_config)
    surface_report = analyze_surface_signals(scan_result)
    modules = {
        "headers": headers_report,
        "tech_detect": technologies_report,
        "cve_checker": cve_report,
        "directories": directories_report,
        "surface": surface_report,
        "tls_analyzer": safe_module_call(lambda: analyze_tls(target_url)),
        "waf_detect": safe_module_call(lambda: detect_waf(scan_result)),
        "api_security": safe_module_call(
            lambda: analyze_api_security(target_url, scan_result)
        ),
        "secret_scanner": safe_module_call(
            lambda: scan_secrets_in_text(
                str((scan_result.get("response") or {}).get("body_sample") or ""),
                source=target_url,
            )
        ),
    }
    if int(scan_options["spider_depth"]) > 0:
        modules["spider"] = crawl_site(
            target_url,
            config=SpiderConfig(
                max_depth=int(scan_options["spider_depth"]),
                max_urls=20,
            ),
        )
    if scan_options["passive_scan"]:
        modules["passive_scan"] = analyze_passive(
            scan_result,
            headers_report=headers_report,
            directories_report=directories_report,
        )
    report_doc = build_report(
        target_url=target_url,
        modules=modules,
    )
    report_doc["owasp_findings"] = (
        classify_owasp_findings(report_doc["target_url"], report_doc["modules"])
        if scan_options["owasp_mapping"]
        else []
    )
    return report_doc


def scan_findings(scan: Scan) -> dict[str, list[dict[str, Any]]]:
    """Extract dashboard-oriented findings from a stored report."""
    report_data = scan.report_data or {}
    modules = report_data.get("modules", {})
    if not isinstance(modules, dict):
        modules = {}

    headers_report = _module_dict(modules, "headers")
    tech_report = _module_dict(modules, "tech_detect")
    directories_report = _module_dict(modules, "directories")
    cve_report = _module_dict(modules, "cve_checker")

    return {
        "missing_headers": [
            finding
            for finding in _dict_items(headers_report.get("findings"))
            if finding.get("status") != "Presente"
        ],
        "technologies": _dict_items(tech_report.get("technologies")),
        "exposed_directories": [
            finding
            for finding in _dict_items(directories_report.get("findings"))
            if finding.get("exposed") is True
        ],
        "cves": _dict_items(cve_report.get("matches")),
        "owasp": scan_owasp_findings(scan),
    }


def _module_dict(modules: dict[str, Any], name: str) -> dict[str, Any]:
    value = modules.get(name)
    return value if isinstance(value, dict) else {}


def _dict_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def detected_technology_counts(limit: int = 6) -> list[dict[str, int | str]]:
    """Count most frequently detected technologies from stored scan reports."""
    counts: dict[str, int] = {}
    for scan in Scan.query.filter(Scan.report_data.is_not(None)).all():
        for technology in scan_findings(scan)["technologies"]:
            name = technology.get("name")
            if not isinstance(name, str) or not name:
                continue
            counts[name] = counts.get(name, 0) + 1

    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [
        {"name": name, "count": count}
        for name, count in ranked[:limit]
    ]


def match_asset_for_url(target_url: str) -> Asset | None:
    """Find a registered asset that corresponds to a scan target."""
    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    normalized_target = target_url.lower()
    for asset in Asset.query.order_by(Asset.created_at.desc()).all():
        value = (asset.value or "").strip().lower()
        if not value:
            continue
        if value == host or value in normalized_target:
            return asset
    return None


def default_scan_options() -> dict[str, Any]:
    """Return default web scan options."""
    return {
        "spider_depth": 1,
        "passive_scan": True,
        "screenshot": True,
        "owasp_mapping": True,
        "cve_lookup": True,
    }


def build_dashboard_stats(scans: list[Scan]) -> dict[str, Any]:
    """Build dashboard cards and chart datasets from stored scans."""
    now = datetime.now(UTC)
    week_start = now - timedelta(days=7)
    completed_scores = [scan.score for scan in scans if scan.score is not None]
    technologies = {
        str(tech.get("name"))
        for scan in scans
        for tech in scan_findings(scan)["technologies"]
        if tech.get("name")
    }
    cve_matches = [
        cve
        for scan in scans
        for cve in scan_findings(scan)["cves"]
    ]
    alerts = [
        alert
        for scan in scans
        for alert in scan_alerts(scan)
    ]
    owasp_findings = [
        finding
        for scan in scans
        for finding in scan_owasp_findings(scan)
    ]
    return {
        "scans_this_week": sum(
            1 for scan in scans if _aware_datetime(scan.created_at) >= week_start
        ),
        "critical_findings": sum(
            1 for alert in alerts if alert.get("severity") == "Critical"
        ),
        "high_findings": sum(1 for alert in alerts if alert.get("severity") == "High"),
        "cve_detected": len(cve_matches),
        "average_risk": round(
            sum(completed_scores) / len(completed_scores), 1
        )
        if completed_scores
        else 0,
        "last_scan": scans[0].created_at.strftime("%Y-%m-%d %H:%M") if scans else "-",
        "unique_technologies": len(technologies),
        "scans_by_day": chart_scans_by_day(scans),
        "findings_by_severity": chart_findings_by_severity(alerts),
        "weekly_risk": chart_weekly_risk(scans),
        "owasp_top": chart_owasp_top(owasp_findings),
        "cve_by_severity": chart_cve_by_severity(cve_matches),
        "high_risk_trend": chart_high_risk_trend(scans),
        "top_risk_sites": [
            {
                "target": scan.target_url,
                "score": scan.score or 0,
                "risk": scan.risk_level or "-",
            }
            for scan in sorted(
                scans,
                key=lambda item: item.score or 0,
                reverse=True,
            )[:5]
        ],
    }


def build_platform_stats(sites: list[MonitoredSite]) -> dict[str, Any]:
    """Build global platform cards for assets and uptime."""
    latest_checks = [
        site.checks[-1]
        for site in sites
        if site.checks
    ]
    monitored_with_checks = [site for site in sites if site.checks]
    average_uptime = (
        round(
            sum(site.uptime_percentage for site in monitored_with_checks)
            / len(monitored_with_checks),
            1,
        )
        if monitored_with_checks
        else 0
    )
    return {
        "asset_count": Asset.query.count(),
        "monitored_sites": len(sites),
        "average_uptime": average_uptime,
        "down_sites": sum(1 for check in latest_checks if not check.up),
        "ssl_attention": sum(
            1
            for site in sites
            if site.ssl_enabled and site.checks and not site.checks[-1].ssl_valid
        ),
    }


def chart_scans_by_day(scans: list[Scan]) -> dict[str, list[Any]]:
    days = [
        (datetime.now(UTC) - timedelta(days=offset)).date()
        for offset in range(6, -1, -1)
    ]
    counts = {day.isoformat(): 0 for day in days}
    for scan in scans:
        day = _aware_datetime(scan.created_at).date().isoformat()
        if day in counts:
            counts[day] += 1
    return {"labels": list(counts.keys()), "values": list(counts.values())}


def chart_findings_by_severity(alerts: list[dict[str, Any]]) -> dict[str, list[Any]]:
    labels = ["Critical", "High", "Medium", "Low", "Informational"]
    counts = {label: 0 for label in labels}
    for alert in alerts:
        severity = str(alert.get("severity"))
        if severity in counts:
            counts[severity] += 1
    return {"labels": labels, "values": [counts[label] for label in labels]}


def chart_weekly_risk(scans: list[Scan]) -> dict[str, list[Any]]:
    weeks = [
        (datetime.now(UTC) - timedelta(weeks=offset)).isocalendar()
        for offset in range(5, -1, -1)
    ]
    labels = [f"{year}-W{week:02d}" for year, week, _weekday in weeks]
    buckets: dict[str, list[int]] = {label: [] for label in labels}
    for scan in scans:
        if scan.score is None:
            continue
        year, week, _weekday = _aware_datetime(scan.created_at).isocalendar()
        label = f"{year}-W{week:02d}"
        if label in buckets:
            buckets[label].append(scan.score)
    values = [
        round(sum(scores) / len(scores), 1) if scores else 0
        for scores in buckets.values()
    ]
    return {"labels": labels, "values": values}


def chart_owasp_top(findings: list[dict[str, Any]]) -> dict[str, list[Any]]:
    counts: dict[str, int] = {}
    for finding in findings:
        category_id = finding.get("category_id")
        if isinstance(category_id, str):
            counts[category_id] = counts.get(category_id, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:10]
    return {
        "labels": [item[0] for item in ranked],
        "values": [item[1] for item in ranked],
    }


def chart_cve_by_severity(cves: list[dict[str, Any]]) -> dict[str, list[Any]]:
    counts: dict[str, int] = {}
    for cve in cves:
        severity = str(cve.get("severity") or "Unknown")
        counts[severity] = counts.get(severity, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: item[0])
    return {
        "labels": [item[0] for item in ranked],
        "values": [item[1] for item in ranked],
    }


def chart_high_risk_trend(scans: list[Scan]) -> dict[str, list[Any]]:
    days = [
        (datetime.now(UTC) - timedelta(days=offset)).date()
        for offset in range(6, -1, -1)
    ]
    counts = {day.isoformat(): 0 for day in days}
    for scan in scans:
        day = _aware_datetime(scan.created_at).date().isoformat()
        if day in counts and scan.risk_level == "Alto":
            counts[day] += 1
    return {"labels": list(counts.keys()), "values": list(counts.values())}


def scan_alerts(scan: Scan) -> list[dict[str, Any]]:
    """Return passive scan alerts for a stored scan."""
    report_data = scan.report_data or {}
    modules = report_data.get("modules") if isinstance(report_data, dict) else None
    if not isinstance(modules, dict):
        return []
    passive = modules.get("passive_scan")
    if not isinstance(passive, dict):
        return []
    return _dict_items(passive.get("alerts"))


def _aware_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def scan_options_from_form(form: ScanForm) -> dict[str, Any]:
    """Build scan options, preserving defaults for compact dashboard submits."""
    defaults = default_scan_options()
    submitted = request.form
    return {
        "spider_depth": int(
            form.spider_depth.data
            if "spider_depth" in submitted and form.spider_depth.data is not None
            else defaults["spider_depth"]
        ),
        "passive_scan": (
            form.enable_passive_scan.data
            if "enable_passive_scan" in submitted
            else defaults["passive_scan"]
        ),
        "screenshot": (
            form.enable_screenshot.data
            if "enable_screenshot" in submitted
            else defaults["screenshot"]
        ),
        "owasp_mapping": (
            form.enable_owasp_mapping.data
            if "enable_owasp_mapping" in submitted
            else defaults["owasp_mapping"]
        ),
        "cve_lookup": (
            form.enable_cve_lookup.data
            if "enable_cve_lookup" in submitted
            else defaults["cve_lookup"]
        ),
    }


def filter_scans_by_owasp(scans: list[Scan], category_id: str) -> list[Scan]:
    """Filter scans by a stored or derived OWASP category id."""
    if not category_id:
        return scans
    return [
        scan
        for scan in scans
        if any(
            finding.get("category_id") == category_id
            for finding in scan_owasp_findings(scan)
        )
    ]


def scan_owasp_findings(scan: Scan) -> list[dict[str, Any]]:
    """Return stored OWASP findings or derive them for older scans."""
    report_data = scan.report_data or {}
    if not isinstance(report_data, dict):
        return []
    stored = report_data.get("owasp_findings")
    if isinstance(stored, list):
        return [item for item in stored if isinstance(item, dict)]
    modules = report_data.get("modules")
    if not isinstance(modules, dict):
        return []
    return classify_owasp_findings(
        str(report_data.get("target_url") or scan.target_url),
        modules,
    )


def scan_owasp_categories(scan: Scan) -> list[dict[str, str]]:
    """Return unique OWASP categories present on a scan."""
    categories: dict[str, str] = {}
    for finding in scan_owasp_findings(scan):
        category_id = finding.get("category_id")
        category = finding.get("category")
        if isinstance(category_id, str) and isinstance(category, str):
            categories[category_id] = category
    return [
        {"id": category_id, "label": label}
        for category_id, label in categories.items()
    ]


def run_uptime_check(site: MonitoredSite) -> UptimeCheck:
    """Run and persist one uptime check for a monitored site."""
    result = check_url(site.url)
    check = UptimeCheck(
        site_id=site.id,
        up=result["up"],
        status_code=result["status_code"],
        response_time_ms=result["response_time_ms"],
        ssl_valid=result["ssl_valid"],
        error=result["error"],
    )
    db.session.add(check)
    site.ssl_enabled = result["ssl_enabled"]
    site.last_check = datetime.now(UTC)
    db.session.flush()
    refresh_site_uptime_metrics(site)
    return check


def refresh_site_uptime_metrics(site: MonitoredSite) -> None:
    checks = UptimeCheck.query.filter_by(site_id=site.id).all()
    total = len(checks)
    up = sum(1 for check in checks if check.up)
    times = [
        check.response_time_ms
        for check in checks
        if check.response_time_ms is not None
    ]
    site.uptime_percentage = round((up / total) * 100, 2) if total else 0.0
    site.avg_response_time = round(sum(times) / len(times), 1) if times else 0.0


def run_due_uptime_checks() -> None:
    """Run checks for active sites older than five minutes."""
    threshold = datetime.now(UTC) - timedelta(minutes=5)
    sites = MonitoredSite.query.filter_by(active=True).all()
    for site in sites:
        if site.last_check is None or _aware_datetime(site.last_check) <= threshold:
            run_uptime_check(site)
    db.session.commit()


def uptime_dashboard_stats(sites: list[MonitoredSite]) -> dict[str, Any]:
    checks = [
        check
        for site in sites
        for check in site.checks
    ]
    response_times = [
        check.response_time_ms
        for check in checks
        if check.response_time_ms is not None
    ]
    latest_checks = [site.checks[-1] for site in sites if site.checks]
    latest_update = max(
        (_aware_datetime(check.checked_at) for check in latest_checks),
        default=None,
    )
    monitored_with_checks = [site for site in sites if site.checks]
    global_uptime = (
        round(
            sum(site.uptime_percentage for site in monitored_with_checks)
            / len(monitored_with_checks),
            2,
        )
        if monitored_with_checks
        else 0.0
    )
    return {
        "total_sites": len(sites),
        "up_sites": sum(1 for site in sites if site.checks and site.checks[-1].up),
        "down_sites": sum(1 for site in sites if site.checks and not site.checks[-1].up),
        "ssl_valid": sum(1 for site in sites if site.ssl_enabled and site.checks and site.checks[-1].ssl_valid),
        "ssl_expired": sum(1 for site in sites if site.ssl_enabled and site.checks and not site.checks[-1].ssl_valid),
        "avg_response_time": round(sum(response_times) / len(response_times), 1)
        if response_times
        else 0,
        "min_response_time": min(response_times) if response_times else 0,
        "max_response_time": max(response_times) if response_times else 0,
        "global_uptime": global_uptime,
        "latest_update": latest_update.strftime("%Y-%m-%d %H:%M:%S")
        if latest_update
        else "-",
        "all_operational": bool(sites) and all(check.up for check in latest_checks)
        if latest_checks
        else False,
    }


def uptime_chart_data(sites: list[MonitoredSite]) -> dict[str, Any]:
    checks = [
        check
        for site in sites
        for check in site.checks
    ]
    return {
        "availability_24h": uptime_availability_series(checks, hours=24),
        "availability_7d": uptime_availability_series(checks, days=7),
        "availability_30d": uptime_availability_series(checks, days=30),
        "avg_response": uptime_response_series(checks),
        "down_trend": uptime_down_trend(checks),
    }


def uptime_availability_series(
    checks: list[UptimeCheck],
    *,
    hours: int | None = None,
    days: int | None = None,
) -> dict[str, list[Any]]:
    now = datetime.now(UTC)
    if hours is not None:
        labels = [
            (now - timedelta(hours=offset)).strftime("%H:00")
            for offset in range(hours - 1, -1, -1)
        ]
        buckets = {label: [] for label in labels}
        for check in checks:
            label = _aware_datetime(check.checked_at).strftime("%H:00")
            if label in buckets:
                buckets[label].append(check.up)
    else:
        length = days or 7
        labels = [
            (now - timedelta(days=offset)).date().isoformat()
            for offset in range(length - 1, -1, -1)
        ]
        buckets = {label: [] for label in labels}
        for check in checks:
            label = _aware_datetime(check.checked_at).date().isoformat()
            if label in buckets:
                buckets[label].append(check.up)
    values = [
        round((sum(1 for item in values if item) / len(values)) * 100, 1)
        if values
        else 0
        for values in buckets.values()
    ]
    return {"labels": labels, "values": values}


def uptime_response_series(checks: list[UptimeCheck]) -> dict[str, list[Any]]:
    latest = sorted(checks, key=lambda item: item.checked_at)[-20:]
    return {
        "labels": [check.checked_at.strftime("%H:%M") for check in latest],
        "values": [check.response_time_ms or 0 for check in latest],
    }


def uptime_down_trend(checks: list[UptimeCheck]) -> dict[str, list[Any]]:
    days = [
        (datetime.now(UTC) - timedelta(days=offset)).date()
        for offset in range(6, -1, -1)
    ]
    buckets = {day.isoformat(): 0 for day in days}
    for check in checks:
        label = _aware_datetime(check.checked_at).date().isoformat()
        if label in buckets and not check.up:
            buckets[label] += 1
    return {"labels": list(buckets.keys()), "values": list(buckets.values())}


def uptime_table_rows(sites: list[MonitoredSite]) -> list[dict[str, Any]]:
    """Build view-oriented uptime rows with compact visual history."""
    rows: list[dict[str, Any]] = []
    for site in sites:
        checks = list(site.checks)
        last = checks[-1] if checks else None
        history_checks = checks[-30:]
        missing_slots = max(0, 30 - len(history_checks))
        history = ["unknown"] * missing_slots
        history.extend("up" if check.up else "down" for check in history_checks)
        rows.append(
            {
                "site": site,
                "last": last,
                "history": history,
                "status_label": _uptime_status_label(last.status_code if last else None),
            }
        )
    return rows


def _uptime_status_label(status_code: int | None) -> str:
    if status_code is None:
        return "-"
    if 200 <= status_code < 400:
        return f"{status_code} - SUCCESS"
    if 400 <= status_code < 500:
        return f"{status_code} - CLIENT ERROR"
    if status_code >= 500:
        return f"{status_code} - SERVER ERROR"
    return str(status_code)


def stored_report_path(scan: Scan) -> Path | None:
    """Return a stored HTML report path if it exists under the report directory."""
    if not scan.report_path:
        return None

    report_dir = Path(str(current_app.config["VIGISCAN_REPORT_DIR"])).resolve()
    path = Path(scan.report_path).resolve()
    if not path.is_relative_to(report_dir) or not path.exists():
        return None
    return path


def scan_screenshot_metadata(scan: Scan) -> dict[str, Any]:
    """Return stored screenshot metadata or an unavailable message."""
    report_data = scan.report_data or {}
    screenshot = report_data.get("screenshot") if isinstance(report_data, dict) else None
    if isinstance(screenshot, dict):
        return screenshot
    return {"ok": False, "path": None, "message": "captura no disponible"}


def stored_screenshot_path(scan: Scan) -> Path | None:
    """Return a stored screenshot path if it exists under reports/screenshots."""
    screenshot = scan_screenshot_metadata(scan)
    if screenshot.get("ok") is not True or not screenshot.get("path"):
        return None

    screenshot_dir = (
        Path(str(current_app.config["VIGISCAN_REPORT_DIR"])) / "screenshots"
    ).resolve()
    path = Path(str(screenshot["path"])).resolve()
    if not path.is_relative_to(screenshot_dir) or not path.exists():
        return None
    return path
