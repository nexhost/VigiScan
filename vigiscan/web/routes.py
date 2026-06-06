"""Routes for the VigiScan web interface."""

from __future__ import annotations

import csv
import io
import json
import requests
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
    jsonify,
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
from vigiscan.modules.dns_lookup import lookup_domain, normalize_lookup_target
from vigiscan.modules.infra_monitor import collect_metrics, human_uptime
from vigiscan.modules.pdf_report import PDFReportUnavailable, generate_pdf_from_html
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
from vigiscan.web.i18n import DEFAULT_LANGUAGE, SUPPORTED_LANGUAGES
from vigiscan.web.forms import (
    AssetForm,
    DomainLookupForm,
    IndicatorForm,
    InfrastructureHostForm,
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
    InfrastructureHost,
    InfrastructureMetric,
    Indicator,
    MonitoredSite,
    RemoteInfrastructureMetric,
    Scan,
    SystemSettings,
    UptimeCheck,
    User,
    VirusTotalResult,
    db,
)

bp = Blueprint("main", __name__)


@bp.get("/")
@bp.get("/dashboard")
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
    overview_stats = build_security_overview_stats(
        all_scans,
        monitored_sites,
        vt_enabled=bool(current_user.virustotal_enabled),
    )
    infra_metric = capture_infrastructure_metric()
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
        overview_stats=overview_stats,
        infrastructure=metric_to_dict(infra_metric),
        regional_settings=get_system_settings(),
        recent_iocs=Indicator.query.order_by(Indicator.created_at.desc()).limit(5).all(),
        vt_summary={
            "cached_results": VirusTotalResult.query.count(),
            "latest_reputation": vt_latest.reputation if vt_latest else 0,
            "latest_target": vt_latest.observable_value if vt_latest else "-",
        },
        dns_summary=build_dns_dashboard_summary(),
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


@bp.post("/settings/language")
@login_required
def set_language():
    language = request.form.get("language", DEFAULT_LANGUAGE).strip().lower()
    if language not in SUPPORTED_LANGUAGES:
        language = DEFAULT_LANGUAGE
    current_user.language_preference = language
    db.session.commit()
    from flask import session

    session["language"] = language
    flash("Idioma actualizado." if language == "es" else "Language updated.", "success")
    next_url = request.form.get("next") or url_for("main.dashboard")
    return redirect(next_url)


@bp.route("/scans/new", methods=("GET", "POST"))
@bp.route("/scan/new", methods=("GET", "POST"))
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
        regional_form.threat_map_url.data = settings_record.threat_map_url or ""
        regional_form.threat_map_external_enabled.data = bool(
            settings_record.threat_map_external_enabled
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
        settings_record.threat_map_url = (
            (regional_form.threat_map_url.data or "").strip() or None
        )
        settings_record.threat_map_external_enabled = bool(
            regional_form.threat_map_external_enabled.data
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


@bp.get("/reports/<int:scan_id>/pdf")
@bp.get("/scans/<int:scan_id>/pdf")
@login_required
def scan_download_pdf(scan_id: int):
    scan = db.get_or_404(Scan, scan_id)
    pdf_dir = Path(str(current_app.config["VIGISCAN_REPORT_DIR"])) / "pdf"
    filename_date = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    output_path = pdf_dir / f"vigiscan-report-{scan.id}-{filename_date}.pdf"
    html = render_template("pdf_report.html", **build_pdf_report_context(scan))
    try:
        pdf_path = generate_pdf_from_html(
            html,
            output_path,
            base_url=str(Path(current_app.root_path).resolve()),
        )
    except PDFReportUnavailable as exc:
        flash(str(exc), "warning")
        return redirect(url_for("main.scan_detail", scan_id=scan.id))
    except Exception as exc:
        current_app.logger.exception("PDF report generation failed")
        flash(f"No se pudo generar el PDF: {exc}", "danger")
        return redirect(url_for("main.scan_detail", scan_id=scan.id))

    flash("PDF ejecutivo generado correctamente.", "success")
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=pdf_path.name,
        mimetype="application/pdf",
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
    configure_monitored_site_form(form)
    if form.validate_on_submit():
        site = MonitoredSite()
        populate_monitored_site_from_form(site, form)
        db.session.add(site)
        db.session.commit()
        run_uptime_check(site)
        db.session.commit()
        flash("Sitio agregado al monitoreo.", "success")
        return redirect(url_for("main.uptime"))

    sites = MonitoredSite.query.order_by(MonitoredSite.created_at.desc()).all()
    stats = uptime_dashboard_stats(sites)
    infra_metric = capture_infrastructure_metric()
    return render_template(
        "uptime.html",
        form=form,
        sites=sites,
        stats=stats,
        infra=metric_to_dict(infra_metric),
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


@bp.route("/uptime/<int:site_id>/edit", methods=("GET", "POST"))
@login_required
def uptime_edit(site_id: int):
    site = db.get_or_404(MonitoredSite, site_id)
    form = MonitoredSiteForm(obj=site)
    configure_monitored_site_form(form)
    if request.method == "GET":
        form.infrastructure_host_id.data = site.infrastructure_host_id or 0
    if form.validate_on_submit():
        populate_monitored_site_from_form(site, form)
        db.session.commit()
        flash("Monitor uptime actualizado.", "success")
        return redirect(url_for("main.uptime"))
    return render_template("uptime_form.html", form=form, site=site)


@bp.post("/uptime/<int:site_id>/pause")
@login_required
def uptime_pause(site_id: int):
    site = db.get_or_404(MonitoredSite, site_id)
    site.active = False
    db.session.commit()
    flash("Monitor pausado.", "success")
    return redirect(url_for("main.uptime"))


@bp.post("/uptime/<int:site_id>/resume")
@login_required
def uptime_resume(site_id: int):
    site = db.get_or_404(MonitoredSite, site_id)
    site.active = True
    db.session.commit()
    flash("Monitor reanudado.", "success")
    return redirect(url_for("main.uptime"))


@bp.post("/uptime/<int:site_id>/delete")
@login_required
def uptime_delete(site_id: int):
    site = db.get_or_404(MonitoredSite, site_id)
    db.session.delete(site)
    db.session.commit()
    flash("Monitor eliminado.", "success")
    return redirect(url_for("main.uptime"))


@bp.route("/infrastructure", methods=("GET", "POST"))
@login_required
def infrastructure():
    form = InfrastructureHostForm()
    if form.validate_on_submit():
        host = InfrastructureHost()
        populate_infrastructure_host_from_form(host, form)
        db.session.add(host)
        db.session.commit()
        flash("Servidor registrado en Infrastructure Monitor.", "success")
        return redirect(url_for("main.infrastructure"))

    metric = capture_infrastructure_metric()
    history = InfrastructureMetric.query.order_by(
        InfrastructureMetric.created_at.desc()
    ).limit(50).all()
    history.reverse()
    hosts = InfrastructureHost.query.order_by(InfrastructureHost.created_at.desc()).all()
    return render_template(
        "infrastructure.html",
        form=form,
        metric=metric_to_dict(metric),
        history=metrics_history_to_chart(history),
        hosts=hosts,
        host_rows=[infrastructure_host_row(host) for host in hosts],
    )


@bp.route("/infrastructure/<int:host_id>", methods=("GET", "POST"))
@login_required
def infrastructure_detail(host_id: int):
    host = db.get_or_404(InfrastructureHost, host_id)
    form = InfrastructureHostForm(obj=host)
    if request.method == "GET":
        form.api_token.data = ""
    if form.validate_on_submit():
        populate_infrastructure_host_from_form(host, form)
        db.session.commit()
        flash("Servidor actualizado.", "success")
        return redirect(url_for("main.infrastructure_detail", host_id=host.id))
    metrics = list(host.metrics)[-50:]
    return render_template(
        "infrastructure_detail.html",
        host=host,
        form=form,
        metrics=metrics,
        chart=remote_metrics_history_to_chart(metrics),
        related_sites=host.monitored_sites,
        related_assets=host.assets,
    )


@bp.post("/infrastructure/<int:host_id>/check")
@login_required
def infrastructure_check(host_id: int):
    host = db.get_or_404(InfrastructureHost, host_id)
    collect_remote_infrastructure_metric(host)
    db.session.commit()
    flash("Chequeo de infraestructura ejecutado.", "success")
    return redirect(url_for("main.infrastructure_detail", host_id=host.id))


@bp.post("/infrastructure/<int:host_id>/delete")
@login_required
def infrastructure_delete(host_id: int):
    host = db.get_or_404(InfrastructureHost, host_id)
    db.session.delete(host)
    db.session.commit()
    flash("Servidor eliminado.", "success")
    return redirect(url_for("main.infrastructure"))


@bp.get("/threat-map")
@login_required
def threat_map():
    settings_record = get_system_settings()
    return render_template(
        "threat_map.html",
        threat_map_url=settings_record.threat_map_url,
        external_enabled=bool(settings_record.threat_map_external_enabled),
        events=demo_threat_events(),
    )


@bp.get("/api/dashboard/summary")
@login_required
def api_dashboard_summary():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    sites = MonitoredSite.query.order_by(MonitoredSite.created_at.desc()).all()
    vt_latest = VirusTotalResult.query.order_by(
        VirusTotalResult.queried_at.desc()
    ).first()
    return jsonify(
        {
            "dashboard": build_dashboard_stats(scans),
            "platform": build_platform_stats(sites),
            "overview": build_security_overview_stats(
                scans,
                sites,
                vt_enabled=bool(current_user.virustotal_enabled),
            ),
            "uptime": uptime_dashboard_stats(sites),
            "virustotal": {
                "enabled": bool(current_user.virustotal_enabled),
                "cached_results": VirusTotalResult.query.count(),
                "latest_target": vt_latest.observable_value if vt_latest else None,
                "latest_reputation": vt_latest.reputation if vt_latest else 0,
            },
            "dns": build_dns_dashboard_summary(),
            "infrastructure": metric_to_dict(capture_infrastructure_metric()),
        }
    )


@bp.get("/api/dashboard/charts")
@login_required
def api_dashboard_charts():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    stats = build_dashboard_stats(scans)
    risk_counts = {
        "Alto": Scan.query.filter_by(risk_level="Alto").count(),
        "Medio": Scan.query.filter_by(risk_level="Medio").count(),
        "Bajo": Scan.query.filter_by(risk_level="Bajo").count(),
    }
    top_technologies = detected_technology_counts(limit=10)
    return jsonify(
        {
            "severity": {"labels": list(risk_counts.keys()), "values": list(risk_counts.values())},
            "technology": {
                "labels": [item["name"] for item in top_technologies],
                "values": [item["count"] for item in top_technologies],
            },
            "scans_by_day": stats["scans_by_day"],
            "findings_by_severity": stats["findings_by_severity"],
            "weekly_risk": stats["weekly_risk"],
            "owasp_top": stats["owasp_top"],
            "cve_by_severity": stats["cve_by_severity"],
            "high_risk_trend": stats["high_risk_trend"],
        }
    )


@bp.get("/api/uptime/summary")
@login_required
def api_uptime_summary():
    sites = MonitoredSite.query.order_by(MonitoredSite.created_at.desc()).all()
    return jsonify(uptime_dashboard_stats(sites))


@bp.get("/api/uptime/history")
@login_required
def api_uptime_history():
    sites = MonitoredSite.query.order_by(MonitoredSite.created_at.desc()).all()
    return jsonify(uptime_chart_data(sites))


@bp.get("/api/infrastructure/metrics")
@login_required
def api_infrastructure_metrics():
    return jsonify(metric_to_dict(capture_infrastructure_metric()))


@bp.get("/api/infrastructure/history")
@login_required
def api_infrastructure_history():
    history = InfrastructureMetric.query.order_by(
        InfrastructureMetric.created_at.desc()
    ).limit(100).all()
    history.reverse()
    return jsonify(metrics_history_to_chart(history))


@bp.route("/assets", methods=("GET", "POST"))
@login_required
def assets():
    form = AssetForm()
    configure_asset_form(form)
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
    configure_asset_form(form)
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
    configure_asset_form(form)
    if request.method == "GET":
        form.ip_address.data = asset.ip_address
        form.infrastructure_host_id.data = asset.infrastructure_host_id or 0
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


@bp.route("/domain-intel/dns", methods=("GET", "POST"))
@bp.route("/dns", methods=("GET", "POST"))
@bp.route("/domain", methods=("GET", "POST"))
@login_required
def domain_dns():
    form = DomainLookupForm()
    result = None
    if form.validate_on_submit():
        result = lookup_domain(form.target.data.strip())
    return render_template(
        "domain_dns.html",
        form=form,
        result=result,
        summary=build_dns_dashboard_summary(),
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


def build_pdf_report_context(scan: Scan) -> dict[str, Any]:
    """Build the executive PDF template context for one scan."""
    report_data = scan.report_data if isinstance(scan.report_data, dict) else None
    if not report_data or "risk" not in report_data or "executive_summary" not in report_data:
        report_data = build_report(
            target_url=scan.target_url,
            modules={},
            generated_at=scan.completed_at or scan.created_at,
        )
    findings = scan_findings(scan)
    settings_record = get_system_settings()
    severity_counts = pdf_severity_counts(findings)
    charts = [
        {
            "title": "Hallazgos por severidad",
            "items": chart_items_from_counts(severity_counts),
        },
        {
            "title": "OWASP Top 10",
            "items": chart_items_from_counts(
                _count_values(
                    item.get("category_id") or item.get("category") or "OWASP"
                    for item in findings["owasp"]
                )
            ),
        },
        {
            "title": "CVE por severidad",
            "items": chart_items_from_counts(
                _count_values(str(cve.get("severity") or "Unknown") for cve in findings["cves"])
            ),
        },
        {
            "title": "Tecnologias detectadas",
            "items": chart_items_from_counts(
                _count_values(str(tech.get("name") or "Unknown") for tech in findings["technologies"])
            ),
        },
        {
            "title": "Score de riesgo",
            "items": [
                {
                    "label": scan.risk_level or report_data["risk"]["level"],
                    "value": scan.score if scan.score is not None else report_data["risk"]["score"],
                    "percent": scan.score if scan.score is not None else report_data["risk"]["score"],
                }
            ],
        },
        {
            "title": "Estado SSL",
            "items": chart_items_from_counts(_count_values([pdf_module_state(scan, "tls_analyzer")])),
        },
    ]
    logo_path = Path(current_app.root_path) / "static" / "img" / "vigiscan-logo.svg"
    return {
        "scan": scan,
        "report": report_data,
        "findings": findings,
        "organization": settings_record.organization_name or "Organizacion no configurada",
        "country": settings_record.country,
        "timezone": settings_record.timezone,
        "generated_local": local_datetime(datetime.now(UTC)),
        "logo_url": logo_path.resolve().as_uri(),
        "severity_counts": severity_counts,
        "charts": charts,
        "tls_state": pdf_module_state(scan, "tls_analyzer"),
        "waf_state": pdf_module_state(scan, "waf_detect"),
        "api_security_state": pdf_module_state(scan, "api_security"),
        "secret_state": pdf_module_state(scan, "secret_scanner"),
        "general_recommendation": pdf_general_recommendation(scan, severity_counts),
        "remediation_plan": pdf_remediation_plan(findings),
        "executive_conclusion": pdf_executive_conclusion(scan),
        "residual_risk": scan.risk_level or report_data["risk"]["level"],
    }


def pdf_severity_counts(findings: dict[str, list[dict[str, Any]]]) -> dict[str, int]:
    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Alto": 0,
        "Medio": 0,
        "Bajo": 0,
        "Unknown": 0,
    }
    for collection in (
        findings["missing_headers"],
        findings["cves"],
        findings["owasp"],
    ):
        for item in collection:
            severity = str(item.get("severity") or "Unknown")
            counts[severity] = counts.get(severity, 0) + 1
    return counts


def chart_items_from_counts(counts: dict[str, int]) -> list[dict[str, Any]]:
    visible = [
        {"label": label, "value": value}
        for label, value in counts.items()
        if value
    ]
    if not visible:
        visible = [{"label": "Sin datos", "value": 0}]
    max_value = max((item["value"] for item in visible), default=1) or 1
    return [
        {
            "label": item["label"],
            "value": item["value"],
            "percent": round((item["value"] / max_value) * 100, 1) if max_value else 0,
        }
        for item in visible[:8]
    ]


def _count_values(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        label = str(value or "Unknown")
        counts[label] = counts.get(label, 0) + 1
    return counts


def pdf_module_state(scan: Scan, module_name: str) -> str:
    report_data = scan.report_data or {}
    modules = report_data.get("modules") if isinstance(report_data, dict) else None
    module = modules.get(module_name) if isinstance(modules, dict) else None
    if not isinstance(module, dict):
        return "Sin datos"
    if module.get("error"):
        return "Requiere revision"
    if module.get("detections") or module.get("findings") or module.get("alerts"):
        return "Hallazgos registrados"
    return "Sin hallazgos relevantes"


def pdf_general_recommendation(scan: Scan, severity_counts: dict[str, int]) -> str:
    high_total = (
        severity_counts.get("Critical", 0)
        + severity_counts.get("High", 0)
        + severity_counts.get("Alto", 0)
    )
    if high_total or scan.risk_level == "Alto":
        return "Priorizar remediaciones criticas y altas antes de cambios funcionales no urgentes."
    if scan.risk_level == "Medio":
        return "Planificar remediacion en el siguiente ciclo operativo y validar controles preventivos."
    return "Mantener monitoreo continuo, parches al dia y revalidacion periodica."


def pdf_executive_conclusion(scan: Scan) -> str:
    score = scan.score if scan.score is not None else 0
    if scan.risk_level == "Alto" or score >= 70:
        return "El objetivo presenta exposicion relevante y requiere remediacion prioritaria con validacion posterior."
    if scan.risk_level == "Medio" or score >= 35:
        return "El objetivo presenta riesgos gestionables que deben tratarse dentro del ciclo de mejora continua."
    return "El objetivo no presenta exposicion alta en los controles evaluados, manteniendo monitoreo preventivo."


def pdf_remediation_plan(findings: dict[str, list[dict[str, Any]]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for cve in findings["cves"][:4]:
        rows.append(
            {
                "priority": str(cve.get("severity") or "Alta"),
                "finding": str(cve.get("cve_id") or cve.get("cve") or "CVE"),
                "action": str(cve.get("recommendation") or "Actualizar componente afectado."),
                "owner": "AppSec / DevOps",
                "eta": "7-15 dias",
            }
        )
    for header in findings["missing_headers"][:4]:
        rows.append(
            {
                "priority": str(header.get("severity") or "Media"),
                "finding": f"Header {header.get('header', 'seguridad')}",
                "action": "Aplicar header recomendado y validar comportamiento.",
                "owner": "Web Platform",
                "eta": "3-7 dias",
            }
        )
    if not rows:
        rows.append(
            {
                "priority": "Baja",
                "finding": "Sin hallazgos criticos",
                "action": "Mantener monitoreo y ejecutar revalidacion periodica.",
                "owner": "SOC",
                "eta": "Continuo",
            }
        )
    return rows[:8]


def masked_api_key(api_key: str | None) -> str:
    """Show only the last four API key characters."""
    if not api_key:
        return "No configurada"
    tail = api_key[-4:] if len(api_key) >= 4 else api_key
    return f"********{tail}"


def populate_monitored_site_from_form(site: MonitoredSite, form: MonitoredSiteForm) -> None:
    """Persist uptime monitor metadata from a submitted form."""
    site.name = form.name.data.strip()
    site.url = form.url.data.strip()
    site.environment = form.environment.data
    site.responsible = (form.responsible.data or "").strip() or None
    site.country = (form.country.data or "").strip() or None
    site.criticality = form.criticality.data
    site.monitor_interval_minutes = int(form.monitor_interval_minutes.data or 5)
    site.notes = (form.notes.data or "").strip() or None
    site.infrastructure_host_id = form.infrastructure_host_id.data or None
    site.active = bool(form.active.data)


def configure_monitored_site_form(form: MonitoredSiteForm) -> None:
    """Populate infrastructure host choices for uptime forms."""
    form.infrastructure_host_id.choices = infrastructure_host_choices()


def configure_asset_form(form: AssetForm) -> None:
    """Populate infrastructure host choices for asset forms."""
    form.infrastructure_host_id.choices = infrastructure_host_choices()


def infrastructure_host_choices() -> list[tuple[int, str]]:
    hosts = InfrastructureHost.query.order_by(InfrastructureHost.name.asc()).all()
    return [(0, "Sin servidor asociado")] + [
        (host.id, host.name) for host in hosts
    ]


def populate_infrastructure_host_from_form(
    host: InfrastructureHost,
    form: InfrastructureHostForm,
) -> None:
    """Persist remote infrastructure host metadata from a form."""
    host.name = form.name.data.strip()
    host.ip_address = (form.ip_address.data or "").strip() or None
    host.hostname = (form.hostname.data or "").strip() or None
    host.operating_system = (form.operating_system.data or "").strip() or None
    host.environment = form.environment.data
    host.responsible = (form.responsible.data or "").strip() or None
    host.criticality = form.criticality.data
    host.monitor_method = form.monitor_method.data
    host.api_url = (form.api_url.data or "").strip() or None
    token = (form.api_token.data or "").strip()
    if token:
        host.api_token_encrypted = encrypt_api_key(token, current_app.config["SECRET_KEY"])
    host.notes = (form.notes.data or "").strip() or None
    host.active = bool(form.active.data)


def infrastructure_host_row(host: InfrastructureHost) -> dict[str, Any]:
    latest = host.metrics[-1] if host.metrics else None
    status = latest.status if latest else (
        "Local" if host.monitor_method == "Local" else "Pendiente de agente"
    )
    return {"host": host, "latest": latest, "status": status}


def collect_remote_infrastructure_metric(host: InfrastructureHost) -> RemoteInfrastructureMetric:
    """Collect one metric snapshot for a registered host."""
    if host.monitor_method == "Local":
        local = metric_to_dict(capture_infrastructure_metric())
        metric = RemoteInfrastructureMetric(
            host_id=host.id,
            cpu_percent=float(local["cpu_percent"]),
            memory_percent=float(local["memory_percent"]),
            disk_percent=float(local["disk_percent"]),
            net_bytes_sent=0,
            net_bytes_recv=0,
            upload_rate=float(local["net_upload_rate"]),
            download_rate=float(local["net_download_rate"]),
            active_processes=int(local["active_processes"]),
            uptime=str(local["server_uptime_label"]),
            status="Activo",
        )
    elif host.monitor_method == "Agent/API" and host.api_url:
        metric = collect_agent_metric(host)
    else:
        metric = RemoteInfrastructureMetric(
            host_id=host.id,
            status="Pendiente de agente",
        )
    db.session.add(metric)
    return metric


def collect_agent_metric(host: InfrastructureHost) -> RemoteInfrastructureMetric:
    """Fetch metrics from a remote JSON agent endpoint."""
    headers = {}
    token = decrypt_api_key(host.api_token_encrypted, current_app.config["SECRET_KEY"])
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = requests.get(host.api_url or "", headers=headers, timeout=5)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        current_app.logger.warning("Remote infrastructure agent failed: %s", exc)
        return RemoteInfrastructureMetric(
            host_id=host.id,
            status="Agente no disponible",
        )
    return RemoteInfrastructureMetric(
        host_id=host.id,
        cpu_percent=float(payload.get("cpu_percent") or 0),
        memory_percent=float(payload.get("memory_percent") or 0),
        disk_percent=float(payload.get("disk_percent") or 0),
        net_bytes_sent=int(payload.get("net_bytes_sent") or 0),
        net_bytes_recv=int(payload.get("net_bytes_recv") or 0),
        upload_rate=float(payload.get("upload_rate") or payload.get("net_upload_rate") or 0),
        download_rate=float(payload.get("download_rate") or payload.get("net_download_rate") or 0),
        active_processes=int(payload.get("active_processes") or 0),
        uptime=str(payload.get("uptime") or "-"),
        status="Activo",
    )


def remote_metrics_history_to_chart(
    metrics: list[RemoteInfrastructureMetric],
) -> dict[str, list[Any]]:
    return {
        "labels": [metric.collected_at.strftime("%H:%M") for metric in metrics],
        "cpu": [metric.cpu_percent for metric in metrics],
        "memory": [metric.memory_percent for metric in metrics],
        "disk": [metric.disk_percent for metric in metrics],
        "network_in": [metric.download_rate for metric in metrics],
        "network_out": [metric.upload_rate for metric in metrics],
        "processes": [metric.active_processes for metric in metrics],
    }


def demo_threat_events() -> list[dict[str, str]]:
    """Return clearly labeled demo events for the local threat map animation."""
    return [
        {"origin": "BR", "target": "DO", "type": "Web scan", "time": "10:42", "severity": "Media"},
        {"origin": "US", "target": "DO", "type": "Credential probe", "time": "10:46", "severity": "Alta"},
        {"origin": "NL", "target": "DO", "type": "Bot traffic", "time": "10:51", "severity": "Baja"},
        {"origin": "DE", "target": "DO", "type": "Exploit attempt", "time": "10:58", "severity": "Critica"},
    ]


def capture_infrastructure_metric() -> InfrastructureMetric:
    """Collect and store one infrastructure metric snapshot."""
    data = collect_metrics()
    metric = InfrastructureMetric(**data)
    db.session.add(metric)
    db.session.commit()
    return metric


def metric_to_dict(metric: InfrastructureMetric | None) -> dict[str, Any]:
    """Serialize an infrastructure metric for templates and APIs."""
    if metric is None:
        return {
            "cpu_percent": 0,
            "memory_percent": 0,
            "memory_used": 0,
            "memory_total": 0,
            "disk_percent": 0,
            "disk_used": 0,
            "disk_total": 0,
            "net_upload_rate": 0,
            "net_download_rate": 0,
            "active_processes": 0,
            "server_uptime": 0,
            "server_uptime_label": "0m",
            "created_at": None,
        }
    return {
        "id": metric.id,
        "cpu_percent": metric.cpu_percent,
        "memory_percent": metric.memory_percent,
        "memory_used": metric.memory_used,
        "memory_total": metric.memory_total,
        "disk_percent": metric.disk_percent,
        "disk_used": metric.disk_used,
        "disk_total": metric.disk_total,
        "net_bytes_sent": metric.net_bytes_sent,
        "net_bytes_recv": metric.net_bytes_recv,
        "net_upload_rate": metric.net_upload_rate,
        "net_download_rate": metric.net_download_rate,
        "active_processes": metric.active_processes,
        "server_uptime": metric.server_uptime,
        "server_uptime_label": human_uptime(metric.server_uptime),
        "created_at": metric.created_at.isoformat() if metric.created_at else None,
        "created_at_label": local_datetime(metric.created_at),
    }


def metrics_history_to_chart(metrics: list[InfrastructureMetric]) -> dict[str, Any]:
    """Build infrastructure chart datasets from stored metric samples."""
    return {
        "labels": [local_datetime(metric.created_at) for metric in metrics],
        "cpu": [metric.cpu_percent for metric in metrics],
        "memory": [metric.memory_percent for metric in metrics],
        "disk": [metric.disk_percent for metric in metrics],
        "network_in": [metric.net_download_rate for metric in metrics],
        "network_out": [metric.net_upload_rate for metric in metrics],
        "processes": [metric.active_processes for metric in metrics],
    }


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
    asset.infrastructure_host_id = form.infrastructure_host_id.data or None
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


def build_dns_dashboard_summary() -> dict[str, Any]:
    """Summarize domain inventory coverage for DNS intelligence."""
    domains = {
        normalize_lookup_target(value)
        for asset in Asset.query.all()
        for value in (asset.domain, asset.url, asset.value)
        if value
    }
    site_domains = {
        normalize_lookup_target(site.url)
        for site in MonitoredSite.query.all()
        if site.url
    }
    domains = {domain for domain in domains | site_domains if domain}
    return {
        "domains": len(domains),
        "assets_with_domain": Asset.query.filter(Asset.domain.isnot(None)).count(),
        "monitored_domains": len(site_domains),
        "latest_domain": sorted(domains)[0] if domains else "-",
    }


def build_security_overview_stats(
    scans: list[Scan],
    sites: list[MonitoredSite],
    *,
    vt_enabled: bool,
) -> dict[str, Any]:
    """Build the high-level dashboard cards requested by the web UI."""
    latest_checks = [site.checks[-1] for site in sites if site.checks]
    ssl_valid = sum(1 for check in latest_checks if check.ssl_valid)
    ssl_total = len(latest_checks)
    cves = [
        cve
        for scan in scans
        for cve in scan_findings(scan)["cves"]
    ]
    owasp_findings = [
        finding
        for scan in scans
        for finding in scan_owasp_findings(scan)
    ]
    waf_detections = [
        detection
        for scan in scans
        for detection in scan_waf_detections(scan)
    ]
    return {
        "total_assets": Asset.query.count(),
        "total_iocs": Indicator.query.count(),
        "virustotal_enabled": vt_enabled,
        "uptime_sites": len(sites),
        "waf_detected": len(waf_detections),
        "ssl_health": f"{ssl_valid}/{ssl_total}" if ssl_total else "0/0",
        "owasp_findings": len(owasp_findings),
        "cve_count": len(cves),
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


def scan_waf_detections(scan: Scan) -> list[dict[str, Any]]:
    """Return passive edge protection detections stored on a scan."""
    report_data = scan.report_data or {}
    modules = report_data.get("modules") if isinstance(report_data, dict) else None
    if not isinstance(modules, dict):
        return []
    waf_report = modules.get("waf_detect")
    if not isinstance(waf_report, dict):
        return []
    return _dict_items(waf_report.get("detections"))


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
    """Run checks for active sites according to their configured interval."""
    now = datetime.now(UTC)
    sites = MonitoredSite.query.filter_by(active=True).all()
    for site in sites:
        interval = max(int(site.monitor_interval_minutes or 5), 1)
        threshold = now - timedelta(minutes=interval)
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
