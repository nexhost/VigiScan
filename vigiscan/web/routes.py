"""Routes for the VigiScan web interface."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    send_file,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from modules.cve_checker import check_tech_report
from modules.directories import DirectoryCheckConfig, analyze_directories
from modules.headers import analyze_headers
from modules.tech_detect import analyze_technologies
from report import ReportDocument, build_report, save_report
from scanner import ScanRequest, ScannerConfig, create_scanner
from vigiscan.web.forms import LoginForm, ScanForm
from vigiscan.web.models import Scan, User, db

bp = Blueprint("main", __name__)


@bp.get("/")
@login_required
def dashboard():
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    total_scans = Scan.query.count()
    risk_counts = {
        "Alto": Scan.query.filter_by(risk_level="Alto").count(),
        "Medio": Scan.query.filter_by(risk_level="Medio").count(),
        "Bajo": Scan.query.filter_by(risk_level="Bajo").count(),
    }
    top_technologies = detected_technology_counts(limit=6)
    return render_template(
        "dashboard.html",
        scans=scans,
        total_scans=total_scans,
        risk_counts=risk_counts,
        severity_chart={
            "labels": list(risk_counts.keys()),
            "values": list(risk_counts.values()),
        },
        technology_chart={
            "labels": [item["name"] for item in top_technologies],
            "values": [item["count"] for item in top_technologies],
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
        scan = Scan(
            target_url=form.target_url.data.strip(),
            status="En ejecucion",
            user_id=current_user.id,
        )
        db.session.add(scan)
        db.session.commit()

        run_vigiscan_scan(scan)
        db.session.commit()

        if scan.status == "Completado":
            flash("Escaneo completado correctamente.", "success")
        else:
            flash("El escaneo no pudo completarse. Revisa el detalle.", "danger")
        return redirect(url_for("main.scan_detail", scan_id=scan.id))
    return render_template("scan_new.html", form=form)


@bp.get("/scans/<int:scan_id>")
@login_required
def scan_detail(scan_id: int):
    scan = db.get_or_404(Scan, scan_id)
    findings = scan_findings(scan)
    return render_template("scan_detail.html", scan=scan, findings=findings)


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


@bp.post("/scans/<int:scan_id>/delete")
@login_required
def scan_delete(scan_id: int):
    scan = db.get_or_404(Scan, scan_id)
    path = stored_report_path(scan)
    db.session.delete(scan)
    db.session.commit()
    if path is not None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    flash("Escaneo eliminado.", "success")
    return redirect(url_for("main.dashboard"))


@bp.get("/reports")
@login_required
def reports():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("reports.html", scans=scans)


def run_vigiscan_scan(scan: Scan) -> None:
    """Run the existing VigiScan engine and persist report metadata."""
    try:
        report_doc = execute_scan(scan.target_url)
        report_dir = Path(str(current_app.config["VIGISCAN_REPORT_DIR"]))
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


def execute_scan(target_url: str) -> ReportDocument:
    """Execute scanner, analysis modules, CVE lookup, and report building."""
    scanner_config = ScannerConfig()
    directory_config = DirectoryCheckConfig()
    scan_result = create_scanner(scanner_config).scan(ScanRequest(url=target_url))
    if not scan_result["ok"]:
        error = scan_result["error"] or {"message": "Error desconocido"}
        raise RuntimeError(str(error["message"]))

    headers_report = analyze_headers(scan_result)
    technologies_report = analyze_technologies(scan_result)
    cve_report = check_tech_report(technologies_report)
    directories_report = analyze_directories(scan_result, config=directory_config)
    return build_report(
        target_url=target_url,
        modules={
            "headers": headers_report,
            "tech_detect": technologies_report,
            "cve_checker": cve_report,
            "directories": directories_report,
        },
    )


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


def stored_report_path(scan: Scan) -> Path | None:
    """Return a stored HTML report path if it exists under the report directory."""
    if not scan.report_path:
        return None

    report_dir = Path(str(current_app.config["VIGISCAN_REPORT_DIR"])).resolve()
    path = Path(scan.report_path).resolve()
    if not path.is_relative_to(report_dir) or not path.exists():
        return None
    return path
