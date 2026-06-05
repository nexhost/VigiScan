"""Report generation for VigiScan.

This module turns normalized scanner/module outputs into TXT, JSON, and HTML
reports. Reports are written to the local ``reports/`` directory by default and
include an executive summary plus a normalized risk score.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any, Literal, NotRequired, TypedDict

DEFAULT_REPORTS_DIR = Path("reports")

ReportFormat = Literal["txt", "json", "html"]
RiskLevel = Literal["Bajo", "Medio", "Alto"]


class RiskSummary(TypedDict):
    """Normalized risk score summary."""

    score: int
    level: RiskLevel
    factors: list[str]


class ExecutiveSummary(TypedDict):
    """Executive summary for a generated report."""

    text: str
    highlights: list[str]


class ReportDocument(TypedDict):
    """Full normalized report document."""

    generated_at: str
    target_url: str | None
    executive_summary: ExecutiveSummary
    risk: RiskSummary
    modules: dict[str, Any]
    screenshot: NotRequired[dict[str, Any]]
    owasp_findings: NotRequired[list[dict[str, Any]]]


@dataclass(frozen=True, slots=True)
class GeneratedReportPaths:
    """Paths written by ``save_reports``."""

    txt: Path
    json: Path
    html: Path


def build_report(
    *,
    target_url: str | None,
    modules: dict[str, Any],
    generated_at: datetime | None = None,
) -> ReportDocument:
    """Build a normalized report document.

    Args:
        target_url: Target URL analyzed by VigiScan.
        modules: Mapping of module names to normalized module reports.
        generated_at: Optional timestamp, mainly for tests.

    Returns:
        A JSON-serializable report document.
    """
    timestamp = generated_at or datetime.now(UTC)
    risk = calculate_risk_score(modules)
    summary = build_executive_summary(target_url=target_url, modules=modules, risk=risk)
    return {
        "generated_at": timestamp.isoformat(),
        "target_url": target_url,
        "executive_summary": summary,
        "risk": risk,
        "modules": modules,
    }


def save_reports(
    report: ReportDocument,
    *,
    output_dir: Path | str = DEFAULT_REPORTS_DIR,
    basename: str | None = None,
) -> GeneratedReportPaths:
    """Save TXT, JSON, and HTML report files.

    Args:
        report: Report document created by ``build_report``.
        output_dir: Directory where files will be written.
        basename: Optional file name stem. A safe default is generated from the
            target URL and timestamp.

    Returns:
        Paths to the generated TXT, JSON, and HTML files.
    """
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    stem = basename or _default_basename(report)
    paths = GeneratedReportPaths(
        txt=destination / f"{stem}.txt",
        json=destination / f"{stem}.json",
        html=destination / f"{stem}.html",
    )

    paths.txt.write_text(render_txt(report), encoding="utf-8")
    paths.json.write_text(render_json(report), encoding="utf-8")
    paths.html.write_text(render_html(report), encoding="utf-8")
    return paths


def save_report(
    report: ReportDocument,
    report_format: ReportFormat,
    *,
    output_dir: Path | str = DEFAULT_REPORTS_DIR,
    basename: str | None = None,
) -> Path:
    """Save one selected report format."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    stem = basename or _default_basename(report)
    path = destination / f"{stem}.{report_format}"

    if report_format == "txt":
        content = render_txt(report)
    elif report_format == "json":
        content = render_json(report)
    else:
        content = render_html(report)

    path.write_text(content, encoding="utf-8")
    return path


def calculate_risk_score(modules: dict[str, Any]) -> RiskSummary:
    """Calculate a normalized 0-100 risk score from module reports."""
    score = 0
    factors: list[str] = []

    headers = modules.get("headers")
    if isinstance(headers, dict):
        header_score, header_factors = _score_headers(headers)
        score += header_score
        factors.extend(header_factors)

    directories = modules.get("directories")
    if isinstance(directories, dict):
        directory_score, directory_factors = _score_directories(directories)
        score += directory_score
        factors.extend(directory_factors)

    cve_report = modules.get("cve_checker")
    if isinstance(cve_report, dict):
        cve_score, cve_factors = _score_cves(cve_report)
        score += cve_score
        factors.extend(cve_factors)

    score = min(100, score)
    return {
        "score": score,
        "level": _risk_level(score),
        "factors": factors or ["No se identificaron factores de riesgo relevantes."],
    }


def build_executive_summary(
    *,
    target_url: str | None,
    modules: dict[str, Any],
    risk: RiskSummary,
) -> ExecutiveSummary:
    """Create an executive summary from module reports and risk."""
    target = target_url or "objetivo no especificado"
    highlights = _summary_highlights(modules)
    text = (
        f"VigiScan evaluo {target}. La puntuacion de riesgo es "
        f"{risk['score']}/100 ({risk['level']}). "
        f"{_summary_sentence(highlights)}"
    )
    return {"text": text, "highlights": highlights}


def render_json(report: ReportDocument) -> str:
    """Render a report as pretty JSON."""
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)


def render_txt(report: ReportDocument) -> str:
    """Render a report as plain text."""
    lines = [
        "VigiScan Security Report",
        "=" * 24,
        f"Generated: {report['generated_at']}",
        f"Target: {report['target_url'] or 'N/A'}",
        "",
        "Executive Summary",
        "-" * 17,
        report["executive_summary"]["text"],
        "",
        "Risk Score",
        "-" * 10,
        f"Score: {report['risk']['score']}/100",
        f"Level: {report['risk']['level']}",
        "Factors:",
    ]
    lines.extend(f"- {factor}" for factor in report["risk"]["factors"])
    lines.extend(["", "OWASP Top 10 2025", "-" * 18])
    lines.extend(_render_txt_owasp(report.get("owasp_findings")))
    lines.extend(["", "Module Results", "-" * 14])

    for module_name, module_report in report["modules"].items():
        lines.extend(_render_txt_module(module_name, module_report))

    return "\n".join(lines) + "\n"


def render_html(report: ReportDocument) -> str:
    """Render a report as a self-contained professional HTML document."""
    target = escape(report["target_url"] or "N/A")
    risk_level = escape(report["risk"]["level"])
    risk_class = risk_level.lower()
    modules_html = "\n".join(
        _render_html_module(name, module)
        for name, module in report["modules"].items()
    )
    factors_html = "\n".join(
        f"<li>{escape(factor)}</li>" for factor in report["risk"]["factors"]
    )
    highlights_html = "\n".join(
        f"<li>{escape(item)}</li>"
        for item in report["executive_summary"]["highlights"]
    )
    screenshot_html = _render_html_screenshot(report.get("screenshot"))
    owasp_html = _render_html_owasp(report.get("owasp_findings"))

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VigiScan Security Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --ink: #18202a;
      --muted: #607080;
      --line: #d8dee6;
      --accent: #0f766e;
      --high: #b42318;
      --medium: #b54708;
      --low: #047857;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.5;
    }}
    .shell {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 24px 48px;
    }}
    header {{
      border-bottom: 1px solid var(--line);
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    h1, h2, h3 {{ margin: 0; }}
    h1 {{ font-size: 30px; }}
    h2 {{ font-size: 20px; margin-bottom: 12px; }}
    h3 {{ font-size: 16px; margin-bottom: 10px; }}
    .meta {{
      color: var(--muted);
      margin-top: 8px;
      overflow-wrap: anywhere;
    }}
    .grid {{
      display: grid;
      grid-template-columns: minmax(0, 1.6fr) minmax(260px, 0.8fr);
      gap: 18px;
      margin-bottom: 18px;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 18px;
    }}
    .score {{
      display: flex;
      align-items: center;
      gap: 16px;
    }}
    .score-number {{
      font-size: 42px;
      font-weight: 700;
    }}
    .badge {{
      display: inline-block;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 13px;
      font-weight: 700;
      color: #ffffff;
    }}
    .badge.alto {{ background: var(--high); }}
    .badge.medio {{ background: var(--medium); }}
    .badge.bajo {{ background: var(--low); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      font-size: 14px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    code {{
      background: #eef2f6;
      border-radius: 4px;
      padding: 2px 5px;
    }}
    .cve-list {{
      display: grid;
      gap: 14px;
      margin-top: 12px;
    }}
    .cve-card {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      background: #fbfcfe;
    }}
    .cve-card h3 {{
      margin: 0;
    }}
    .cve-heading {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }}
    .cve-heading .badge {{
      background: var(--medium);
    }}
    .detail-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin: 12px 0;
    }}
    .detail-item {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      background: #ffffff;
      overflow-wrap: anywhere;
    }}
    .detail-label {{
      color: var(--muted);
      display: block;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .references a {{
      color: var(--accent);
      overflow-wrap: anywhere;
    }}
    ul {{ padding-left: 20px; }}
    @media (max-width: 780px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .detail-grid {{ grid-template-columns: 1fr; }}
      .shell {{ padding: 22px 14px 36px; }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    <header>
      <h1>VigiScan Security Report</h1>
      <div class="meta">Target: {target}</div>
      <div class="meta">Generated: {escape(report['generated_at'])}</div>
    </header>

    <div class="grid">
      <section>
        <h2>Resumen Ejecutivo</h2>
        <p>{escape(report['executive_summary']['text'])}</p>
        <ul>{highlights_html}</ul>
      </section>
      <section>
        <h2>Puntuacion de Riesgo</h2>
        <div class="score">
          <div class="score-number">{report['risk']['score']}</div>
          <div>
            <div>/ 100</div>
            <span class="badge {risk_class}">{risk_level}</span>
          </div>
        </div>
        <ul>{factors_html}</ul>
      </section>
    </div>

    {screenshot_html}
    {owasp_html}
    {modules_html}
  </main>
</body>
</html>
"""


def _score_headers(report: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    factors: list[str] = []
    weights = {"Alto": 18, "Medio": 10, "Bajo": 4}
    for finding in _as_list(report.get("findings")):
        if not isinstance(finding, dict):
            continue
        if finding.get("status") == "Presente":
            continue
        severity = str(finding.get("severity", "Bajo"))
        points = weights.get(severity, 4)
        score += points
        factors.append(
            f"Header {finding.get('header', 'desconocido')} "
            f"{str(finding.get('status', '')).lower()} ({severity})."
        )
    return min(score, 40), factors


def _score_directories(report: dict[str, Any]) -> tuple[int, list[str]]:
    exposed = [
        finding
        for finding in _as_list(report.get("findings"))
        if isinstance(finding, dict) and finding.get("exposed") is True
    ]
    factors = [
        f"Ruta expuesta detectada: {finding.get('path', 'desconocida')}."
        for finding in exposed
    ]
    return min(len(exposed) * 20, 40), factors


def _score_cves(report: dict[str, Any]) -> tuple[int, list[str]]:
    weights = {
        "critical": 35,
        "critica": 35,
        "high": 25,
        "alta": 25,
        "medium": 12,
        "media": 12,
        "low": 5,
        "baja": 5,
    }
    score = 0
    factors: list[str] = []
    for match in _as_list(report.get("matches")):
        if not isinstance(match, dict):
            continue
        severity = str(match.get("severity", "low"))
        points = weights.get(severity.lower(), 5)
        score += points
        cve_id = match.get("cve_id") or match.get("cve", "CVE desconocido")
        factors.append(
            f"{cve_id} afecta "
            f"{match.get('product', 'producto desconocido')} ({severity})."
        )
    return min(score, 60), factors


def _summary_highlights(modules: dict[str, Any]) -> list[str]:
    highlights: list[str] = []
    headers = modules.get("headers")
    if isinstance(headers, dict):
        weak_headers = [
            item
            for item in _as_list(headers.get("findings"))
            if isinstance(item, dict) and item.get("status") != "Presente"
        ]
        highlights.append(f"{len(weak_headers)} cabeceras requieren revision.")

    directories = modules.get("directories")
    if isinstance(directories, dict):
        count = int(directories.get("exposed_count", 0))
        highlights.append(f"{count} rutas comunes aparecen expuestas.")

    cve_report = modules.get("cve_checker")
    if isinstance(cve_report, dict):
        matches = _as_list(cve_report.get("matches"))
        highlights.append(f"{len(matches)} coincidencias CVE locales encontradas.")

    technologies = modules.get("tech_detect")
    if isinstance(technologies, dict):
        tech_count = len(_as_list(technologies.get("technologies")))
        highlights.append(f"{tech_count} tecnologias detectadas.")

    return highlights or ["No hay modulos con hallazgos para resumir."]


def _summary_sentence(highlights: list[str]) -> str:
    return " ".join(highlights)


def _render_txt_module(module_name: str, module_report: Any) -> list[str]:
    lines = ["", module_name, "~" * len(module_name)]
    if isinstance(module_report, dict):
        if module_name == "headers":
            lines.extend(_render_txt_headers(module_report))
        elif module_name == "directories":
            lines.extend(_render_txt_directories(module_report))
        elif module_name == "tech_detect":
            lines.extend(_render_txt_technologies(module_report))
        elif module_name == "cve_checker":
            lines.extend(_render_txt_cves(module_report))
        else:
            lines.append(json.dumps(module_report, ensure_ascii=False, indent=2))
    else:
        lines.append(str(module_report))
    return lines


def _render_txt_owasp(findings: Any) -> list[str]:
    rows = _as_dicts(findings)
    if not rows:
        return ["- Sin clasificaciones OWASP."]
    return [
        "- "
        f"{item.get('finding')} | {item.get('severity')} | "
        f"{item.get('category')} | {item.get('recommendation')}"
        for item in rows
    ]


def _render_txt_headers(report: dict[str, Any]) -> list[str]:
    return [
        f"- {item.get('header')}: {item.get('status')} / {item.get('severity')}"
        for item in _as_dicts(report.get("findings"))
    ]


def _render_txt_directories(report: dict[str, Any]) -> list[str]:
    return [
        f"- {item.get('path')}: {item.get('status')} ({item.get('status_code')})"
        for item in _as_dicts(report.get("findings"))
    ]


def _render_txt_technologies(report: dict[str, Any]) -> list[str]:
    return [
        f"- {item.get('name')} {item.get('version') or 'version desconocida'} "
        f"({item.get('confidence_level')})"
        for item in _as_dicts(report.get("technologies"))
    ]


def _render_txt_cves(report: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for item in _as_dicts(report.get("matches")):
        lines.extend(
            [
                f"- CVE ID: {item.get('cve_id') or item.get('cve')}",
                f"  Product: {item.get('product')}",
                f"  Affected version: "
                f"{item.get('affected_version') or item.get('matched_version') or '-'}",
                f"  Severity: {item.get('severity')}",
                f"  CVSS: {item.get('cvss') if item.get('cvss') is not None else '-'}",
                f"  CWE: {item.get('cwe') or '-'}",
                f"  Description: {item.get('description')}",
                f"  Impact: {item.get('impact') or '-'}",
                f"  Recommendation: {item.get('recommendation') or '-'}",
                "  References: "
                + (
                    ", ".join(str(ref) for ref in _as_list(item.get("references")))
                    or "-"
                ),
            ]
        )
    return lines or ["- Sin CVE encontradas."]


def _render_html_module(module_name: str, module_report: Any) -> str:
    title = escape(module_name.replace("_", " ").title())
    if not isinstance(module_report, dict):
        body = escape(str(module_report))
        return f"<section><h2>{title}</h2><pre>{body}</pre></section>"

    if module_name == "headers":
        rows = _html_rows(
            ("Header", "Estado", "Riesgo", "Valor"),
            (
                (
                    item.get("header"),
                    item.get("status"),
                    item.get("severity"),
                    item.get("value") or "-",
                )
                for item in _as_dicts(module_report.get("findings"))
            ),
        )
    elif module_name == "directories":
        rows = _html_rows(
            ("Ruta", "Estado", "HTTP", "URL"),
            (
                (
                    item.get("path"),
                    item.get("status"),
                    item.get("status_code"),
                    item.get("url"),
                )
                for item in _as_dicts(module_report.get("findings"))
            ),
        )
    elif module_name == "tech_detect":
        rows = _html_rows(
            ("Tecnologia", "Version", "Confianza", "Evidencia"),
            (
                (
                    item.get("name"),
                    item.get("version") or "-",
                    f"{item.get('confidence')} ({item.get('confidence_level')})",
                    "; ".join(str(e) for e in _as_list(item.get("evidence"))),
                )
                for item in _as_dicts(module_report.get("technologies"))
            ),
        )
    elif module_name == "cve_checker":
        return _render_html_cve_module(title, module_report)
    else:
        body = escape(json.dumps(module_report, ensure_ascii=False, indent=2))
        return f"<section><h2>{title}</h2><pre>{body}</pre></section>"

    return f"<section><h2>{title}</h2>{rows}</section>"


def _render_html_screenshot(screenshot: Any) -> str:
    if not isinstance(screenshot, dict):
        return (
            "<section><h2>Captura visual</h2>"
            "<p>captura no disponible</p></section>"
        )
    if screenshot.get("ok") is True:
        image_src = screenshot.get("relative_path") or screenshot.get("path")
        if image_src:
            return (
                "<section><h2>Captura visual</h2>"
                f"<img src=\"{escape(str(image_src), quote=True)}\" "
                "alt=\"Captura visual del sitio escaneado\" "
                "style=\"width:100%;border:1px solid var(--line);"
                "border-radius:8px;display:block;\">"
                "</section>"
            )
    message = str(screenshot.get("message") or "captura no disponible")
    return f"<section><h2>Captura visual</h2><p>{escape(message)}</p></section>"


def _render_html_owasp(findings: Any) -> str:
    rows = _html_rows(
        ("Hallazgo", "Severidad", "Categoria OWASP", "Recomendacion"),
        (
            (
                item.get("finding"),
                item.get("severity"),
                item.get("category"),
                item.get("recommendation"),
            )
            for item in _as_dicts(findings)
        ),
    )
    return f"<section><h2>Clasificacion OWASP Top 10 2025</h2>{rows}</section>"


def _render_html_cve_module(title: str, module_report: dict[str, Any]) -> str:
    cards = []
    for item in _as_dicts(module_report.get("matches")):
        cve_id = item.get("cve_id") or item.get("cve") or "CVE desconocido"
        affected_version = item.get("affected_version") or item.get("matched_version")
        references = _as_list(item.get("references"))
        references_html = "".join(
            f"<li><a href=\"{escape(str(ref), quote=True)}\">"
            f"{escape(str(ref))}</a></li>"
            for ref in references
        ) or "<li>Sin referencias locales.</li>"
        cards.append(
            f"""
      <article class="cve-card">
        <div class="cve-heading">
          <h3>{escape(str(cve_id))}</h3>
          <span class="badge">{escape(str(item.get('severity') or '-'))}</span>
        </div>
        <div class="detail-grid">
          {_detail_item("CVE ID", cve_id)}
          {_detail_item("Producto", item.get("product"))}
          {_detail_item("Version afectada", affected_version)}
          {_detail_item("Severidad", item.get("severity"))}
          {_detail_item("CVSS", item.get("cvss"))}
          {_detail_item("CWE", item.get("cwe"))}
        </div>
        <p><strong>Descripcion:</strong> {escape(str(item.get('description') or '-'))}</p>
        <p><strong>Impacto:</strong> {escape(str(item.get('impact') or '-'))}</p>
        <p><strong>Recomendacion:</strong> {escape(str(item.get('recommendation') or '-'))}</p>
        <div class="references">
          <strong>Referencias:</strong>
          <ul>{references_html}</ul>
        </div>
      </article>
"""
        )
    if not cards:
        cards.append("<p>Sin CVE encontradas.</p>")
    return (
        f"<section><h2>{title}</h2>"
        f"<div class=\"cve-list\">{''.join(cards)}</div></section>"
    )


def _detail_item(label: str, value: Any) -> str:
    display = "-" if value is None or value == "" else str(value)
    return (
        "<div class=\"detail-item\">"
        f"<span class=\"detail-label\">{escape(label)}</span>"
        f"{escape(display)}"
        "</div>"
    )


def _html_rows(headers: tuple[str, ...], rows: Any) -> str:
    header_cells = "".join(f"<th>{escape(header)}</th>" for header in headers)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{escape(str(value))}</td>" for value in row)
        body_rows.append(f"<tr>{cells}</tr>")
    if not body_rows:
        body_rows.append(
            f"<tr><td colspan=\"{len(headers)}\">Sin resultados.</td></tr>"
        )
    return (
        f"<table><thead><tr>{header_cells}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table>"
    )


def _risk_level(score: int) -> RiskLevel:
    if score >= 60:
        return "Alto"
    if score >= 21:
        return "Medio"
    return "Bajo"


def _default_basename(report: ReportDocument) -> str:
    target = report["target_url"] or "vigiscan"
    safe_target = "".join(char if char.isalnum() else "-" for char in target.lower())
    safe_target = "-".join(part for part in safe_target.split("-") if part)
    timestamp = report["generated_at"].replace(":", "").replace("+", "-")
    return f"{safe_target[:48]}-{timestamp[:15]}"


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in _as_list(value) if isinstance(item, dict)]
