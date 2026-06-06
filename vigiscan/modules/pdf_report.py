"""Executive PDF generation helpers for VigiScan reports."""

from __future__ import annotations

from pathlib import Path
from html.parser import HTMLParser


class PDFReportUnavailable(RuntimeError):
    """Raised when the optional PDF backend is not installed."""


def generate_pdf_from_html(
    html: str,
    output_path: Path | str,
    *,
    base_url: str | None = None,
) -> Path:
    """Render HTML into a PDF file using WeasyPrint, falling back to ReportLab."""
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        from weasyprint import HTML
    except Exception:
        return generate_pdf_with_reportlab(html, destination)

    try:
        HTML(string=html, base_url=base_url).write_pdf(str(destination))
        return destination
    except Exception:
        return generate_pdf_with_reportlab(html, destination)


def pdf_available() -> bool:
    """Return True when the optional PDF backend can be imported."""
    try:
        import weasyprint  # noqa: F401
    except Exception:
        try:
            import reportlab  # noqa: F401
        except Exception:
            return False
    return True


def generate_pdf_with_reportlab(html: str, destination: Path) -> Path:
    """Generate a stable executive fallback PDF from HTML text."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception as exc:  # pragma: no cover - depends on optional package
        raise PDFReportUnavailable(
            "La generacion PDF requiere WeasyPrint o ReportLab. Instala el extra con: "
            'pip install -e ".[pdf]"'
        ) from exc

    text = extract_text(html)
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(destination), pagesize=A4, title="Informe Ejecutivo de Seguridad Web")
    story = [
        Paragraph("VigiScan", styles["Title"]),
        Paragraph("Informe Ejecutivo de Seguridad Web", styles["Heading1"]),
        Paragraph("Desarrollado por Kendry Rosario", styles["Normal"]),
        Spacer(1, 18),
    ]
    rows = [["Seccion", "Contenido"]]
    for line in [item for item in text.splitlines() if item.strip()][:42]:
        rows.append(["Reporte", line.strip()])
    table = Table(rows, colWidths=[100, 380])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#10162A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D7E3F4")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )
    story.append(table)
    doc.build(story)
    return destination


class TextExtractor(HTMLParser):
    """Small HTML text extractor for fallback PDF generation."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        value = data.strip()
        if value:
            self.parts.append(value)


def extract_text(html: str) -> str:
    parser = TextExtractor()
    parser.feed(html)
    return "\n".join(parser.parts)
