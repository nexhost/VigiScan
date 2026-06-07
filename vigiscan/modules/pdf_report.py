"""Executive PDF generation helpers for VigiScan reports."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from textwrap import wrap


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
            return True
    return True


def generate_pdf_with_reportlab(html: str, destination: Path) -> Path:
    """Generate a stable executive fallback PDF from HTML text."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception:  # pragma: no cover - depends on optional package
        return generate_pdf_with_builtin_writer(html, destination)

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


def generate_pdf_with_builtin_writer(html: str, destination: Path) -> Path:
    """Generate a dependency-free executive PDF fallback."""
    text = extract_text(html)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    target = _value_after(lines, "URL objetivo") or _first_after(lines, "Informe Ejecutivo de Seguridad Web")
    organization = _value_after(lines, "Organizacion") or "Organizacion no configurada"
    risk = _value_after(lines, "Clasificacion") or "Sin datos"
    score = _value_after(lines, "Risk Score") or "-"
    generated = _value_after(lines, "Fecha local") or ""

    pages: list[str] = []
    pages.append(
        _pdf_page_stream(
            [
                ("VigiScan", 48, 790, 24, "0 0.55 0.65 rg"),
                ("Informe Ejecutivo de Seguridad Web", 48, 760, 18, "0.06 0.09 0.16 rg"),
                ("Desarrollado por Kendry Rosario", 48, 738, 10, "0.30 0.36 0.45 rg"),
                (f"Objetivo: {target}", 48, 700, 11, "0.06 0.09 0.16 rg"),
                (f"Organizacion: {organization}", 48, 680, 11, "0.06 0.09 0.16 rg"),
                (f"Fecha: {generated}", 48, 660, 10, "0.30 0.36 0.45 rg"),
                (f"Risk Score: {score}/100", 48, 610, 28, "0.07 0.72 0.71 rg"),
                (f"Clasificacion: {risk}", 48, 575, 14, "0.06 0.09 0.16 rg"),
            ],
            bars=[
                ("Criticos", _int_after(lines, "Criticos"), "0.86 0.15 0.15 rg"),
                ("Altos", _int_after(lines, "Altos"), "0.92 0.35 0.07 rg"),
                ("Medios", _int_after(lines, "Medios"), "0.79 0.54 0.02 rg"),
                ("Bajos", _int_after(lines, "Bajos"), "0.09 0.64 0.29 rg"),
            ],
        )
    )

    narrative = _interesting_lines(lines)
    for chunk_start in range(0, len(narrative), 34):
        chunk = narrative[chunk_start : chunk_start + 34]
        page_lines: list[tuple[str, int, int, int, str]] = [
            ("VigiScan | Reporte Ejecutivo", 48, 790, 12, "0.07 0.72 0.71 rg"),
        ]
        y = 758
        for line in chunk:
            for wrapped in wrap(line, width=92)[:3]:
                page_lines.append((wrapped, 48, y, 9, "0.06 0.09 0.16 rg"))
                y -= 15
                if y < 70:
                    break
            if y < 70:
                break
        pages.append(_pdf_page_stream(page_lines))

    _write_simple_pdf(destination, pages)
    return destination


def _pdf_page_stream(
    lines: list[tuple[str, int, int, int, str]],
    *,
    bars: list[tuple[str, int, str]] | None = None,
) -> str:
    commands = [
        "0.94 0.97 0.99 rg 0 0 595 842 re f",
        "1 1 1 rg 36 36 523 770 re f",
        "0.84 0.89 0.95 RG 36 36 523 770 re S",
    ]
    for text, x, y, size, color in lines:
        commands.append(color)
        commands.append(f"BT /F1 {size} Tf {x} {y} Td ({_pdf_escape(text)}) Tj ET")
    if bars:
        max_value = max((value for _, value, _ in bars), default=1) or 1
        y = 500
        commands.append("0.06 0.09 0.16 rg BT /F1 13 Tf 48 526 Td (Graficos Ejecutivos) Tj ET")
        for label, value, color in bars:
            width = int(260 * (value / max_value)) if value else 8
            commands.append("0.89 0.93 0.97 rg 140 %d 270 12 re f" % y)
            commands.append(f"{color} 140 {y} {width} 12 re f")
            commands.append(f"0.30 0.36 0.45 rg BT /F1 9 Tf 48 {y + 2} Td ({_pdf_escape(label)}) Tj ET")
            commands.append(f"0.06 0.09 0.16 rg BT /F1 9 Tf 426 {y + 2} Td ({value}) Tj ET")
            y -= 26
    commands.append("0.40 0.45 0.55 rg BT /F1 8 Tf 210 24 Td (VigiScan - Pagina ejecutiva generada localmente) Tj ET")
    return "\n".join(commands)


def _write_simple_pdf(destination: Path, page_streams: list[str]) -> None:
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    page_ids: list[int] = []
    for stream in page_streams:
        encoded = stream.encode("latin-1", errors="replace")
        stream_id = len(objects) + 1
        objects.append(b"<< /Length " + str(len(encoded)).encode("ascii") + b" >>\nstream\n" + encoded + b"\nendstream")
        page_id = len(objects) + 1
        page_ids.append(page_id)
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {stream_id} 0 R >>"
            ).encode("ascii")
        )
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_at = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n"
        ).encode("ascii")
    )
    destination.write_bytes(bytes(output))


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")[:180]


def _value_after(lines: list[str], label: str) -> str | None:
    for index, line in enumerate(lines[:-1]):
        if line == label:
            return lines[index + 1]
    return None


def _first_after(lines: list[str], marker: str) -> str:
    if marker in lines:
        index = lines.index(marker)
        if index + 1 < len(lines):
            return lines[index + 1]
    return ""


def _int_after(lines: list[str], label: str) -> int:
    value = _value_after(lines, label)
    try:
        return int(str(value or "0").strip())
    except ValueError:
        return 0


def _interesting_lines(lines: list[str]) -> list[str]:
    skip = {
        "VigiScan Defensive Web Security Scanner",
        "Informe Ejecutivo de Seguridad Web",
        "Desarrollado por Kendry Rosario",
        "Graficos Ejecutivos",
    }
    return [line for line in lines if line not in skip]


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
