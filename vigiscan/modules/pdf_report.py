"""Executive PDF generation helpers for VigiScan reports."""

from __future__ import annotations

from pathlib import Path


class PDFReportUnavailable(RuntimeError):
    """Raised when the optional PDF backend is not installed."""


def generate_pdf_from_html(
    html: str,
    output_path: Path | str,
    *,
    base_url: str | None = None,
) -> Path:
    """Render HTML into a PDF file using WeasyPrint when available."""
    try:
        from weasyprint import HTML
    except Exception as exc:  # pragma: no cover - depends on optional package
        raise PDFReportUnavailable(
            "La generacion PDF requiere WeasyPrint. Instala el extra con: "
            'pip install -e ".[pdf]"'
        ) from exc

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=base_url).write_pdf(str(destination))
    return destination


def pdf_available() -> bool:
    """Return True when the optional PDF backend can be imported."""
    try:
        import weasyprint  # noqa: F401
    except Exception:
        return False
    return True
