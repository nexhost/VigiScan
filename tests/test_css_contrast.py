import re
from pathlib import Path


APP_CSS = Path(__file__).resolve().parents[1] / "vigiscan" / "web" / "static" / "css" / "app.css"


def test_dark_contrast_safety_classes_exist():
    css = APP_CSS.read_text(encoding="utf-8").lower()

    required_snippets = [
        ".text-primary-safe",
        ".text-secondary-safe",
        ".text-muted-safe",
        ".cyber-card",
        ".cyber-panel",
        ".cyber-table",
        "background: #0f172a",
        "background: #111c33",
        "background: #0b1326",
        "color: #f8fafc",
        "color: #cbd5e1",
        "color: #94a3b8",
    ]

    missing = [snippet for snippet in required_snippets if snippet not in css]
    assert not missing


def test_app_css_avoids_dark_text_tokens():
    css = APP_CSS.read_text(encoding="utf-8").lower()
    dangerous_text_colors = re.findall(
        r"color\s*:\s*(#0f172a|#111827|#1e293b|#101828|black|#000(?:000)?)\b",
        css,
    )

    assert dangerous_text_colors == []
