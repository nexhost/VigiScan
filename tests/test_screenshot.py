from __future__ import annotations

from pathlib import Path

from vigiscan.modules.screenshot import (
    UNAVAILABLE_MESSAGE,
    ScreenshotResult,
    capture_site_screenshot,
)


def test_capture_returns_unavailable_when_optional_drivers_are_missing(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr("vigiscan.modules.screenshot._module_available", lambda _: False)

    result = capture_site_screenshot("https://example.com", tmp_path)

    assert result.ok is False
    assert result.path is None
    assert result.message == UNAVAILABLE_MESSAGE


def test_capture_uses_playwright_when_available(tmp_path, monkeypatch):
    def fake_capture(url: str, output_path: Path, timeout_ms: int):
        output_path.write_bytes(b"\x89PNG\r\n\x1a\n")
        return ScreenshotResult(
            ok=True,
            path=str(output_path),
            message="captura disponible",
            engine="playwright",
        )

    monkeypatch.setattr(
        "vigiscan.modules.screenshot._module_available",
        lambda name: name == "playwright.sync_api",
    )
    monkeypatch.setattr(
        "vigiscan.modules.screenshot._capture_with_playwright",
        fake_capture,
    )

    result = capture_site_screenshot("https://example.com/app", tmp_path)

    assert result.ok is True
    assert result.engine == "playwright"
    assert result.path is not None
    assert Path(result.path).exists()
