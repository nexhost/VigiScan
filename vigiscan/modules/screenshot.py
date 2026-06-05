"""Optional visual screenshot capture for dashboard scans."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path
from urllib.parse import urlparse


UNAVAILABLE_MESSAGE = "captura no disponible"


@dataclass(frozen=True, slots=True)
class ScreenshotResult:
    """Normalized screenshot capture result."""

    ok: bool
    path: str | None
    message: str
    engine: str | None = None

    def to_dict(self) -> dict[str, str | bool | None]:
        """Return a JSON-serializable result."""
        return {
            "ok": self.ok,
            "path": self.path,
            "message": self.message,
            "engine": self.engine,
        }


def capture_site_screenshot(
    url: str,
    output_dir: Path | str,
    *,
    basename: str | None = None,
    timeout_ms: int = 15000,
) -> ScreenshotResult:
    """Capture a visual screenshot when an optional browser driver exists.

    The function never raises for missing optional dependencies or browser
    runtime failures. Callers can safely attach the returned metadata to a scan.
    """
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    output_path = destination / f"{basename or _safe_basename(url)}.png"

    if _module_available("playwright.sync_api"):
        result = _capture_with_playwright(url, output_path, timeout_ms)
        if result.ok:
            return result

    if _module_available("selenium"):
        return _capture_with_selenium(url, output_path, timeout_ms)

    return ScreenshotResult(
        ok=False,
        path=None,
        message=UNAVAILABLE_MESSAGE,
        engine=None,
    )


def _capture_with_playwright(
    url: str,
    output_path: Path,
    timeout_ms: int,
) -> ScreenshotResult:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 1366, "height": 768})
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            page.screenshot(path=str(output_path), full_page=True)
            browser.close()
    except Exception:
        return ScreenshotResult(
            ok=False,
            path=None,
            message=UNAVAILABLE_MESSAGE,
            engine="playwright",
        )

    return ScreenshotResult(
        ok=True,
        path=str(output_path),
        message="captura disponible",
        engine="playwright",
    )


def _capture_with_selenium(
    url: str,
    output_path: Path,
    timeout_ms: int,
) -> ScreenshotResult:
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--window-size=1366,768")
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(max(1, timeout_ms // 1000))
        driver.get(url)
        driver.save_screenshot(str(output_path))
        driver.quit()
    except Exception:
        return ScreenshotResult(
            ok=False,
            path=None,
            message=UNAVAILABLE_MESSAGE,
            engine="selenium",
        )

    return ScreenshotResult(
        ok=True,
        path=str(output_path),
        message="captura disponible",
        engine="selenium",
    )


def _safe_basename(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path or "screenshot"
    text = f"{host}{parsed.path}".strip("/") or "screenshot"
    safe = "".join(char if char.isalnum() else "-" for char in text.lower())
    safe = "-".join(part for part in safe.split("-") if part)
    return safe[:64] or "screenshot"


def _module_available(name: str) -> bool:
    try:
        return find_spec(name) is not None
    except ModuleNotFoundError:
        return False
