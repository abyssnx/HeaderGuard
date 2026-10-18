from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "HeaderGuard-Lite.html"


def test_lite_complete_offline_browser_flow(tmp_path: Path) -> None:
    folder = tmp_path / "HeaderGuard Lite con espacios"
    folder.mkdir()
    local_file = folder / "HeaderGuard-Lite.html"
    shutil.copy2(ARTIFACT, local_file)
    remote_requests: list[str] = []

    with playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.on(
            "request",
            lambda request: remote_requests.append(request.url)
            if request.url.startswith(("http://", "https://"))
            else None,
        )
        page.goto(local_file.resolve().as_uri())

        assert page.url.startswith("file://")
        assert page.get_by_text("Edición Lite · análisis local").is_visible()
        page.get_by_role("button", name="Cargar ejemplo").click()
        page.get_by_role("button", name="Analizar ahora").click()
        page.locator("#results:not(.hidden)").wait_for()

        assert page.locator("#score").inner_text() == "75"
        assert "__Host-session" in page.locator("#cookie-list").inner_text()
        assert "demo-value" not in page.locator("body").inner_text()
        assert "demo-value" not in page.evaluate(
            "() => localStorage.getItem('headerguard.lite.history.v1') || ''"
        )
        assert "__Host-session" not in page.evaluate(
            "() => localStorage.getItem('headerguard.lite.history.v1') || ''"
        )

        original_theme = page.locator("html").get_attribute("data-theme")
        page.locator("#theme-toggle").click()
        assert page.locator("html").get_attribute("data-theme") != original_theme

        page.locator("#server-type").select_option("fastapi")
        assert '@app.middleware("http")' in page.locator("#config-output").inner_text()

        with page.expect_download() as json_download_info:
            page.locator("#download-json").click()
        json_download = json_download_info.value
        json_payload = json.loads(Path(json_download.path()).read_text(encoding="utf-8"))
        assert json_payload["generator"] == "HeaderGuard Lite by abyssnx"
        assert json_payload["analysis"]["score"] == 75
        assert "demo-value" not in json.dumps(json_payload)

        with page.expect_download() as html_download_info:
            page.locator("#download-html").click()
        html_report = Path(html_download_info.value.path()).read_text(encoding="utf-8")
        assert "HeaderGuard Lite · abyssnx" in html_report
        assert "demo-value" not in html_report

        capture_dir = os.environ.get("HEADERGUARD_SCREENSHOT_DIR")
        if capture_dir:
            output = Path(capture_dir)
            output.mkdir(parents=True, exist_ok=True)
            page.locator("#toast:not(.visible)").wait_for()
            page.evaluate(
                "document.documentElement.style.scrollBehavior='auto'; window.scrollTo(0, 0)"
            )
            page.wait_for_function("window.scrollY === 0")
            assert page.evaluate("window.scrollY") == 0
            page.screenshot(path=output / "headerguard-lite-desktop.png", full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_function("window.scrollY === 0")
            page.screenshot(path=output / "headerguard-lite-mobile.png", full_page=True)

        assert remote_requests == []
        browser.close()
