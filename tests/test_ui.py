from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="session")
def live_server():
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8765",
    ]
    process = subprocess.Popen(  # noqa: S603
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8765/api/health", timeout=1) as response:  # noqa: S310
                if response.status == 200:
                    break
        except OSError:
            time.sleep(0.2)
    else:
        process.terminate()
        raise RuntimeError("La aplicación no arrancó para las pruebas de interfaz.")

    yield "http://127.0.0.1:8765"
    process.terminate()
    process.wait(timeout=5)


def test_complete_browser_flow(live_server):
    capture_dir = os.environ.get("HEADERGUARD_SCREENSHOT_DIR")
    with playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.goto(live_server)
        page.get_by_role("tab", name="Pegar cabeceras").click()
        page.get_by_role("button", name="Cargar ejemplo").click()
        page.locator("#paste-panel").get_by_role("button", name="Analizar").click()
        page.locator("#results:not(.hidden)").wait_for()

        assert page.locator("#score").inner_text() == "75"
        assert "__Host-session" in page.locator("#cookie-list").inner_text()
        assert "demo-value" not in page.locator("body").inner_text()
        assert "add_header" in page.locator("#config-output").inner_text()

        page.locator("#server-type").select_option("fastapi")
        assert '@app.middleware("http")' in page.locator("#config-output").inner_text()

        with page.expect_download() as download_info:
            page.get_by_role("button", name="Informe HTML").click()
        assert download_info.value.suggested_filename.endswith(".html")

        if capture_dir:
            output = Path(capture_dir)
            output.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=output / "headerguard-desktop.png", full_page=True)
            page.evaluate(
                "document.documentElement.style.scrollBehavior='auto'; "
                "window.scrollTo(0, document.querySelector('#results').offsetTop)"
            )
            page.screenshot(path=output / "headerguard-preview.png")
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=output / "headerguard-mobile.png", full_page=True)

        browser.close()
