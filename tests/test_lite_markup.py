from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "HeaderGuard-Lite.html"


class MarkupProbe(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: dict[str, tuple[str, dict[str, str | None]]] = {}
        self.labels: set[str] = set()
        self.body_text: list[str] = []
        self.url_inputs: list[dict[str, str | None]] = []
        self._in_body = False
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "body":
            self._in_body = True
        if tag in {"script", "style"}:
            self._ignored_depth += 1
        if values.get("id"):
            self.ids[values["id"] or ""] = (tag, values)
        if tag == "label" and values.get("for"):
            self.labels.add(values["for"] or "")
        if tag == "input" and values.get("type") == "url":
            self.url_inputs.append(values)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self._ignored_depth -= 1
        if tag == "body":
            self._in_body = False

    def handle_data(self, data: str) -> None:
        if self._in_body and not self._ignored_depth and data.strip():
            self.body_text.append(data.strip())


def document() -> str:
    return ARTIFACT.read_text(encoding="utf-8")


def probe() -> MarkupProbe:
    parser = MarkupProbe()
    parser.feed(document())
    return parser


def test_lite_exposes_only_the_local_analysis_workflow() -> None:
    markup = probe()

    assert markup.ids["headers"][0] == "textarea"
    assert markup.ids["analyze-button"][0] == "button"
    assert markup.ids["sample-button"][0] == "button"
    assert not markup.url_inputs
    assert "url" not in markup.ids
    assert "remote-tab" not in markup.ids


def test_lite_has_accessible_form_status_and_results() -> None:
    markup = probe()
    status_attrs = markup.ids["status"][1]

    assert "headers" in markup.labels
    assert status_attrs["role"] == "status"
    assert status_attrs["aria-live"] == "polite"
    assert markup.ids["results"][1]["aria-live"] == "polite"
    assert markup.ids["theme-toggle"][1]["aria-label"]


def test_lite_identifies_the_edition_and_author_in_visible_content() -> None:
    visible_text = " ".join(probe().body_text)

    assert "Edición Lite · análisis local" in visible_text
    assert "Creado por abyssnx" in visible_text
    assert "Todo ocurre en este navegador" in visible_text


def test_lite_includes_stable_result_regions() -> None:
    markup = probe()

    for element_id in (
        "score",
        "grade",
        "priority-list",
        "header-list",
        "cookie-list",
        "complete-edition",
        "server-type",
        "config-output",
        "download-json",
        "download-html",
        "copy-summary",
        "copy-badge",
        "print-report",
        "history-list",
    ):
        assert element_id in markup.ids


def test_lite_styles_cover_keyboard_mobile_themes_and_reduced_motion() -> None:
    markup = document()

    assert ":focus-visible" in markup
    assert "@media (max-width: 700px)" in markup
    assert "prefers-reduced-motion: reduce" in markup
    assert '[data-theme="light"]' in markup


def test_lite_renders_untrusted_values_without_inner_html() -> None:
    source = (ROOT / "standalone" / "lite.js").read_text(encoding="utf-8")

    assert ".innerHTML" not in source
    assert "document.createElement" in source
    assert ".textContent" in source
    assert ".replaceChildren" in source
