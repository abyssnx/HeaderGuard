from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_complete_edition_uses_obsidian_audit_identity() -> None:
    styles = (ROOT / "app" / "static" / "obsidian.css").read_text(encoding="utf-8")
    markup = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")

    assert "--obsidian: #09090b" in styles
    assert "--audit-purple: #7657d6" in styles
    assert "--radius-panel: 6px" in styles
    assert 'content="#09090b"' in markup
    assert 'href="/static/obsidian.css"' in markup
    assert 'class="hero-dossier"' in markup
    assert "hero-visual" not in markup
    assert "orbit-one" not in markup


def test_lite_edition_matches_the_obsidian_audit_identity() -> None:
    styles = (ROOT / "standalone" / "lite.obsidian.css").read_text(encoding="utf-8")
    markup = (ROOT / "standalone" / "lite.template.html").read_text(encoding="utf-8")

    assert "--obsidian: #09090b" in styles
    assert "--audit-purple: #7657d6" in styles
    assert "--radius-panel: 6px" in styles
    assert ':root[data-theme="light"]' in styles
    assert "color-scheme: dark" in styles
    assert 'class="hero-dossier"' in markup
    assert "privacy-card" not in markup
