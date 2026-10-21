from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_complete_edition_uses_black_and_purple_security_identity() -> None:
    styles = (ROOT / "app" / "static" / "styles.css").read_text(encoding="utf-8")
    markup = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")

    assert "--security-purple: #8b5cf6" in styles
    assert "--security-black: #050507" in styles
    assert "--font-display: Inter" in styles
    assert 'content="#8b5cf6"' in markup


def test_lite_edition_matches_the_complete_visual_identity() -> None:
    styles = (ROOT / "standalone" / "lite.css").read_text(encoding="utf-8")

    assert "--security-purple: #8b5cf6" in styles
    assert "--security-black: #050507" in styles
    assert ':root[data-theme="light"]' in styles
    assert "color-scheme: dark" in styles
