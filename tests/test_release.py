from __future__ import annotations

import tomllib
from pathlib import Path

from app.main import app

ROOT = Path(__file__).resolve().parents[1]


def test_release_version_is_consistent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    complete_ui = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
    scanner = (ROOT / "app" / "scanner.py").read_text(encoding="utf-8")

    assert project["project"]["version"] == "1.3.0"
    assert app.version == "1.3.0"
    assert 'org.opencontainers.image.version="1.3.0"' in dockerfile
    assert "v1.3" in complete_ui
    assert 'USER_AGENT = "HeaderGuard/1.3 (+security-header-auditor)"' in scanner


def test_public_repository_contains_only_product_documentation() -> None:
    assert {path.name for path in (ROOT / "docs").iterdir()} == {
        "ARQUITECTURA.md",
        "assets",
    }
    assert not list(ROOT.glob("*.txt"))


def test_readme_gives_a_working_start_for_both_editions() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "[HeaderGuard-Lite.html](HeaderGuard-Lite.html)" in readme
    assert "doble clic" in readme.lower()
    assert "python -m venv .venv" in readme
    assert "uvicorn app.main:app --reload" in readme
    assert "docker build -t headerguard ." in readme
    assert "Escanear una URL" in readme
    assert "Pegar cabeceras" in readme
    assert "Solución de problemas" in readme


def test_public_architecture_document_replaces_internal_spec() -> None:
    architecture = ROOT / "docs" / "ARQUITECTURA.md"

    assert architecture.exists()
    assert "Lite" in architecture.read_text(encoding="utf-8")
