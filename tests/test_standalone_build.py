from __future__ import annotations

import base64
import hashlib
import importlib.util
import re
from html.parser import HTMLParser
from pathlib import Path
from types import ModuleType

from app.analyzer import RULES

ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "scripts" / "build_standalone.py"
OUTPUT_PATH = ROOT / "HeaderGuard-Lite.html"


def load_builder() -> ModuleType:
    assert BUILDER_PATH.exists(), "Falta scripts/build_standalone.py"
    spec = importlib.util.spec_from_file_location("headerguard_standalone_builder", BUILDER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_source(source: str) -> str:
    digest = hashlib.sha256(source.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


class AssetCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.assets.append(values["src"] or "")
        if tag == "link" and values.get("href"):
            self.assets.append(values["href"] or "")
        if tag in {"img", "source"} and values.get("src"):
            self.assets.append(values["src"] or "")


def test_serialized_rules_match_backend() -> None:
    builder = load_builder()

    assert builder.serialize_rules() == [
        {
            "name": rule.name,
            "weight": rule.weight,
            "purpose": rule.purpose,
            "recommendation": rule.recommendation,
            "reference": rule.reference,
        }
        for rule in RULES
    ]


def test_build_is_deterministic() -> None:
    builder = load_builder()

    assert builder.build_document() == builder.build_document()


def test_generated_document_has_hashed_csp() -> None:
    document = load_builder().build_document()
    style = re.search(r"<style>(.*?)</style>", document, re.DOTALL)
    script = re.search(r"<script>(.*?)</script>", document, re.DOTALL)
    csp = re.search(
        r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', document
    )

    assert style and script and csp
    policy = csp.group(1)
    assert "default-src 'none'" in policy
    assert "connect-src 'none'" in policy
    assert "base-uri 'none'" in policy
    assert "form-action 'none'" in policy
    assert f"style-src 'sha256-{sha256_source(style.group(1))}'" in policy
    assert f"script-src 'sha256-{sha256_source(script.group(1))}'" in policy


def test_generated_document_has_no_remote_assets() -> None:
    document = load_builder().build_document()
    parser = AssetCollector()
    parser.feed(document)

    assert not [asset for asset in parser.assets if asset.startswith(("http://", "https://"))]
    assert "fetch(" not in document
    assert "XMLHttpRequest" not in document
    assert "WebSocket" not in document


def test_checked_in_artifact_is_current() -> None:
    assert OUTPUT_PATH.exists(), "Falta HeaderGuard-Lite.html"
    assert OUTPUT_PATH.read_text(encoding="utf-8") == load_builder().build_document()
