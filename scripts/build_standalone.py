from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "standalone" / "lite.template.html"
CSS_PATH = ROOT / "standalone" / "lite.css"
JS_PATH = ROOT / "standalone" / "lite.js"
OUTPUT_PATH = ROOT / "HeaderGuard-Lite.html"

sys.path.insert(0, str(ROOT))
from app.analyzer import RULES  # noqa: E402


def serialize_rules() -> list[dict[str, object]]:
    return [
        {
            "name": rule.name,
            "weight": rule.weight,
            "purpose": rule.purpose,
            "recommendation": rule.recommendation,
            "reference": rule.reference,
        }
        for rule in RULES
    ]


def _sha256_source(source: str) -> str:
    digest = hashlib.sha256(source.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def build_document(
    template_path: Path = TEMPLATE_PATH,
    css_path: Path = CSS_PATH,
    js_path: Path = JS_PATH,
) -> str:
    template = template_path.read_text(encoding="utf-8")
    style = css_path.read_text(encoding="utf-8")
    rules_json = json.dumps(
        serialize_rules(), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).replace("<", "\\u003c")
    script = js_path.read_text(encoding="utf-8").replace("__HEADERGUARD_RULES__", rules_json)
    policy = "; ".join(
        (
            "default-src 'none'",
            f"script-src 'sha256-{_sha256_source(script)}'",
            f"style-src 'sha256-{_sha256_source(style)}'",
            "img-src data:",
            "connect-src 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        )
    )
    return (
        template.replace("{{CSP}}", policy)
        .replace("{{STYLE}}", style)
        .replace("{{SCRIPT}}", script)
    )


def write_document(output_path: Path = OUTPUT_PATH) -> Path:
    output_path.write_bytes(build_document().encode("utf-8"))
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Genera HeaderGuard-Lite.html")
    parser.add_argument(
        "--check", action="store_true", help="Comprueba el artefacto sin modificarlo"
    )
    args = parser.parse_args()
    expected = build_document().encode("utf-8")
    if args.check:
        if not OUTPUT_PATH.exists() or OUTPUT_PATH.read_bytes() != expected:
            print("HeaderGuard-Lite.html está desactualizado.", file=sys.stderr)
            return 1
        print("HeaderGuard-Lite.html está actualizado.")
        return 0
    OUTPUT_PATH.write_bytes(expected)
    print(f"Generado: {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
