from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.analyzer import analyze_headers, parse_raw_headers

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests" / "js" / "run_lite_analysis.js"
ARTIFACT = ROOT / "HeaderGuard-Lite.html"
NODE = shutil.which("node")


def run_lite(raw: str) -> dict[str, object]:
    assert NODE, "Node.js es necesario para comprobar la paridad del analizador Lite."
    completed = subprocess.run(  # noqa: S603
        [NODE, str(RUNNER), str(ARTIFACT)],
        input=json.dumps({"operation": "analyze", "raw": raw}),
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
    )
    return json.loads(completed.stdout)


FULL_HEADERS = "\n".join(
    (
        "HTTP/2 200",
        "Strict-Transport-Security: max-age=31536000",
        "Content-Security-Policy: default-src 'self'",
        "X-Content-Type-Options: nosniff",
        "X-Frame-Options: DENY",
        "Referrer-Policy: no-referrer",
        "Permissions-Policy: camera=()",
        "Cross-Origin-Opener-Policy: same-origin",
        "Cross-Origin-Resource-Policy: same-origin",
        "Cross-Origin-Embedder-Policy: require-corp",
    )
)

CASES = (
    FULL_HEADERS,
    "\n".join(
        (
            "Content-Security-Policy: default-src * 'unsafe-inline'",
            "Strict-Transport-Security: max-age=300",
            "X-Content-Type-Options: off",
        )
    ),
    "X-CoNtEnT-TyPe-OpTiOnS: nosniff",
    "X-Frame-Options: DENY",
    "\n".join(
        (
            "Set-Cookie: session=top-secret-one",
            "set-cookie: __Host-token=top-secret-two; SameSite=None; Domain=example.com",
            "Set-Cookie: __Secure-id=top-secret-three; HttpOnly; SameSite=Lax",
        )
    ),
)


@pytest.mark.parametrize("raw", CASES)
def test_lite_analysis_matches_python(raw: str) -> None:
    response = run_lite(raw)
    expected = analyze_headers(parse_raw_headers(raw))

    assert response["ok"] is True
    result = response["result"]
    assert result["score"] == expected["score"]
    assert result["grade"] == expected["grade"]
    assert [(item["status"], item["earned"]) for item in result["results"]] == [
        (item["status"], item["earned"]) for item in expected["results"]
    ]
    assert result["priorities"] == expected["priorities"]
    assert result["cookies"] == expected["cookies"]


def test_lite_full_fixture_scores_one_hundred() -> None:
    result = run_lite(FULL_HEADERS)["result"]

    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["secure"] == 9
    assert result["missing"] == 0


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        ("", "Pega al menos una cabecera"),
        ("invalid", "Línea de cabecera no válida"),
        (" Bad: folded", "No se admiten cabeceras continuadas"),
        ("Bad Name: value", "Nombre de cabecera no válido"),
        (f"X-Test: {'a' * 32_768}", "supera el límite de 32 KB"),
    ),
    ids=("empty", "missing-colon", "continued", "space-in-name", "over-32-kb"),
)
def test_lite_rejects_the_same_invalid_input_as_python(raw: str, message: str) -> None:
    response = run_lite(raw)

    assert response["ok"] is False
    assert message in response["error"]
    with pytest.raises(ValueError, match=message):
        parse_raw_headers(raw)


def test_lite_discards_cookie_values() -> None:
    secrets = ("top-secret-one", "top-secret-two", "top-secret-three")
    raw = "\n".join(
        (
            f"Set-Cookie: session={secrets[0]}",
            f"Set-Cookie: __Host-token={secrets[1]}; Secure; Path=/",
            f"Set-Cookie: __Secure-id={secrets[2]}; HttpOnly",
        )
    )
    response = run_lite(raw)
    serialized = json.dumps(response, ensure_ascii=False)

    assert response["ok"] is True
    assert response["result"]["cookies"]["count"] == 3
    assert not any(secret in serialized for secret in secrets)
