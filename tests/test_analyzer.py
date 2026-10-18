import pytest

from app.analyzer import analyze_headers, parse_raw_headers


def test_full_score_with_all_headers():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
    }
    result = analyze_headers(headers)
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["present"] == result["total"] == 9


def test_header_names_are_case_insensitive():
    result = analyze_headers({"X-CoNtEnT-TyPe-OpTiOnS": "nosniff"})
    assert result["score"] == 10


def test_weak_values_are_flagged_and_penalized():
    result = analyze_headers(
        {
            "Content-Security-Policy": "default-src * 'unsafe-inline'",
            "Strict-Transport-Security": "max-age=300",
            "X-Content-Type-Options": "off",
        }
    )
    assert result["score"] == 40
    assert result["warnings"] == 3
    assert result["secure"] == 0
    assert len(result["priorities"]) == 3


def test_missing_headers_are_prioritized():
    result = analyze_headers({"X-Frame-Options": "DENY"})
    assert result["missing"] == 8
    assert result["priorities"][0]["status"] == "missing"


def test_parse_raw_headers_accepts_status_line():
    parsed = parse_raw_headers(
        "HTTP/2 200\r\nContent-Security-Policy: default-src 'self'\r\nX-Frame-Options: DENY"
    )
    assert parsed["X-Frame-Options"] == "DENY"


def test_cookie_analysis_never_returns_cookie_values():
    cookie_value = "opaque-session-value"
    result = analyze_headers(
        {"Set-Cookie": (f"__Host-session={cookie_value}; Secure; HttpOnly; SameSite=Lax; Path=/")}
    )
    cookie = result["cookies"]["cookies"][0]
    assert cookie["name"] == "__Host-session"
    assert cookie["status"] == "secure"
    assert cookie_value not in str(result)


def test_cookie_analysis_flags_weak_attributes_and_preserves_duplicates():
    parsed = parse_raw_headers(
        "Set-Cookie: session=one\nset-cookie: preferences=two; SameSite=None"
    )
    result = analyze_headers(parsed)
    assert result["cookies"]["count"] == 2
    assert result["cookies"]["warnings"] == 2
    assert all(cookie["issues"] for cookie in result["cookies"]["cookies"])


@pytest.mark.parametrize("raw", ["", "invalid", " Bad: folded"])
def test_parse_rejects_malformed_input(raw):
    with pytest.raises(ValueError):
        parse_raw_headers(raw)
