from unittest.mock import patch

import httpx
import pytest

from app.main import app, limiter


def setup_function():
    limiter.entries.clear()


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client


@pytest.mark.anyio
async def test_health_and_security_headers(client):
    response = await client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]


@pytest.mark.anyio
async def test_analyze_endpoint(client):
    raw_headers = "\n".join(
        ["Content-Security-Policy: default-src 'self'", "X-Content-Type-Options: nosniff"]
    )
    response = await client.post(
        "/api/analyze",
        json={"headers": raw_headers},
    )
    assert response.status_code == 200
    assert response.json()["analysis"]["score"] == 35


@pytest.mark.anyio
async def test_analyze_redacts_cookie_values_from_response(client):
    response = await client.post(
        "/api/analyze",
        json={"headers": "Set-Cookie: session=secret; Secure; HttpOnly; SameSite=Lax"},
    )
    body = response.json()
    assert "set-cookie" not in {name.lower() for name in body["headers"]}
    assert "secret" not in str(body)
    assert body["analysis"]["cookies"]["secure"] == 1


@pytest.mark.anyio
async def test_bad_pasted_headers_return_422(client):
    response = await client.post("/api/analyze", json={"headers": "not a header"})
    assert response.status_code == 422


@patch("app.main.scan_url")
@pytest.mark.anyio
async def test_remote_scan_endpoint(mock_scan, client):
    mock_scan.return_value = {
        "requested_url": "https://example.com",
        "final_url": "https://example.com/",
        "status_code": 200,
        "redirects": [],
        "headers": {"x-frame-options": "DENY"},
    }
    response = await client.post("/api/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["analysis"]["score"] == 10
