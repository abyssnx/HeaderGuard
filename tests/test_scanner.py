import socket
from unittest.mock import patch

import pytest

from app.scanner import ScanError, resolve_safe_target, scan_url


def public_dns(*_args, **_kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.4/",
        "https://user:pass@example.com/",
        "https://example.com:8443/",
    ],
)
def test_rejects_unsafe_targets(url):
    with pytest.raises(ScanError):
        resolve_safe_target(url)


@patch("app.scanner.socket.getaddrinfo", side_effect=public_dns)
def test_public_target_is_pinned(mock_dns):
    target = resolve_safe_target("https://example.com/path?q=hello world")
    assert target.ip == "93.184.216.34"
    assert target.request_target == "/path?q=hello%20world"
    mock_dns.assert_called_once()


@patch("app.scanner.socket.getaddrinfo")
def test_mixed_public_private_dns_is_rejected(mock_dns):
    mock_dns.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
    ]
    with pytest.raises(ScanError, match="no pública"):
        resolve_safe_target("https://example.com")


@patch("app.scanner._request_once")
@patch("app.scanner.socket.getaddrinfo", side_effect=public_dns)
def test_redirect_to_private_ip_is_blocked(_mock_dns, mock_request):
    mock_request.return_value = (302, {"location": "http://127.0.0.1/admin"})
    with pytest.raises(ScanError):
        scan_url("https://example.com")


@patch("app.scanner._request_once")
@patch("app.scanner.socket.getaddrinfo", side_effect=public_dns)
def test_successful_scan(_mock_dns, mock_request):
    mock_request.return_value = (200, {"x-content-type-options": "nosniff"})
    result = scan_url("https://example.com")
    assert result["status_code"] == 200
    assert result["headers"]["x-content-type-options"] == "nosniff"
