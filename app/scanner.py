from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

ALLOWED_PORTS = {80, 443}
MAX_REDIRECTS = 4
MAX_RESPONSE_BYTES = 65_536
USER_AGENT = "HeaderGuard/1.2 (+security-header-auditor)"


class ScanError(ValueError):
    """A safe, user-facing scan error."""


@dataclass(frozen=True)
class SafeTarget:
    url: str
    scheme: str
    hostname: str
    port: int
    ip: str
    request_target: str


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    return ip.is_global and not any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def resolve_safe_target(url: str) -> SafeTarget:
    if len(url) > 2048:
        raise ScanError("La URL es demasiado larga.")
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except ValueError as exc:
        raise ScanError("La URL no es válida.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ScanError("Solo se permiten URLs HTTP o HTTPS.")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ScanError("La URL debe tener un host y no puede incluir credenciales.")
    if parsed.fragment:
        raise ScanError("Elimina el fragmento (#...) de la URL.")

    port = port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ScanError("Por seguridad, solo se permiten los puertos 80 y 443.")

    try:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScanError("El nombre de host no es válido.") from exc

    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        raise ScanError("No se permiten hosts locales o privados.")

    try:
        addresses = {
            item[4][0] for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise ScanError("No se pudo resolver el nombre de dominio.") from exc
    if not addresses or not all(_is_public_ip(address) for address in addresses):
        raise ScanError("El dominio resuelve a una dirección no pública y ha sido bloqueado.")

    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="=&?/:;+,%@-._~")
    request_target = path + (f"?{query}" if query else "")
    canonical = urlunsplit((scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    return SafeTarget(canonical, scheme, hostname, port, sorted(addresses)[0], request_target)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, target: SafeTarget, timeout: float):
        super().__init__(target.ip, target.port, timeout=timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: SafeTarget, timeout: float):
        self._server_hostname = target.hostname
        super().__init__(
            target.ip, target.port, timeout=timeout, context=ssl.create_default_context()
        )

    def connect(self) -> None:
        raw_socket = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self._server_hostname)


def _host_header(target: SafeTarget) -> str:
    host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
    default = 443 if target.scheme == "https" else 80
    return host if target.port == default else f"{host}:{target.port}"


def _request_once(target: SafeTarget, method: str, timeout: float) -> tuple[int, dict[str, str]]:
    connection_class = _PinnedHTTPSConnection if target.scheme == "https" else _PinnedHTTPConnection
    connection = connection_class(target, timeout)
    try:
        connection.request(
            method,
            target.request_target,
            headers={
                "Host": _host_header(target),
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Connection": "close",
                **({"Range": "bytes=0-0"} if method == "GET" else {}),
            },
        )
        response = connection.getresponse()
        headers: dict[str, str] = {}
        for name, value in response.getheaders():
            lowered = name.lower()
            if lowered == "set-cookie" and lowered in headers:
                headers[lowered] = f"{headers[lowered]}\n{value}"
            else:
                headers[lowered] = value
        if method == "GET":
            response.read(MAX_RESPONSE_BYTES)
        return response.status, headers
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise ScanError("El servidor no respondió de forma válida o segura.") from exc
    finally:
        connection.close()


def scan_url(url: str, timeout: float = 5.0) -> dict[str, object]:
    started = time.monotonic()
    current_url = url
    redirects: list[str] = []

    for _ in range(MAX_REDIRECTS + 1):
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise ScanError("El escaneo superó el tiempo máximo permitido.")
        target = resolve_safe_target(current_url)
        status, headers = _request_once(target, "HEAD", remaining)
        if status in {405, 501}:
            status, headers = _request_once(target, "GET", remaining)

        if status in {301, 302, 303, 307, 308} and "location" in headers:
            if len(redirects) >= MAX_REDIRECTS:
                raise ScanError("La URL supera el máximo de redirecciones permitido.")
            next_url = urljoin(target.url, headers["location"])
            resolve_safe_target(next_url)  # validate before recording or following
            redirects.append(next_url)
            current_url = next_url
            continue

        return {
            "requested_url": url,
            "final_url": target.url,
            "status_code": status,
            "redirects": redirects,
            "headers": headers,
        }

    raise ScanError("La URL supera el máximo de redirecciones permitido.")
