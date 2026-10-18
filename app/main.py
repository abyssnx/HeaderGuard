from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .analyzer import analyze_headers, parse_raw_headers
from .scanner import ScanError, scan_url

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

SECURITY_HEADERS = {
    b"content-security-policy": (
        b"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        b"base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    b"referrer-policy": b"no-referrer",
    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"cross-origin-opener-policy": b"same-origin",
}


class SecurityHeadersMiddleware:
    """Small pure-ASGI middleware; it does not buffer response bodies."""

    def __init__(self, asgi_app):
        self.app = asgi_app

    async def __call__(self, scope, receive, send):
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                existing = {name.lower() for name, _ in message.get("headers", [])}
                additions = [
                    (name, value)
                    for name, value in SECURITY_HEADERS.items()
                    if name not in existing
                ]
                message["headers"] = [*message.get("headers", []), *additions]
            await send(message)

        await self.app(scope, receive, send_with_headers)


app = FastAPI(
    title="HeaderGuard API",
    version="1.2.0",
    description="Analizador educativo de cabeceras HTTP de seguridad.",
    docs_url="/api/docs",
    redoc_url=None,
)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class PasteRequest(BaseModel):
    headers: str = Field(min_length=1, max_length=32_768)


class RateLimiter:
    def __init__(self, limit: int = 20, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self.entries: dict[str, deque[float]] = defaultdict(deque)
        self.lock = Lock()

    def check(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            bucket = self.entries[key]
            while bucket and bucket[0] <= now - self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True


limiter = RateLimiter()


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze(payload: PasteRequest) -> dict[str, object]:
    try:
        headers = parse_raw_headers(payload.headers)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    analysis = analyze_headers(headers)
    public_headers = {key: value for key, value in headers.items() if key.lower() != "set-cookie"}
    return {"source": "pasted", "headers": public_headers, "analysis": analysis}


@app.post("/api/scan")
async def scan(payload: ScanRequest, request: Request) -> dict[str, object]:
    client_ip = request.client.host if request.client else "unknown"
    if not limiter.check(client_ip):
        raise HTTPException(status_code=429, detail="Demasiadas solicitudes. Espera un minuto.")
    try:
        scan_result = await asyncio.wait_for(asyncio.to_thread(scan_url, payload.url), timeout=7)
    except TimeoutError as exc:
        raise HTTPException(
            status_code=504, detail="El escaneo agotó el tiempo de espera."
        ) from exc
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    analysis = analyze_headers(scan_result["headers"])
    scan_result["headers"] = {
        key: value for key, value in scan_result["headers"].items() if key != "set-cookie"
    }
    return {**scan_result, "analysis": analysis}
