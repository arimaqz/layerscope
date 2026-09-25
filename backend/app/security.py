import ipaddress
import logging
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings


logger = logging.getLogger("layerscope.security")
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def _trusted_proxy(peer: str) -> bool:
    try:
        address = ipaddress.ip_address(peer)
        return any(address in ipaddress.ip_network(item.strip(), strict=False)
                   for item in settings.trusted_proxy_cidrs.split(",") if item.strip())
    except ValueError:
        return False


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-real-ip", "").strip()
    if forwarded and _trusted_proxy(peer):
        try:
            return ipaddress.ip_address(forwarded).compressed
        except ValueError:
            pass
    try:
        return ipaddress.ip_address(peer).compressed
    except ValueError:
        return peer[:64]


def origin_allowed(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    return origin.rstrip("/") in settings.allowed_origins


def safe_advisory_url(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        return ""
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return ""
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.username or parsed.password or CONTROL_CHARACTERS.search(value):
        return ""
    return urlunsplit((parsed.scheme.casefold(), parsed.netloc, parsed.path, parsed.query, parsed.fragment))


def safe_download_name(value: str, fallback: str) -> str:
    name = Path(value).name.strip()
    name = CONTROL_CHARACTERS.sub("", name).replace('"', "").replace(";", "")
    return name[:180] or fallback


def sanitize_untrusted_text(value: object, limit: int = 4000) -> str:
    text = ANSI_ESCAPE.sub("", str(value or ""))
    text = CONTROL_CHARACTERS.sub("", text).strip()
    for root in [*settings.roots, settings.upload_dir.resolve(), settings.raw_results_dir.resolve()]:
        text = text.replace(str(root), "[managed storage]")
    return text[-limit:]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith("/api/"):
            if not origin_allowed(request):
                return JSONResponse({"detail": "Request origin is not allowed"}, status_code=403)
        if request.url.path.startswith("/api/"):
            try:
                content_length = int(request.headers.get("content-length", "0"))
            except ValueError:
                content_length = 0
            if request.url.path == "/api/reports/import" and content_length > settings.max_report_import_bytes:
                return JSONResponse({"detail": "Report exceeds the configured import limit"}, status_code=413)
            large_routes = request.url.path in {"/api/uploads", "/api/backups/import", "/api/reports/import"}
            if not large_routes and content_length > settings.max_json_body_bytes:
                return JSONResponse({"detail": "Request body exceeds the configured limit"}, status_code=413)
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response
