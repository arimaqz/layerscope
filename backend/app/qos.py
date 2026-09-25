import asyncio
import secrets
import shutil
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings
from .security import client_ip


AUTH_RATE_PATHS = {
    "/api/auth/setup", "/api/auth/login", "/api/auth/activate",
    "/api/auth/reenroll-2fa", "/api/auth/totp/verify",
}


def storage_capacity(path: Path, incoming_bytes: int = 0) -> dict:
    """Return filesystem headroom without exposing a host path to normal API clients."""
    path.mkdir(parents=True, exist_ok=True)
    volume_usage = shutil.disk_usage(path)
    probe = settings.host_storage_probe_dir
    host_usage = shutil.disk_usage(probe) if probe and probe.is_dir() else None
    usage = min((item for item in (volume_usage, host_usage) if item is not None), key=lambda item: item.free)
    limiting_source = "host_probe" if host_usage is not None and host_usage.free <= volume_usage.free else "container_volume"
    available_after = usage.free - max(0, incoming_bytes)
    reserve = settings.storage_reserve_bytes
    low_percentage = usage.total > 0 and usage.free / usage.total < 0.1
    status = "critical" if available_after < reserve else "warning" if available_after < reserve * 2 or low_percentage else "ok"
    return {
        "status": status, "free_bytes": usage.free, "total_bytes": usage.total,
        "reserve_bytes": reserve, "available_after_bytes": available_after,
        "limiting_source": limiting_source, "container_volume_free_bytes": volume_usage.free,
        "host_probe_free_bytes": host_usage.free if host_usage is not None else None,
    }


def require_storage_capacity(path: Path, incoming_bytes: int = 0):
    capacity = storage_capacity(path, incoming_bytes)
    if capacity["status"] == "critical":
        raise HTTPException(
            status_code=507,
            detail="Insufficient storage headroom. Free space or reduce the operation size, then retry.",
            headers={"Retry-After": "60"},
        )
    return capacity


class QualityOfServiceMiddleware(BaseHTTPMiddleware):
    """Bound expensive anonymous auth work and attach safe request diagnostics."""

    def __init__(self, app):
        super().__init__(app)
        self.attempts: dict[str, deque[float]] = defaultdict(deque)
        self.lock = asyncio.Lock()
        self.requests = 0

    @staticmethod
    def client_key(request: Request) -> str:
        return client_ip(request)

    async def allowed(self, request: Request) -> tuple[bool, int]:
        now = time.monotonic()
        window = settings.auth_rate_limit_window_seconds
        key = f"{self.client_key(request)}:{request.url.path}"
        async with self.lock:
            bucket = self.attempts[key]
            while bucket and bucket[0] <= now - window:
                bucket.popleft()
            if len(bucket) >= settings.auth_rate_limit_attempts:
                retry = max(1, int(window - (now - bucket[0])) + 1)
                return False, retry
            bucket.append(now)
            self.requests += 1
            if self.requests % 500 == 0:
                stale = [item for item, values in self.attempts.items() if not values or values[-1] <= now - window]
                for item in stale:
                    self.attempts.pop(item, None)
        return True, 0

    async def dispatch(self, request: Request, call_next):
        request_id = secrets.token_hex(16)
        request.state.request_id = request_id
        started = time.perf_counter()
        if request.method == "POST" and request.url.path in AUTH_RATE_PATHS:
            allowed, retry = await self.allowed(request)
            if not allowed:
                return JSONResponse(
                    {"detail": "Too many authentication attempts. Wait briefly and retry."},
                    status_code=429,
                    headers={"Retry-After": str(retry), "X-Request-ID": request_id},
                )
        response = await call_next(request)
        duration_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        if getattr(request.state, "user", None) is not None:
            response.headers["Server-Timing"] = f"app;dur={duration_ms:.1f}"
        return response
