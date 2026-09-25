import asyncio
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session
from .config import settings
from .scanner import manager
from .components import component_manager, component_payloads, database_info
from .models import User
from .qos import storage_capacity


def check(check_id: str, label: str, status: str, summary: str, details: dict | None = None):
    return {"id": check_id, "label": label, "status": status, "summary": summary, "details": details or {}}


def writable_directory(check_id: str, label: str, path: Path):
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix="diagnostic-", dir=path, delete=True):
            pass
        capacity = storage_capacity(path)
        status = "error" if capacity["status"] == "critical" else "warning" if capacity["status"] == "warning" else "ok"
        source = "host filesystem limit" if capacity["limiting_source"] == "host_probe" else "container volume limit"
        summary = f"Writable; {format_bytes(capacity['free_bytes'])} free ({source})"
        return check(check_id, label, status, summary, {"path": str(path), **capacity})
    except Exception as exc:
        return check(check_id, label, "error", "Not writable", {"path": str(path), "error": str(exc)})


async def trivy_check():
    try:
        process = await asyncio.create_subprocess_exec(settings.trivy_binary, "--version", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
        output = (stdout or stderr).decode("utf-8", errors="replace").strip()
        if process.returncode:
            return check("trivy", "Trivy scanner", "error", "Trivy returned an error", {"output": output})
        return check("trivy", "Trivy scanner", "ok", output.splitlines()[0] if output else "Installed", {"binary": settings.trivy_binary, "output": output})
    except FileNotFoundError:
        return check("trivy", "Trivy scanner", "error", "Trivy executable was not found", {"binary": settings.trivy_binary})
    except Exception as exc:
        return check("trivy", "Trivy scanner", "error", "Unable to execute Trivy", {"error": str(exc)})


def trivy_database_check():
    metadata_path = settings.trivy_cache_dir / "db" / "metadata.json"
    if not metadata_path.is_file():
        return check("trivy_db", "Vulnerability database", "warning", "Database has not been downloaded yet", {"metadata_path": str(metadata_path)})
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        return check("trivy_db", "Vulnerability database", "ok", "Database cache is present", {"metadata_path": str(metadata_path), "metadata": metadata})
    except Exception as exc:
        return check("trivy_db", "Vulnerability database", "warning", "Database metadata could not be read", {"error": str(exc)})


async def registry_checks():
    results = []
    async with httpx.AsyncClient(timeout=6, follow_redirects=False) as client:
        sources = (
            ("vulnerability", "Vulnerability DB", settings.db_repositories, True),
            ("java", "Java DB", settings.java_db_repositories, False),
        )
        for component, label, repositories, required in sources:
            for index, repository in enumerate(repositories):
                host = urlsplit("https://" + repository).hostname
                details = {"component": component, "repository": repository, "required": required}
                try:
                    response = await client.get(f"https://{host}/v2/")
                    if response.status_code in (200, 401):
                        status, summary = "ok", f"Reachable (HTTP {response.status_code})"
                    elif response.status_code == 403:
                        status, summary = ("error" if required else "warning"), "Registry denied access (HTTP 403)"
                    else:
                        status, summary = "warning", f"Unexpected HTTP {response.status_code}"
                    results.append(check(f"{component}_db_registry_{index}", f"{label} registry: {host}", status, summary, details))
                except Exception as exc:
                    details["error"] = str(exc)
                    results.append(check(f"{component}_db_registry_{index}", f"{label} registry: {host}",
                                         "error" if required else "warning", "Registry is unreachable", details))
    return results


async def run_diagnostics(db: Session):
    checks = []
    try:
        db.execute(text("SELECT 1")).scalar_one()
        checks.append(check("database", "SQLite database", "ok", "Connection successful", {"url": settings.database_url.split("@")[-1]}))
        if settings.database_url.startswith("sqlite"):
            journal = db.execute(text("PRAGMA journal_mode")).scalar_one()
            busy_timeout = db.execute(text("PRAGMA busy_timeout")).scalar_one()
            foreign_keys = db.execute(text("PRAGMA foreign_keys")).scalar_one()
            tuned = str(journal).casefold() == "wal" and int(busy_timeout) >= 15000 and bool(foreign_keys)
            checks.append(check("database_qos", "SQLite concurrency safeguards", "ok" if tuned else "warning",
                                "WAL, contention timeout, and foreign keys enabled" if tuned else "One or more concurrency safeguards are inactive",
                                {"journal_mode": journal, "busy_timeout_ms": busy_timeout,
                                 "foreign_keys": bool(foreign_keys), "synchronous": "NORMAL"}))
    except Exception as exc:
        checks.append(check("database", "SQLite database", "error", "Connection failed", {"error": str(exc)}))
    active_users = db.query(User).filter(User.active.is_(True)).count()
    mfa_users = db.query(User).filter(User.active.is_(True), User.totp_enabled.is_(True)).count()
    auth_status = "ok" if active_users and active_users == mfa_users and settings.auth_key_path.is_file() else "error"
    checks.append(check("authentication", "Local authentication", auth_status,
                        f"{active_users} active user(s); {mfa_users} protected by TOTP",
                        {"key_present": settings.auth_key_path.is_file(), "cookie_secure": settings.auth_cookie_secure,
                         "idle_minutes": settings.auth_idle_minutes, "absolute_hours": settings.auth_absolute_hours}))
    checks.append(await trivy_check())
    checks.append(trivy_database_check())
    java_info = database_info("java_db")
    checks.append(check("trivy_java_db", "Java index database", "ok" if java_info["installed"] else "info",
                        "Database cache is present" if java_info["installed"] else "Optional database is not installed",
                        {"path": java_info["path"], "size_bytes": java_info["size_bytes"],
                         "required": False, "installed": java_info["installed"],
                         "repositories": settings.java_db_repositories,
                         "updated_at": str(java_info["updated_at"]) if java_info["updated_at"] else None,
                         "next_update": str(java_info["next_update"]) if java_info["next_update"] else None}))
    checks.append(writable_directory("raw_storage", "Raw result storage", settings.raw_results_dir))
    checks.append(writable_directory("upload_storage", "Upload storage", settings.upload_dir))
    checks.append(writable_directory("trivy_cache", "Trivy cache storage", settings.trivy_cache_dir))
    checks.append(writable_directory("trivy_temp", "Trivy scan workspace", settings.trivy_temp_dir))
    for index, root in enumerate(settings.roots):
        if root.is_dir():
            try:
                archive_count = sum(1 for path in root.rglob("*.tar") if path.is_file())
                checks.append(check(f"scan_root_{index}", f"Scan root: {root}", "ok", f"Readable; {archive_count} TAR archive(s)", {"path": str(root)}))
            except Exception as exc:
                checks.append(check(f"scan_root_{index}", f"Scan root: {root}", "warning", "Root exists but could not be enumerated", {"error": str(exc)}))
        else:
            checks.append(check(f"scan_root_{index}", f"Scan root: {root}", "warning", "Configured root does not exist", {"path": str(root)}))
    alive = sum(1 for worker in manager.workers if not worker.done())
    active_jobs = len(manager.queued_ids) + len(manager.active_ids)
    utilization = active_jobs / settings.max_pending_scans * 100
    worker_status = "error" if not alive or alive != len(manager.workers) else "warning" if utilization >= 80 else "ok"
    checks.append(check("queue", "Persistent scan job handler", worker_status,
                        f"{alive}/{len(manager.workers)} workers active; {active_jobs}/{settings.max_pending_scans} capacity used",
                        {"queued_jobs": len(manager.queued_ids), "running_jobs": len(manager.active_ids),
                         "tracked_processes": len(manager.processes), "configured_concurrency": settings.scan_concurrency,
                         "max_pending_scans": settings.max_pending_scans, "utilization_percent": round(utilization, 1),
                         "restart_recovery": True, "cancellation": True, "retry": True}))
    event_utilization = len(manager.subscribers) / settings.max_sse_clients * 100
    event_status = "warning" if event_utilization >= 80 or manager.dropped_events else "ok"
    checks.append(check("live_events", "Live progress delivery", event_status,
                        f"{len(manager.subscribers)}/{settings.max_sse_clients} clients connected; {manager.dropped_events} events dropped",
                        {"connected_clients": len(manager.subscribers), "max_clients": settings.max_sse_clients,
                         "subscriber_queue_size": settings.sse_queue_size, "dropped_events": manager.dropped_events,
                         "rejected_clients": manager.rejected_sse_clients, "polling_fallback": True}))
    maintenance_alive = bool(component_manager.task and not component_manager.task.done())
    checks.append(check("maintenance_queue", "Component maintenance worker", "ok" if maintenance_alive else "error",
                        "Worker active" if maintenance_alive else "Worker unavailable",
                        {"queued_jobs": len(component_manager.queued_ids), "running_processes": len(component_manager.processes)}))
    checks.extend(await registry_checks())
    overall = "error" if any(item["status"] == "error" for item in checks) else "warning" if any(item["status"] == "warning" for item in checks) else "ok"
    return {"overall": overall, "checked_at": datetime.now(timezone.utc),
            "components": component_payloads(db), "checks": checks}


def format_bytes(value: int):
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"
        amount /= 1024
