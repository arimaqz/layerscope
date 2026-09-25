import asyncio
import json
import os
import subprocess
import tempfile
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import desc, select

from .config import settings
from .database import SessionLocal
from .locks import database_access
from .models import MaintenanceJob
from .security import sanitize_untrusted_text
from .scanner import manager as scan_manager


DATABASE_COMPONENTS = {"vulnerability_db", "java_db"}
TERMINAL = {"completed", "failed", "cancelled"}


def utcnow():
    return datetime.now(timezone.utc)


@contextmanager
def maintenance_workspace(job_id: int):
    """Create a private, automatically cleaned Trivy workspace on persistent storage."""
    root = settings.component_temp_dir
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix=f"job-{job_id}-", dir=root) as temporary_name:
        workspace = Path(temporary_name)
        workspace.chmod(0o700)
        yield workspace


def maintenance_environment(workspace: Path):
    environment = os.environ.copy()
    temporary_path = str(workspace)
    environment.update({"TMPDIR": temporary_path, "TMP": temporary_path, "TEMP": temporary_path})
    return environment


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def directory_size(path: Path):
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file()) if path.is_dir() else 0


def database_info(component: str):
    directory = settings.trivy_cache_dir / ("db" if component == "vulnerability_db" else "java-db")
    metadata_path = directory / "metadata.json"
    metadata = {}
    if metadata_path.is_file():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            metadata = {}
    next_update = parse_time(metadata.get("NextUpdate"))
    updated_at = parse_time(metadata.get("UpdatedAt"))
    return {
        "installed": metadata_path.is_file(), "metadata": metadata, "updated_at": updated_at,
        "next_update": next_update, "update_available": bool(next_update and next_update <= utcnow()),
        "size_bytes": directory_size(directory), "path": str(directory),
    }


def trivy_version():
    try:
        result = subprocess.run([settings.trivy_binary, "--version"], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=10, check=False)
        return (result.stdout or result.stderr).strip().splitlines()[0]
    except (OSError, subprocess.TimeoutExpired):
        return "Unavailable"


def component_payloads(db):
    latest = {}
    for component in DATABASE_COMPONENTS:
        latest[component] = db.scalar(select(MaintenanceJob).where(MaintenanceJob.component == component)
                                      .order_by(desc(MaintenanceJob.id)).limit(1))
    vulnerability = database_info("vulnerability_db")
    java = database_info("java_db")
    return [
        {"id": "vulnerability_db", "name": "Vulnerability database", "description": "CVE and advisory data used by every vulnerability scan",
         "required": True, "bundled": (settings.trivy_seed_cache_dir / "db" / "metadata.json").is_file(),
         "repositories": settings.db_repositories, **vulnerability, "latest_job": maintenance_payload(latest["vulnerability_db"])},
        {"id": "java_db", "name": "Java index database", "description": "Artifact index used when images contain Java JAR files",
         "required": False, "bundled": (settings.trivy_seed_cache_dir / "java-db" / "metadata.json").is_file(),
         "repositories": settings.java_db_repositories, **java, "latest_job": maintenance_payload(latest["java_db"])},
        {"id": "trivy_engine", "name": "Trivy scanner engine", "description": "Scanner binary pinned in the backend container image",
         "required": True, "bundled": True, "installed": True, "version": trivy_version(), "update_available": False,
         "update_method": "Rebuild the backend image after changing its pinned Trivy version", "latest_job": None},
        {"id": "checks_bundle", "name": "Misconfiguration checks bundle", "description": "Not downloaded because this dashboard currently runs vulnerability-only scans; embedded checks remain available",
         "required": False, "bundled": True, "installed": True, "update_available": False, "update_method": "Enable only when misconfiguration scanning is added", "latest_job": None},
        {"id": "vex_hub", "name": "VEX Hub", "description": "Optional online VEX repository; disabled so normal archive scans never make hidden internet requests",
         "required": False, "bundled": False, "installed": False, "update_available": False, "update_method": "Disabled by policy", "latest_job": None},
    ]


def maintenance_payload(job: MaintenanceJob | None):
    if not job:
        return None
    try:
        result = json.loads(job.result_json or "{}")
    except json.JSONDecodeError:
        result = {}
    return {"id": job.id, "component": job.component, "action": job.action, "status": job.status,
            "progress": job.progress, "stage": job.stage, "message": job.message, "result": result,
            "error": job.error, "queued_at": job.queued_at, "started_at": job.started_at,
            "finished_at": job.finished_at, "updated_at": job.updated_at}


class ComponentManager:
    def __init__(self):
        self.queue: asyncio.Queue[int] = asyncio.Queue()
        self.queued_ids: set[int] = set()
        self.task: asyncio.Task | None = None
        self.processes: dict[int, asyncio.subprocess.Process] = {}
        self.stopping = False

    async def start(self):
        self.stopping = False
        recovered = []
        with SessionLocal() as db:
            jobs = db.scalars(select(MaintenanceJob).where(MaintenanceJob.status.in_(["queued", "running"]))
                              .order_by(MaintenanceJob.queued_at, MaintenanceJob.id)).all()
            for job in jobs:
                job.status = "queued"; job.progress = 0; job.stage = "recovered"
                job.message = "Recovered after an application restart"; job.started_at = None
                recovered.append(job.id)
            db.commit()
        for job_id in recovered:
            await self.enqueue(job_id)
        self.task = asyncio.create_task(self.worker(), name="component-maintenance-worker")

    async def stop(self):
        self.stopping = True
        for process in self.processes.values():
            if process.returncode is None:
                process.terminate()
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
            self.task = None

    async def request(self, component: str, action: str):
        if component not in DATABASE_COMPONENTS or action not in {"check", "update"}:
            raise ValueError("Unsupported component maintenance request")
        with SessionLocal() as db:
            active = db.scalar(select(MaintenanceJob).where(MaintenanceJob.component == component,
                                                             MaintenanceJob.status.in_(["queued", "running"]))
                               .order_by(desc(MaintenanceJob.id)).limit(1))
            if active:
                return active.id, True
            job = MaintenanceJob(component=component, action=action, status="queued", progress=0, stage="queued",
                                 message="Waiting for the maintenance worker")
            db.add(job); db.commit(); job_id = job.id
        await self.enqueue(job_id)
        return job_id, False

    async def enqueue(self, job_id: int):
        if job_id not in self.queued_ids:
            self.queued_ids.add(job_id)
            await self.queue.put(job_id)
            await self.publish(job_id)

    async def cancel(self, job_id: int):
        with SessionLocal() as db:
            job = db.get(MaintenanceJob, job_id)
            if not job:
                return None
            if job.status in TERMINAL:
                return job.status
            job.status = "cancelled"; job.stage = "cancelled"; job.message = "Cancelled by a user"
            job.finished_at = utcnow(); db.commit()
        process = self.processes.get(job_id)
        if process and process.returncode is None:
            process.terminate()
        self.queued_ids.discard(job_id)
        await self.publish(job_id)
        return "cancelled"

    async def publish(self, job_id: int):
        with SessionLocal() as db:
            job = db.get(MaintenanceJob, job_id)
            if not job:
                return
            payload = maintenance_payload(job)
        await scan_manager.publish({"type": "component_job", "job": payload})

    async def update(self, job_id: int, progress: int, stage: str, message: str):
        with SessionLocal() as db:
            job = db.get(MaintenanceJob, job_id)
            if not job or job.status == "cancelled":
                return False
            job.progress = max(job.progress, progress); job.stage = stage; job.message = message[:500]; job.updated_at = utcnow()
            db.commit()
        await self.publish(job_id)
        return True

    async def worker(self):
        while True:
            job_id = await self.queue.get()
            self.queued_ids.discard(job_id)
            try:
                with SessionLocal() as db:
                    job = db.get(MaintenanceJob, job_id)
                    runnable = bool(job and job.status == "queued")
                if runnable:
                    await self.run(job_id)
            finally:
                self.queue.task_done()

    async def run(self, job_id: int):
        with SessionLocal() as db:
            job = db.get(MaintenanceJob, job_id)
            if not job:
                return
            component, action = job.component, job.action
            job.status = "running"; job.progress = 5; job.stage = "starting"; job.message = f"Starting {action}"
            job.started_at = utcnow(); job.error = None; db.commit()
        await self.publish(job_id)
        try:
            if action == "check":
                await self.check(job_id, component)
            else:
                await self.download(job_id, component)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self.fail(job_id, exc)

    async def check(self, job_id: int, component: str):
        await self.update(job_id, 35, "inspecting", "Reading installed database metadata")
        info = database_info(component)
        repositories = settings.db_repositories if component == "vulnerability_db" else settings.java_db_repositories
        await self.update(job_id, 65, "checking_registry", "Checking configured registry access")
        reachable = await registry_reachable(repositories)
        result = {"installed": info["installed"], "updated_at": str(info["updated_at"]) if info["updated_at"] else None,
                  "next_update": str(info["next_update"]) if info["next_update"] else None,
                  "update_available": info["update_available"] or not info["installed"], "registry_reachable": reachable}
        message = "Update recommended" if result["update_available"] else "Installed database is within its update window"
        await self.complete(job_id, result, message)

    async def download(self, job_id: int, component: str):
        command = [settings.trivy_binary, "image", "--cache-dir", str(settings.trivy_cache_dir), "--no-progress", "--disable-telemetry"]
        if component == "vulnerability_db":
            command.append("--download-db-only")
            for repository in settings.db_repositories:
                command.extend(["--db-repository", repository])
        else:
            command.append("--download-java-db-only")
            for repository in settings.java_db_repositories:
                command.extend(["--java-db-repository", repository])
        await self.update(job_id, 12, "waiting_for_scans", "Waiting for active scans to release the database")
        await database_access.acquire_write()
        process = None
        lines: deque[str] = deque(maxlen=80)
        try:
            await self.update(job_id, 20, "connecting", "Connecting to the configured database registry")
            with maintenance_workspace(job_id) as workspace:
                process = await asyncio.create_subprocess_exec(
                    *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    env=maintenance_environment(workspace),
                )
                self.processes[job_id] = process
                stdout_task = asyncio.create_task(self.consume(job_id, process.stdout, lines))
                stderr_task = asyncio.create_task(self.consume(job_id, process.stderr, lines))
                try:
                    await asyncio.wait_for(process.wait(), timeout=settings.trivy_timeout_seconds)
                except asyncio.TimeoutError as exc:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        process.kill(); await process.wait()
                    raise RuntimeError(f"Database maintenance exceeded the {settings.trivy_timeout_seconds}-second timeout") from exc
                finally:
                    await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            with SessionLocal() as db:
                current = db.get(MaintenanceJob, job_id)
                if not current or current.status == "cancelled":
                    return
            if process.returncode:
                raise RuntimeError("\n".join(lines)[-4000:] or f"Trivy exited with code {process.returncode}")
            await self.update(job_id, 90, "verifying", "Verifying downloaded metadata")
            info = database_info(component)
            if not info["installed"]:
                raise RuntimeError("Trivy completed without installing database metadata")
            await self.complete(job_id, {"updated_at": str(info["updated_at"]) if info["updated_at"] else None,
                                         "next_update": str(info["next_update"]) if info["next_update"] else None,
                                         "size_bytes": info["size_bytes"]}, "Database is up to date")
        finally:
            self.processes.pop(job_id, None)
            await database_access.release_write()

    async def consume(self, job_id: int, stream, lines: deque[str]):
        if not stream:
            return
        while line := await stream.readline():
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            lines.append(text)
            lowered = text.casefold()
            if "downloading" in lowered:
                await self.update(job_id, 48, "downloading", "Downloading the OCI database artifact")
            elif "artifact" in lowered or "blob" in lowered:
                await self.update(job_id, 68, "extracting", "Extracting and installing database files")

    async def complete(self, job_id: int, result: dict, message: str):
        with SessionLocal() as db:
            job = db.get(MaintenanceJob, job_id)
            if not job or job.status == "cancelled":
                return
            job.status = "completed"; job.progress = 100; job.stage = "completed"; job.message = message
            job.result_json = json.dumps(result, ensure_ascii=True); job.finished_at = utcnow(); job.updated_at = job.finished_at
            db.commit()
        await self.publish(job_id)

    async def fail(self, job_id: int, exc: Exception):
        with SessionLocal() as db:
            job = db.get(MaintenanceJob, job_id)
            if not job or job.status == "cancelled":
                return
            job.status = "failed"; job.stage = "failed"; job.message = "Component maintenance failed"
            job.error = sanitize_untrusted_text(exc) or exc.__class__.__name__
            job.finished_at = utcnow(); job.updated_at = job.finished_at; db.commit()
        await self.publish(job_id)


async def registry_reachable(repositories: list[str]):
    async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
        for repository in repositories:
            host = repository.split("/", 1)[0]
            try:
                response = await client.get(f"https://{host}/v2/")
                if response.status_code in {200, 401}:
                    return True
            except httpx.HTTPError:
                continue
    return False


component_manager = ComponentManager()
