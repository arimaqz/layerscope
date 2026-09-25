import asyncio
import json
import os
import shutil
import tempfile
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, insert, select

from .config import settings
from .database import SessionLocal
from .locks import database_access
from .models import Finding, Package, Scan
from .security import safe_advisory_url, sanitize_untrusted_text


TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
JAVA_ARCHIVE_PATTERNS = ("**/*.jar", "**/*.war", "**/*.ear", "**/*.par", "**/*.jpi", "**/*.hpi")
JAVA_COVERAGE_WARNING = (
    "Java archive vulnerabilities were skipped because the Java index database is not installed. "
    "Install Java DB from Components and rescan for full Java coverage."
)
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
NORMALIZED_INSERT_BATCH = 5000


def create_scan_workspace(scan_id: int) -> Path:
    """Create a private Trivy workspace on persistent, disk-backed storage."""
    root = settings.trivy_temp_dir
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    workspace = Path(tempfile.mkdtemp(prefix=f"scan-{scan_id}-", dir=root))
    workspace.chmod(0o700)
    return workspace


def scan_environment(workspace: Path):
    environment = os.environ.copy()
    temporary_path = str(workspace)
    environment.update({"TMPDIR": temporary_path, "TMP": temporary_path, "TEMP": temporary_path})
    return environment


def cleanup_scan_workspace(workspace: Path | None):
    if workspace is None:
        return
    root = settings.trivy_temp_dir.resolve()
    resolved = workspace.resolve()
    if workspace.name.startswith("scan-") and root in resolved.parents:
        shutil.rmtree(resolved, ignore_errors=True)


def cleanup_abandoned_scan_workspaces():
    root = settings.trivy_temp_dir
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    for item in root.glob("scan-*"):
        if item.is_symlink() or item.is_file():
            item.unlink(missing_ok=True)
        elif item.is_dir():
            shutil.rmtree(item, ignore_errors=True)


def bulk_insert_models(db, model, items):
    """Persist normalized rows through bounded executemany batches."""
    if not items:
        return
    columns = [column.name for column in model.__table__.columns if column.name != "id"]
    for start in range(0, len(items), NORMALIZED_INSERT_BATCH):
        batch = items[start:start + NORMALIZED_INSERT_BATCH]
        db.execute(insert(model), [{name: getattr(item, name) for name in columns} for item in batch])


def normalized_text(value) -> str:
    """Convert Trivy scalar or structured values into deterministic UTF-8 text."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def package_identifier(package: dict) -> str:
    value = package.get("ID") or package.get("Identifier")
    if isinstance(value, dict):
        # Recent Trivy releases emit {"PURL": "...", "UID": "..."}. PURL is
        # stable and useful in the UI; the complete object remains in raw JSON.
        return normalized_text(value.get("PURL") or value.get("UID") or value)
    return normalized_text(value)


def package_licenses(value) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(filter(None, (normalized_text(item) for item in value)))
    return normalized_text(value)


def build_scan_command(image_path: str, raw_path: Path, java_db_available: bool) -> list[str]:
    """Build a network-quiet Trivy command that remains usable before Java DB installation."""
    command = [
        settings.trivy_binary, "image", "--input", image_path, "--format", "json", "--output", str(raw_path),
        "--scanners", "vuln", "--cache-dir", str(settings.trivy_cache_dir), "--no-progress",
        "--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update", "--disable-telemetry",
        "--offline-scan",
    ]
    for repository in settings.db_repositories:
        command.extend(["--db-repository", repository])
    for repository in settings.java_db_repositories:
        command.extend(["--java-db-repository", repository])
    if not java_db_available:
        # Trivy rejects --skip-java-db-update on first use only when it discovers a Java archive.
        # Excluding those archives preserves OS and non-Java language scanning without a hidden download.
        for pattern in JAVA_ARCHIVE_PATTERNS:
            command.extend(["--skip-files", pattern])
    return command


class ScanManager:
    """Persistent scan-job dispatcher backed by the scans table."""

    def __init__(self):
        self.queue: asyncio.Queue[int] = asyncio.Queue()
        self.subscribers: set[asyncio.Queue] = set()
        self.workers: list[asyncio.Task] = []
        self.queued_ids: set[int] = set()
        self.active_ids: set[int] = set()
        self.processes: dict[int, asyncio.subprocess.Process] = {}
        self.admission_lock = asyncio.Lock()
        self.dropped_events = 0
        self.rejected_sse_clients = 0
        self.stopping = False

    async def start(self):
        settings.raw_results_dir.mkdir(parents=True, exist_ok=True)
        settings.trivy_cache_dir.mkdir(parents=True, exist_ok=True)
        cleanup_abandoned_scan_workspaces()
        # A lifespan restart may run on a new event loop (for example in tests
        # or an embedded deployment). Do not retain loop-bound queue state.
        self.queue = asyncio.Queue()
        self.queued_ids.clear()
        self.active_ids.clear()
        self.subscribers.clear()
        self.stopping = False
        await self.recover_jobs()
        self.workers = [
            asyncio.create_task(self.worker(index), name=f"scan-worker-{index + 1}")
            for index in range(max(1, settings.scan_concurrency))
        ]

    async def stop(self):
        self.stopping = True
        for process in list(self.processes.values()):
            if process.returncode is None:
                process.terminate()
        for worker in self.workers:
            worker.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        self.processes.clear()

    async def recover_jobs(self):
        """Requeue persisted queued/running work after an application restart."""
        recovered: list[int] = []
        with SessionLocal() as db:
            jobs = db.scalars(select(Scan).where(Scan.status.in_(["queued", "running"])).order_by(Scan.queued_at, Scan.id)).all()
            for job in jobs:
                if job.status == "running":
                    job.status = "queued"
                    job.started_at = None
                    job.progress = 0
                    job.stage = "recovered"
                    job.message = "Recovered after an application restart"
                recovered.append(job.id)
            db.commit()
        for job_id in recovered:
            await self.enqueue(job_id, publish=False)
            await self.publish_job(job_id)

    async def enqueue(self, scan_id: int, publish: bool = True):
        if scan_id in self.queued_ids or scan_id in self.active_ids:
            return False
        self.queued_ids.add(scan_id)
        await self.queue.put(scan_id)
        if publish:
            await self.publish_job(scan_id)
        return True

    async def cancel(self, scan_id: int):
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if not scan:
                return None
            if scan.status in TERMINAL_STATUSES:
                return scan.status
            scan.status = "cancelled"
            scan.stage = "cancelled"
            scan.message = "Cancelled by a user"
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
        self.queued_ids.discard(scan_id)
        process = self.processes.get(scan_id)
        if process and process.returncode is None:
            process.terminate()
        await self.publish_job(scan_id)
        return "cancelled"

    async def publish(self, event: dict):
        for queue in list(self.subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                self.dropped_events += 1

    async def publish_job(self, scan_id: int):
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if not scan:
                return
            event = {
                "type": "job", "scan_id": scan.id, "image_id": scan.image_id,
                "status": scan.status, "progress": scan.progress, "stage": scan.stage,
                "message": scan.message, "error": scan.error, "coverage_warning": scan.coverage_warning,
            }
        await self.publish(event)

    async def update_job(self, scan_id: int, *, status: str | None = None, progress: int | None = None,
                         stage: str | None = None, message: str | None = None, error: str | None = None):
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if not scan or scan.status == "cancelled":
                return False
            if status:
                scan.status = status
            if progress is not None:
                scan.progress = max(scan.progress or 0, min(100, max(0, progress)))
            if stage:
                scan.stage = stage[:40]
            if message is not None:
                scan.message = message.strip()[:500]
            if error is not None:
                scan.error = error[:4000]
            scan.updated_at = datetime.now(timezone.utc)
            db.commit()
        await self.publish_job(scan_id)
        return True

    async def worker(self, worker_number: int):
        while True:
            scan_id = await self.queue.get()
            self.queued_ids.discard(scan_id)
            self.active_ids.add(scan_id)
            try:
                with SessionLocal() as db:
                    scan = db.get(Scan, scan_id)
                    should_run = bool(scan and scan.status == "queued")
                if should_run:
                    await self.run_scan(scan_id, worker_number)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await self.fail_job(scan_id, exc)
            finally:
                self.active_ids.discard(scan_id)
                self.queue.task_done()

    async def run_scan(self, scan_id: int, worker_number: int):
        raw_path = settings.raw_results_dir / f"scan-{scan_id}.json"
        stderr_tail: deque[str] = deque(maxlen=80)
        process: asyncio.subprocess.Process | None = None
        workspace: Path | None = None
        read_lock = False
        try:
            with SessionLocal() as db:
                scan = db.get(Scan, scan_id)
                if not scan or scan.status != "queued":
                    return
                scan.status = "running"
                scan.progress = max(scan.progress or 0, 3)
                scan.stage = "preparing"
                scan.message = f"Worker {worker_number + 1} is validating the archive"
                scan.started_at = datetime.now(timezone.utc)
                scan.finished_at = None
                scan.error = None
                scan.coverage_warning = None
                image_path = scan.image.path
                db.commit()
            await self.publish_job(scan_id)

            await database_access.acquire_read()
            read_lock = True
            java_db_available = (settings.trivy_cache_dir / "java-db" / "metadata.json").is_file()
            command = build_scan_command(image_path, raw_path, java_db_available)
            with SessionLocal() as db:
                current = db.get(Scan, scan_id)
                if current:
                    current.coverage_warning = None if java_db_available else JAVA_COVERAGE_WARNING
                    db.commit()
            await self.update_job(
                scan_id, progress=8, stage="initializing",
                message="Starting Trivy" if java_db_available else "Starting Trivy without Java archive coverage",
            )
            workspace = create_scan_workspace(scan_id)
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=scan_environment(workspace),
            )
            self.processes[scan_id] = process
            stderr_task = asyncio.create_task(self.consume_output(scan_id, process.stderr, stderr_tail))
            stdout_task = asyncio.create_task(self.consume_output(scan_id, process.stdout, None))
            try:
                await asyncio.wait_for(process.wait(), timeout=settings.trivy_timeout_seconds)
            except asyncio.TimeoutError as exc:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                raise RuntimeError(f"Trivy exceeded the {settings.trivy_timeout_seconds}-second timeout") from exc
            finally:
                await asyncio.gather(stderr_task, stdout_task, return_exceptions=True)

            with SessionLocal() as db:
                current = db.get(Scan, scan_id)
                if not current or current.status == "cancelled":
                    raw_path.unlink(missing_ok=True)
                    return
            if process.returncode != 0:
                detail = "\n".join(stderr_tail).strip() or f"Trivy exited with code {process.returncode}"
                raise RuntimeError(detail[-4000:])

            await self.update_job(scan_id, progress=78, stage="reading_results", message="Reading the Trivy JSON result")
            if raw_path.stat().st_size > settings.max_raw_result_bytes:
                raise RuntimeError("Trivy JSON exceeded the configured normalized-result size limit")
            with raw_path.open("r", encoding="utf-8") as raw_stream:
                payload = json.load(raw_stream)
            packages, findings = self.normalize(payload, scan_id)
            await self.update_job(scan_id, progress=88, stage="normalizing", message=f"Prepared {len(findings):,} findings and {len(packages):,} packages")

            with SessionLocal() as db:
                scan = db.get(Scan, scan_id)
                if not scan or scan.status == "cancelled":
                    raw_path.unlink(missing_ok=True)
                    return
                db.execute(delete(Finding).where(Finding.scan_id == scan_id))
                db.execute(delete(Package).where(Package.scan_id == scan_id))
                bulk_insert_models(db, Package, packages)
                bulk_insert_models(db, Finding, findings)
                scan.progress = 96
                scan.stage = "saving"
                scan.message = "Saving normalized results"
                db.commit()
            await self.publish_job(scan_id)

            with SessionLocal() as db:
                scan = db.get(Scan, scan_id)
                if not scan or scan.status == "cancelled":
                    return
                scan.status = "completed"
                scan.progress = 100
                scan.stage = "completed"
                scan.message = f"Completed with {len(findings):,} findings"
                if scan.coverage_warning:
                    scan.message += ". Java archives were skipped; install Java DB and rescan for full coverage"
                scan.finished_at = datetime.now(timezone.utc)
                scan.updated_at = scan.finished_at
                scan.raw_json_path = str(raw_path)
                db.commit()
            await self.publish_job(scan_id)
        except asyncio.CancelledError:
            if process and process.returncode is None:
                process.terminate()
                await process.wait()
            if self.stopping:
                with SessionLocal() as db:
                    scan = db.get(Scan, scan_id)
                    if scan and scan.status == "running":
                        scan.status = "queued"
                        scan.progress = 0
                        scan.stage = "recovered"
                        scan.message = "Paused during shutdown; it will resume after restart"
                        scan.started_at = None
                        db.commit()
            raise
        except Exception as exc:
            raw_path.unlink(missing_ok=True)
            await self.fail_job(scan_id, exc)
        finally:
            self.processes.pop(scan_id, None)
            cleanup_scan_workspace(workspace)
            if read_lock:
                await database_access.release_read()

    async def consume_output(self, scan_id: int, stream: asyncio.StreamReader | None, tail: deque[str] | None):
        if stream is None:
            return
        last_stage = ""
        while line := await stream.readline():
            message = line.decode("utf-8", errors="replace").strip()
            if not message:
                continue
            if tail is not None:
                tail.append(message)
            progress, stage, friendly = self.infer_progress(message)
            if stage and stage != last_stage:
                last_stage = stage
                await self.update_job(scan_id, progress=progress, stage=stage, message=friendly)

    @staticmethod
    def infer_progress(message: str):
        lowered = message.casefold()
        if "need to update db" in lowered or "downloading vulnerability db" in lowered:
            return 12, "updating_database", "Updating the vulnerability database"
        if "downloading artifact" in lowered or "downloading db" in lowered:
            return 20, "downloading_database", "Downloading vulnerability data"
        if "vulnerability scanning is enabled" in lowered:
            return 32, "loading_archive", "Loading the image archive"
        if "detecting" in lowered or "detected os" in lowered:
            return 48, "detecting_os", "Detecting operating system and packages"
        if "scanning" in lowered or "vulnerability" in lowered:
            return 58, "scanning", "Scanning packages for vulnerabilities"
        return 0, "", ""

    @staticmethod
    def normalize(payload: dict, scan_id: int):
        packages: list[Package] = []
        findings: list[Finding] = []
        for result in payload.get("Results") or []:
            if not isinstance(result, dict):
                continue
            target = normalized_text(result.get("Target"))
            for package in result.get("Packages") or []:
                if not isinstance(package, dict):
                    continue
                packages.append(Package(
                    scan_id=scan_id, target=target, name=normalized_text(package.get("Name")),
                    version=normalized_text(package.get("Version")), identifier=package_identifier(package),
                    licenses=package_licenses(package.get("Licenses")),
                ))
            for vuln in result.get("Vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                severity = normalized_text(vuln.get("Severity")).upper()
                findings.append(Finding(
                    scan_id=scan_id, target=target,
                    vulnerability_id=normalized_text(vuln.get("VulnerabilityID")) or "UNKNOWN",
                    package_name=normalized_text(vuln.get("PkgName")),
                    installed_version=normalized_text(vuln.get("InstalledVersion")),
                    fixed_version=normalized_text(vuln.get("FixedVersion")),
                    severity=severity if severity in SEVERITIES else "UNKNOWN",
                    title=normalized_text(vuln.get("Title")),
                    description=normalized_text(vuln.get("Description")),
                    primary_url=safe_advisory_url(vuln.get("PrimaryURL")),
                ))
        return packages, findings

    async def fail_job(self, scan_id: int, exc: Exception):
        message = sanitize_untrusted_text(exc) or exc.__class__.__name__
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if not scan or scan.status == "cancelled":
                return
            scan.status = "failed"
            scan.stage = "failed"
            scan.message = "Scan failed"
            scan.finished_at = datetime.now(timezone.utc)
            scan.updated_at = scan.finished_at
            scan.error = message[-4000:]
            db.commit()
        await self.publish_job(scan_id)


manager = ScanManager()
