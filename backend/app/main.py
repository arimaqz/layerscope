import asyncio
import json
import logging
import shutil
import tarfile
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import case, delete, desc, func, select
from sqlalchemy.orm import Session, selectinload
from .config import settings
from .auth import AuthenticationMiddleware, audit, require_roles, router as auth_router
from .api_tokens import router as api_tokens_router
from .api_docs import router as api_docs_router
from .backups import apply_pending_restore, router as backups_router
from .database import Base, SessionLocal, apply_schema_upgrades, engine, get_db
from .components import component_manager, component_payloads
from .diagnostics import run_diagnostics
from .groups import router as groups_router
from .models import Finding, ImageArchive, ImageGroup, ImageGroupMember, Package, Scan, UploadJob
from .reports import (MAX_REPORT_LOGO_BYTES, GroupExportError, ReportImportError, ReportLogoError,
                      defectdojo_payload, group_export_selection, import_report_payload, is_imported_scan,
                      is_report_path, render_elastic_bulk, render_html, render_pdf, report_payload,
                      sanitize_report_logo)
from .scanner import manager
from .schemas import BulkImageDeleteRequest, BulkScanDeleteRequest, FindingOut, ScanRequest
from .users import router as users_router
from .qos import QualityOfServiceMiddleware, require_storage_capacity, storage_capacity
from .security import SecurityHeadersMiddleware, safe_download_name, sanitize_untrusted_text
from .uploads import stream_archive_uploads


logger = logging.getLogger("layerscope.api")


def event_json(event: dict) -> str:
    return json.dumps(jsonable_encoder(event), separators=(",", ":"), ensure_ascii=True)


def allowed_path(path: Path) -> bool:
    resolved = path.resolve()
    return any(resolved == root or root in resolved.parents for root in settings.roots)


def uploaded_archive(path: str) -> bool:
    if is_report_path(path):
        return False
    resolved = Path(path).resolve()
    upload_root = settings.upload_dir.resolve()
    return resolved.suffix.lower() == ".tar" and upload_root in resolved.parents


def archive_source(path: str) -> str:
    if is_report_path(path):
        return "report"
    return "upload" if uploaded_archive(path) else "mounted"


def plausible_image_archive(path: Path, member_limit: int = 10000) -> bool:
    """Check Docker/OCI control files without extracting attacker-controlled content."""
    try:
        with tarfile.open(path, mode="r:") as archive:
            for index, member in enumerate(archive):
                name = member.name.replace("\\", "/").lstrip("./")
                if name in {"manifest.json", "index.json", "oci-layout"}:
                    return True
                if index + 1 >= member_limit:
                    break
    except (OSError, tarfile.TarError):
        return False
    return False


def remove_scan_record(db: Session, scan: Scan):
    if scan.status in {"queued", "running"}:
        raise HTTPException(409, "Active scans must be cancelled before removal")
    if scan.raw_json_path and not is_imported_scan(scan):
        raw_path = Path(scan.raw_json_path)
        try:
            resolved = raw_path.resolve()
            if settings.raw_results_dir.resolve() in resolved.parents:
                raw_path.unlink(missing_ok=True)
        except OSError:
            raise HTTPException(500, "The raw scan result could not be removed")
    db.execute(delete(Finding).where(Finding.scan_id == scan.id))
    db.execute(delete(Package).where(Package.scan_id == scan.id))
    db.execute(delete(Scan).where(Scan.id == scan.id))


def remove_scan_records(db: Session, scans: list[Scan]):
    active_ids = [scan.id for scan in scans if scan.status in {"queued", "running"}]
    if active_ids:
        raise HTTPException(409, f"Cancel active scans before removal: {', '.join(map(str, active_ids))}")
    for scan in scans:
        remove_scan_record(db, scan)


def remove_image_record(db: Session, image: ImageArchive, scans: list[Scan] | None = None):
    scans = scans if scans is not None else db.scalars(
        select(Scan).where(Scan.image_id == image.id).order_by(Scan.id)).all()
    remove_scan_records(db, scans)
    archive_deleted = False
    report_only = is_report_path(image.path)
    if uploaded_archive(image.path):
        try:
            Path(image.path).unlink(missing_ok=True)
        except OSError as exc:
            raise HTTPException(500, "The uploaded archive could not be removed") from exc
        archive_deleted = True
        db.execute(delete(ImageGroupMember).where(ImageGroupMember.image_id == image.id))
        db.execute(delete(ImageArchive).where(ImageArchive.id == image.id))
    elif report_only:
        db.execute(delete(ImageGroupMember).where(ImageGroupMember.image_id == image.id))
        db.execute(delete(ImageArchive).where(ImageArchive.id == image.id))
    else:
        image.hidden = True
        image.removed_at = datetime.now(timezone.utc)
    return {"image_id": image.id, "source": archive_source(image.path), "removed_scans": len(scans),
            "uploaded_archive_deleted": archive_deleted, "restorable": not archive_deleted and not report_only}


_discovery_lock = threading.Lock()
_last_discovery_at = 0.0


def discover(db: Session, force: bool = False):
    """Discover archives with a short cache and one database read, not one query per file."""
    global _last_discovery_at
    now = time.monotonic()
    if not force and now - _last_discovery_at < settings.discovery_interval_seconds:
        return []
    with _discovery_lock:
        now = time.monotonic()
        if not force and now - _last_discovery_at < settings.discovery_interval_seconds:
            return []
        existing = {item.path: item for item in db.scalars(select(ImageArchive)).all()}
        found: list[ImageArchive] = []
        seen: set[str] = set()
        for root in settings.roots:
            if not root.exists():
                continue
            try:
                candidates = root.rglob("*.tar")
                for path in candidates:
                    try:
                        resolved = path.resolve()
                        resolved_text = str(resolved)
                        if resolved_text in seen or not path.is_file() or not allowed_path(resolved):
                            continue
                        stat = path.stat()
                    except OSError:
                        continue
                    seen.add(resolved_text)
                    modified_at = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                    item = existing.get(resolved_text)
                    if item is None:
                        item = ImageArchive(path=resolved_text, name=path.name, size=stat.st_size,
                                            modified_at=modified_at)
                        db.add(item)
                    elif item.size != stat.st_size or item.modified_at != modified_at:
                        item.size = stat.st_size
                        item.modified_at = modified_at
                    found.append(item)
                    if len(found) >= settings.max_discovered_archives:
                        break
            except OSError:
                continue
            if len(found) >= settings.max_discovered_archives:
                break
        db.commit()
        _last_discovery_at = time.monotonic()
        return found


def scan_payload(scan: Scan, counts: dict[str, int]):
    return {"id": scan.id, "status": scan.status, "progress": scan.progress, "stage": scan.stage,
            "message": scan.message, "queued_at": scan.queued_at, "started_at": scan.started_at,
            "finished_at": scan.finished_at, "error": scan.error, "coverage_warning": scan.coverage_warning,
            "counts": counts, "total": sum(counts.values())}


def latest_scans_with_counts(db: Session, image_ids: list[int]):
    if not image_ids:
        return {}, {}
    latest = (select(Scan.image_id, func.max(Scan.id).label("scan_id"))
              .where(Scan.image_id.in_(image_ids)).group_by(Scan.image_id).subquery())
    scans = db.scalars(select(Scan).join(latest, Scan.id == latest.c.scan_id)).all()
    by_image = {scan.image_id: scan for scan in scans}
    scan_ids = [scan.id for scan in scans]
    counts_by_scan: dict[int, dict[str, int]] = {}
    if scan_ids:
        for scan_id, severity, count in db.execute(
                select(Finding.scan_id, Finding.severity, func.count())
                .where(Finding.scan_id.in_(scan_ids)).group_by(Finding.scan_id, Finding.severity)).all():
            counts_by_scan.setdefault(scan_id, {})[severity] = count
    return by_image, counts_by_scan


def image_groups_by_id(db: Session, image_ids: list[int]):
    groups: dict[int, list[dict]] = {image_id: [] for image_id in image_ids}
    if not image_ids:
        return groups
    rows = db.execute(
        select(ImageGroupMember.image_id, ImageGroup.id, ImageGroup.name, ImageGroup.color)
        .join(ImageGroup, ImageGroup.id == ImageGroupMember.group_id)
        .where(ImageGroupMember.image_id.in_(image_ids)).order_by(ImageGroup.name)).all()
    for image_id, group_id, name, color in rows:
        groups[image_id].append({"id": group_id, "name": name, "color": color})
    return groups


def image_payloads(db: Session, rows: list[ImageArchive]):
    image_ids = [image.id for image in rows]
    scans, counts_by_scan = latest_scans_with_counts(db, image_ids)
    groups = image_groups_by_id(db, image_ids)
    result = []
    for image in rows:
        latest = scans.get(image.id)
        result.append({"id": image.id, "name": image.name, "source": archive_source(image.path),
                       "size": image.size, "modified_at": image.modified_at,
                       "latest_scan": scan_payload(latest, counts_by_scan.get(latest.id, {})) if latest else None,
                       "groups": groups.get(image.id, [])})
    return result


def latest_scan_payload(db: Session, image_id: int):
    scans, counts = latest_scans_with_counts(db, [image_id])
    scan = scans.get(image_id)
    if not scan:
        return None
    return scan_payload(scan, counts.get(scan.id, {}))


def image_group_refs(db: Session, image_id: int):
    return image_groups_by_id(db, [image_id]).get(image_id, [])


def job_payload(scan: Scan, queue_position: int | None = None):
    return {"id": scan.id, "image_id": scan.image_id, "image_name": scan.image.name, "status": scan.status,
            "progress": scan.progress, "stage": scan.stage, "message": scan.message, "queue_position": queue_position,
            "queued_at": scan.queued_at, "started_at": scan.started_at, "finished_at": scan.finished_at,
            "updated_at": scan.updated_at, "error": scan.error, "coverage_warning": scan.coverage_warning}


def upload_job_payload(job: UploadJob):
    return {"id": job.id, "archive_name": job.archive_name, "status": job.status,
            "progress": job.progress, "stage": job.stage, "message": job.message,
            "bytes_received": job.bytes_received, "total_bytes": job.total_bytes,
            "image_id": job.image_id, "image_count": job.image_count, "error": job.error,
            "queued_at": job.queued_at, "started_at": job.started_at,
            "finished_at": job.finished_at, "updated_at": job.updated_at}


async def update_upload_job(job_id: int, **values):
    with SessionLocal() as job_db:
        job = job_db.get(UploadJob, job_id)
        if not job:
            return
        for name, value in values.items():
            setattr(job, name, value)
        job.updated_at = datetime.now(timezone.utc)
        job_db.commit()
        payload = upload_job_payload(job)
    await manager.publish({"type": "upload_job", "job": payload})


def seed_trivy_databases():
    """Populate an empty persistent cache from databases bundled into the image."""
    for directory in ("db", "java-db"):
        source = settings.trivy_seed_cache_dir / directory
        destination = settings.trivy_cache_dir / directory
        if source.is_dir() and not (destination / "metadata.json").is_file():
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, destination, dirs_exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    apply_pending_restore()
    Base.metadata.create_all(engine)
    apply_schema_upgrades()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    seed_trivy_databases()
    with SessionLocal() as db:
        await asyncio.to_thread(discover, db, True)
    await manager.start()
    await component_manager.start()
    yield
    await component_manager.stop()
    await manager.stop()


app = FastAPI(title="LayerScope API", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(AuthenticationMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_methods=["GET", "POST", "DELETE"],
                   allow_headers=["Accept", "Authorization", "Content-Type", "X-CSRF-Token"],
                   expose_headers=["Retry-After", "Server-Timing", "X-Request-ID"], allow_credentials=True)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(QualityOfServiceMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.include_router(auth_router)
app.include_router(api_tokens_router)
app.include_router(api_docs_router)
app.include_router(users_router)
app.include_router(groups_router)
app.include_router(backups_router)


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, exc: RequestValidationError):
    errors = [{"loc": list(item.get("loc", ())), "msg": item.get("msg", "Invalid value"),
               "type": item.get("type", "validation_error")} for item in exc.errors()]
    return JSONResponse({"detail": errors}, status_code=422)


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", "unavailable")
    logger.exception("Unhandled API exception request_id=%s method=%s path=%s",
                     request_id, request.method, request.url.path, exc_info=exc)
    return JSONResponse({"detail": "An unexpected server error occurred", "request_id": request_id}, status_code=500)


@app.get("/api/health")
def health():
    database_ok = False
    try:
        with SessionLocal() as db:
            db.execute(select(1)).scalar_one()
            database_ok = True
    except Exception:
        database_ok = False
    workers = sum(1 for worker in manager.workers if not worker.done())
    storage = storage_capacity(settings.raw_results_dir)
    ready = database_ok and workers == len(manager.workers) and workers > 0 and storage["status"] != "critical"
    payload = {"status": "ok" if ready else "unavailable"}
    return JSONResponse(payload, status_code=200 if ready else 503)


@app.get("/api/service-status")
def service_status(db: Session = Depends(get_db)):
    status_counts = dict(db.execute(
        select(Scan.status, func.count()).where(Scan.status.in_(["queued", "running"]))
        .group_by(Scan.status)).all())
    queued = status_counts.get("queued", 0)
    running = status_counts.get("running", 0)
    active = queued + running
    storage = storage_capacity(settings.upload_dir)
    return {
        "queue": {"queued": queued, "running": running, "active": active,
                  "capacity": settings.max_pending_scans,
                  "utilization": round(active / settings.max_pending_scans * 100, 1)},
        "workers": {"available": sum(1 for worker in manager.workers if not worker.done()),
                    "configured": settings.scan_concurrency},
        "storage": storage,
        "events": {"clients": len(manager.subscribers), "capacity": settings.max_sse_clients,
                   "dropped": manager.dropped_events, "rejected": manager.rejected_sse_clients},
        "limits": {"scan_timeout_seconds": settings.trivy_timeout_seconds,
                   "max_upload_bytes": settings.max_upload_bytes,
                   "max_upload_request_bytes": settings.max_upload_request_bytes,
                   "max_upload_files": settings.max_upload_files},
    }


@app.get("/api/diagnostics")
async def diagnostics(db: Session = Depends(get_db), _user=Depends(require_roles("admin"))):
    return await run_diagnostics(db)


@app.get("/api/components")
def components(db: Session = Depends(get_db), _user=Depends(require_roles("admin"))):
    return component_payloads(db)


@app.post("/api/components/check", status_code=202)
async def check_components(_user=Depends(require_roles("admin"))):
    jobs = []
    for component in ("vulnerability_db", "java_db"):
        job_id, reused = await component_manager.request(component, "check")
        jobs.append({"job_id": job_id, "component": component, "reused": reused})
    return {"jobs": jobs}


@app.post("/api/components/{component}/update", status_code=202)
async def update_component(component: str, _user=Depends(require_roles("admin"))):
    try:
        job_id, reused = await component_manager.request(component, "update")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"job_id": job_id, "component": component, "reused": reused}


@app.post("/api/component-jobs/{job_id}/cancel")
async def cancel_component_job(job_id: int, _user=Depends(require_roles("admin"))):
    status = await component_manager.cancel(job_id)
    if status is None:
        raise HTTPException(404, "Maintenance job not found")
    if status != "cancelled":
        raise HTTPException(409, f"A {status} maintenance job cannot be cancelled")
    return {"job_id": job_id, "status": status}


@app.post("/api/discover")
def run_discovery(db: Session = Depends(get_db), _user=Depends(require_roles("operator", "admin"))):
    return {"discovered": len(discover(db, force=True))}


@app.post("/api/uploads", status_code=201)
async def upload_archives(request: Request, db: Session = Depends(get_db),
                          _user=Depends(require_roles("operator", "admin"))):
    uploaded = []
    archives = []
    created_paths = []
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    if not allowed_path(settings.upload_dir):
        raise HTTPException(500, "Upload directory is not included in configured scan roots")
    try:
        content_length = int(request.headers.get("content-length", "0"))
    except ValueError:
        content_length = 0
    started_at = datetime.now(timezone.utc)
    upload_job = UploadJob(status="running", progress=0, stage="receiving", message="Receiving archive data",
                           total_bytes=content_length or None, started_at=started_at)
    db.add(upload_job)
    db.commit()
    job_id = upload_job.id
    await manager.publish({"type": "upload_job", "job": upload_job_payload(upload_job)})
    last_update_at = 0.0
    last_progress = -1
    known_name = ""

    async def track_progress(bytes_received: int, total_bytes: int, archive_name: str | None):
        nonlocal last_update_at, last_progress, known_name
        current_time = time.monotonic()
        progress = min(85, round(bytes_received / total_bytes * 85)) if total_bytes else min(85, last_progress + 1)
        name_changed = bool(archive_name and archive_name != known_name)
        if not name_changed and progress < 85 and current_time - last_update_at < 0.5:
            return
        known_name = archive_name or known_name
        await update_upload_job(
            job_id, archive_name=known_name or "Archive upload", progress=max(0, progress),
            bytes_received=bytes_received, total_bytes=total_bytes or None,
            message=f"Received {bytes_received:,} bytes",
        )
        last_update_at, last_progress = current_time, progress

    try:
        archives = await stream_archive_uploads(request, track_progress)
        created_paths = [archive.path for archive in archives]
        display_name = archives[0].name if len(archives) == 1 else f"{len(archives)} archives"
        await update_upload_job(job_id, archive_name=display_name, progress=90, stage="validating",
                                message="Validating Docker or OCI archive metadata")
        for archive in archives:
            if not await asyncio.to_thread(plausible_image_archive, archive.path):
                raise HTTPException(400, f"Archive is not a recognizable Docker or OCI image TAR: {archive.name}")
            stat = archive.path.stat()
            item = ImageArchive(path=str(archive.path.resolve()), name=archive.name, size=stat.st_size,
                                modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc))
            db.add(item)
            db.flush()
            uploaded.append({"id": item.id, "name": item.name})
        db.commit()
        await update_upload_job(job_id, progress=100, stage="completed", status="completed",
                                message=f"{len(uploaded)} archive{'s' if len(uploaded) != 1 else ''} uploaded and ready",
                                image_id=uploaded[0]["id"] if len(uploaded) == 1 else None,
                                image_count=len(uploaded), finished_at=datetime.now(timezone.utc))
    except Exception as exc:
        db.rollback()
        for path in created_paths:
            path.unlink(missing_ok=True)
        detail = exc.detail if isinstance(exc, HTTPException) else exc
        await update_upload_job(job_id, status="failed", stage="failed", message="Upload failed",
                                error=sanitize_untrusted_text(detail) or exc.__class__.__name__,
                                finished_at=datetime.now(timezone.utc))
        raise
    return {"uploaded": uploaded}


@app.get("/api/upload-jobs")
def upload_jobs(status: list[str] = Query(default=[]), limit: int = Query(100, ge=1, le=500),
                db: Session = Depends(get_db)):
    query = select(UploadJob).order_by(desc(UploadJob.id)).limit(limit)
    if status:
        query = (select(UploadJob).where(UploadJob.status.in_([value.casefold() for value in status]))
                 .order_by(desc(UploadJob.id)).limit(limit))
    return [upload_job_payload(job) for job in db.scalars(query).all()]


@app.get("/api/images")
def images(db: Session = Depends(get_db)):
    discover(db)
    rows = db.scalars(select(ImageArchive).where(ImageArchive.hidden.is_(False)).order_by(ImageArchive.name)).all()
    return image_payloads(db, rows)


@app.get("/api/images/removed")
def removed_images(db: Session = Depends(get_db), _user=Depends(require_roles("admin"))):
    rows = db.scalars(select(ImageArchive).where(ImageArchive.hidden.is_(True)).order_by(ImageArchive.name)).all()
    return [{"id": item.id, "name": item.name, "source": archive_source(item.path),
             "removed_at": item.removed_at} for item in rows]


@app.post("/api/images/{image_id}/restore")
def restore_image(image_id: int, request: Request, db: Session = Depends(get_db), actor=Depends(require_roles("admin"))):
    image = db.get(ImageArchive, image_id)
    if not image or not image.hidden:
        raise HTTPException(404, "Removed image not found")
    if not allowed_path(Path(image.path)) or not Path(image.path).is_file():
        raise HTTPException(409, "The mounted archive is no longer available")
    image.hidden = False
    image.removed_at = None
    audit(db, "image_restore", "success", request, actor.id,
          {"image_id": image.id, "source": archive_source(image.path)})
    db.commit()
    return {"id": image.id, "restored": True}


@app.delete("/api/images/{image_id}")
def remove_image(image_id: int, request: Request, db: Session = Depends(get_db), actor=Depends(require_roles("admin"))):
    image = db.get(ImageArchive, image_id)
    if not image or image.hidden:
        raise HTTPException(404, "Image not found")
    result = remove_image_record(db, image)
    audit(db, "image_remove", "success", request, actor.id,
          {"image_id": image_id, "source": result["source"], "scan_count": result["removed_scans"],
           "uploaded_archive_deleted": result["uploaded_archive_deleted"]})
    db.commit()
    return result


@app.post("/api/images/bulk-delete")
def bulk_remove_images(body: BulkImageDeleteRequest, request: Request, db: Session = Depends(get_db),
                       actor=Depends(require_roles("admin"))):
    image_ids = list(dict.fromkeys(body.image_ids))
    images = db.scalars(select(ImageArchive).where(
        ImageArchive.id.in_(image_ids), ImageArchive.hidden.is_(False)).order_by(ImageArchive.id)).all()
    found_ids = {image.id for image in images}
    missing = [image_id for image_id in image_ids if image_id not in found_ids]
    if missing:
        raise HTTPException(404, f"Images not found: {', '.join(map(str, missing))}")
    scans_by_image = {image.id: [] for image in images}
    for scan in db.scalars(select(Scan).where(Scan.image_id.in_(image_ids)).order_by(Scan.image_id, Scan.id)).all():
        scans_by_image[scan.image_id].append(scan)
    active = [image.id for image in images if any(
        scan.status in {"queued", "running"} for scan in scans_by_image[image.id])]
    if active:
        raise HTTPException(409, f"Cancel active scans for images: {', '.join(map(str, active))}")
    results = [remove_image_record(db, image, scans_by_image[image.id]) for image in images]
    audit(db, "image_bulk_remove", "success", request, actor.id,
          {"image_ids": image_ids, "image_count": len(results),
           "removed_scan_count": sum(item["removed_scans"] for item in results),
           "uploaded_archive_count": sum(item["uploaded_archive_deleted"] for item in results)})
    db.commit()
    return {"removed": True, "image_ids": image_ids, "image_count": len(results), "results": results}


@app.get("/api/images/{image_id}/archive")
def download_image_archive(image_id: int, db: Session = Depends(get_db),
                           _user=Depends(require_roles("operator", "admin"))):
    image = db.get(ImageArchive, image_id)
    if not image or image.hidden:
        raise HTTPException(404, "Image not found")
    path = Path(image.path)
    if path.suffix.casefold() != ".tar" or not allowed_path(path) or not path.is_file():
        raise HTTPException(404, "Image archive is unavailable")
    return FileResponse(path, media_type="application/x-tar",
                        filename=safe_download_name(image.name, f"image-{image.id}.tar"))


@app.get("/api/images/{image_id}")
def image_detail(image_id: int, db: Session = Depends(get_db)):
    image = db.get(ImageArchive, image_id)
    if not image or image.hidden:
        raise HTTPException(404, "Image not found")
    history = db.scalars(select(Scan).where(Scan.image_id == image_id).order_by(desc(Scan.id))).all()
    latest = history[0] if history else None
    counts = dict(db.execute(select(Finding.severity, func.count()).where(
        Finding.scan_id == latest.id).group_by(Finding.severity)).all()) if latest else {}
    return {"id": image.id, "name": image.name, "source": archive_source(image.path), "size": image.size,
            "modified_at": image.modified_at, "latest_scan": scan_payload(latest, counts) if latest else None,
            "groups": image_group_refs(db, image_id),
            "history": [{"id": s.id, "status": s.status, "progress": s.progress, "stage": s.stage,
                         "message": s.message, "queued_at": s.queued_at, "started_at": s.started_at,
                         "finished_at": s.finished_at, "error": s.error,
                         "coverage_warning": s.coverage_warning} for s in history]}


@app.post("/api/scans", status_code=202)
async def scans(body: ScanRequest, db: Session = Depends(get_db), _user=Depends(require_roles("operator", "admin"))):
    if not body.image_ids:
        raise HTTPException(400, "Select at least one image")
    result, new_jobs, reused = [], [], []
    unique_ids = list(dict.fromkeys(body.image_ids))
    require_storage_capacity(settings.raw_results_dir)
    async with manager.admission_lock:
        images_by_id = {image.id: image for image in db.scalars(select(ImageArchive).where(
            ImageArchive.id.in_(unique_ids), ImageArchive.hidden.is_(False))).all()}
        for image_id in unique_ids:
            image = images_by_id.get(image_id)
            if not image or not allowed_path(Path(image.path)) or not Path(image.path).is_file():
                raise HTTPException(400, f"Image {image_id} is unavailable or outside configured roots")
        active_rows = db.scalars(select(Scan).where(
            Scan.image_id.in_(unique_ids), Scan.status.in_(["queued", "running"])).order_by(desc(Scan.id))).all()
        existing: dict[int, Scan] = {}
        for active in active_rows:
            existing.setdefault(active.image_id, active)
        additional = len(unique_ids) - len(existing)
        active_count = db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running"]))) or 0
        if active_count + additional > settings.max_pending_scans:
            raise HTTPException(429, f"Scan queue capacity is {settings.max_pending_scans}; cancel work or wait for jobs to finish",
                                headers={"Retry-After": "30"})
        for image_id in unique_ids:
            scan = existing.get(image_id)
            if scan:
                result.append(scan.id); reused.append(scan.id); continue
            scan = Scan(image_id=image_id, progress=0, stage="queued", message="Waiting for an available worker")
            db.add(scan); db.flush(); result.append(scan.id); new_jobs.append(scan.id)
        db.commit()
        for scan_id in new_jobs:
            await manager.enqueue(scan_id)
    return {"scan_ids": result, "reused_scan_ids": reused}


@app.get("/api/jobs")
def jobs(status: list[str] = Query(default=[]), limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    query = select(Scan).options(selectinload(Scan.image)).order_by(desc(Scan.id)).limit(limit)
    if status:
        query = (select(Scan).options(selectinload(Scan.image))
                 .where(Scan.status.in_([value.casefold() for value in status])).order_by(desc(Scan.id)).limit(limit))
    rows = db.scalars(query).all()
    queued = db.scalars(select(Scan.id).where(Scan.status == "queued").order_by(Scan.queued_at, Scan.id)).all()
    positions = {scan_id: index + 1 for index, scan_id in enumerate(queued)}
    return [job_payload(scan, positions.get(scan.id)) for scan in rows]


@app.post("/api/jobs/{scan_id}/cancel")
async def cancel_job(scan_id: int, _user=Depends(require_roles("operator", "admin"))):
    status = await manager.cancel(scan_id)
    if status is None:
        raise HTTPException(404, "Scan job not found")
    if status != "cancelled":
        raise HTTPException(409, f"A {status} job cannot be cancelled")
    return {"scan_id": scan_id, "status": status}


@app.post("/api/jobs/{scan_id}/retry", status_code=202)
async def retry_job(scan_id: int, db: Session = Depends(get_db), _user=Depends(require_roles("operator", "admin"))):
    original = db.get(Scan, scan_id)
    if not original:
        raise HTTPException(404, "Scan job not found")
    if original.status not in {"failed", "cancelled"}:
        raise HTTPException(409, "Only failed or cancelled jobs can be retried")
    if not allowed_path(Path(original.image.path)) or not Path(original.image.path).is_file():
        raise HTTPException(400, "The image archive is unavailable or outside configured roots")
    require_storage_capacity(settings.raw_results_dir)
    async with manager.admission_lock:
        active = db.scalar(select(Scan).where(Scan.image_id == original.image_id, Scan.status.in_(["queued", "running"])).limit(1))
        if active:
            return {"scan_id": active.id, "reused": True}
        active_count = db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running"]))) or 0
        if active_count >= settings.max_pending_scans:
            raise HTTPException(429, "Scan queue is at capacity; cancel work or wait for a job to finish",
                                headers={"Retry-After": "30"})
        replacement = Scan(image_id=original.image_id, progress=0, stage="queued", message=f"Retry of scan #{original.id}")
        db.add(replacement); db.commit(); await manager.enqueue(replacement.id)
    return {"scan_id": replacement.id, "reused": False}


@app.delete("/api/scans/{scan_id}")
def remove_scan(scan_id: int, request: Request, db: Session = Depends(get_db), actor=Depends(require_roles("admin"))):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    image_id = scan.image_id
    raw_result_removed = bool(scan.raw_json_path and not is_imported_scan(scan))
    remove_scan_record(db, scan)
    audit(db, "scan_remove", "success", request, actor.id,
          {"scan_id": scan_id, "image_id": image_id, "raw_result_removed": raw_result_removed})
    db.commit()
    return {"scan_id": scan_id, "image_id": image_id, "removed": True,
            "raw_result_removed": raw_result_removed}


@app.post("/api/scans/bulk-delete")
def bulk_remove_scans(body: BulkScanDeleteRequest, request: Request, db: Session = Depends(get_db),
                      actor=Depends(require_roles("admin"))):
    scan_ids = list(dict.fromkeys(body.scan_ids))
    scans = db.scalars(select(Scan).where(Scan.id.in_(scan_ids)).order_by(Scan.id)).all()
    found_ids = {scan.id for scan in scans}
    missing_ids = [scan_id for scan_id in scan_ids if scan_id not in found_ids]
    if missing_ids:
        raise HTTPException(404, f"Scans not found: {', '.join(map(str, missing_ids))}")
    image_ids = sorted({scan.image_id for scan in scans})
    raw_result_count = sum(bool(scan.raw_json_path and not is_imported_scan(scan)) for scan in scans)
    remove_scan_records(db, scans)
    audit(db, "scan_bulk_remove", "success", request, actor.id,
          {"scan_ids": scan_ids, "image_ids": image_ids, "scan_count": len(scans),
           "raw_result_count": raw_result_count})
    db.commit()
    return {"removed": True, "scan_ids": scan_ids, "scan_count": len(scans),
            "image_ids": image_ids, "raw_result_count": raw_result_count}


@app.get("/api/scans/{scan_id}/findings", response_model=list[FindingOut])
def findings(scan_id: int, severity: list[str] = Query(default=[], max_length=5),
             search: str = Query("", max_length=200),
             package_name: str = Query("", max_length=300), target: str = Query("", max_length=500),
             fix_status: str = Query("", pattern="^(|fixed|unfixed)$"),
             db: Session = Depends(get_db)):
    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity.in_([s.upper() for s in severity]))
    if search.strip():
        term = f"%{search.strip()}%"
        query = query.where(Finding.vulnerability_id.ilike(term) | Finding.package_name.ilike(term) |
                            Finding.title.ilike(term) | Finding.description.ilike(term))
    if package_name.strip():
        query = query.where(Finding.package_name == package_name.strip())
    if target.strip():
        query = query.where(Finding.target == target.strip())
    if fix_status == "fixed":
        query = query.where(Finding.fixed_version != "")
    elif fix_status == "unfixed":
        query = query.where(Finding.fixed_version == "")
    rank = case({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}, value=Finding.severity, else_=4)
    return db.scalars(query.order_by(rank, Finding.package_name, Finding.vulnerability_id)).all()


@app.get("/api/scans/{scan_id}/summary")
def scan_summary(scan_id: int, db: Session = Depends(get_db)):
    """Return compact scan status and severity counts for automation clients."""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    counts = dict(db.execute(
        select(Finding.severity, func.count())
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
    ).all())
    return {"image_id": scan.image_id, **scan_payload(scan, counts)}


@app.get("/api/scans/{scan_id}/finding-filters")
def finding_filters(scan_id: int, db: Session = Depends(get_db)):
    if not db.get(Scan, scan_id):
        raise HTTPException(404, "Scan not found")
    packages = db.scalars(select(Finding.package_name).where(Finding.scan_id == scan_id)
                          .distinct().order_by(Finding.package_name)).all()
    targets = db.scalars(select(Finding.target).where(Finding.scan_id == scan_id)
                         .distinct().order_by(Finding.target)).all()
    return {"packages": [value for value in packages if value],
            "targets": [value for value in targets if value]}


@app.get("/api/scans/{scan_id}/packages")
def packages(scan_id: int, search: str = Query("", max_length=200), db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    package_query = select(Package).where(Package.scan_id == scan_id)
    if search.strip():
        term = f"%{search.strip()}%"
        package_query = package_query.where(Package.name.ilike(term) | Package.version.ilike(term) |
                                            Package.target.ilike(term))
    rows = db.scalars(package_query.order_by(Package.name, Package.version)).all()
    items = [{"name": p.name, "version": p.version, "target": p.target, "identifier": p.identifier, "licenses": p.licenses} for p in rows]
    has_inventory = bool(items)
    if search.strip() and not has_inventory:
        has_inventory = db.scalar(select(Package.id).where(Package.scan_id == scan_id).limit(1)) is not None
    if not has_inventory:
        fallback_query = select(Finding.package_name, Finding.installed_version, Finding.target, func.count()).where(
            Finding.scan_id == scan_id)
        if search.strip():
            term = f"%{search.strip()}%"
            fallback_query = fallback_query.where(Finding.package_name.ilike(term) |
                                                  Finding.installed_version.ilike(term) |
                                                  Finding.target.ilike(term))
        fallback = db.execute(fallback_query.group_by(
            Finding.package_name, Finding.installed_version, Finding.target).order_by(Finding.package_name)).all()
        items = [{"name": r[0], "version": r[1], "target": r[2], "identifier": "", "licenses": "", "vulnerabilities": r[3]} for r in fallback]
    return items


def finding_key(finding: Finding):
    return (finding.vulnerability_id, finding.package_name, finding.installed_version, finding.target)


@app.get("/api/images/{image_id}/compare")
def compare_scans(image_id: int, base_scan_id: int | None = None, target_scan_id: int | None = None, db: Session = Depends(get_db)):
    completed = db.scalars(select(Scan).where(Scan.image_id == image_id, Scan.status == "completed").order_by(desc(Scan.id))).all()
    if target_scan_id is None and completed:
        target_scan_id = completed[0].id
    if base_scan_id is None and len(completed) > 1:
        base_scan_id = completed[1].id
    if not base_scan_id or not target_scan_id:
        raise HTTPException(400, "At least two completed scans are required")
    base = db.get(Scan, base_scan_id); target = db.get(Scan, target_scan_id)
    if not base or not target or base.image_id != image_id or target.image_id != image_id:
        raise HTTPException(400, "Both scans must belong to this image")
    base_rows = {finding_key(f): f for f in db.scalars(select(Finding).where(Finding.scan_id == base.id)).all()}
    target_rows = {finding_key(f): f for f in db.scalars(select(Finding).where(Finding.scan_id == target.id)).all()}
    def serialize(f: Finding):
        return {"vulnerability_id": f.vulnerability_id, "severity": f.severity, "package_name": f.package_name,
                "installed_version": f.installed_version, "fixed_version": f.fixed_version, "target": f.target, "title": f.title}
    new_keys = target_rows.keys() - base_rows.keys(); resolved_keys = base_rows.keys() - target_rows.keys()
    unchanged_keys = target_rows.keys() & base_rows.keys()
    return {"base_scan_id": base.id, "target_scan_id": target.id,
            "summary": {"new": len(new_keys), "resolved": len(resolved_keys), "unchanged": len(unchanged_keys),
                        "net": len(target_rows) - len(base_rows)},
            "new": [serialize(target_rows[k]) for k in sorted(new_keys)],
            "resolved": [serialize(base_rows[k]) for k in sorted(resolved_keys)]}


@app.get("/api/exports")
def export_reports(scan_ids: list[int] | None = Query(None), group_ids: list[int] | None = Query(None),
                   format: str = Query("json", pattern="^(json|html|pdf|elastic|defectdojo)$"),
                   db: Session = Depends(get_db)):
    return build_export_response(scan_ids, group_ids, format, db)


def build_export_response(scan_ids: list[int] | None, group_ids: list[int] | None, format: str,
                          db: Session, logo_png: bytes | None = None):
    if logo_png and format not in {"html", "pdf"}:
        raise HTTPException(422, "Custom branding is supported only for HTML and PDF exports")
    if bool(scan_ids) == bool(group_ids):
        raise HTTPException(422, "Provide either scan_ids or group_ids, but not both")
    selection = None
    group_export = bool(group_ids)
    if group_ids:
        try:
            unique_scan_ids, selection = group_export_selection(db, group_ids)
        except GroupExportError as exc:
            raise HTTPException(exc.status_code, str(exc)) from exc
    else:
        unique_scan_ids = list(dict.fromkeys(scan_ids or []))
        if not unique_scan_ids or len(unique_scan_ids) > 100 or any(scan_id < 1 for scan_id in unique_scan_ids):
            raise HTTPException(422, "Export between 1 and 100 valid scan IDs")
    payload = report_payload(db, unique_scan_ids)
    if selection:
        payload["selection"] = selection
    if not payload["reports"]:
        raise HTTPException(404, "No matching scans found")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    extension = "ndjson" if format == "elastic" else "json" if format == "defectdojo" else format
    label = "elastic" if format == "elastic" else "defectdojo" if format == "defectdojo" else "report"
    prefix = "group-" if group_export else ""
    headers = {"Content-Disposition": f'attachment; filename="layerscope-{prefix}{label}-{stamp}.{extension}"'}
    if format == "html":
        return HTMLResponse(render_html(payload, logo_png), headers=headers)
    if format == "pdf":
        return Response(render_pdf(payload, logo_png), media_type="application/pdf", headers=headers)
    if format == "elastic":
        return Response(render_elastic_bulk(payload), media_type="application/x-ndjson", headers=headers)
    if format == "defectdojo":
        return Response(json.dumps(defectdojo_payload(payload), ensure_ascii=False, indent=2),
                        media_type="application/json; charset=utf-8", headers=headers)
    return Response(json.dumps(payload, default=str, ensure_ascii=False, indent=2), media_type="application/json; charset=utf-8", headers=headers)


async def read_report_logo(request: Request) -> tuple[bytes, str]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if content_type not in {"image/png", "image/jpeg"}:
        raise HTTPException(415, "Report logos must use image/png or image/jpeg")
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            content_length = int(declared)
        except ValueError as exc:
            raise HTTPException(400, "Invalid Content-Length header") from exc
        if content_length < 0:
            raise HTTPException(400, "Invalid Content-Length header")
        if content_length > MAX_REPORT_LOGO_BYTES:
            raise HTTPException(413, f"Report logos are limited to {MAX_REPORT_LOGO_BYTES // (1024 * 1024)} MiB")
    chunks, received = [], 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > MAX_REPORT_LOGO_BYTES:
            raise HTTPException(413, f"Report logos are limited to {MAX_REPORT_LOGO_BYTES // (1024 * 1024)} MiB")
        if chunk:
            chunks.append(chunk)
    return b"".join(chunks), content_type


@app.post("/api/exports/branded")
async def export_branded_reports(request: Request, scan_ids: list[int] | None = Query(None),
                                 group_ids: list[int] | None = Query(None),
                                 format: str = Query(..., pattern="^(html|pdf)$"),
                                 db: Session = Depends(get_db),
                                 actor=Depends(require_roles("viewer", "operator", "admin"))):
    try:
        encoded_logo, content_type = await read_report_logo(request)
        logo_png = sanitize_report_logo(encoded_logo, content_type)
        response = build_export_response(scan_ids, group_ids, format, db, logo_png)
    except ReportLogoError as exc:
        audit(db, "branded_report_export", "denied", request, actor.id,
              {"format": format, "reason": "invalid_logo"})
        db.commit()
        raise HTTPException(400, str(exc)) from exc
    except HTTPException as exc:
        audit(db, "branded_report_export", "denied", request, actor.id,
              {"format": format, "reason": "request_rejected", "status_code": exc.status_code})
        db.commit()
        raise
    audit(db, "branded_report_export", "success", request, actor.id,
          {"format": format, "source_logo_bytes": len(encoded_logo), "sanitized_logo_bytes": len(logo_png),
           "selection": "groups" if group_ids else "scans"})
    db.commit()
    return response


@app.post("/api/reports/import", status_code=201)
async def import_reports(request: Request, db: Session = Depends(get_db), actor=Depends(require_roles("admin"))):
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if content_type not in {"application/json", "text/json"}:
        raise HTTPException(415, "Report imports must use JSON content")
    try:
        content_length = int(request.headers.get("content-length", "0"))
    except ValueError as exc:
        raise HTTPException(400, "Invalid Content-Length header") from exc
    if content_length < 0:
        raise HTTPException(400, "Invalid Content-Length header")
    if content_length > settings.max_report_import_bytes:
        raise HTTPException(413, f"Report exceeds the {settings.max_report_import_bytes} byte import limit")
    chunks, received = [], 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > settings.max_report_import_bytes:
            raise HTTPException(413, f"Report exceeds the {settings.max_report_import_bytes} byte import limit")
        if chunk:
            chunks.append(chunk)
    if not chunks:
        raise HTTPException(400, "The report file is empty")
    require_storage_capacity(settings.raw_results_dir, min(received * 2, settings.max_report_import_bytes * 2))
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, "The report file is not valid UTF-8 JSON") from exc
    try:
        result = import_report_payload(db, payload)
        audit(db, "report_import", "success", request, actor.id, result)
        db.commit()
    except ReportImportError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    return result


@app.get("/api/scans/{scan_id}/raw")
def raw_result(scan_id: int, db: Session = Depends(get_db), _user=Depends(require_roles("admin"))):
    scan = db.get(Scan, scan_id)
    if not scan or not scan.raw_json_path or not Path(scan.raw_json_path).is_file():
        raise HTTPException(404, "Raw result not available")
    path = Path(scan.raw_json_path)
    if settings.raw_results_dir.resolve() not in path.resolve().parents:
        raise HTTPException(403, "Invalid raw result path")
    return FileResponse(path, media_type="application/json",
                        filename=safe_download_name(path.name, f"scan-{scan_id}.json"))


@app.get("/api/events")
async def events():
    if len(manager.subscribers) >= settings.max_sse_clients:
        manager.rejected_sse_clients += 1
        raise HTTPException(503, "Live-event connection capacity reached; polling remains available",
                            headers={"Retry-After": "10"})
    queue: asyncio.Queue = asyncio.Queue(maxsize=settings.sse_queue_size)
    manager.subscribers.add(queue)
    async def stream():
        try:
            yield "retry: 3000\nevent: connected\ndata: {}\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {event_json(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            manager.subscribers.discard(queue)
    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache, no-store", "X-Accel-Buffering": "no"})


@app.get("/api/overview")
def overview(db: Session = Depends(get_db)):
    image_count = db.scalar(select(func.count()).select_from(ImageArchive).where(ImageArchive.hidden.is_(False))) or 0
    latest = (select(Scan.image_id, func.max(Scan.id).label("scan_id"))
              .join(ImageArchive, ImageArchive.id == Scan.image_id)
              .where(ImageArchive.hidden.is_(False)).group_by(Scan.image_id).subquery())
    latest_ids = list(db.scalars(select(latest.c.scan_id)).all())
    severity = dict(db.execute(select(Finding.severity, func.count()).where(Finding.scan_id.in_(latest_ids)).group_by(Finding.severity)).all()) if latest_ids else {}
    vulnerable = []
    if latest_ids:
        vulnerable = [{"image_id": row[0], "name": row[1], "total": row[2]} for row in db.execute(
            select(ImageArchive.id, ImageArchive.name, func.count(Finding.id))
            .select_from(ImageArchive)
            .join(Scan, Scan.image_id == ImageArchive.id)
            .join(Finding, Finding.scan_id == Scan.id)
            .where(Scan.id.in_(latest_ids)).group_by(ImageArchive.id).order_by(desc(func.count(Finding.id))).limit(8)).all()]
        packages = [{"name": row[0], "total": row[1], "critical": row[2]} for row in db.execute(
            select(Finding.package_name, func.count(), func.sum(case((Finding.severity == "CRITICAL", 1), else_=0)))
            .where(Finding.scan_id.in_(latest_ids)).group_by(Finding.package_name).order_by(desc(func.count())).limit(8)).all()]
    else:
        packages = []
    statuses = dict(db.execute(select(Scan.status, func.count()).group_by(Scan.status)).all())
    return {"image_count": image_count, "scanned_count": len(latest_ids), "severity": severity,
            "total_findings": sum(severity.values()), "most_vulnerable": vulnerable, "risk_packages": packages, "statuses": statuses}
