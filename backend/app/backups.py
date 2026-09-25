import asyncio
import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import tempfile
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from starlette.background import BackgroundTask

from .auth import audit, auth_key, clear_session_cookie, require_roles
from .config import settings
from .database import SessionLocal, engine
from .locks import database_access
from .models import MaintenanceJob, Scan
from .qos import require_storage_capacity


router = APIRouter(prefix="/api/backups", tags=["backups"])
MAGIC = b"TRIVYDBBACKUP\x00\x01"
TAG_SIZE = 16
FORMAT_VERSION = 1
APP_VERSION = "1.0.0"
TOKEN_PATTERN = re.compile(r"^[a-f0-9]{32}$")
CHUNK_SIZE = 1024 * 1024
REQUIRED_TABLES = {"users", "images", "scans", "findings", "packages"}


class BackupError(ValueError):
    pass


class BackupPassword(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=12, max_length=256)


class RestoreConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: str = Field(min_length=1, max_length=64)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def stored_bytes(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    if path.is_dir():
        return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
    return 0


def sqlite_database_path() -> Path:
    url = make_url(settings.database_url)
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        raise BackupError("Backup and restore currently require a file-backed SQLite database")
    return Path(url.database).resolve()


def derive_key(password: str, salt: bytes) -> bytes:
    if len(password) < 12 or len(password) > 256:
        raise BackupError("Backup password must be between 12 and 256 characters")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def file_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def add_zip_file(archive: zipfile.ZipFile, source: Path, name: str, compress_type: int) -> dict:
    digest = hashlib.sha256()
    size = 0
    info = zipfile.ZipInfo(name, datetime.now().timetuple()[:6])
    info.compress_type = compress_type
    info.external_attr = 0o600 << 16
    with source.open("rb") as input_stream, archive.open(info, "w") as output_stream:
        while chunk := input_stream.read(CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
            output_stream.write(chunk)
    return {"sha256": digest.hexdigest(), "size": size}


def snapshot_database(source: Path, destination: Path):
    source.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as current, sqlite3.connect(destination) as snapshot:
        current.backup(snapshot)
        result = snapshot.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            raise BackupError("SQLite could not create a valid backup snapshot")


def database_summary(path: Path) -> dict:
    with sqlite3.connect(path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        def count(table: str) -> int:
            return connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] if table in tables else 0
        return {"users": count("users"), "images": count("images"), "scans": count("scans"),
                "findings": count("findings"), "groups": count("image_groups")}


def stored_files(root: Path, prefix: str):
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() and not path.name.endswith(".part"):
            yield path, f"{prefix}/{path.relative_to(root).as_posix()}"


def create_encrypted_backup(output_path: Path, password: str, database_path: Path, auth_path: Path,
                            raw_dir: Path, upload_dir: Path) -> dict:
    salt, nonce = os.urandom(16), os.urandom(12)
    key = derive_key(password, salt)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="backup-build-", dir=output_path.parent) as temporary_name:
        temporary = Path(temporary_name)
        database_snapshot = temporary / "database.sqlite"
        plain_archive = temporary / "payload.zip"
        snapshot_database(database_path, database_snapshot)
        if not auth_path.is_file():
            raise BackupError("The local authentication key is missing")

        files: dict[str, dict] = {}
        with zipfile.ZipFile(plain_archive, "w", allowZip64=True) as archive:
            files["database.sqlite"] = add_zip_file(archive, database_snapshot, "database.sqlite", zipfile.ZIP_DEFLATED)
            files["auth.key"] = add_zip_file(archive, auth_path, "auth.key", zipfile.ZIP_DEFLATED)
            for source, name in stored_files(raw_dir, "raw") or []:
                files[name] = add_zip_file(archive, source, name, zipfile.ZIP_DEFLATED)
            for source, name in stored_files(upload_dir, "uploads") or []:
                files[name] = add_zip_file(archive, source, name, zipfile.ZIP_STORED)
            summary = database_summary(database_snapshot)
            summary.update({"raw_results": sum(name.startswith("raw/") for name in files),
                            "uploaded_archives": sum(name.startswith("uploads/") for name in files),
                            "payload_bytes": sum(item["size"] for item in files.values())})
            manifest = {"format": "trivy-dashboard-backup", "format_version": FORMAT_VERSION,
                        "app_version": APP_VERSION, "created_at": utcnow().isoformat(),
                        "summary": summary, "files": files,
                        "excluded": ["Trivy vulnerability database cache", "Java database cache"]}
            archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2))

        header = {"format": "trivy-dashboard-encrypted-backup", "format_version": FORMAT_VERSION,
                  "app_version": APP_VERSION, "created_at": manifest["created_at"], "kdf": "scrypt",
                  "cipher": "AES-256-GCM", "salt": base64.b64encode(salt).decode("ascii"),
                  "nonce": base64.b64encode(nonce).decode("ascii")}
        header_bytes = json.dumps(header, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        prefix = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(prefix)
        with plain_archive.open("rb") as source, output_path.open("xb") as destination:
            destination.write(prefix)
            while chunk := source.read(CHUNK_SIZE):
                destination.write(encryptor.update(chunk))
            destination.write(encryptor.finalize())
            destination.write(encryptor.tag)
        os.chmod(output_path, 0o600)
        return manifest


def decrypt_backup(source_path: Path, password: str, destination_zip: Path):
    total_size = source_path.stat().st_size
    with source_path.open("rb") as source:
        magic = source.read(len(MAGIC))
        if magic != MAGIC:
            raise BackupError("This is not a LayerScope encrypted backup")
        length_bytes = source.read(4)
        if len(length_bytes) != 4:
            raise BackupError("Backup header is incomplete")
        header_length = struct.unpack(">I", length_bytes)[0]
        if header_length < 50 or header_length > 16_384:
            raise BackupError("Backup header length is invalid")
        header_bytes = source.read(header_length)
        try:
            header = json.loads(header_bytes.decode("utf-8"))
            salt = base64.b64decode(header["salt"], validate=True)
            nonce = base64.b64decode(header["nonce"], validate=True)
        except (KeyError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BackupError("Backup header is invalid") from exc
        if header.get("format") != "trivy-dashboard-encrypted-backup" or header.get("format_version") != FORMAT_VERSION:
            raise BackupError("Backup format is not supported by this application version")
        ciphertext_length = total_size - len(MAGIC) - 4 - header_length - TAG_SIZE
        if ciphertext_length <= 0:
            raise BackupError("Backup payload is missing")
        source.seek(total_size - TAG_SIZE)
        tag = source.read(TAG_SIZE)
        source.seek(len(MAGIC) + 4 + header_length)
        prefix = MAGIC + length_bytes + header_bytes
        key = derive_key(password, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(prefix)
        remaining = ciphertext_length
        try:
            with destination_zip.open("xb") as destination:
                while remaining:
                    chunk = source.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise BackupError("Backup payload is incomplete")
                    remaining -= len(chunk)
                    destination.write(decryptor.update(chunk))
                destination.write(decryptor.finalize())
        except InvalidTag as exc:
            destination_zip.unlink(missing_ok=True)
            raise BackupError("The backup password is wrong or the file has been modified") from exc


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or not path.parts:
        return False
    return name in {"database.sqlite", "auth.key", "manifest.json"} or path.parts[0] in {"raw", "uploads"}


def validate_sqlite(path: Path):
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA query_only=ON")
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            executable_schema = connection.execute(
                "SELECT type, name FROM sqlite_master WHERE type IN ('trigger', 'view')"
            ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise BackupError("The backup does not contain a valid SQLite database") from exc
    if executable_schema:
        raise BackupError("The backup database contains unsupported executable schema objects")
    if not integrity or integrity[0] != "ok" or not REQUIRED_TABLES.issubset(tables):
        raise BackupError("The backup database failed integrity or schema validation")


def validate_stage(stage: Path) -> dict:
    try:
        manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError("Backup manifest is missing or invalid") from exc
    if manifest.get("format") != "trivy-dashboard-backup" or manifest.get("format_version") != FORMAT_VERSION:
        raise BackupError("Backup manifest version is not supported")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise BackupError("Backup manifest does not list its files")
    actual_files = {path.relative_to(stage).as_posix() for path in stage.rglob("*")
                    if path.is_file() and path.name != "READY"}
    if actual_files != set(files) | {"manifest.json"}:
        raise BackupError("Backup contents do not match the signed manifest")
    for name, expected in files.items():
        if not safe_member(name) or name == "manifest.json" or not isinstance(expected, dict):
            raise BackupError("Backup manifest contains an unsafe file entry")
        path = stage.joinpath(*PurePosixPath(name).parts)
        if not path.is_file() or path.is_symlink():
            raise BackupError(f"Backup file is missing: {name}")
        digest, size = file_digest(path)
        if digest != expected.get("sha256") or size != expected.get("size"):
            raise BackupError(f"Backup integrity check failed: {name}")
    validate_sqlite(stage / "database.sqlite")
    try:
        Fernet((stage / "auth.key").read_bytes().strip())
    except Exception as exc:
        raise BackupError("Backup authentication key is invalid") from exc
    return manifest


def stage_encrypted_backup(source_path: Path, password: str, stage: Path, max_uncompressed_bytes: int) -> dict:
    stage.mkdir(parents=True, mode=0o700)
    plain_zip = stage / ".payload.zip"
    try:
        decrypt_backup(source_path, password, plain_zip)
        with zipfile.ZipFile(plain_zip) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if len(names) != len(set(names)) or len(names) > 100_000:
                raise BackupError("Backup has duplicate or excessive file entries")
            total = sum(member.file_size for member in members)
            if total > max_uncompressed_bytes:
                raise BackupError("Backup expands beyond the configured size limit")
            extracted = 0
            for member in members:
                mode = member.external_attr >> 16
                if not safe_member(member.filename) or (mode & 0o170000) == 0o120000:
                    raise BackupError(f"Backup contains an unsafe entry: {member.filename}")
                destination = stage.joinpath(*PurePosixPath(member.filename).parts)
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(destination.parent, 0o700)
                with archive.open(member) as source, destination.open("xb") as output:
                    written = 0
                    while chunk := source.read(CHUNK_SIZE):
                        written += len(chunk)
                        extracted += len(chunk)
                        if written > member.file_size or extracted > max_uncompressed_bytes:
                            raise BackupError("Backup expands beyond the configured size limit")
                        if extracted % (64 * CHUNK_SIZE) < CHUNK_SIZE:
                            require_storage_capacity(stage)
                        output.write(chunk)
                    if written != member.file_size:
                        raise BackupError("Backup entry size does not match its metadata")
                os.chmod(destination, 0o600)
        plain_zip.unlink(missing_ok=True)
        return validate_stage(stage)
    except (zipfile.BadZipFile, OSError) as exc:
        raise BackupError("Backup payload is invalid or could not be extracted") from exc
    finally:
        plain_zip.unlink(missing_ok=True)


def cleanup_path(path: Path):
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)


def cleanup_paths(*paths: Path):
    for path in paths:
        cleanup_path(path)


def cleanup_stale_backups():
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    cutoff = utcnow().timestamp() - 24 * 60 * 60
    for path in settings.backup_dir.iterdir():
        if path.name.startswith(("export-", "incoming-", "restore-")) and path.stat().st_mtime < cutoff:
            cleanup_path(path)


def stage_path(token: str) -> Path:
    if not TOKEN_PATTERN.fullmatch(token):
        raise HTTPException(404, "Staged backup not found")
    path = (settings.backup_dir / f"restore-{token}").resolve()
    root = settings.backup_dir.resolve()
    if path.parent != root:
        raise HTTPException(404, "Staged backup not found")
    return path


def active_work() -> bool:
    with SessionLocal() as db:
        scans = db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(["queued", "running"]))) or 0
        maintenance = db.scalar(select(func.count()).select_from(MaintenanceJob)
                                .where(MaintenanceJob.status.in_(["queued", "running"]))) or 0
        return scans > 0 or maintenance > 0


async def restart_process():
    await asyncio.sleep(1.5)
    os._exit(0)


def replace_with_restore(stage: Path):
    manifest = validate_stage(stage)
    database_path = sqlite_database_path()
    rollback = settings.backup_dir / f"rollback-{uuid.uuid4().hex}"
    rollback.mkdir(parents=True, mode=0o700)
    destinations = [(database_path, stage / "database.sqlite", "database.sqlite"),
                    (settings.auth_key_path, stage / "auth.key", "auth.key"),
                    (settings.raw_results_dir, stage / "raw", "raw"),
                    (settings.upload_dir, stage / "uploads", "uploads")]
    moved: list[tuple[Path, Path]] = []
    installed: list[tuple[Path, Path]] = []
    try:
        engine.dispose()
        for suffix in ("-wal", "-shm"):
            Path(str(database_path) + suffix).unlink(missing_ok=True)
        for destination, source, name in destinations:
            destination.parent.mkdir(parents=True, exist_ok=True)
            previous = rollback / name
            if destination.exists():
                os.replace(destination, previous)
                moved.append((previous, destination))
            if source.exists():
                os.replace(source, destination)
                installed.append((destination, source))
            elif name in {"raw", "uploads"}:
                destination.mkdir(parents=True, exist_ok=True)
                installed.append((destination, source))
        validate_sqlite(database_path)
        with sqlite3.connect(database_path) as connection:
            connection.execute("DELETE FROM auth_sessions")
            has_api_tokens = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'api_tokens'").fetchone()
            if has_api_tokens:
                connection.execute("UPDATE api_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE revoked_at IS NULL")
            connection.commit()
        completion = {"restored_at": utcnow().isoformat(), "backup_created_at": manifest.get("created_at"),
                      "app_version": manifest.get("app_version"), "summary": manifest.get("summary", {})}
        (settings.backup_dir / "last-restore.json").write_text(json.dumps(completion, indent=2), encoding="utf-8")
    except Exception:
        for destination, _source in reversed(installed):
            cleanup_path(destination)
        for previous, destination in reversed(moved):
            if previous.exists():
                os.replace(previous, destination)
        raise
    finally:
        cleanup_path(rollback)
        cleanup_path(stage)


def apply_pending_restore():
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    ready = sorted((path for path in settings.backup_dir.glob("restore-*")
                    if path.is_dir() and (path / "READY").is_file()), key=lambda path: path.stat().st_mtime, reverse=True)
    if ready:
        replace_with_restore(ready[0])
    cleanup_stale_backups()


@router.post("/export", status_code=201)
async def export_backup(body: BackupPassword, request: Request, actor=Depends(require_roles("admin"))):
    password = body.password
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    auth_key()
    cleanup_stale_backups()
    filename = f"layerscope-{utcnow().strftime('%Y%m%d-%H%M%S')}.tdbackup"
    token = uuid.uuid4().hex
    destination = settings.backup_dir / f"export-{token}.tdbackup"
    estimated_payload = sum(stored_bytes(path) for path in (
        sqlite_database_path(), settings.auth_key_path, settings.raw_results_dir, settings.upload_dir,
    ))
    require_storage_capacity(settings.backup_dir, estimated_payload * 2)
    await database_access.acquire_write()
    try:
        with SessionLocal() as db:
            audit(db, "backup_export", "started", request, actor.id, {"filename": filename})
            db.commit()
        manifest = await asyncio.to_thread(create_encrypted_backup, destination, password, sqlite_database_path(),
                                           settings.auth_key_path, settings.raw_results_dir, settings.upload_dir)
    except BackupError as exc:
        cleanup_path(destination)
        raise HTTPException(400, str(exc)) from exc
    finally:
        await database_access.release_write()
    expires_at = utcnow() + timedelta(hours=1)
    ticket = {"token": token, "filename": filename, "actor_id": actor.id,
              "expires_at": expires_at.isoformat(), "summary": manifest["summary"],
              "size": destination.stat().st_size}
    ticket_path = settings.backup_dir / f"export-{token}.json"
    ticket_path.write_text(json.dumps(ticket), encoding="utf-8")
    os.chmod(ticket_path, 0o600)
    return ticket


@router.get("/download/{token}")
def download_backup(token: str, actor=Depends(require_roles("admin"))):
    if not TOKEN_PATTERN.fullmatch(token):
        raise HTTPException(404, "Backup download not found")
    destination = settings.backup_dir / f"export-{token}.tdbackup"
    ticket_path = settings.backup_dir / f"export-{token}.json"
    try:
        ticket = json.loads(ticket_path.read_text(encoding="utf-8"))
        expires_at = datetime.fromisoformat(ticket["expires_at"])
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(404, "Backup download not found") from exc
    if ticket.get("actor_id") != actor.id or expires_at <= utcnow() or not destination.is_file():
        cleanup_paths(destination, ticket_path)
        raise HTTPException(404, "Backup download expired or is unavailable")
    return FileResponse(destination, media_type="application/octet-stream", filename=ticket["filename"],
                        background=BackgroundTask(cleanup_paths, destination, ticket_path))


@router.post("/import", status_code=201)
async def import_backup(request: Request, file: UploadFile = File(...), password: str = Form(...),
                        actor=Depends(require_roles("admin"))):
    safe_name = Path(file.filename or "").name
    if not safe_name.lower().endswith(".tdbackup"):
        raise HTTPException(400, "Select a .tdbackup file created by LayerScope")
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    cleanup_stale_backups()
    token = uuid.uuid4().hex
    stage = stage_path(token)
    encrypted = settings.backup_dir / f"incoming-{token}.tdbackup"
    received = 0
    checked_at = 0
    try:
        with encrypted.open("xb") as output:
            while chunk := await file.read(CHUNK_SIZE):
                received += len(chunk)
                if received > settings.max_backup_bytes:
                    raise HTTPException(413, "Backup exceeds the configured size limit")
                if received - checked_at >= 64 * 1024 * 1024:
                    require_storage_capacity(settings.backup_dir)
                    checked_at = received
                output.write(chunk)
        os.chmod(encrypted, 0o600)
        require_storage_capacity(settings.backup_dir, received)
        manifest = await asyncio.to_thread(stage_encrypted_backup, encrypted, password, stage, settings.max_backup_bytes)
    except BackupError as exc:
        cleanup_path(stage)
        raise HTTPException(400, str(exc)) from exc
    finally:
        await file.close()
        cleanup_path(encrypted)
    with SessionLocal() as db:
        audit(db, "backup_import", "validated", request, actor.id,
              {"token": token, "created_at": manifest.get("created_at"), "summary": manifest.get("summary", {})})
        db.commit()
    return {"token": token, "created_at": manifest.get("created_at"), "app_version": manifest.get("app_version"),
            "summary": manifest.get("summary", {}), "excluded": manifest.get("excluded", [])}


@router.delete("/{token}")
def cancel_import(token: str, request: Request, actor=Depends(require_roles("admin"))):
    stage = stage_path(token)
    if not stage.is_dir() or (stage / "READY").exists():
        raise HTTPException(404, "Staged backup not found")
    cleanup_path(stage)
    with SessionLocal() as db:
        audit(db, "backup_import", "cancelled", request, actor.id, {"token": token})
        db.commit()
    return {"cancelled": True}


@router.post("/{token}/restore", status_code=202)
def restore_backup(token: str, body: RestoreConfirmation, request: Request, background: BackgroundTasks,
                   actor=Depends(require_roles("admin"))):
    if body.confirmation != "RESTORE BACKUP":
        raise HTTPException(400, "Type RESTORE BACKUP exactly to confirm")
    stage = stage_path(token)
    if not stage.is_dir() or (stage / "READY").exists():
        raise HTTPException(404, "Staged backup not found")
    if active_work():
        raise HTTPException(409, "Cancel or wait for all scan and component jobs before restoring a backup")
    validate_stage(stage)
    with SessionLocal() as db:
        audit(db, "backup_restore", "scheduled", request, actor.id, {"token": token})
        db.commit()
    (stage / "READY").write_text(utcnow().isoformat(), encoding="ascii")
    background.add_task(restart_process)
    response = JSONResponse({"status": "restarting", "message": "Backup validated; the application is restarting"}, status_code=202)
    clear_session_cookie(response)
    return response
