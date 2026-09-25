import asyncio
import json
from datetime import datetime, timezone
import io
import tarfile
from collections import namedtuple
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.config import settings
from app.database import engine
from app.qos import QualityOfServiceMiddleware, require_storage_capacity, storage_capacity
from app.scanner import ScanManager
from app.main import event_json, plausible_image_archive


DiskUsage = namedtuple("DiskUsage", "total used free")


def test_storage_reserve_reports_warning_and_rejects_critical(monkeypatch, tmp_path):
    original = settings.storage_reserve_bytes
    settings.storage_reserve_bytes = 100
    try:
        monkeypatch.setattr("app.qos.shutil.disk_usage", lambda _path: DiskUsage(1000, 850, 150))
        assert storage_capacity(tmp_path)["status"] == "warning"
        monkeypatch.setattr("app.qos.shutil.disk_usage", lambda _path: DiskUsage(1000, 950, 50))
        with pytest.raises(HTTPException) as error:
            require_storage_capacity(tmp_path)
        assert error.value.status_code == 507
        assert error.value.headers["Retry-After"] == "60"
    finally:
        settings.storage_reserve_bytes = original


def test_storage_capacity_uses_smaller_host_probe_free_space(monkeypatch, tmp_path):
    data_path = tmp_path / "data"
    probe_path = tmp_path / "probe"
    data_path.mkdir(); probe_path.mkdir()
    monkeypatch.setattr(settings, "host_storage_probe_dir", probe_path)
    monkeypatch.setattr(settings, "storage_reserve_bytes", 100)
    monkeypatch.setattr("app.qos.shutil.disk_usage", lambda path: (
        DiskUsage(1000, 100, 900) if Path(path) == data_path else DiskUsage(500, 420, 80)
    ))

    capacity = storage_capacity(data_path)

    assert capacity["free_bytes"] == 80
    assert capacity["container_volume_free_bytes"] == 900
    assert capacity["host_probe_free_bytes"] == 80
    assert capacity["limiting_source"] == "host_probe"
    assert capacity["status"] == "critical"


def test_auth_qos_rate_limit_returns_retry_after():
    original_attempts = settings.auth_rate_limit_attempts
    original_window = settings.auth_rate_limit_window_seconds
    settings.auth_rate_limit_attempts = 2
    settings.auth_rate_limit_window_seconds = 60
    app = FastAPI()
    app.add_middleware(QualityOfServiceMiddleware)

    @app.post("/api/auth/login")
    def login():
        return {"ok": True}

    try:
        with TestClient(app) as client:
            assert client.post("/api/auth/login").status_code == 200
            assert client.post("/api/auth/login").status_code == 200
            limited = client.post("/api/auth/login")
            assert limited.status_code == 429
            assert int(limited.headers["Retry-After"]) > 0
            assert limited.headers["X-Request-ID"]
    finally:
        settings.auth_rate_limit_attempts = original_attempts
        settings.auth_rate_limit_window_seconds = original_window


def test_sqlite_connection_uses_concurrency_pragmas():
    with engine.connect() as connection:
        assert str(connection.exec_driver_sql("PRAGMA journal_mode").scalar()).casefold() == "wal"
        assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar() >= 15000
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


def test_slow_subscriber_drops_are_counted():
    manager = ScanManager()
    subscriber = asyncio.Queue(maxsize=1)
    subscriber.put_nowait({"old": True})
    manager.subscribers.add(subscriber)
    asyncio.run(manager.publish({"new": True}))
    assert manager.dropped_events == 1


def test_sse_events_encode_database_timestamps_as_json():
    timestamp = datetime(2026, 8, 23, 9, 30, tzinfo=timezone.utc)

    payload = json.loads(event_json({"type": "upload_job", "job": {"updated_at": timestamp}}))

    assert payload == {"type": "upload_job", "job": {"updated_at": "2026-08-23T09:30:00+00:00"}}


def test_uploaded_archive_plausibility_requires_docker_or_oci_metadata(tmp_path):
    valid = tmp_path / "valid.tar"
    with tarfile.open(valid, "w") as archive:
        payload = b"[]"
        info = tarfile.TarInfo("manifest.json")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    invalid = tmp_path / "invalid.tar"
    invalid.write_bytes(b"not a tar archive")
    assert plausible_image_archive(valid)
    assert not plausible_image_archive(invalid)
