import asyncio
import io
import tarfile

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from app.config import settings
from app.database import Base
from app.main import upload_jobs
from app.models import UploadJob
from app.uploads import stream_archive_uploads


def docker_tar_bytes() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        payload = b"[]"
        info = tarfile.TarInfo("manifest.json")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def multipart_body(boundary: str, files: list[tuple[str, bytes]]) -> bytes:
    parts = []
    for filename, payload in files:
        parts.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="files"; filename="{filename}"\r\n'.encode(),
            b"Content-Type: application/x-tar\r\n\r\n",
            payload,
            b"\r\n",
        ])
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts)


def streaming_request(body: bytes, boundary: str, chunk_size: int = 1024) -> Request:
    offset = 0

    async def receive():
        nonlocal offset
        chunk = body[offset:offset + chunk_size]
        offset += len(chunk)
        return {"type": "http.request", "body": chunk, "more_body": offset < len(body)}

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/uploads",
        "raw_path": b"/api/uploads",
        "query_string": b"",
        "headers": [
            (b"content-type", f"multipart/form-data; boundary={boundary}".encode()),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope, receive)


def configure_uploads(monkeypatch, tmp_path, *, per_file=1024 * 1024, request_limit=2 * 1024 * 1024):
    upload_dir = tmp_path / "uploads"
    monkeypatch.setattr(settings, "upload_dir", upload_dir)
    monkeypatch.setattr(settings, "max_upload_bytes", per_file)
    monkeypatch.setattr(settings, "max_upload_request_bytes", request_limit)
    monkeypatch.setattr(settings, "max_upload_files", 3)
    monkeypatch.setattr(settings, "storage_reserve_bytes", 0)
    return upload_dir


def test_streams_multiple_archives_directly_to_managed_storage(monkeypatch, tmp_path):
    upload_dir = configure_uploads(monkeypatch, tmp_path)
    archive = docker_tar_bytes()
    boundary = "streaming-upload-boundary"
    body = multipart_body(boundary, [("first.tar", archive), ("nested\\second.tar", archive)])

    uploaded = asyncio.run(stream_archive_uploads(streaming_request(body, boundary, chunk_size=257)))

    assert [item.name for item in uploaded] == ["first.tar", "second.tar"]
    assert all(item.path.parent == upload_dir for item in uploaded)
    assert all(item.path.read_bytes() == archive for item in uploaded)
    assert not list(upload_dir.glob("*.part"))


def test_stream_reports_server_side_progress_and_sanitized_archive_name(monkeypatch, tmp_path):
    configure_uploads(monkeypatch, tmp_path)
    archive = docker_tar_bytes()
    boundary = "progress-upload-boundary"
    body = multipart_body(boundary, [("nested\\progress.tar", archive)])
    progress_events = []

    async def capture_progress(received, total, archive_name):
        progress_events.append((received, total, archive_name))

    uploaded = asyncio.run(stream_archive_uploads(
        streaming_request(body, boundary, chunk_size=193), capture_progress,
    ))

    assert uploaded[0].name == "progress.tar"
    assert progress_events
    assert progress_events[-1][0] == len(body)
    assert progress_events[-1][1] == len(body)
    assert any(event[2] == "progress.tar" for event in progress_events)


def test_upload_job_history_filters_status_and_orders_newest_first():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add_all([
        UploadJob(archive_name="completed.tar", status="completed", progress=100),
        UploadJob(archive_name="active.tar", status="running", progress=40),
    ])
    session.commit()

    result = upload_jobs(status=["running"], limit=100, db=session)

    assert len(result) == 1
    assert result[0]["archive_name"] == "active.tar"
    assert result[0]["status"] == "running"
    assert result[0]["progress"] == 40


def test_oversized_stream_is_rejected_and_partial_files_are_removed(monkeypatch, tmp_path):
    upload_dir = configure_uploads(monkeypatch, tmp_path, per_file=512, request_limit=4096)
    boundary = "oversized-upload-boundary"
    body = multipart_body(boundary, [("too-large.tar", b"x" * 1024)])

    with pytest.raises(HTTPException) as error:
        asyncio.run(stream_archive_uploads(streaming_request(body, boundary, chunk_size=73)))

    assert error.value.status_code == 413
    assert list(upload_dir.iterdir()) == []


def test_truncated_multipart_is_rejected_and_partial_files_are_removed(monkeypatch, tmp_path):
    upload_dir = configure_uploads(monkeypatch, tmp_path)
    boundary = "truncated-upload-boundary"
    complete = multipart_body(boundary, [("incomplete.tar", docker_tar_bytes())])
    body = complete[:complete.rfind(f"--{boundary}--".encode())]

    with pytest.raises(HTTPException) as error:
        asyncio.run(stream_archive_uploads(streaming_request(body, boundary, chunk_size=211)))

    assert error.value.status_code == 400
    assert list(upload_dir.iterdir()) == []
