import asyncio
import errno
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, BinaryIO, Callable

from fastapi import HTTPException, Request
from python_multipart.exceptions import MultipartParseError
from python_multipart.multipart import MultipartParser, parse_options_header

from .config import settings
from .qos import require_storage_capacity


@dataclass(frozen=True)
class StreamedArchive:
    path: Path
    name: str
    size: int


@dataclass
class _ArchivePart:
    path: Path
    temporary: Path
    output: BinaryIO
    size: int = 0


@dataclass
class _MultipartPart:
    header_name: bytearray
    header_value: bytearray
    content_disposition: bytes = b""
    archive: _ArchivePart | None = None


def _decode_header(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin-1")


class _ArchiveMultipartWriter:
    """Bounded multipart callbacks that write file data directly to persistent storage."""

    def __init__(self, upload_dir: Path):
        self.upload_dir = upload_dir
        self.current: _MultipartPart | None = None
        self.file_count = 0
        self.file_bytes = 0
        self.body_bytes = 0
        self.checked_at = 0
        self.ended = False
        self.reserved: set[Path] = set()
        self.open_archives: list[_ArchivePart] = []
        self.completed: list[StreamedArchive] = []
        self.pending_writes: list[tuple[_ArchivePart, bytes]] = []
        self.pending_finished: list[_ArchivePart] = []

    def callbacks(self):
        return {
            "on_part_begin": self.on_part_begin,
            "on_part_data": self.on_part_data,
            "on_part_end": self.on_part_end,
            "on_header_field": self.on_header_field,
            "on_header_value": self.on_header_value,
            "on_header_end": self.on_header_end,
            "on_headers_finished": self.on_headers_finished,
            "on_end": self.on_end,
        }

    def on_part_begin(self):
        self.current = _MultipartPart(bytearray(), bytearray())

    def on_header_field(self, data: bytes, start: int, end: int):
        if self.current is None:
            raise HTTPException(400, "Malformed multipart upload")
        self.current.header_name.extend(data[start:end])

    def on_header_value(self, data: bytes, start: int, end: int):
        if self.current is None:
            raise HTTPException(400, "Malformed multipart upload")
        self.current.header_value.extend(data[start:end])

    def on_header_end(self):
        if self.current is None:
            raise HTTPException(400, "Malformed multipart upload")
        if bytes(self.current.header_name).lower() == b"content-disposition":
            self.current.content_disposition = bytes(self.current.header_value)
        self.current.header_name.clear()
        self.current.header_value.clear()

    def on_headers_finished(self):
        if self.current is None:
            raise HTTPException(400, "Malformed multipart upload")
        disposition, options = parse_options_header(self.current.content_disposition)
        if disposition != b"form-data" or options.get(b"name") != b"files" or b"filename" not in options:
            raise HTTPException(400, "The upload must contain only file fields named 'files'")
        self.file_count += 1
        if self.file_count > settings.max_upload_files:
            raise HTTPException(413, f"Upload between 1 and {settings.max_upload_files} archives at a time")

        supplied_name = _decode_header(options[b"filename"]).replace("\\", "/")
        safe_name = Path(supplied_name).name.strip()
        if not safe_name or safe_name in {".", ".."} or not safe_name.lower().endswith(".tar"):
            raise HTTPException(400, "Only named .tar archives are accepted")
        if len(safe_name.encode("utf-8")) > 240:
            raise HTTPException(400, "Archive filename is too long")

        destination = self.upload_dir / safe_name
        while destination.exists() or destination in self.reserved:
            destination = self.upload_dir / f"{Path(safe_name).stem}-{uuid.uuid4().hex[:8]}.tar"
        self.reserved.add(destination)
        temporary = self.upload_dir / f".{destination.name}.{uuid.uuid4().hex}.part"
        try:
            output = temporary.open("xb")
        except OSError as exc:
            self._raise_storage_error(exc)
        archive = _ArchivePart(destination, temporary, output)
        self.open_archives.append(archive)
        self.current.archive = archive

    def on_part_data(self, data: bytes, start: int, end: int):
        if self.current is None or self.current.archive is None:
            raise HTTPException(400, "Malformed multipart upload")
        payload = bytes(data[start:end])
        archive = self.current.archive
        archive.size += len(payload)
        self.file_bytes += len(payload)
        if archive.size > settings.max_upload_bytes:
            raise HTTPException(413, f"Archive exceeds the {settings.max_upload_bytes} byte upload limit")
        if self.file_bytes > settings.max_upload_request_bytes:
            raise HTTPException(413, "The combined upload exceeds the configured request limit")
        self.pending_writes.append((archive, payload))

    def on_part_end(self):
        if self.current is None or self.current.archive is None:
            raise HTTPException(400, "Malformed multipart upload")
        self.pending_finished.append(self.current.archive)
        self.current = None

    def on_end(self):
        self.ended = True

    async def flush_events(self):
        writes, finished = self.pending_writes, self.pending_finished
        self.pending_writes, self.pending_finished = [], []
        if writes:
            try:
                await asyncio.to_thread(self._write_all, writes)
            except OSError as exc:
                self._raise_storage_error(exc)
        if self.file_bytes - self.checked_at >= 64 * 1024 * 1024:
            require_storage_capacity(self.upload_dir)
            self.checked_at = self.file_bytes
        for archive in finished:
            try:
                await asyncio.to_thread(self._finish, archive)
            except OSError as exc:
                self._raise_storage_error(exc)
            self.completed.append(StreamedArchive(archive.path, archive.path.name, archive.size))

    @staticmethod
    def _write_all(writes: list[tuple[_ArchivePart, bytes]]):
        for archive, payload in writes:
            archive.output.write(payload)

    @staticmethod
    def _finish(archive: _ArchivePart):
        archive.output.flush()
        archive.output.close()
        os.replace(archive.temporary, archive.path)

    @staticmethod
    def _raise_storage_error(exc: OSError):
        if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
            raise HTTPException(507, "Upload storage is full or has reached its quota") from exc
        raise HTTPException(500, "The upload could not be written to managed storage") from exc

    def cleanup(self):
        for archive in self.open_archives:
            try:
                archive.output.close()
            except OSError:
                pass
            for path in (archive.temporary, archive.path):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass


async def stream_archive_uploads(
    request: Request,
    on_progress: Callable[[int, int, str | None], Awaitable[None]] | None = None,
) -> list[StreamedArchive]:
    """Parse a multipart upload without spooling large files into container /tmp."""
    content_type, options = parse_options_header(request.headers.get("content-type"))
    boundary = options.get(b"boundary")
    if content_type != b"multipart/form-data" or not boundary:
        raise HTTPException(400, "A multipart/form-data upload is required")

    try:
        content_length = int(request.headers.get("content-length", "0"))
    except ValueError as exc:
        raise HTTPException(400, "Invalid Content-Length header") from exc
    if content_length < 0:
        raise HTTPException(400, "Invalid Content-Length header")
    multipart_allowance = settings.max_upload_files * 1024 * 1024
    max_body_bytes = settings.max_upload_request_bytes + multipart_allowance
    if content_length > max_body_bytes:
        raise HTTPException(413, "The combined upload exceeds the configured request limit")

    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    require_storage_capacity(settings.upload_dir)
    writer = _ArchiveMultipartWriter(settings.upload_dir)
    try:
        parser = MultipartParser(boundary, writer.callbacks(), max_size=max_body_bytes)
        async for chunk in request.stream():
            writer.body_bytes += len(chunk)
            if writer.body_bytes > max_body_bytes:
                raise HTTPException(413, "The combined upload exceeds the configured request limit")
            if chunk:
                consumed = parser.write(chunk)
                if consumed != len(chunk):
                    raise HTTPException(413, "The combined upload exceeds the configured request limit")
                await writer.flush_events()
                if on_progress:
                    current_name = writer.current.archive.path.name if writer.current and writer.current.archive else None
                    await on_progress(writer.body_bytes, content_length, current_name)
        parser.finalize()
        await writer.flush_events()
        if not writer.ended:
            raise HTTPException(400, "The multipart upload ended before its closing boundary")
        if not writer.completed:
            raise HTTPException(400, "At least one .tar archive is required")
        return writer.completed
    except HTTPException:
        writer.cleanup()
        raise
    except MultipartParseError as exc:
        writer.cleanup()
        raise HTTPException(400, "Malformed multipart upload") from exc
    except OSError as exc:
        writer.cleanup()
        writer._raise_storage_error(exc)
    except Exception:
        writer.cleanup()
        raise
