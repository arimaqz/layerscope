"""Dependency-free LayerScope CLI.

The client is intentionally a thin wrapper around the authenticated HTTP API. It
does not run Trivy or manipulate LayerScope's database directly.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import secrets
import ssl
import stat
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlencode, urlsplit

from . import __version__

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_PERMISSION = 4
EXIT_NOT_FOUND = 5
EXIT_CONFLICT = 6
EXIT_CAPACITY = 7
EXIT_SERVER = 8
EXIT_NETWORK = 9
EXIT_JOB_FAILED = 10
EXIT_CANCELLED = 11
EXIT_POLICY = 12
EXIT_TIMEOUT = 13

MAX_JSON_BYTES = 32 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
MAX_REPORT_LOGO_BYTES = 2 * 1024 * 1024
TERMINAL = {"completed", "failed", "cancelled"}
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class CliError(Exception):
    def __init__(self, message: str, exit_code: int, *, status: int | None = None,
                 request_id: str | None = None, retry_after: str | None = None):
        super().__init__(message)
        self.exit_code = exit_code
        self.status = status
        self.request_id = request_id
        self.retry_after = retry_after


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliError(message, EXIT_USAGE)


def _http_exit(status_code: int) -> int:
    if status_code == 401:
        return EXIT_AUTH
    if status_code == 403:
        return EXIT_PERMISSION
    if status_code == 404:
        return EXIT_NOT_FOUND
    if status_code in {409, 412}:
        return EXIT_CONFLICT
    if status_code in {429, 507}:
        return EXIT_CAPACITY
    if status_code >= 500:
        return EXIT_SERVER
    return EXIT_USAGE


def _detail(body: bytes, fallback: str) -> tuple[str, str | None]:
    if not body:
        return fallback, None
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return fallback, None
    if not isinstance(parsed, dict):
        return fallback, None
    value = parsed.get("detail")
    if isinstance(value, str):
        message = value
    elif isinstance(value, list):
        parts = [str(item.get("msg", "Invalid request")) for item in value if isinstance(item, dict)]
        message = "; ".join(parts) or fallback
    else:
        message = fallback
    request_id = parsed.get("request_id")
    return message[:2000], request_id if isinstance(request_id, str) else None


class ApiClient:
    def __init__(self, base_url: str, token: str | None, timeout: float,
                 ca_file: str | None = None):
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise CliError("--url must be an absolute HTTP or HTTPS URL", EXIT_USAGE)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise CliError("--url must not contain credentials, a query, or a fragment", EXIT_USAGE)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port
        self.base_path = parsed.path.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.ssl_context = ssl.create_default_context(cafile=ca_file) if self.scheme == "https" else None

    def _connection(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=self.ssl_context
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _path(self, path: str) -> str:
        return f"{self.base_path}/{path.lstrip('/')}"

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": f"layerscope-cli/{__version__}"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if extra:
            headers.update(extra)
        return headers

    def _raise_response(self, response: http.client.HTTPResponse, body: bytes) -> None:
        message, request_id = _detail(body, f"LayerScope returned HTTP {response.status}")
        raise CliError(message, _http_exit(response.status), status=response.status,
                       request_id=request_id, retry_after=response.getheader("Retry-After"))

    def request(self, method: str, path: str, payload: Any | None = None) -> Any:
        body = None
        headers = self._headers()
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            headers.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
        connection = self._connection()
        try:
            connection.request(method, self._path(path), body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(MAX_JSON_BYTES + 1)
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            raise CliError(f"Could not reach LayerScope: {exc}", EXIT_NETWORK) from exc
        finally:
            connection.close()
        if len(response_body) > MAX_JSON_BYTES:
            raise CliError("LayerScope returned an unexpectedly large JSON response", EXIT_SERVER)
        if response.status >= 400:
            self._raise_response(response, response_body)
        if not response_body:
            return None
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CliError("LayerScope returned invalid JSON", EXIT_SERVER) from exc

    def upload(self, archive: Path) -> Any:
        if archive.suffix.casefold() != ".tar" or not archive.is_file() or archive.is_symlink():
            raise CliError(f"Archive must be a regular .tar file: {archive}", EXIT_USAGE)
        boundary = f"layerscope-{secrets.token_hex(16)}"
        safe_name = archive.name.replace('"', "_").replace("\r", "_").replace("\n", "_")
        prefix = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; "
                  f"filename=\"{safe_name}\"\r\nContent-Type: application/x-tar\r\n\r\n").encode("utf-8")
        suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
        content_length = len(prefix) + archive.stat().st_size + len(suffix)
        connection = self._connection()
        try:
            connection.putrequest("POST", self._path("/api/uploads"))
            for name, value in self._headers({
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(content_length),
            }).items():
                connection.putheader(name, value)
            connection.endheaders()
            connection.send(prefix)
            with archive.open("rb") as source:
                while chunk := source.read(CHUNK_SIZE):
                    connection.send(chunk)
            connection.send(suffix)
            response = connection.getresponse()
            body = response.read(MAX_JSON_BYTES + 1)
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            raise CliError(f"Upload connection failed: {exc}", EXIT_NETWORK) from exc
        finally:
            connection.close()
        if len(body) > MAX_JSON_BYTES:
            raise CliError("LayerScope returned an unexpectedly large upload response", EXIT_SERVER)
        if response.status >= 400:
            self._raise_response(response, body)
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CliError("LayerScope returned invalid JSON after upload", EXIT_SERVER) from exc

    def download(self, path: str, destination: Path, force: bool, upload: Path | None = None,
                 upload_content_type: str | None = None) -> dict[str, Any]:
        destination = destination.absolute()
        if destination.is_symlink():
            raise CliError(f"Refusing to write through a symbolic link: {destination}", EXIT_CONFLICT)
        if destination.exists() and not force:
            raise CliError(f"Output already exists: {destination}", EXIT_CONFLICT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(6)}.partial")
        connection = self._connection()
        try:
            if upload:
                connection.putrequest("POST", self._path(path))
                for name, value in self._headers({"Accept": "*/*", "Content-Type": upload_content_type or "",
                                                  "Content-Length": str(upload.stat().st_size)}).items():
                    connection.putheader(name, value)
                connection.endheaders()
                with upload.open("rb") as source:
                    while chunk := source.read(CHUNK_SIZE):
                        connection.send(chunk)
            else:
                connection.request("GET", self._path(path), headers=self._headers({"Accept": "*/*"}))
            response = connection.getresponse()
            if response.status >= 400:
                body = response.read(MAX_JSON_BYTES + 1)
                self._raise_response(response, body)
            total = 0
            with temporary.open("xb") as target:
                while chunk := response.read(CHUNK_SIZE):
                    target.write(chunk)
                    total += len(chunk)
            if destination.exists() and not force:
                raise CliError(f"Output appeared during download: {destination}", EXIT_CONFLICT)
            if force:
                temporary.replace(destination)
            else:
                os.link(temporary, destination)
                temporary.unlink()
            return {"output": str(destination), "bytes": total}
        except CliError:
            raise
        except FileExistsError as exc:
            raise CliError(f"Output already exists: {destination}", EXIT_CONFLICT) from exc
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            raise CliError(f"Download failed: {exc}", EXIT_NETWORK) from exc
        finally:
            connection.close()
            temporary.unlink(missing_ok=True)


def query(path: str, **values: Any) -> str:
    items: list[tuple[str, Any]] = []
    for name, value in values.items():
        if value is None or value == "" or value == []:
            continue
        if isinstance(value, list):
            items.extend((name, item) for item in value)
        else:
            items.append((name, value))
    return f"{path}?{urlencode(items)}" if items else path


def report_logo_content_type(path: Path) -> str:
    resolved = path.absolute()
    if not resolved.is_file() or resolved.is_symlink():
        raise CliError(f"Report logo must be a regular PNG or JPEG file: {resolved}", EXIT_USAGE)
    size = resolved.stat().st_size
    if size < 1 or size > MAX_REPORT_LOGO_BYTES:
        raise CliError("Report logo must be between 1 byte and 2 MiB", EXIT_USAGE)
    with resolved.open("rb") as source:
        signature = source.read(12)
    if signature.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if signature.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    raise CliError("Report logo must have a PNG or JPEG signature", EXIT_USAGE)


def read_token(args: argparse.Namespace) -> str | None:
    env_token = os.environ.get("LAYERSCOPE_TOKEN")
    sources = int(bool(env_token)) + int(bool(args.token_file)) + int(bool(args.token_stdin))
    if sources > 1:
        raise CliError("Use only one token source: environment, file, or standard input", EXIT_USAGE)
    if args.token_stdin:
        token = sys.stdin.readline().strip()
    elif args.token_file:
        path = Path(args.token_file)
        if os.name != "nt":
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                raise CliError("Token file permissions must exclude group and other users", EXIT_PERMISSION)
        token = path.read_text(encoding="utf-8").strip()
    else:
        token = env_token
    if token is not None and not token.strip():
        raise CliError("The selected token source is empty", EXIT_USAGE)
    return token.strip() if token else None


def emit(command: str, result: Any, compact: bool) -> None:
    envelope = {"cli_schema_version": 1, "command": command, "result": result}
    print(json.dumps(envelope, ensure_ascii=True, separators=(",", ":") if compact else None,
                     indent=None if compact else 2, default=str))


def emit_error(command: str, error: CliError, compact: bool) -> None:
    details: dict[str, Any] = {"message": str(error), "exit_code": error.exit_code}
    if error.status is not None:
        details["http_status"] = error.status
    if error.request_id:
        details["request_id"] = error.request_id
    if error.retry_after:
        details["retry_after"] = error.retry_after
    envelope = {"cli_schema_version": 1, "command": command, "error": details}
    print(json.dumps(envelope, ensure_ascii=True, separators=(",", ":") if compact else None,
                     indent=None if compact else 2), file=sys.stderr)


def gate_result(summary: dict[str, Any], fail_on: str | None,
                fail_on_unknown: bool) -> dict[str, Any]:
    counts = {str(key).upper(): int(value) for key, value in (summary.get("counts") or {}).items()}
    matched: dict[str, int] = {}
    if fail_on:
        threshold = SEVERITY_RANK[fail_on.upper()]
        matched.update({severity: count for severity, count in counts.items()
                        if count and SEVERITY_RANK.get(severity, 0) >= threshold})
    if fail_on_unknown and counts.get("UNKNOWN", 0):
        matched["UNKNOWN"] = counts["UNKNOWN"]
    return {"passed": not matched, "fail_on": fail_on, "fail_on_unknown": fail_on_unknown,
            "matched": matched}


def wait_for_scans(client: ApiClient, scan_ids: list[int], timeout: float, poll: float,
                   cancel_on_timeout: bool, quiet: bool) -> tuple[list[dict[str, Any]], int]:
    deadline = time.monotonic() + timeout
    pending = set(scan_ids)
    completed: dict[int, dict[str, Any]] = {}
    while pending:
        jobs = client.request("GET", query("/api/jobs", limit=500))
        by_id = {int(item["id"]): item for item in jobs if int(item.get("id", 0)) in pending}
        missing = pending - by_id.keys()
        if missing:
            raise CliError(f"Scan jobs are unavailable: {sorted(missing)}", EXIT_NOT_FOUND)
        for scan_id, job in by_id.items():
            status = str(job.get("status", ""))
            if not quiet:
                print(f"scan {scan_id}: {status} {job.get('progress', 0)}% {job.get('stage', '')}",
                      file=sys.stderr)
            if status in TERMINAL:
                completed[scan_id] = job
                pending.remove(scan_id)
        if not pending:
            break
        if time.monotonic() >= deadline:
            cancelled: list[int] = []
            if cancel_on_timeout:
                for scan_id in sorted(pending):
                    try:
                        client.request("POST", f"/api/jobs/{scan_id}/cancel")
                        cancelled.append(scan_id)
                    except CliError:
                        pass
            suffix = f"; cancellation requested for {cancelled}" if cancelled else ""
            raise CliError(f"Timed out waiting for scans {sorted(pending)}{suffix}", EXIT_TIMEOUT)
        time.sleep(min(poll, max(0.0, deadline - time.monotonic())))
    summaries = [client.request("GET", f"/api/scans/{scan_id}/summary") for scan_id in scan_ids]
    if any(item.get("status") == "failed" for item in summaries):
        return summaries, EXIT_JOB_FAILED
    if any(item.get("status") == "cancelled" for item in summaries):
        return summaries, EXIT_CANCELLED
    return summaries, EXIT_OK


def add_wait_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--timeout", type=float, default=3600, help="Overall wait limit in seconds")
    parser.add_argument("--poll-interval", type=float, default=2, help="Polling interval in seconds")
    parser.add_argument("--cancel-on-timeout", action="store_true")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"])
    parser.add_argument("--fail-on-unknown", action="store_true")


def validate_arguments(args: argparse.Namespace) -> None:
    if args.request_timeout <= 0:
        raise CliError("--request-timeout must be greater than zero", EXIT_USAGE)
    if hasattr(args, "timeout") and args.timeout <= 0:
        raise CliError("--timeout must be greater than zero", EXIT_USAGE)
    if hasattr(args, "poll_interval") and args.poll_interval <= 0:
        raise CliError("--poll-interval must be greater than zero", EXIT_USAGE)
    if hasattr(args, "limit") and not 1 <= args.limit <= 500:
        raise CliError("--limit must be between 1 and 500", EXIT_USAGE)
    for name in ("image_id", "scan_id", "scan_ids", "group_id"):
        values = getattr(args, name, None)
        if values is None:
            continue
        values = values if isinstance(values, list) else [values]
        if any(value < 1 for value in values):
            raise CliError(f"--{name.replace('_', '-')} values must be positive", EXIT_USAGE)


def parser() -> argparse.ArgumentParser:
    root = JsonArgumentParser(prog="layerscope", description="LayerScope automation client")
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    root.add_argument("--url", default=os.environ.get("LAYERSCOPE_URL", "http://localhost:8080"))
    credentials = root.add_mutually_exclusive_group()
    credentials.add_argument("--token-file")
    credentials.add_argument("--token-stdin", action="store_true")
    root.add_argument("--ca-file", help="Custom CA bundle for HTTPS")
    root.add_argument("--request-timeout", type=float, default=120)
    root.add_argument("--compact", action="store_true", help="Emit one-line JSON")
    root.add_argument("--quiet", action="store_true", help="Suppress progress on standard error")
    commands = root.add_subparsers(dest="command", required=True)

    commands.add_parser("health")
    commands.add_parser("whoami")
    commands.add_parser("overview")
    commands.add_parser("discover")

    images = commands.add_parser("images")
    images.add_argument("--source", choices=["upload", "mounted", "report"])

    jobs = commands.add_parser("jobs")
    jobs.add_argument("--status", action="append", choices=["queued", "running", "completed", "failed", "cancelled"])
    jobs.add_argument("--limit", type=int, default=100)

    upload = commands.add_parser("upload")
    upload.add_argument("archives", nargs="+", type=Path)
    upload.add_argument("--if-absent", action="store_true",
                        help="Skip a file when visible name and byte size already match")

    scan = commands.add_parser("scan")
    scan.add_argument("--image-id", action="append", type=int, required=True)
    scan.add_argument("--wait", action="store_true")
    add_wait_options(scan)

    wait = commands.add_parser("wait")
    wait.add_argument("--scan-id", action="append", type=int, required=True)
    add_wait_options(wait)

    cancel = commands.add_parser("cancel")
    cancel.add_argument("scan_ids", nargs="+", type=int)

    retry = commands.add_parser("retry")
    retry.add_argument("scan_id", type=int)
    retry.add_argument("--wait", action="store_true")
    add_wait_options(retry)

    findings = commands.add_parser("findings")
    findings.add_argument("scan_id", type=int)
    findings.add_argument("--severity", action="append", choices=["critical", "high", "medium", "low", "unknown"])
    findings.add_argument("--search")
    findings.add_argument("--package-name")
    findings.add_argument("--target")
    findings.add_argument("--fix-status", choices=["fixed", "unfixed"])

    export = commands.add_parser("export")
    export_source = export.add_mutually_exclusive_group(required=True)
    export_source.add_argument("--scan-id", action="append", type=int)
    export_source.add_argument("--group-id", action="append", type=int,
                               help="Export latest completed scans for visible group members")
    export.add_argument("--format", choices=["json", "html", "pdf", "elastic", "defectdojo"], default="json")
    export.add_argument("--output", required=True, type=Path)
    export.add_argument("--logo", type=Path, help="One-time PNG/JPEG branding for HTML or PDF only")
    export.add_argument("--force", action="store_true")
    return root


def require_token(command: str, token: str | None) -> None:
    if command != "health" and not token:
        raise CliError("Set LAYERSCOPE_TOKEN or use --token-file/--token-stdin", EXIT_USAGE)


def policy(summaries: list[dict[str, Any]], args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    gates = [{"scan_id": summary.get("id"), **gate_result(summary, args.fail_on, args.fail_on_unknown)}
             for summary in summaries]
    return {"scans": summaries, "gates": gates}, EXIT_POLICY if any(not gate["passed"] for gate in gates) else EXIT_OK


def execute(client: ApiClient, args: argparse.Namespace) -> tuple[Any, int]:
    if args.command == "health":
        return client.request("GET", "/api/health"), EXIT_OK
    if args.command == "whoami":
        return client.request("GET", "/api/auth/me"), EXIT_OK
    if args.command == "overview":
        return client.request("GET", "/api/overview"), EXIT_OK
    if args.command == "discover":
        return client.request("POST", "/api/discover"), EXIT_OK
    if args.command == "images":
        items = client.request("GET", "/api/images")
        if args.source:
            items = [item for item in items if item.get("source") == args.source]
        return items, EXIT_OK
    if args.command == "jobs":
        return client.request("GET", query("/api/jobs", status=args.status, limit=args.limit)), EXIT_OK
    if args.command == "upload":
        identity = client.request("GET", "/api/auth/me")
        role = identity.get("user", {}).get("role") if isinstance(identity, dict) else None
        if role not in {"operator", "admin"}:
            raise CliError("Archive upload requires an operator or administrator token", EXIT_PERMISSION)
        visible = client.request("GET", "/api/images") if args.if_absent else []
        known = {(item.get("name"), int(item.get("size", -1))): item for item in visible}
        results = []
        for archive in args.archives:
            resolved = archive.resolve()
            existing = known.get((resolved.name, resolved.stat().st_size)) if args.if_absent else None
            if existing:
                results.append({"archive": str(resolved), "status": "skipped", "image_id": existing["id"]})
                continue
            response = client.upload(resolved)
            results.append({"archive": str(resolved), "status": "uploaded", "response": response})
        return {"archives": results}, EXIT_OK
    if args.command == "scan":
        response = client.request("POST", "/api/scans", {"image_ids": args.image_id})
        if not args.wait:
            return response, EXIT_OK
        summaries, code = wait_for_scans(client, response["scan_ids"], args.timeout,
                                         args.poll_interval, args.cancel_on_timeout, args.quiet)
        if code:
            return {"submission": response, "scans": summaries}, code
        result, code = policy(summaries, args)
        result["submission"] = response
        return result, code
    if args.command == "wait":
        summaries, code = wait_for_scans(client, args.scan_id, args.timeout, args.poll_interval,
                                         args.cancel_on_timeout, args.quiet)
        if code:
            return {"scans": summaries}, code
        return policy(summaries, args)
    if args.command == "cancel":
        return {"jobs": [client.request("POST", f"/api/jobs/{scan_id}/cancel")
                          for scan_id in args.scan_ids]}, EXIT_OK
    if args.command == "retry":
        response = client.request("POST", f"/api/jobs/{args.scan_id}/retry")
        if not args.wait:
            return response, EXIT_OK
        summaries, code = wait_for_scans(client, [response["scan_id"]], args.timeout,
                                         args.poll_interval, args.cancel_on_timeout, args.quiet)
        if code:
            return {"retry": response, "scans": summaries}, code
        result, code = policy(summaries, args)
        result["retry"] = response
        return result, code
    if args.command == "findings":
        return client.request("GET", query(f"/api/scans/{args.scan_id}/findings",
                                           severity=args.severity, search=args.search,
                                           package_name=args.package_name, target=args.target,
                                           fix_status=args.fix_status)), EXIT_OK
    if args.command == "export":
        logo_type = None
        endpoint = "/api/exports"
        if args.logo:
            if args.format not in {"html", "pdf"}:
                raise CliError("--logo can be used only with --format html or --format pdf", EXIT_USAGE)
            logo_type = report_logo_content_type(args.logo)
            endpoint = "/api/exports/branded"
        return client.download(query(endpoint, scan_ids=args.scan_id, group_ids=args.group_id,
                                     format=args.format), args.output, args.force, args.logo, logo_type), EXIT_OK
    raise CliError("Unknown command", EXIT_USAGE)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    compact = "--compact" in arguments
    command = "arguments"
    try:
        args = parser().parse_args(arguments)
        command = args.command
        compact = args.compact
        validate_arguments(args)
        token = read_token(args)
        require_token(args.command, token)
        client = ApiClient(args.url, token, args.request_timeout, args.ca_file)
        result, exit_code = execute(client, args)
        emit(args.command, result, args.compact)
        return exit_code
    except CliError as error:
        emit_error(command, error, compact)
        return error.exit_code
    except (OSError, ValueError) as error:
        wrapped = CliError(str(error), EXIT_USAGE)
        emit_error(command, wrapped, compact)
        return wrapped.exit_code
