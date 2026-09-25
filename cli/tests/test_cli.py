from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from layerscope_cli.cli import EXIT_CONFLICT, EXIT_OK, EXIT_POLICY, EXIT_USAGE, main  # noqa: E402


class FakeLayerScope(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests: list[dict] = []
    role = "operator"

    def log_message(self, _format, *_args):
        return

    def record(self, body: bytes = b""):
        self.__class__.requests.append({
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "content_type": self.headers.get("Content-Type"),
            "body": body,
        })

    def send_json(self, status: int, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.record()
        if self.path == "/api/health":
            return self.send_json(200, {"status": "ok"})
        if self.path == "/api/auth/me":
            return self.send_json(200, {"user": {"username": "automation", "role": self.__class__.role},
                                        "csrf_token": "", "auth_method": "api_token"})
        if self.path == "/api/images":
            return self.send_json(200, [{"id": 7, "name": "existing.tar", "size": 4,
                                         "source": "upload"}])
        if self.path.startswith("/api/jobs"):
            return self.send_json(200, [{"id": 11, "image_id": 7, "status": "completed",
                                         "progress": 100, "stage": "complete"}])
        if self.path == "/api/scans/11/summary":
            return self.send_json(200, {"id": 11, "image_id": 7, "status": "completed",
                                        "progress": 100, "stage": "complete",
                                        "counts": {"HIGH": 1, "LOW": 2}, "total": 3})
        if self.path.startswith("/api/exports?"):
            body = b"synthetic report"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_json(404, {"detail": "Not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.record(body)
        if self.path == "/api/uploads":
            return self.send_json(201, {"uploaded": [{"id": 8, "name": "sample.tar"}]})
        if self.path.startswith("/api/exports/branded?"):
            result = b"synthetic branded report"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
            return
        if self.path == "/api/scans":
            return self.send_json(202, {"scan_ids": [11], "reused_scan_ids": []})
        if self.path == "/api/jobs/11/cancel":
            return self.send_json(200, {"scan_id": 11, "status": "cancelled"})
        self.send_json(404, {"detail": "Not found"})


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeLayerScope)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        FakeLayerScope.requests.clear()
        FakeLayerScope.role = "operator"

    def invoke(self, arguments: list[str], token: str | None = "synthetic-test-token"):
        stdout, stderr = io.StringIO(), io.StringIO()
        environment = {} if token is None else {"LAYERSCOPE_TOKEN": token}
        with patch.dict(os.environ, environment, clear=True), redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--url", self.url, *arguments])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_health_is_public_and_emits_versioned_json(self):
        code, output, errors = self.invoke(["health"], token=None)

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(errors, "")
        payload = json.loads(output)
        self.assertEqual(payload["cli_schema_version"], 1)
        self.assertEqual(payload["result"], {"status": "ok"})
        self.assertIsNone(FakeLayerScope.requests[-1]["authorization"])

    def test_invalid_invocation_emits_structured_error(self):
        code, output, errors = self.invoke(["--compact", "scan"])

        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        payload = json.loads(errors)
        self.assertEqual(payload["cli_schema_version"], 1)
        self.assertEqual(payload["command"], "arguments")
        self.assertEqual(payload["error"]["exit_code"], 2)

    def test_token_is_sent_but_never_printed(self):
        code, output, errors = self.invoke(["whoami"])

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(FakeLayerScope.requests[-1]["authorization"], "Bearer synthetic-test-token")
        self.assertNotIn("synthetic-test-token", output + errors)

    def test_upload_uses_streaming_multipart_field(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "sample.tar"
            archive.write_bytes(b"synthetic archive bytes")
            code, output, errors = self.invoke(["upload", str(archive)])

        self.assertEqual(code, EXIT_OK, errors)
        request = next(item for item in FakeLayerScope.requests if item["path"] == "/api/uploads")
        self.assertIn("multipart/form-data; boundary=", request["content_type"])
        self.assertIn(b'name="files"; filename="sample.tar"', request["body"])
        self.assertIn(b"synthetic archive bytes", request["body"])
        self.assertEqual(json.loads(output)["result"]["archives"][0]["status"], "uploaded")

    def test_upload_preserves_utf8_filename_without_header_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "synthetic-Δ.tar"
            archive.write_bytes(b"synthetic")
            code, _output, errors = self.invoke(["upload", str(archive)])

        self.assertEqual(code, EXIT_OK, errors)
        request = next(item for item in FakeLayerScope.requests if item["path"] == "/api/uploads")
        self.assertIn('filename="synthetic-Δ.tar"'.encode(), request["body"])

    def test_viewer_upload_is_rejected_before_archive_transfer(self):
        FakeLayerScope.role = "viewer"
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "sample.tar"
            archive.write_bytes(b"synthetic")
            code, output, errors = self.invoke(["upload", str(archive)])

        self.assertEqual(code, 4, output)
        self.assertIn("requires an operator", errors)
        self.assertFalse(any(item["path"] == "/api/uploads" for item in FakeLayerScope.requests))

    def test_completed_scan_can_fail_a_severity_gate(self):
        code, output, errors = self.invoke([
            "--quiet", "scan", "--image-id", "7", "--wait", "--fail-on", "high",
            "--timeout", "2", "--poll-interval", "0.01",
        ])

        self.assertEqual(code, EXIT_POLICY, errors)
        gate = json.loads(output)["result"]["gates"][0]
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["matched"], {"HIGH": 1})

    def test_export_does_not_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("keep", encoding="utf-8")
            code, stdout, stderr = self.invoke([
                "export", "--scan-id", "11", "--format", "json", "--output", str(output),
            ])
            self.assertEqual(code, EXIT_CONFLICT, stdout)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")
            self.assertIn("already exists", stderr)

            code, stdout, stderr = self.invoke([
                "export", "--scan-id", "11", "--format", "json", "--output", str(output), "--force",
            ])
            self.assertEqual(code, EXIT_OK, stderr)
            self.assertEqual(output.read_bytes(), b"synthetic report")

    def test_compatibility_export_formats_are_sent_to_the_api(self):
        with tempfile.TemporaryDirectory() as directory:
            for export_format, suffix in (("elastic", "ndjson"), ("defectdojo", "json")):
                FakeLayerScope.requests.clear()
                output = Path(directory) / f"report.{suffix}"
                code, _stdout, stderr = self.invoke([
                    "export", "--scan-id", "11", "--format", export_format, "--output", str(output),
                ])
                self.assertEqual(code, EXIT_OK, stderr)
                self.assertTrue(any(
                    item["path"] == f"/api/exports?scan_ids=11&format={export_format}"
                    for item in FakeLayerScope.requests
                ))

    def test_group_export_is_mutually_exclusive_and_sent_to_the_api(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "group-report.json"
            FakeLayerScope.requests.clear()
            code, _stdout, stderr = self.invoke([
                "export", "--group-id", "9", "--group-id", "10", "--format", "json",
                "--output", str(output),
            ])
            self.assertEqual(code, EXIT_OK, stderr)
            self.assertTrue(any(
                item["path"] == "/api/exports?group_ids=9&group_ids=10&format=json"
                for item in FakeLayerScope.requests
            ))

            code, _stdout, _stderr = self.invoke([
                "export", "--scan-id", "11", "--group-id", "9", "--output", str(output), "--force",
            ])
            self.assertEqual(code, EXIT_USAGE)

    def test_branded_export_streams_logo_only_for_html_or_pdf(self):
        with tempfile.TemporaryDirectory() as directory:
            logo = Path(directory) / "logo.png"
            logo.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic")
            output = Path(directory) / "report.pdf"
            code, _stdout, stderr = self.invoke([
                "export", "--scan-id", "11", "--format", "pdf", "--logo", str(logo),
                "--output", str(output),
            ])
            self.assertEqual(code, EXIT_OK, stderr)
            request = next(item for item in FakeLayerScope.requests if item["path"].startswith("/api/exports/branded?"))
            self.assertEqual(request["method"], "POST")
            self.assertEqual(request["content_type"], "image/png")
            self.assertEqual(request["body"], logo.read_bytes())
            self.assertEqual(output.read_bytes(), b"synthetic branded report")

            code, _stdout, _stderr = self.invoke([
                "export", "--scan-id", "11", "--format", "json", "--logo", str(logo),
                "--output", str(Path(directory) / "report.json"),
            ])
            self.assertEqual(code, EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
