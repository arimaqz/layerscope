from pathlib import Path
from fastapi.testclient import TestClient

from app.main import allowed_path
from app.config import settings
from app.main import app
from app.security import safe_advisory_url, sanitize_untrusted_text


def test_allowed_path_inside_root(tmp_path):
    original = settings.scan_roots
    settings.scan_roots = str(tmp_path)
    try:
        assert allowed_path(tmp_path / "image.tar")
        assert not allowed_path(tmp_path.parent / "escape.tar")
    finally:
        settings.scan_roots = original


def test_advisory_links_allow_only_http_and_https():
    assert safe_advisory_url("https://nvd.nist.gov/vuln/detail/CVE-2026-0001").startswith("https://")
    assert safe_advisory_url("http://example.test/advisory") == "http://example.test/advisory"
    assert safe_advisory_url("javascript:alert(1)") == ""
    assert safe_advisory_url("data:text/html,unsafe") == ""
    assert safe_advisory_url("https://user:password@example.test/private") == ""


def test_untrusted_errors_remove_controls_and_managed_paths(tmp_path):
    original = settings.scan_roots
    settings.scan_roots = str(tmp_path)
    try:
        cleaned = sanitize_untrusted_text(f"\x1b[31mfailed at {tmp_path / 'image.tar'}\x00")
        assert "\x1b" not in cleaned and "\x00" not in cleaned
        assert str(tmp_path) not in cleaned
        assert "[managed storage]" in cleaned
    finally:
        settings.scan_roots = original


def test_host_origin_headers_health_privacy_and_validation_redaction():
    with TestClient(app) as client:
        assert client.get("/api/health", headers={"host": "attacker.example"}).status_code == 400
        bad_origin = client.post("/api/auth/login", headers={"origin": "https://attacker.example"},
                                 json={"username": "admin", "password": "not-a-real-password"})
        assert bad_origin.status_code == 403
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}
        assert health.headers["cache-control"] == "no-store"
        assert health.headers["x-content-type-options"] == "nosniff"
        assert client.get("/api/exports?group_ids=1&format=json").status_code == 401
        assert client.post("/api/exports/branded?scan_ids=1&format=html",
                           headers={"Content-Type": "image/png"}, content=b"invalid").status_code == 401
        rejected = client.post("/api/auth/login", json={"username": "admin", "password": "s3cr3tX"})
        assert rejected.status_code == 422
        assert "s3cr3tX" not in rejected.text
