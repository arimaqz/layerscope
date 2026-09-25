import asyncio
from datetime import datetime, timezone
from pathlib import Path
from app.database import Base, SessionLocal, engine
from app.models import ImageArchive, Scan
from app.config import settings
from app.scanner import (JAVA_ARCHIVE_PATTERNS, ScanManager, build_scan_command,
                         cleanup_abandoned_scan_workspaces, cleanup_scan_workspace,
                         create_scan_workspace, scan_environment)


def test_scan_command_uses_java_database_when_installed():
    command = build_scan_command("/images/example.tar", Path("/tmp/result.json"), True)
    assert "--skip-java-db-update" in command
    assert "--java-db-repository" in command
    assert "--skip-files" not in command
    assert "--offline-scan" in command


def test_scan_command_excludes_only_java_archives_when_database_is_missing():
    command = build_scan_command("/images/example.tar", Path("/tmp/result.json"), False)
    skipped = [command[index + 1] for index, value in enumerate(command[:-1]) if value == "--skip-files"]
    assert set(skipped) == set(JAVA_ARCHIVE_PATTERNS)
    assert "--pkg-types" not in command


def test_trivy_output_maps_to_progress_stages():
    manager = ScanManager()
    assert manager.infer_progress("Need to update DB")[1] == "updating_database"
    assert manager.infer_progress("Downloading artifact")[1] == "downloading_database"
    assert manager.infer_progress("Detected OS: alpine")[1] == "detecting_os"
    assert manager.infer_progress("Vulnerability scanning is enabled")[1] == "loading_archive"


def test_scan_workspace_uses_disk_backed_configured_storage_and_cleans_up(tmp_path, monkeypatch):
    root = tmp_path / "trivy-tmp"
    monkeypatch.setattr(settings, "trivy_temp_dir", root)
    workspace = create_scan_workspace(42)
    (workspace / "large-layer-file").write_bytes(b"synthetic")
    environment = scan_environment(workspace)

    assert workspace.parent == root
    assert workspace.name.startswith("scan-42-")
    assert environment["TMPDIR"] == str(workspace)
    assert environment["TMP"] == str(workspace)
    assert environment["TEMP"] == str(workspace)

    cleanup_scan_workspace(workspace)
    assert not workspace.exists()


def test_startup_cleanup_removes_only_abandoned_scan_workspaces(tmp_path, monkeypatch):
    root = tmp_path / "trivy-tmp"
    monkeypatch.setattr(settings, "trivy_temp_dir", root)
    abandoned = root / "scan-99-abandoned"
    preserved = root / "keep-marker"
    abandoned.mkdir(parents=True)
    (abandoned / "temporary-file").write_bytes(b"synthetic")
    preserved.write_text("preserve", encoding="utf-8")

    cleanup_abandoned_scan_workspaces()

    assert not abandoned.exists()
    assert preserved.is_file()


def test_normalize_trivy_json():
    packages, findings = ScanManager.normalize({"Results": [{
        "Target": "alpine", "Packages": [{"Name": "openssl", "Version": "1.0", "Licenses": ["Apache-2.0"]}],
        "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "PkgName": "openssl", "InstalledVersion": "1.0",
                             "FixedVersion": "1.1", "Severity": "HIGH", "Title": "Example"}],
    }]}, 42)
    assert len(packages) == 1 and packages[0].scan_id == 42
    assert len(findings) == 1 and findings[0].severity == "HIGH"


def test_normalize_structured_package_identifier_for_sqlite():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        image = ImageArchive(path="/images/structured-identifier-test.tar", name="structured-identifier-test.tar",
                             size=1, modified_at=datetime.now(timezone.utc))
        db.add(image)
        db.flush()
        scan = Scan(image_id=image.id, status="running")
        db.add(scan)
        db.flush()
        scan_id = scan.id
        db.commit()

    packages, _ = ScanManager.normalize({"Results": [{
        "Target": "Python",
        "Packages": [{
            "Name": "Cython", "Version": "3.2.4",
            "Identifier": {"PURL": "pkg:pypi/cython@3.2.4", "UID": "7bea341fa66f632c"},
            "Licenses": ["Apache-2.0"],
        }],
    }]}, scan_id)
    assert len(packages) == 1
    assert packages[0].identifier == "pkg:pypi/cython@3.2.4"
    assert packages[0].licenses == "Apache-2.0"
    assert all(isinstance(value, str) for value in (
        packages[0].target, packages[0].name, packages[0].version,
        packages[0].identifier, packages[0].licenses,
    ))
    with SessionLocal() as db:
        db.add(packages[0])
        db.commit()
        db.refresh(packages[0])
        assert packages[0].identifier == "pkg:pypi/cython@3.2.4"
        db.get(Scan, scan_id).status = "completed"
        db.commit()


def test_persisted_running_job_is_recovered_and_can_be_cancelled():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        image = ImageArchive(path="/images/recovery-test.tar", name="recovery-test.tar", size=1,
                             modified_at=datetime.now(timezone.utc))
        db.add(image); db.flush()
        scan = Scan(image_id=image.id, status="running", progress=58, stage="scanning", message="Scanning")
        db.add(scan); db.commit(); scan_id = scan.id

    manager = ScanManager()
    asyncio.run(manager.recover_jobs())
    assert scan_id in manager.queued_ids
    assert manager.queue.get_nowait() == scan_id

    with SessionLocal() as db:
        recovered = db.get(Scan, scan_id)
        assert recovered.status == "queued"
        assert recovered.stage == "recovered"
        assert recovered.progress == 0

    assert asyncio.run(manager.cancel(scan_id)) == "cancelled"
    with SessionLocal() as db:
        assert db.get(Scan, scan_id).status == "cancelled"
