from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.database import Base
from app.main import remove_image_record, remove_scan_record, remove_scan_records
from app.models import Finding, ImageArchive, Package, Scan


def isolated_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_remove_scan_deletes_normalized_and_raw_data(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "raw_results_dir", tmp_path)
    raw = tmp_path / "scan-1.json"
    raw.write_text("{}", encoding="utf-8")
    db = isolated_session()
    image = ImageArchive(path="/images/example.tar", name="example.tar", size=1,
                         modified_at=datetime.now(timezone.utc))
    db.add(image); db.flush()
    scan = Scan(image_id=image.id, status="completed", raw_json_path=str(raw))
    db.add(scan); db.flush()
    db.add(Finding(scan_id=scan.id, target="os", vulnerability_id="CVE-1", package_name="pkg",
                   installed_version="1", fixed_version="2", severity="HIGH", title="", description="", primary_url=""))
    db.add(Package(scan_id=scan.id, target="os", name="pkg", version="1", identifier="", licenses=""))
    db.commit()

    remove_scan_record(db, scan)
    db.commit()

    assert not raw.exists()
    assert db.scalar(select(func.count()).select_from(Scan)) == 0
    assert db.scalar(select(func.count()).select_from(Finding)) == 0
    assert db.scalar(select(func.count()).select_from(Package)) == 0
    assert db.scalar(select(func.count()).select_from(ImageArchive)) == 1


def test_remove_scan_rejects_active_work():
    db = isolated_session()
    image = ImageArchive(path="/images/active.tar", name="active.tar", size=1,
                         modified_at=datetime.now(timezone.utc))
    db.add(image); db.flush()
    scan = Scan(image_id=image.id, status="running")
    db.add(scan); db.commit()

    with pytest.raises(HTTPException) as error:
        remove_scan_record(db, scan)

    assert error.value.status_code == 409
    assert db.get(Scan, scan.id) is not None


def test_bulk_remove_scans_is_prevalidated_and_deletes_all_terminal_records(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "raw_results_dir", tmp_path)
    db = isolated_session()
    image = ImageArchive(path="/images/bulk.tar", name="bulk.tar", size=1,
                         modified_at=datetime.now(timezone.utc))
    db.add(image)
    db.flush()
    completed = Scan(image_id=image.id, status="completed", raw_json_path=str(tmp_path / "completed.json"))
    failed = Scan(image_id=image.id, status="failed", raw_json_path=str(tmp_path / "failed.json"))
    active = Scan(image_id=image.id, status="running")
    db.add_all([completed, failed, active])
    db.commit()
    for path in (tmp_path / "completed.json", tmp_path / "failed.json"):
        path.write_text("{}", encoding="utf-8")

    with pytest.raises(HTTPException) as error:
        remove_scan_records(db, [completed, active, failed])
    assert error.value.status_code == 409
    assert (tmp_path / "completed.json").exists()
    assert db.get(Scan, completed.id) is not None

    remove_scan_records(db, [completed, failed])
    db.commit()
    assert db.get(Scan, completed.id) is None
    assert db.get(Scan, failed.id) is None
    assert db.get(Scan, active.id) is not None
    assert not (tmp_path / "completed.json").exists()
    assert not (tmp_path / "failed.json").exists()


def test_remove_uploaded_image_deletes_archive_and_mounted_image_is_hidden(tmp_path, monkeypatch):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(settings, "upload_dir", upload_dir)
    db = isolated_session()
    uploaded_path = upload_dir / "uploaded.tar"
    uploaded_path.write_bytes(b"tar")
    uploaded = ImageArchive(path=str(uploaded_path), name=uploaded_path.name, size=3,
                            modified_at=datetime.now(timezone.utc))
    mounted = ImageArchive(path="/images/mounted.tar", name="mounted.tar", size=3,
                           modified_at=datetime.now(timezone.utc))
    db.add_all([uploaded, mounted]); db.commit()

    uploaded_result = remove_image_record(db, uploaded)
    mounted_result = remove_image_record(db, mounted)
    db.commit()

    assert uploaded_result["uploaded_archive_deleted"] is True
    assert not uploaded_path.exists()
    assert db.get(ImageArchive, uploaded.id) is None
    assert mounted_result["restorable"] is True
    assert db.get(ImageArchive, mounted.id).hidden is True


def test_remove_report_only_image_deletes_database_record_without_touching_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "upload_dir", tmp_path / "uploads")
    db = isolated_session()
    image = ImageArchive(path="report://" + "a" * 64, name="historical-example.tar", size=0,
                         modified_at=datetime.now(timezone.utc))
    db.add(image); db.flush()
    scan = Scan(image_id=image.id, status="completed", progress=100, stage="imported_report",
                raw_json_path="report-import:" + "b" * 64)
    db.add(scan); db.commit()

    result = remove_image_record(db, image)
    db.commit()

    assert result["source"] == "report"
    assert result["restorable"] is False
    assert result["uploaded_archive_deleted"] is False
    assert db.get(ImageArchive, image.id) is None
