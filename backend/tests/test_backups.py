import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.backups import (BackupError, create_encrypted_backup, replace_with_restore, safe_member,
                         stage_encrypted_backup, validate_sqlite)
from app.config import settings


def sample_database(path: Path):
    with sqlite3.connect(path) as connection:
        for table in ("users", "images", "scans", "findings", "packages", "image_groups", "auth_sessions"):
            connection.execute(f'CREATE TABLE "{table}" (id INTEGER PRIMARY KEY, value TEXT)')
        connection.execute("INSERT INTO users (value) VALUES ('admin')")
        connection.execute("INSERT INTO images (value) VALUES ('example.tar')")
        connection.execute("INSERT INTO scans (value) VALUES ('completed')")
        connection.execute("INSERT INTO findings (value) VALUES ('CVE-2026-0001')")
        connection.execute("INSERT INTO auth_sessions (value) VALUES ('session must be revoked')")
        connection.commit()


def test_encrypted_backup_round_trip_and_integrity(tmp_path: Path):
    database = tmp_path / "trivy.db"
    auth = tmp_path / "auth.key"
    raw = tmp_path / "raw"
    uploads = tmp_path / "uploads"
    backup = tmp_path / "portable.tdbackup"
    stage = tmp_path / "stage"
    sample_database(database)
    auth.write_bytes(Fernet.generate_key() + b"\n")
    raw.mkdir(); uploads.mkdir()
    (raw / "scan-1.json").write_text('{"secret-evidence":true}', encoding="utf-8")
    (uploads / "example.tar").write_bytes(b"sample docker archive")

    manifest = create_encrypted_backup(backup, "correct horse backup phrase", database, auth, raw, uploads)

    assert backup.read_bytes().startswith(b"TRIVYDBBACKUP")
    assert b"secret-evidence" not in backup.read_bytes()
    assert manifest["summary"]["images"] == 1
    restored = stage_encrypted_backup(backup, "correct horse backup phrase", stage, 10_000_000)
    assert restored["summary"]["scans"] == 1
    assert (stage / "raw/scan-1.json").read_text(encoding="utf-8") == '{"secret-evidence":true}'
    assert (stage / "uploads/example.tar").read_bytes() == b"sample docker archive"
    assert (stage / "auth.key").read_bytes() == auth.read_bytes()


def test_backup_rejects_wrong_password_and_tampering(tmp_path: Path):
    database = tmp_path / "trivy.db"
    auth = tmp_path / "auth.key"
    raw = tmp_path / "raw"
    uploads = tmp_path / "uploads"
    backup = tmp_path / "portable.tdbackup"
    sample_database(database)
    auth.write_bytes(Fernet.generate_key())
    raw.mkdir(); uploads.mkdir()
    create_encrypted_backup(backup, "correct horse backup phrase", database, auth, raw, uploads)

    with pytest.raises(BackupError, match="password is wrong|modified"):
        stage_encrypted_backup(backup, "incorrect horse backup phrase", tmp_path / "wrong", 10_000_000)

    tampered = bytearray(backup.read_bytes())
    tampered[-20] ^= 1
    damaged = tmp_path / "damaged.tdbackup"
    damaged.write_bytes(tampered)
    with pytest.raises(BackupError, match="password is wrong|modified"):
        stage_encrypted_backup(damaged, "correct horse backup phrase", tmp_path / "damaged", 10_000_000)


def test_backup_member_path_validation():
    assert safe_member("database.sqlite")
    assert safe_member("raw/scan.json")
    assert safe_member("uploads/image.tar")
    assert not safe_member("../auth.key")
    assert not safe_member("/etc/passwd")
    assert not safe_member("raw/../../escape")
    assert not safe_member("other/file")


def test_backup_database_rejects_executable_schema(tmp_path: Path):
    database = tmp_path / "unsafe.db"
    sample_database(database)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE VIEW exposed_users AS SELECT * FROM users")
        connection.commit()
    with pytest.raises(BackupError, match="executable schema"):
        validate_sqlite(database)


def test_validated_restore_replaces_data_and_revokes_sessions(tmp_path: Path, monkeypatch):
    current_db = tmp_path / "current.db"
    source_db = tmp_path / "source.db"
    current_auth = tmp_path / "current-auth.key"
    source_auth = tmp_path / "source-auth.key"
    current_raw, current_uploads = tmp_path / "current-raw", tmp_path / "current-uploads"
    source_raw, source_uploads = tmp_path / "source-raw", tmp_path / "source-uploads"
    backup_dir = tmp_path / "backups"
    backup = tmp_path / "restore.tdbackup"
    stage = backup_dir / "restore-0123456789abcdef0123456789abcdef"
    sample_database(current_db); sample_database(source_db)
    with sqlite3.connect(source_db) as connection:
        connection.execute("UPDATE images SET value='restored.tar'")
        connection.commit()
    current_auth.write_bytes(Fernet.generate_key()); source_auth.write_bytes(Fernet.generate_key())
    for directory in (current_raw, current_uploads, source_raw, source_uploads, backup_dir):
        directory.mkdir()
    (current_raw / "old.json").write_text("old", encoding="utf-8")
    (current_uploads / "old.tar").write_bytes(b"old")
    (source_raw / "restored.json").write_text("restored", encoding="utf-8")
    (source_uploads / "restored.tar").write_bytes(b"restored")
    create_encrypted_backup(backup, "correct horse backup phrase", source_db, source_auth, source_raw, source_uploads)
    stage_encrypted_backup(backup, "correct horse backup phrase", stage, 10_000_000)

    monkeypatch.setattr(settings, "database_url", f"sqlite:///{current_db}")
    monkeypatch.setattr(settings, "auth_key_path", current_auth)
    monkeypatch.setattr(settings, "raw_results_dir", current_raw)
    monkeypatch.setattr(settings, "upload_dir", current_uploads)
    monkeypatch.setattr(settings, "backup_dir", backup_dir)
    replace_with_restore(stage)

    with sqlite3.connect(current_db) as connection:
        assert connection.execute("SELECT value FROM images").fetchone()[0] == "restored.tar"
        assert connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0
    assert current_auth.read_bytes() == source_auth.read_bytes()
    assert not (current_raw / "old.json").exists()
    assert (current_raw / "restored.json").read_text(encoding="utf-8") == "restored"
    assert not (current_uploads / "old.tar").exists()
    assert (current_uploads / "restored.tar").read_bytes() == b"restored"
    assert (backup_dir / "last-restore.json").is_file()
    assert not stage.exists()
