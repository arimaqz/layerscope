import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.components import component_payloads, database_info, maintenance_environment, maintenance_workspace
from app.config import settings
from app.database import Base


def test_database_info_reads_metadata_and_update_window(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "trivy_cache_dir", tmp_path)
    database = tmp_path / "db"
    database.mkdir()
    now = datetime.now(timezone.utc)
    metadata = {
        "Version": 2,
        "UpdatedAt": (now - timedelta(hours=7)).isoformat().replace("+00:00", "Z"),
        "NextUpdate": (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    }
    (database / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    (database / "trivy.db").write_bytes(b"database")

    info = database_info("vulnerability_db")

    assert info["installed"] is True
    assert info["update_available"] is True
    assert info["size_bytes"] > 0
    assert info["metadata"]["Version"] == 2


def test_database_info_marks_missing_optional_java_database(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "trivy_cache_dir", tmp_path)

    info = database_info("java_db")

    assert info["installed"] is False
    assert info["update_available"] is False
    assert info["size_bytes"] == 0


def test_maintenance_workspace_uses_configured_storage_and_cleans_up(tmp_path, monkeypatch):
    workspace_root = tmp_path / "component-tmp"
    monkeypatch.setattr(settings, "component_temp_dir", workspace_root)

    with maintenance_workspace(42) as workspace:
        assert workspace.parent == workspace_root
        assert workspace.name.startswith("job-42-")
        environment = maintenance_environment(workspace)
        assert environment["TMPDIR"] == str(workspace)
        assert environment["TMP"] == str(workspace)
        assert environment["TEMP"] == str(workspace)
        (workspace / "artifact.part").write_bytes(b"temporary")
        temporary_path = workspace

    assert workspace_root.is_dir()
    assert not temporary_path.exists()


def test_component_inventory_includes_installed_and_missing_components(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "trivy_cache_dir", tmp_path / "cache")
    monkeypatch.setattr(settings, "trivy_seed_cache_dir", tmp_path / "seed")
    monkeypatch.setattr(settings, "trivy_binary", "missing-trivy-for-test")
    database = settings.trivy_cache_dir / "db"
    database.mkdir(parents=True)
    now = datetime.now(timezone.utc)
    (database / "metadata.json").write_text(json.dumps({
        "UpdatedAt": now.isoformat(),
        "NextUpdate": (now + timedelta(hours=6)).isoformat(),
    }), encoding="utf-8")
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    components = component_payloads(session)
    by_id = {component["id"]: component for component in components}

    assert set(by_id) == {"vulnerability_db", "java_db", "trivy_engine", "checks_bundle", "vex_hub"}
    assert by_id["vulnerability_db"]["installed"] is True
    assert by_id["vulnerability_db"]["required"] is True
    assert by_id["java_db"]["installed"] is False
    assert by_id["java_db"]["required"] is False
