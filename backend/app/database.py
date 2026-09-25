from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .config import settings


class Base(DeclarativeBase):
    pass


connect_args = {"check_same_thread": False, "timeout": 15} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


if settings.database_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def configure_sqlite(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=15000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA wal_autocheckpoint=1000")
        cursor.execute("PRAGMA cache_size=-16384")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.close()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def apply_schema_upgrades():
    """Apply small additive upgrades without requiring users to discard their SQLite volume."""
    tables = inspect(engine).get_table_names()
    with engine.begin() as connection:
        if "scans" in tables:
            columns = {column["name"] for column in inspect(engine).get_columns("scans")}
            additions = {
                "progress": "INTEGER NOT NULL DEFAULT 0",
                "stage": "VARCHAR(40) NOT NULL DEFAULT 'queued'",
                "message": "TEXT NOT NULL DEFAULT 'Waiting for an available worker'",
                "updated_at": "DATETIME",
                "coverage_warning": "TEXT",
            }
            for name, definition in additions.items():
                if name not in columns:
                    connection.execute(text(f"ALTER TABLE scans ADD COLUMN {name} {definition}"))
            connection.execute(text("UPDATE scans SET progress = CASE WHEN status = 'completed' THEN 100 ELSE 0 END "
                                    "WHERE progress IS NULL OR (status = 'completed' AND progress != 100)"))
            connection.execute(text("UPDATE scans SET stage = COALESCE(NULLIF(stage, ''), status, 'queued') "
                                    "WHERE stage IS NULL OR stage = ''"))
            connection.execute(text("UPDATE scans SET message = '' WHERE message IS NULL"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_image_id_id ON scans (image_id, id)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_status_queued_at_id ON scans (status, queued_at, id)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_image_status_id ON scans (image_id, status, id)"))
        if "users" in tables:
            user_columns = {column["name"] for column in inspect(engine).get_columns("users")}
            if "activation_token_hash" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN activation_token_hash VARCHAR(64)"))
            if "activation_expires_at" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN activation_expires_at DATETIME"))
            if "mfa_reset_token_hash" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN mfa_reset_token_hash VARCHAR(64)"))
            if "mfa_reset_expires_at" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN mfa_reset_expires_at DATETIME"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_users_activation_token_hash ON users (activation_token_hash)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_users_mfa_reset_token_hash ON users (mfa_reset_token_hash)"))
        if "images" in tables:
            image_columns = {column["name"] for column in inspect(engine).get_columns("images")}
            if "hidden" not in image_columns:
                connection.execute(text("ALTER TABLE images ADD COLUMN hidden BOOLEAN NOT NULL DEFAULT 0"))
            if "removed_at" not in image_columns:
                connection.execute(text("ALTER TABLE images ADD COLUMN removed_at DATETIME"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_images_hidden ON images (hidden)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_images_hidden_name ON images (hidden, name)"))
        if "findings" in tables:
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_scan_severity ON findings (scan_id, severity)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_scan_package ON findings (scan_id, package_name)"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_scan_target ON findings (scan_id, target)"))
        if "packages" in tables:
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_packages_scan_name ON packages (scan_id, name)"))
        if settings.database_url.startswith("sqlite"):
            connection.execute(text("PRAGMA optimize"))
