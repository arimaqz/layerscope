from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.admin_recovery import AdminRecoveryError, reset_admin_password
from app.auth import encrypt_secret, password_hasher, recovery_hash
from app.config import settings
from app.database import Base
from app.models import ApiToken, AuditEvent, AuthSession, RecoveryCode, User


def isolated_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def enrolled_admin(db, secret: str):
    user = User(username="admin", display_name="Local Admin",
                password_hash=password_hasher.hash("original synthetic passphrase 2026"),
                role="admin", active=True, totp_enabled=True,
                totp_secret_encrypted=encrypt_secret(secret), failed_login_count=3,
                locked_until=datetime.now(timezone.utc) + timedelta(minutes=10))
    db.add(user); db.flush()
    db.add(AuthSession(token_hash="a" * 64, user_id=user.id, csrf_token="csrf",
                       auth_level="full", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
    db.add(ApiToken(user_id=user.id, name="Synthetic automation", token_hash="b" * 64,
                    token_prefix="lsp_example", expires_at=datetime.now(timezone.utc) + timedelta(days=30)))
    db.commit()
    return user


def test_server_local_admin_password_reset_preserves_totp_and_revokes_sessions(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "auth_key_path", tmp_path / "auth.key")
    db = isolated_session()
    secret = pyotp.random_base32(length=32)
    user = enrolled_admin(db, secret)
    encrypted_secret = user.totp_secret_encrypted

    result = reset_admin_password(db, None, "replacement synthetic passphrase 2026", pyotp.TOTP(secret).now())

    db.refresh(user)
    assert result["sessions_revoked"] is True
    assert result["api_tokens_revoked"] is True
    assert password_hasher.verify(user.password_hash, "replacement synthetic passphrase 2026")
    assert user.totp_secret_encrypted == encrypted_secret
    assert user.totp_enabled is True
    assert user.failed_login_count == 0
    assert user.locked_until is None
    assert db.scalar(select(func.count()).select_from(AuthSession)) == 0
    api_token = db.scalar(select(ApiToken))
    assert api_token.revoked_at is not None
    event = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()))
    assert event.action == "admin_password_recovery"
    assert event.outcome == "success"
    assert event.ip_address == "local-console"


def test_server_local_admin_password_reset_accepts_and_consumes_recovery_code(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "auth_key_path", tmp_path / "auth.key")
    db = isolated_session()
    user = enrolled_admin(db, pyotp.random_base32(length=32))
    code = "ABCD-EF01-2345-6789"
    recovery = RecoveryCode(user_id=user.id, code_hash=recovery_hash(code))
    db.add(recovery); db.commit()

    result = reset_admin_password(db, "admin", "replacement recovery passphrase 2026", code)
    db.refresh(recovery)

    assert result["recovery_code_used"] is True
    assert recovery.used_at is not None
    with pytest.raises(AdminRecoveryError, match="already-used"):
        reset_admin_password(db, "admin", "another replacement passphrase 2026", code)


def test_server_local_password_reset_rejects_non_admin_and_password_reuse(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "auth_key_path", tmp_path / "auth.key")
    db = isolated_session()
    secret = pyotp.random_base32(length=32)
    enrolled_admin(db, secret)
    viewer = User(username="viewer", display_name="Viewer",
                  password_hash=password_hasher.hash("viewer synthetic passphrase 2026"),
                  role="viewer", active=True, totp_enabled=True,
                  totp_secret_encrypted=encrypt_secret(pyotp.random_base32(length=32)))
    db.add(viewer); db.commit()

    with pytest.raises(AdminRecoveryError, match="verification failed"):
        reset_admin_password(db, "viewer", "replacement viewer passphrase 2026", "000000")
    with pytest.raises(AdminRecoveryError, match="must differ"):
        reset_admin_password(db, "admin", "original synthetic passphrase 2026", pyotp.TOTP(secret).now())
