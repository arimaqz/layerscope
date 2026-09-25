import json

from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException
from sqlalchemy import delete, select, text, update
from sqlalchemy.orm import Session

from .auth import (normalize_username, password_hasher, recovery_hash, utcnow,
                   validate_password, verify_totp)
from .models import ApiToken, AuditEvent, AuthSession, RecoveryCode, User


class AdminRecoveryError(ValueError):
    pass


def _audit(db: Session, user: User | None, outcome: str, details: dict):
    db.add(AuditEvent(user_id=user.id if user else None, action="admin_password_recovery",
                      outcome=outcome, ip_address="local-console",
                      details=json.dumps(details, ensure_ascii=True)[:4000]))


def _active_admin(db: Session, username: str | None) -> User:
    if username:
        try:
            normalized = normalize_username(username)
        except HTTPException as exc:
            _audit(db, None, "denied", {"method": "server_console", "reason": "ineligible_account"})
            db.commit()
            raise AdminRecoveryError("Recovery verification failed") from exc
        user = db.scalar(select(User).where(User.username == normalized, User.role == "admin",
                                            User.active.is_(True), User.totp_enabled.is_(True)))
        if not user:
            _audit(db, None, "denied", {"method": "server_console", "reason": "ineligible_account"})
            db.commit()
            raise AdminRecoveryError("Recovery verification failed")
        return user
    admins = db.scalars(select(User).where(User.role == "admin", User.active.is_(True),
                                           User.totp_enabled.is_(True)).order_by(User.id).limit(2)).all()
    if len(admins) != 1:
        db.rollback()
        raise AdminRecoveryError("Specify --username when there is not exactly one active administrator")
    return admins[0]


def reset_admin_password(db: Session, username: str | None, new_password: str, mfa_code: str) -> dict:
    if db.bind and db.bind.dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))
    user = _active_admin(db, username)
    try:
        validate_password(new_password, user.username)
    except HTTPException as exc:
        _audit(db, user, "denied", {"method": "server_console", "reason": "password_policy"})
        db.commit()
        raise AdminRecoveryError(str(exc.detail)) from exc
    try:
        if password_hasher.verify(user.password_hash, new_password):
            _audit(db, user, "denied", {"method": "server_console", "reason": "password_reuse"})
            db.commit()
            raise AdminRecoveryError("The new password must differ from the current password")
    except VerifyMismatchError:
        pass

    supplied = mfa_code.strip()
    step = verify_totp(user, supplied)
    recovery = None
    if step is None and supplied:
        candidate = recovery_hash(supplied)
        recovery = db.scalar(select(RecoveryCode).where(
            RecoveryCode.user_id == user.id, RecoveryCode.code_hash == candidate,
            RecoveryCode.used_at.is_(None)))
    if step is None and recovery is None:
        _audit(db, user, "denied", {"method": "server_console", "reason": "mfa_verification"})
        db.commit()
        raise AdminRecoveryError("Invalid or already-used authenticator/recovery code")

    if step is not None:
        user.last_totp_step = step
    if recovery is not None:
        recovery.used_at = utcnow()
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id))
    db.execute(update(ApiToken).where(ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None))
               .values(revoked_at=utcnow()).execution_options(synchronize_session="fetch"))
    user.password_hash = password_hasher.hash(new_password)
    user.failed_login_count = 0
    user.locked_until = None
    user.activation_token_hash = None
    user.activation_expires_at = None
    user.mfa_reset_token_hash = None
    user.mfa_reset_expires_at = None
    _audit(db, user, "success", {"method": "server_console",
                                 "recovery_code_used": recovery is not None,
                                 "sessions_revoked": True, "api_tokens_revoked": True})
    db.commit()
    return {"user_id": user.id, "username": user.username,
            "recovery_code_used": recovery is not None, "sessions_revoked": True,
            "api_tokens_revoked": True}
