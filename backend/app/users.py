from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from .auth import (audit, aware, dummy_password_hash, new_activation_code, normalize_username,
                   require_roles, utcnow)
from .database import get_db
from .models import ApiToken, AuditEvent, AuthSession, RecoveryCode, User


router = APIRouter(prefix="/api/users", tags=["users"])
ROLES = {"viewer", "operator", "admin"}


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=1, max_length=100)
    role: str = "viewer"


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    role: str | None = None
    active: bool | None = None


def status_for(user: User):
    if user.active:
        return "active"
    if user.activation_token_hash:
        if user.activation_expires_at and aware(user.activation_expires_at) <= utcnow():
            return "activation_expired"
        return "pending_activation"
    return "disabled"


def payload(user: User):
    return {"id": user.id, "username": user.username, "display_name": user.display_name,
            "role": user.role, "active": user.active, "totp_enabled": user.totp_enabled,
            "status": status_for(user), "activation_expires_at": user.activation_expires_at,
            "locked_until": user.locked_until, "failed_login_count": user.failed_login_count,
            "created_at": user.created_at, "updated_at": user.updated_at}


def ensure_role(role: str):
    normalized = role.strip().casefold()
    if normalized not in ROLES:
        raise HTTPException(400, "Role must be viewer, operator, or admin")
    return normalized


def ensure_not_last_admin(db: Session, target: User, next_role: str, next_active: bool):
    removes_admin = target.role == "admin" and target.active and (next_role != "admin" or not next_active)
    if removes_admin:
        count = db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.active.is_(True))) or 0
        if count <= 1:
            raise HTTPException(409, "The last active administrator cannot be disabled or demoted")


def revoke_credentials(db: Session, user_id: int):
    db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))
    db.execute(update(ApiToken).where(ApiToken.user_id == user_id, ApiToken.revoked_at.is_(None))
               .values(revoked_at=utcnow()).execution_options(synchronize_session="fetch"))


@router.get("")
def list_users(db: Session = Depends(get_db), _actor=Depends(require_roles("admin"))):
    return [payload(user) for user in db.scalars(select(User).order_by(User.username)).all()]


@router.post("", status_code=201)
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db), actor=Depends(require_roles("admin"))):
    username = normalize_username(body.username)
    display_name = body.display_name.strip()
    role = ensure_role(body.role)
    if not display_name:
        raise HTTPException(400, "Display name cannot be blank")
    if db.scalar(select(User.id).where(User.username == username)):
        raise HTTPException(409, "That username is already in use")
    code, code_hash, expires_at = new_activation_code()
    user = User(username=username, display_name=display_name, password_hash=dummy_password_hash,
                role=role, active=False, totp_enabled=False,
                activation_token_hash=code_hash, activation_expires_at=expires_at)
    db.add(user); db.flush()
    audit(db, "user_create", "success", request, actor.id,
          {"target_user_id": user.id, "target_username": username, "role": role})
    db.commit()
    return {"user": payload(user), "activation_code": code, "activation_expires_at": expires_at}


@router.post("/{user_id}/update")
def update_user(user_id: int, body: UserUpdate, request: Request, db: Session = Depends(get_db), actor=Depends(require_roles("admin"))):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    next_role = ensure_role(body.role) if body.role is not None else target.role
    next_active = body.active if body.active is not None else target.active
    if target.id == actor.id and (next_role != "admin" or not next_active):
        raise HTTPException(409, "You cannot disable or remove your own administrator access")
    if next_active and not target.totp_enabled:
        raise HTTPException(409, "The user must complete activation and 2FA enrollment before being enabled")
    ensure_not_last_admin(db, target, next_role, next_active)
    changes = {}
    if body.display_name is not None:
        display_name = body.display_name.strip()
        if not display_name:
            raise HTTPException(400, "Display name cannot be blank")
        if display_name != target.display_name:
            changes["display_name"] = display_name; target.display_name = display_name
    if next_role != target.role:
        changes["role"] = {"from": target.role, "to": next_role}; target.role = next_role
        revoke_credentials(db, target.id)
    if next_active != target.active:
        changes["active"] = next_active; target.active = next_active
        if not next_active:
            revoke_credentials(db, target.id)
    audit(db, "user_update", "success", request, actor.id,
          {"target_user_id": target.id, "target_username": target.username, "changes": changes})
    db.commit()
    return payload(target)


@router.post("/{user_id}/reissue-activation")
def reissue_activation(user_id: int, request: Request, db: Session = Depends(get_db), actor=Depends(require_roles("admin"))):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == actor.id:
        raise HTTPException(409, "Use a self-service security flow for your own account")
    ensure_not_last_admin(db, target, target.role, False)
    code, code_hash, expires_at = new_activation_code()
    revoke_credentials(db, target.id)
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == target.id))
    target.password_hash = dummy_password_hash
    target.active = False; target.totp_enabled = False
    target.totp_secret_encrypted = None; target.last_totp_step = None
    target.activation_token_hash = code_hash; target.activation_expires_at = expires_at
    target.failed_login_count = 0; target.locked_until = None
    audit(db, "user_activation_reissue", "success", request, actor.id,
          {"target_user_id": target.id, "target_username": target.username})
    db.commit()
    return {"user": payload(target), "activation_code": code, "activation_expires_at": expires_at}


@router.post("/{user_id}/reissue-2fa")
def reissue_2fa(user_id: int, request: Request, db: Session = Depends(get_db), actor=Depends(require_roles("admin"))):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == actor.id:
        raise HTTPException(409, "An administrator cannot reissue their own 2FA enrollment")
    if not target.active or not target.totp_enabled:
        raise HTTPException(409, "2FA can only be reissued for an active, enrolled user")
    code, code_hash, expires_at = new_activation_code()
    revoke_credentials(db, target.id)
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == target.id))
    target.mfa_reset_token_hash = code_hash
    target.mfa_reset_expires_at = expires_at
    target.failed_login_count = 0
    target.locked_until = None
    audit(db, "user_2fa_reissue", "success", request, actor.id,
          {"target_user_id": target.id, "target_username": target.username})
    db.commit()
    return {"user": payload(target), "reissue_code": code, "reissue_expires_at": expires_at}


@router.post("/{user_id}/unlock")
def unlock_user(user_id: int, request: Request, db: Session = Depends(get_db), actor=Depends(require_roles("admin"))):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    target.failed_login_count = 0; target.locked_until = None
    audit(db, "user_unlock", "success", request, actor.id,
          {"target_user_id": target.id, "target_username": target.username})
    db.commit()
    return payload(target)


@router.delete("/{user_id}")
def remove_user(user_id: int, request: Request, db: Session = Depends(get_db), actor=Depends(require_roles("admin"))):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == actor.id:
        raise HTTPException(409, "You cannot remove your own account")
    ensure_not_last_admin(db, target, target.role, False)
    target_details = {"target_user_id": target.id, "target_username": target.username,
                      "target_display_name": target.display_name, "target_role": target.role}
    revoke_credentials(db, target.id)
    db.execute(delete(ApiToken).where(ApiToken.user_id == target.id))
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == target.id))
    db.execute(update(AuditEvent).where(AuditEvent.user_id == target.id).values(user_id=None))
    audit(db, "user_delete", "success", request, actor.id, target_details)
    db.delete(target)
    db.commit()
    return {"deleted": True, "user_id": user_id, "username": target_details["target_username"]}
