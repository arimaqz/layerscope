import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .auth import audit, aware, require_session_auth, token_hash, utcnow
from .config import settings
from .database import get_db
from .models import ApiToken


router = APIRouter(prefix="/api/api-tokens", tags=["API tokens"])


class ApiTokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    expires_in_days: int = Field(default=90, ge=1, le=365)


def payload(api_token: ApiToken):
    now = utcnow()
    status = "revoked" if api_token.revoked_at else ("expired" if aware(api_token.expires_at) <= now else "active")
    return {"id": api_token.id, "name": api_token.name, "token_prefix": api_token.token_prefix,
            "created_at": api_token.created_at, "expires_at": api_token.expires_at,
            "last_used_at": api_token.last_used_at, "revoked_at": api_token.revoked_at, "status": status}


@router.get("")
def list_api_tokens(db: Session = Depends(get_db), actor=Depends(require_session_auth)):
    return [payload(item) for item in db.scalars(select(ApiToken).where(ApiToken.user_id == actor.id)
                                                 .order_by(ApiToken.created_at.desc(), ApiToken.id.desc())).all()]


@router.post("", status_code=201)
def create_api_token(body: ApiTokenCreate, request: Request, db: Session = Depends(get_db),
                     actor=Depends(require_session_auth)):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Token name cannot be blank")
    now = utcnow()
    active = db.scalar(select(func.count()).select_from(ApiToken).where(
        ApiToken.user_id == actor.id, ApiToken.revoked_at.is_(None), ApiToken.expires_at > now)) or 0
    if active >= settings.auth_max_api_tokens_per_user:
        raise HTTPException(409, f"Revoke an existing token before creating more than {settings.auth_max_api_tokens_per_user}")
    raw_token = "lsp_" + secrets.token_urlsafe(32)
    api_token = ApiToken(user_id=actor.id, name=name, token_hash=token_hash(raw_token),
                         token_prefix=raw_token[:12], created_at=now,
                         expires_at=now + timedelta(days=body.expires_in_days))
    db.add(api_token)
    db.flush()
    audit(db, "api_token_create", "success", request, actor.id,
          {"api_token_id": api_token.id, "name": name, "expires_at": api_token.expires_at.isoformat()})
    db.commit()
    return {**payload(api_token), "token": raw_token}


@router.delete("/{token_id}")
def revoke_api_token(token_id: int, request: Request, db: Session = Depends(get_db),
                     actor=Depends(require_session_auth)):
    api_token = db.scalar(select(ApiToken).where(ApiToken.id == token_id, ApiToken.user_id == actor.id))
    if not api_token:
        raise HTTPException(404, "API token not found")
    if not api_token.revoked_at:
        api_token.revoked_at = utcnow()
        audit(db, "api_token_revoke", "success", request, actor.id,
              {"api_token_id": api_token.id, "name": api_token.name})
        db.commit()
    return payload(api_token)
