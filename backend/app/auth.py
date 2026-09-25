import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from .config import settings
from .database import SessionLocal, get_db
from .models import ApiToken, AuditEvent, AuthSession, RecoveryCode, User
from .security import client_ip


router = APIRouter(prefix="/api/auth", tags=["authentication"])
password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
dummy_password_hash = password_hasher.hash(secrets.token_urlsafe(32))
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{3,64}$")
COMMON_PASSWORDS = {"password", "password123", "admin123", "qwerty123", "letmein123", "changeme123", "trivydashboard", "layerscope"}
PUBLIC_API_PATHS = {"/api/health", "/api/auth/status", "/api/auth/setup", "/api/auth/activate", "/api/auth/reenroll-2fa", "/api/auth/login", "/api/auth/totp/verify"}
API_TOKEN_PATTERN = re.compile(r"^lsp_[A-Za-z0-9_-]{43}$")


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)


class SetupRequest(Credentials):
    display_name: str = Field(min_length=1, max_length=100)


class ActivationRequest(Credentials):
    activation_code: str = Field(min_length=20, max_length=200)


class ReenrollRequest(Credentials):
    reissue_code: str = Field(min_length=20, max_length=200)


class TotpRequest(BaseModel):
    code: str = Field(min_length=6, max_length=32)
    csrf_token: str = Field(min_length=20, max_length=200)


def utcnow():
    return datetime.now(timezone.utc)


def aware(value: datetime):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def token_hash(token: str):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_activation_code():
    code = secrets.token_urlsafe(32)
    return code, token_hash(code), utcnow() + timedelta(hours=settings.auth_activation_hours)


def normalize_username(username: str):
    value = username.strip().casefold()
    if not USERNAME_PATTERN.fullmatch(value):
        raise HTTPException(400, "Username must be 3-64 characters using letters, numbers, dot, underscore, or hyphen")
    return value


def validate_password(password: str, username: str):
    if len(password) < 12 or len(password) > 128:
        raise HTTPException(400, "Password must be between 12 and 128 characters")
    lowered = password.casefold()
    if lowered in COMMON_PASSWORDS or username in lowered:
        raise HTTPException(400, "Choose a less predictable password that does not contain the username")


def auth_key() -> bytes:
    path = settings.auth_key_path
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        key = path.read_bytes().strip()
    except FileNotFoundError:
        key = Fernet.generate_key()
        try:
            with path.open("xb") as output:
                output.write(key + b"\n")
            os.chmod(path, 0o600)
        except FileExistsError:
            key = path.read_bytes().strip()
    Fernet(key)
    return key


def encrypt_secret(secret: str):
    return Fernet(auth_key()).encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_secret(encrypted: str):
    try:
        return Fernet(auth_key()).decrypt(encrypted.encode("ascii")).decode("ascii")
    except InvalidToken as exc:
        raise HTTPException(500, "The local authentication key cannot decrypt the TOTP secret") from exc


def recovery_hash(code: str):
    normalized = code.replace("-", "").strip().upper().encode("ascii", errors="ignore")
    return hmac.new(auth_key(), normalized, hashlib.sha256).hexdigest()


def generate_recovery_codes(count: int = 10):
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(8).upper()
        codes.append("-".join(raw[index:index + 4] for index in range(0, 16, 4)))
    return codes


def audit(db: Session, action: str, outcome: str, request: Request, user_id: int | None = None, details: dict | None = None):
    safe_details = dict(details or {})
    request_id = getattr(request.state, "request_id", None)
    if request_id:
        safe_details["request_id"] = request_id
    db.add(AuditEvent(user_id=user_id, action=action, outcome=outcome,
                      ip_address=client_ip(request),
                      details=json.dumps(safe_details, ensure_ascii=True)[:4000]))


def create_session(db: Session, user: User, request: Request, level: str, lifetime: timedelta):
    raw = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    now = utcnow()
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id,
                                         (AuthSession.expires_at <= now) | (AuthSession.revoked_at.is_not(None)))
               .execution_options(synchronize_session="fetch"))
    active_ids = list(db.scalars(select(AuthSession.id).where(AuthSession.user_id == user.id)
                                 .order_by(AuthSession.created_at.desc(), AuthSession.id.desc())).all())
    retained = max(0, settings.auth_max_sessions_per_user - 1)
    if len(active_ids) > retained:
        db.execute(delete(AuthSession).where(AuthSession.id.in_(active_ids[retained:]))
                   .execution_options(synchronize_session="fetch"))
    session = AuthSession(token_hash=token_hash(raw), user_id=user.id, csrf_token=csrf, auth_level=level,
                          created_at=now, last_seen_at=now, expires_at=now + lifetime,
                          ip_address=client_ip(request),
                          user_agent=request.headers.get("user-agent", "")[:300])
    db.add(session); db.flush()
    return session, raw


def set_session_cookie(response: Response, raw_token: str, max_age: int):
    response.set_cookie(settings.auth_cookie_name, raw_token, max_age=max_age, httponly=True,
                        secure=settings.auth_cookie_secure, samesite="strict", path="/")


def clear_session_cookie(response: Response):
    response.delete_cookie(settings.auth_cookie_name, path="/", secure=settings.auth_cookie_secure, samesite="strict")


def get_session(db: Session, request: Request, required_level: str | None = None):
    raw = request.cookies.get(settings.auth_cookie_name)
    if not raw:
        return None
    session = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_hash(raw), AuthSession.revoked_at.is_(None)))
    if not session:
        return None
    now = utcnow()
    if aware(session.expires_at) <= now or (required_level == "full" and aware(session.last_seen_at) + timedelta(minutes=settings.auth_idle_minutes) <= now):
        session.revoked_at = now; db.commit(); return None
    current_agent = request.headers.get("user-agent", "")[:300]
    if settings.auth_bind_user_agent and session.user_agent and not hmac.compare_digest(session.user_agent, current_agent):
        session.revoked_at = now; db.commit(); return None
    if required_level and session.auth_level != required_level:
        return None
    user = db.get(User, session.user_id)
    if not user or (required_level == "full" and (not user.active or not user.totp_enabled)):
        return None
    return session, user


def get_api_token(db: Session, raw: str):
    if not API_TOKEN_PATTERN.fullmatch(raw):
        return None
    api_token = db.scalar(select(ApiToken).where(
        ApiToken.token_hash == token_hash(raw), ApiToken.revoked_at.is_(None)))
    if not api_token or aware(api_token.expires_at) <= utcnow():
        return None
    user = db.get(User, api_token.user_id)
    if not user or not user.active or not user.totp_enabled:
        return None
    return api_token, user


def user_payload(user: User):
    return {"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role, "totp_enabled": user.totp_enabled}


def csrf_valid(session: AuthSession, supplied: str | None):
    return bool(supplied and hmac.compare_digest(session.csrf_token, supplied))


def verify_totp(user: User, code: str):
    if not user.totp_secret_encrypted or not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(decrypt_secret(user.totp_secret_encrypted), digits=6, interval=30)
    current = int(time.time())
    for offset in (-30, 0, 30):
        timestamp = current + offset
        if hmac.compare_digest(totp.at(timestamp), code):
            step = timestamp // 30
            if user.last_totp_step is not None and step <= user.last_totp_step:
                return None
            return step
    return None


class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if request.method == "OPTIONS" or not path.startswith("/api/") or path in PUBLIC_API_PATHS:
            return await call_next(request)
        with SessionLocal() as db:
            authorization = request.headers.get("authorization")
            session_cookie = request.cookies.get(settings.auth_cookie_name)
            auth_method = "api_token" if authorization else "session"
            if authorization and session_cookie:
                audit(db, "authentication", "denied", request,
                      details={"method": request.method, "path": path, "reason": "ambiguous_credentials"})
                db.commit()
                return JSONResponse({"detail": "Use either a browser session or a bearer token, not both"}, status_code=400)
            if authorization:
                scheme, separator, raw_token = authorization.partition(" ")
                result = (get_api_token(db, raw_token) if separator and scheme.casefold() == "bearer"
                          and " " not in raw_token else None)
            else:
                result = get_session(db, request, "full")
            if not result:
                audit(db, "authentication", "denied", request,
                      details={"method": request.method, "path": path, "auth_method": auth_method})
                db.commit()
                response = JSONResponse({"detail": "Authentication required"}, status_code=401)
                if not authorization:
                    clear_session_cookie(response)
                return response
            credential, user = result
            request.state.auth_method = auth_method
            request.state.user = user
            if auth_method == "session":
                session = credential
                if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not csrf_valid(session, request.headers.get("x-csrf-token")):
                    audit(db, "csrf_validation", "denied", request, user.id,
                          {"method": request.method, "path": path})
                    db.commit()
                    return JSONResponse({"detail": "CSRF validation failed"}, status_code=403)
                request.state.auth_session_id = session.id
                if utcnow() - aware(session.last_seen_at) > timedelta(minutes=1):
                    session.last_seen_at = utcnow(); db.commit()
            else:
                api_token = credential
                request.state.api_token_id = api_token.id
                if not api_token.last_used_at or utcnow() - aware(api_token.last_used_at) > timedelta(minutes=5):
                    api_token.last_used_at = utcnow(); db.commit()
        return await call_next(request)


def require_session_auth(request: Request):
    user = getattr(request.state, "user", None)
    if not user or getattr(request.state, "auth_method", None) != "session":
        with SessionLocal() as db:
            audit(db, "authorization", "denied", request, getattr(user, "id", None),
                  {"method": request.method, "path": request.url.path, "required_auth": "browser_session"})
            db.commit()
        raise HTTPException(403, "A signed-in browser session is required")
    return user


require_session_auth.layerscope_session_only = True


def require_roles(*roles: str):
    def dependency(request: Request):
        user = getattr(request.state, "user", None)
        if not user or user.role not in roles:
            with SessionLocal() as db:
                audit(db, "authorization", "denied", request, getattr(user, "id", None),
                      {"method": request.method, "path": request.url.path, "required_roles": sorted(roles)})
                db.commit()
            raise HTTPException(403, "Insufficient permissions")
        return user
    dependency.layerscope_roles = tuple(roles)
    return dependency


@router.get("/status")
def auth_status(db: Session = Depends(get_db)):
    configured = (db.scalar(select(func.count()).select_from(User).where(User.active.is_(True))) or 0) > 0
    return {"configured": configured, "local_auth": True, "totp_required": True}


@router.post("/setup", status_code=201)
def setup(body: SetupRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    username = normalize_username(body.username)
    display_name = body.display_name.strip()
    if not display_name:
        raise HTTPException(400, "Display name cannot be blank")
    validate_password(body.password, username)
    db.execute(text("BEGIN IMMEDIATE"))
    if (db.scalar(select(func.count()).select_from(User).where(User.active.is_(True))) or 0) > 0:
        raise HTTPException(409, "Initial setup is already complete")
    pending_ids = list(db.scalars(select(User.id).where(User.active.is_(False))).all())
    if pending_ids:
        db.execute(delete(ApiToken).where(ApiToken.user_id.in_(pending_ids)))
        db.execute(delete(AuthSession).where(AuthSession.user_id.in_(pending_ids)))
        db.execute(delete(RecoveryCode).where(RecoveryCode.user_id.in_(pending_ids)))
        db.execute(delete(User).where(User.id.in_(pending_ids)))
    secret = pyotp.random_base32(length=32)
    user = User(username=username, display_name=display_name, password_hash=password_hasher.hash(body.password),
                role="admin", active=False, totp_enabled=False, totp_secret_encrypted=encrypt_secret(secret))
    db.add(user); db.flush()
    session, raw = create_session(db, user, request, "mfa_setup", timedelta(minutes=10))
    audit(db, "initial_setup", "pending_mfa", request, user.id)
    db.commit()
    set_session_cookie(response, raw, 600)
    uri = pyotp.TOTP(secret, digits=6, interval=30).provisioning_uri(name=username, issuer_name=settings.auth_issuer)
    return {"requires_totp_setup": True, "secret": secret, "otpauth_uri": uri, "csrf_token": session.csrf_token}


@router.post("/login")
async def login(body: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    username = body.username.strip().casefold()
    user = db.scalar(select(User).where(User.username == username, User.active.is_(True)))
    valid = False
    try:
        valid = password_hasher.verify(user.password_hash if user else dummy_password_hash, body.password)
    except VerifyMismatchError:
        valid = False
    now = utcnow()
    if user and user.locked_until and aware(user.locked_until) > now:
        valid = False
    if not valid or not user:
        if user:
            user.failed_login_count += 1
            if user.failed_login_count >= settings.auth_login_max_attempts:
                user.locked_until = now + timedelta(minutes=settings.auth_lockout_minutes)
                user.failed_login_count = 0
        audit(db, "login_password", "denied", request, user.id if user else None, {"username": username})
        db.commit(); await asyncio.sleep(0.35)
        raise HTTPException(401, "Invalid username or password")
    if password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = password_hasher.hash(body.password)
    user.failed_login_count = 0; user.locked_until = None
    session, raw = create_session(db, user, request, "password", timedelta(minutes=5))
    audit(db, "login_password", "mfa_required", request, user.id)
    db.commit(); set_session_cookie(response, raw, 300)
    return {"requires_totp": True, "csrf_token": session.csrf_token}


@router.post("/activate")
async def activate(body: ActivationRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    username = body.username.strip().casefold()
    user = db.scalar(select(User).where(User.username == username))
    now = utcnow()
    supplied_hash = token_hash(body.activation_code.strip())
    valid = bool(user and not user.active and user.activation_token_hash and user.activation_expires_at
                 and aware(user.activation_expires_at) > now
                 and hmac.compare_digest(user.activation_token_hash, supplied_hash))
    if not valid or not user:
        audit(db, "user_activation", "denied", request, user.id if user else None, {"username": username})
        db.commit(); await asyncio.sleep(0.35)
        raise HTTPException(401, "Invalid or expired activation code")
    validate_password(body.password, username)
    secret = pyotp.random_base32(length=32)
    db.execute(update(ApiToken).where(ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None))
               .values(revoked_at=now).execution_options(synchronize_session="fetch"))
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id))
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    user.password_hash = password_hasher.hash(body.password)
    user.totp_secret_encrypted = encrypt_secret(secret)
    user.totp_enabled = False; user.last_totp_step = None
    user.activation_token_hash = None; user.activation_expires_at = None
    user.failed_login_count = 0; user.locked_until = None
    session, raw = create_session(db, user, request, "activation", timedelta(minutes=10))
    audit(db, "user_activation", "pending_mfa", request, user.id)
    db.commit(); set_session_cookie(response, raw, 600)
    uri = pyotp.TOTP(secret, digits=6, interval=30).provisioning_uri(name=username, issuer_name=settings.auth_issuer)
    return {"requires_totp_setup": True, "secret": secret, "otpauth_uri": uri, "csrf_token": session.csrf_token}


@router.post("/reenroll-2fa")
async def reenroll_2fa(body: ReenrollRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    username = body.username.strip().casefold()
    user = db.scalar(select(User).where(User.username == username, User.active.is_(True)))
    now = utcnow()
    password_valid = False
    try:
        password_valid = password_hasher.verify(user.password_hash if user else dummy_password_hash, body.password)
    except VerifyMismatchError:
        password_valid = False
    supplied_hash = token_hash(body.reissue_code.strip())
    code_valid = bool(user and user.mfa_reset_token_hash and user.mfa_reset_expires_at
                      and aware(user.mfa_reset_expires_at) > now
                      and hmac.compare_digest(user.mfa_reset_token_hash, supplied_hash))
    if not user or not password_valid or not code_valid:
        audit(db, "user_2fa_reenrollment", "denied", request, user.id if user else None,
              {"username": username})
        db.commit()
        await asyncio.sleep(0.35)
        raise HTTPException(401, "Invalid credentials or expired 2FA reissue code")
    secret = pyotp.random_base32(length=32)
    db.execute(update(ApiToken).where(ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None))
               .values(revoked_at=now).execution_options(synchronize_session="fetch"))
    db.execute(delete(AuthSession).where(AuthSession.user_id == user.id))
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    user.totp_secret_encrypted = encrypt_secret(secret)
    user.totp_enabled = False
    user.last_totp_step = None
    user.mfa_reset_token_hash = None
    user.mfa_reset_expires_at = None
    user.failed_login_count = 0
    user.locked_until = None
    session, raw = create_session(db, user, request, "mfa_reenroll", timedelta(minutes=10))
    audit(db, "user_2fa_reenrollment", "pending_mfa", request, user.id)
    db.commit()
    set_session_cookie(response, raw, 600)
    uri = pyotp.TOTP(secret, digits=6, interval=30).provisioning_uri(name=username, issuer_name=settings.auth_issuer)
    return {"requires_totp_setup": True, "secret": secret, "otpauth_uri": uri, "csrf_token": session.csrf_token}


@router.post("/totp/verify")
def totp_verify(body: TotpRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    result = get_session(db, request)
    if not result:
        raise HTTPException(401, "Authentication challenge expired")
    session, user = result
    if session.auth_level not in {"password", "mfa_setup", "activation", "mfa_reenroll"} or not csrf_valid(session, body.csrf_token):
        raise HTTPException(403, "Authentication challenge is invalid")
    step = verify_totp(user, body.code.strip())
    recovery = None
    if step is None and session.auth_level == "password":
        candidate = recovery_hash(body.code)
        recovery = db.scalar(select(RecoveryCode).where(RecoveryCode.user_id == user.id, RecoveryCode.code_hash == candidate, RecoveryCode.used_at.is_(None)))
    if step is None and recovery is None:
        session.failed_attempts += 1
        if session.failed_attempts >= 5:
            session.revoked_at = utcnow(); clear_session_cookie(response)
        audit(db, "totp_verify", "denied", request, user.id)
        db.commit()
        raise HTTPException(401, "Invalid or already-used authentication code")
    if step is not None:
        user.last_totp_step = step
    if recovery is not None:
        recovery.used_at = utcnow()
    recovery_codes = []
    if session.auth_level in {"mfa_setup", "activation", "mfa_reenroll"}:
        user.active = True; user.totp_enabled = True
        recovery_codes = generate_recovery_codes()
        for code in recovery_codes:
            db.add(RecoveryCode(user_id=user.id, code_hash=recovery_hash(code)))
    session.revoked_at = utcnow()
    full, raw = create_session(db, user, request, "full", timedelta(hours=settings.auth_absolute_hours))
    completed_actions = {"activation": "user_activation_complete", "mfa_reenroll": "mfa_reenrollment_complete"}
    completed_action = completed_actions.get(session.auth_level, "initial_setup_complete")
    audit(db, "login_complete" if not recovery_codes else completed_action, "success", request, user.id, {"recovery_code_used": recovery is not None})
    db.commit()
    set_session_cookie(response, raw, settings.auth_absolute_hours * 3600)
    return {"user": user_payload(user), "csrf_token": full.csrf_token, "recovery_codes": recovery_codes,
            "recovery_code_used": recovery is not None}


@router.get("/me")
def me(request: Request, db: Session = Depends(get_db)):
    user = db.get(User, request.state.user.id)
    if request.state.auth_method == "api_token":
        return {"user": user_payload(user), "csrf_token": "", "auth_method": "api_token"}
    session = db.get(AuthSession, request.state.auth_session_id)
    return {"user": user_payload(user), "csrf_token": session.csrf_token, "auth_method": "session"}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db), _user=Depends(require_session_auth)):
    session = db.get(AuthSession, request.state.auth_session_id)
    if session:
        session.revoked_at = utcnow()
        audit(db, "logout", "success", request, request.state.user.id)
        db.commit()
    clear_session_cookie(response)
    return {"logged_out": True}
