from datetime import datetime, timezone
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


def now():
    return datetime.now(timezone.utc)


class ImageArchive(Base):
    __tablename__ = "images"
    __table_args__ = (Index("ix_images_hidden_name", "hidden", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String, index=True)
    size: Mapped[int] = mapped_column(Integer)
    modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    hidden: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scans: Mapped[list["Scan"]] = relationship(back_populates="image", cascade="all, delete-orphan")


class ImageGroup(Base):
    __tablename__ = "image_groups"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    color: Mapped[str] = mapped_column(String(20), default="blue")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class ImageGroupMember(Base):
    __tablename__ = "image_group_members"
    __table_args__ = (UniqueConstraint("group_id", "image_id", name="uq_image_group_member"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("image_groups.id"), index=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("images.id"), index=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_image_id_id", "image_id", "id"),
        Index("ix_scans_status_queued_at_id", "status", "queued_at", "id"),
        Index("ix_scans_image_status_id", "image_id", "status", "id"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("images.id"), index=True)
    status: Mapped[str] = mapped_column(String, default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str] = mapped_column(String(40), default="queued")
    message: Mapped[str] = mapped_column(Text, default="Waiting for an available worker")
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)
    raw_json_path: Mapped[str | None] = mapped_column(String, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    coverage_warning: Mapped[str | None] = mapped_column(Text, nullable=True)
    image: Mapped[ImageArchive] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_package", "scan_id", "package_name"),
        Index("ix_findings_scan_target", "scan_id", "target"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    target: Mapped[str] = mapped_column(String, default="")
    vulnerability_id: Mapped[str] = mapped_column(String, index=True)
    package_name: Mapped[str] = mapped_column(String, index=True)
    installed_version: Mapped[str] = mapped_column(String, default="")
    fixed_version: Mapped[str] = mapped_column(String, default="")
    severity: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    primary_url: Mapped[str] = mapped_column(Text, default="")
    scan: Mapped[Scan] = relationship(back_populates="findings")


class Package(Base):
    __tablename__ = "packages"
    __table_args__ = (Index("ix_packages_scan_name", "scan_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    target: Mapped[str] = mapped_column(String, default="")
    name: Mapped[str] = mapped_column(String, index=True)
    version: Mapped[str] = mapped_column(String, default="")
    identifier: Mapped[str] = mapped_column(String, default="")
    licenses: Mapped[str] = mapped_column(Text, default="")


class MaintenanceJob(Base):
    __tablename__ = "maintenance_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    component: Mapped[str] = mapped_column(String(40), index=True)
    action: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str] = mapped_column(String(40), default="queued")
    message: Mapped[str] = mapped_column(Text, default="Waiting for the maintenance worker")
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class UploadJob(Base):
    __tablename__ = "upload_jobs"
    __table_args__ = (Index("ix_upload_jobs_status_queued_at_id", "status", "queued_at", "id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    archive_name: Mapped[str] = mapped_column(String(240), default="Archive upload")
    status: Mapped[str] = mapped_column(String(20), default="running", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str] = mapped_column(String(40), default="receiving")
    message: Mapped[str] = mapped_column(Text, default="Receiving archive data")
    bytes_received: Mapped[int] = mapped_column(BigInteger, default=0)
    total_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    image_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    image_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    activation_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    activation_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_reset_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mfa_reset_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_totp_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(128))
    auth_level: Mapped[str] = mapped_column(String(20), default="password")
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(300), default="")


class ApiToken(Base):
    __tablename__ = "api_tokens"
    __table_args__ = (Index("ix_api_tokens_user_active", "user_id", "revoked_at", "expires_at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    outcome: Mapped[str] = mapped_column(String(20), index=True)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
