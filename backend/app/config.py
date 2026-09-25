from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:////data/trivy.db"
    raw_results_dir: Path = Path("/data/raw")
    upload_dir: Path = Path("/data/uploads")
    scan_roots: str = "/images"
    scan_concurrency: int = Field(default=2, ge=1, le=16)
    max_pending_scans: int = Field(default=100, ge=1, le=10000)
    trivy_binary: str = "trivy"
    trivy_cache_dir: Path = Path("/data/trivy-cache")
    trivy_temp_dir: Path = Path("/data/trivy-tmp")
    component_temp_dir: Path = Path("/data/component-tmp")
    trivy_db_repositories: str = "ghcr.io/aquasecurity/trivy-db:2,public.ecr.aws/aquasecurity/trivy-db:2"
    trivy_java_db_repositories: str = "ghcr.io/aquasecurity/trivy-java-db:1,public.ecr.aws/aquasecurity/trivy-java-db:1"
    trivy_seed_cache_dir: Path = Path("/opt/trivy-cache-seed")
    trivy_timeout_seconds: int = Field(default=1800, ge=60, le=86400)
    max_raw_result_bytes: int = Field(default=268435456, ge=1048576, le=4294967296)
    max_report_import_bytes: int = Field(default=67108864, ge=1048576, le=1073741824)
    cors_origins: str = "http://localhost:8080,http://127.0.0.1:8080"
    max_upload_bytes: int = Field(default=21474836480, ge=1048576)
    max_upload_request_bytes: int = Field(default=42949672960, ge=1048576)
    max_upload_files: int = Field(default=20, ge=1, le=500)
    storage_reserve_bytes: int = Field(default=2147483648, ge=67108864)
    host_storage_probe_dir: Path | None = None
    max_sse_clients: int = Field(default=100, ge=1, le=10000)
    sse_queue_size: int = Field(default=200, ge=10, le=10000)
    auth_rate_limit_attempts: int = Field(default=20, ge=5, le=10000)
    auth_rate_limit_window_seconds: int = Field(default=60, ge=10, le=3600)
    auth_key_path: Path = Path("/data/auth.key")
    backup_dir: Path = Path("/data/backups")
    max_backup_bytes: int = Field(default=107374182400, ge=1048576)
    auth_cookie_name: str = "trivy_session"
    auth_cookie_secure: bool = False
    auth_idle_minutes: int = Field(default=30, ge=5, le=1440)
    auth_absolute_hours: int = Field(default=8, ge=1, le=168)
    auth_login_max_attempts: int = Field(default=5, ge=3, le=20)
    auth_lockout_minutes: int = Field(default=15, ge=1, le=1440)
    auth_activation_hours: int = Field(default=24, ge=1, le=168)
    auth_max_sessions_per_user: int = Field(default=5, ge=1, le=50)
    auth_max_api_tokens_per_user: int = Field(default=20, ge=1, le=100)
    auth_bind_user_agent: bool = True
    auth_issuer: str = "LayerScope"
    trusted_hosts: str = "backend,localhost,127.0.0.1,testserver"
    trusted_proxy_cidrs: str = "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    max_json_body_bytes: int = Field(default=1048576, ge=16384, le=16777216)
    max_discovered_archives: int = Field(default=10000, ge=1, le=1000000)
    discovery_interval_seconds: int = Field(default=30, ge=0, le=3600)
    model_config = SettingsConfigDict(env_prefix="TRIVY_DASHBOARD_")

    @property
    def roots(self) -> list[Path]:
        return [Path(p.strip()).resolve() for p in self.scan_roots.split(",") if p.strip()]

    @property
    def db_repositories(self) -> list[str]:
        return [repo.strip() for repo in self.trivy_db_repositories.split(",") if repo.strip()]

    @property
    def java_db_repositories(self) -> list[str]:
        return [repo.strip() for repo in self.trivy_java_db_repositories.split(",") if repo.strip()]

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip().rstrip("/") for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def allowed_hosts(self) -> list[str]:
        return [host.strip().casefold() for host in self.trusted_hosts.split(",") if host.strip()]

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, value: str) -> str:
        for raw_origin in value.split(","):
            origin = raw_origin.strip().rstrip("/")
            if not origin:
                continue
            parsed = urlsplit(origin)
            if origin == "*" or parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("CORS origins must be explicit http(s) origins; wildcards are not allowed")
            if parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
                raise ValueError("CORS origins cannot contain paths, credentials, queries, or fragments")
        return value

    @field_validator("trusted_hosts")
    @classmethod
    def validate_trusted_hosts(cls, value: str) -> str:
        hosts = [item.strip() for item in value.split(",") if item.strip()]
        if not hosts or "*" in hosts:
            raise ValueError("Trusted hosts must be explicit and cannot contain a wildcard")
        return value


settings = Settings()
