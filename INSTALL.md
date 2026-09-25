# Installing LayerScope

Docker Compose is the recommended installation because it supplies the pinned Trivy binary, initializes the vulnerability database, isolates the backend, and applies the documented container hardening. A native installation is also supported for local development and controlled workstation deployments.

## Option 1: Docker Compose

### Requirements

- Docker Desktop with Linux containers on Windows or macOS, or Docker Engine with the Compose plugin on Linux
- At least 4 GiB of free memory for comfortable concurrent scans
- Enough disk space for uploaded TAR files, raw results, SQLite data, backups, and Trivy databases

### Windows PowerShell

```powershell
Copy-Item .env.example .env
```

Edit `.env` and set the host directory containing Docker/OCI TAR files:

```dotenv
IMAGE_DIR=D:/DockerImages
HOST_STORAGE_PROBE_DIR=./storage-probe
```

Use forward slashes and do not add quotes. The storage probe must be an empty directory on the drive containing Docker Desktop's Linux disk image; keep the default when that is the same drive as the project. Never use a drive root or private directory. Then start the application:

```powershell
docker compose up --build -d
docker compose ps
```

Open [http://localhost:8080](http://localhost:8080). On first use, create the local administrator and enroll TOTP with an authenticator such as Aegis or FreeOTP.

The Compose project is named `layerscope`. For upgrade safety, `LAYERSCOPE_DATA_VOLUME_NAME` defaults to the existing `trivy-dashboard_trivy-data` volume name. Keep that setting unchanged when upgrading an installation that already contains application data.

### Linux or macOS

```bash
cp .env.example .env
```

Set an absolute readable directory in `.env`, for example:

```dotenv
IMAGE_DIR=/srv/docker-images
```

Start the application:

```bash
docker compose up --build -d
docker compose ps
```

Open `http://localhost:8080` and complete local administrator enrollment.

### Docker operations

View service logs:

```powershell
docker compose logs -f backend frontend
```

Stop containers without deleting saved data:

```powershell
docker compose down
```

Update after pulling source changes:

```powershell
docker compose build --pull
docker compose up -d
```

The named `trivy-data` volume contains the database, authentication key, uploads, raw results, backups, and Trivy cache. Do not use `docker compose down -v` unless permanent deletion of all dashboard data is intended.

### Install the automation CLI

The optional CLI runs on the host and calls either the Compose or native LayerScope HTTP API. It requires Python 3.12+ but no third-party runtime packages:

```powershell
python -m pip install ./cli
layerscope --version
```

Create an operator or administrator personal token from **API tokens** in the signed-in app. Supply it through the protected CI secret environment or read it interactively into `LAYERSCOPE_TOKEN`; never put it in a URL or command argument. For a local Compose installation, the default URL is `http://localhost:8080`. Any remote URL must use HTTPS with certificate verification; `--ca-file` can supply a private CA bundle.

```powershell
$secureToken = Read-Host 'LayerScope API token' -AsSecureString
$env:LAYERSCOPE_TOKEN = [Net.NetworkCredential]::new('', $secureToken).Password
try {
    layerscope whoami
    layerscope upload --if-absent C:/path/to/example.tar
} finally {
    Remove-Item Env:LAYERSCOPE_TOKEN -ErrorAction SilentlyContinue
    Remove-Variable secureToken
}
```

The server continues to own authorization, upload validation, queue limits, scanning, and persistence. Full command, retry, output, and exit-code documentation is in [cli/README.md](cli/README.md).

### Recover a lost administrator password

When the administrator still has their current TOTP authenticator or an unused recovery code, run this from the Compose project directory in an interactive PowerShell terminal:

```powershell
docker compose exec backend python -m app.admin_cli reset-admin-password --username admin
```

Replace `admin` with the actual username, or omit `--username` when exactly one active administrator exists. Enter the new password twice and then a fresh six-digit authenticator code or unused recovery code. Inputs are hidden and must not be placed in command arguments, environment variables, scripts, source files, or chat. A successful reset preserves TOTP enrollment, consumes a recovery code if used, unlocks the account, revokes all existing sessions and API tokens, and is audited. No restart is required.

For a native installation, activate the documented virtual environment and run the same module from `backend` with the environment variables that point to the live database and authentication key:

```powershell
.venv\Scripts\python -m app.admin_cli reset-admin-password --username admin
```

The command cannot bypass MFA. If the password and every second factor are both lost, restore a valid encrypted application backup or use another active administrator's documented account-management flow.

To mount multiple read-only image directories, add a local Compose override as described in [README.md](README.md#mount-multiple-directories). Do not commit an override containing private host paths.

### HTTPS and network access

The default binding is `127.0.0.1:8080` and the session cookie is configured for local HTTP. Before exposing the app to a LAN or the internet:

- terminate HTTPS at a trusted reverse proxy;
- set `AUTH_COOKIE_SECURE=true`;
- restrict `CORS_ORIGINS` and trusted hosts to exact deployed names;
- keep the backend network private;
- apply firewall rules, backup protection, and an update process.

See [SECURITY.md](SECURITY.md) before changing network exposure.

## Option 2: Native installation without Docker

Native installation runs FastAPI and Vite directly. It is best suited to development or a single trusted workstation. For a production-style native deployment, place the built frontend and backend behind an HTTPS reverse proxy and reproduce the response headers and limits from `frontend/nginx.conf`.

### Native requirements

- Python 3.12
- Node.js 22 with Corepack
- pnpm 11.19.x
- Trivy 0.74.x available on `PATH`
- DejaVu fonts for consistent PDF rendering
- Platform build tools required by Python packages, if wheels are unavailable

Confirm the main tools:

```powershell
python --version
node --version
trivy --version
corepack enable
corepack prepare pnpm@11.19.0 --activate
pnpm --version
```

### Windows native setup

From the repository root:

```powershell
$dataRoot = Join-Path (Get-Location) '.local-data'
$cacheRoot = Join-Path $dataRoot 'trivy-cache'
$trivyTempRoot = Join-Path $dataRoot 'trivy-tmp'
$componentTempRoot = Join-Path $dataRoot 'component-tmp'
$uploadRoot = Join-Path $dataRoot 'uploads'
$rawRoot = Join-Path $dataRoot 'raw'
$backupRoot = Join-Path $dataRoot 'backups'
New-Item -ItemType Directory -Force $dataRoot,$cacheRoot,$trivyTempRoot,$componentTempRoot,$uploadRoot,$rawRoot,$backupRoot | Out-Null

$scanRoot = (Resolve-Path 'D:/DockerImages').Path
$dbPath = (Join-Path $dataRoot 'trivy.db').Replace('\','/')
$env:TRIVY_DASHBOARD_DATABASE_URL = "sqlite:///$dbPath"
$env:TRIVY_DASHBOARD_SCAN_ROOTS = "$scanRoot,$uploadRoot"
$env:TRIVY_DASHBOARD_UPLOAD_DIR = $uploadRoot
$env:TRIVY_DASHBOARD_RAW_RESULTS_DIR = $rawRoot
$env:TRIVY_DASHBOARD_BACKUP_DIR = $backupRoot
$env:TRIVY_DASHBOARD_AUTH_KEY_PATH = (Join-Path $dataRoot 'auth.key')
$env:TRIVY_DASHBOARD_TRIVY_CACHE_DIR = $cacheRoot
$env:TRIVY_DASHBOARD_TRIVY_TEMP_DIR = $trivyTempRoot
$env:TRIVY_DASHBOARD_COMPONENT_TEMP_DIR = $componentTempRoot
$env:TRIVY_DASHBOARD_CORS_ORIGINS = 'http://localhost:5173,http://127.0.0.1:5173'
$env:TRIVY_DASHBOARD_TRUSTED_HOSTS = 'localhost,127.0.0.1'
$env:TRIVY_DASHBOARD_AUTH_COOKIE_SECURE = 'false'
```

Download the required vulnerability database into the private local cache:

```powershell
trivy image --cache-dir $cacheRoot --no-progress --disable-telemetry --download-db-only --db-repository ghcr.io/aquasecurity/trivy-db:2 --db-repository public.ecr.aws/aquasecurity/trivy-db:2
```

Install and start the backend:

```powershell
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Keep that terminal open. In a second PowerShell window, repeat the environment-variable block above so the frontend and future maintenance commands use the same paths, then run:

```powershell
cd frontend
corepack enable
corepack prepare pnpm@11.19.0 --activate
pnpm install --frozen-lockfile
pnpm run dev
```

Open [http://localhost:5173](http://localhost:5173).

### Linux or macOS native setup

From the repository root, replace `/srv/docker-images` with the directory containing your TAR files:

```bash
export DASHBOARD_DATA_ROOT="$PWD/.local-data"
mkdir -p "$DASHBOARD_DATA_ROOT"/{trivy-cache,trivy-tmp,component-tmp,uploads,raw,backups}

export TRIVY_DASHBOARD_DATABASE_URL="sqlite:////${DASHBOARD_DATA_ROOT#/}/trivy.db"
export TRIVY_DASHBOARD_SCAN_ROOTS="/srv/docker-images,$DASHBOARD_DATA_ROOT/uploads"
export TRIVY_DASHBOARD_UPLOAD_DIR="$DASHBOARD_DATA_ROOT/uploads"
export TRIVY_DASHBOARD_RAW_RESULTS_DIR="$DASHBOARD_DATA_ROOT/raw"
export TRIVY_DASHBOARD_BACKUP_DIR="$DASHBOARD_DATA_ROOT/backups"
export TRIVY_DASHBOARD_AUTH_KEY_PATH="$DASHBOARD_DATA_ROOT/auth.key"
export TRIVY_DASHBOARD_TRIVY_CACHE_DIR="$DASHBOARD_DATA_ROOT/trivy-cache"
export TRIVY_DASHBOARD_TRIVY_TEMP_DIR="$DASHBOARD_DATA_ROOT/trivy-tmp"
export TRIVY_DASHBOARD_COMPONENT_TEMP_DIR="$DASHBOARD_DATA_ROOT/component-tmp"
export TRIVY_DASHBOARD_CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"
export TRIVY_DASHBOARD_TRUSTED_HOSTS="localhost,127.0.0.1"
export TRIVY_DASHBOARD_AUTH_COOKIE_SECURE=false

trivy image --cache-dir "$DASHBOARD_DATA_ROOT/trivy-cache" --no-progress --disable-telemetry --download-db-only \
  --db-repository ghcr.io/aquasecurity/trivy-db:2 \
  --db-repository public.ecr.aws/aquasecurity/trivy-db:2
```

Start the backend:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a second terminal, export the same environment variables, then start the frontend:

```bash
cd frontend
corepack enable
corepack prepare pnpm@11.19.0 --activate
pnpm install --frozen-lockfile
pnpm run dev
```

Open `http://localhost:5173`.

### Optional Java database

The app can scan non-Java ecosystems without the Java database. To add JAR/WAR/EAR coverage natively, use the Components page after signing in as an administrator, or run:

```powershell
trivy image --cache-dir $cacheRoot --no-progress --disable-telemetry --download-java-db-only --java-db-repository ghcr.io/aquasecurity/trivy-java-db:1 --java-db-repository public.ecr.aws/aquasecurity/trivy-java-db:1
```

On Linux or macOS, replace `$cacheRoot` with `$DASHBOARD_DATA_ROOT/trivy-cache`.

## Native data protection

`.local-data/` is ignored by Git, but ignore rules are not access control. Restrict the directory to the dashboard account, keep it out of cloud-synchronized folders when possible, and protect backups separately. Never commit or share:

- `auth.key`;
- SQLite database, WAL, or SHM files;
- uploaded image archives;
- raw scan JSON or generated reports;
- encrypted backups or their passwords;
- `.env` files containing private paths or deployment values.

## Troubleshooting

- If the UI cannot reach the backend, confirm port 8000 is listening and that Vite is running on port 5173.
- If diagnostics reports a missing vulnerability database, run the download command above or use Components → Update.
- If a scan reports incomplete Java coverage, install the optional Java database and rescan.
- If a mounted archive is absent, confirm the configured root is absolute, readable by the process, and included in `TRIVY_DASHBOARD_SCAN_ROOTS`.
- If Docker Desktop reports a missing Linux engine pipe, start Docker Desktop and select Linux containers before running Compose.
