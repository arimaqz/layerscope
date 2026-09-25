# LayerScope

A local-first dashboard for discovering Docker/OCI image archives (`.tar`), scanning them with Trivy, and exploring persisted results without rerunning scans.

Current release: **1.0.0**. This release keeps the complete security baseline while replacing per-row database lookups with set-based queries, batching normalized scan inserts, throttling live-event refreshes, reducing idle polling, caching filesystem discovery briefly, paginating large archive tables, lazy-loading chart code, and tuning SQLite and Nginx for the local dashboard workload. It also includes a thin authenticated CLI for CI/CD automation without duplicating the scanner or job queue. The release images rebuild Trivy 0.74.0 from checksum-verified source with patched gRPC and Go dependencies and upgrade frontend OS packages during the build. Saved scans, raw JSON, authentication, exports, groups, and all existing workflows remain compatible.

## Documentation

- [INSTALL.md](INSTALL.md): Docker Compose and native installation on Windows, Linux, and macOS
- [TECHNICAL_README.md](TECHNICAL_README.md): architecture, persistence, API, queue, performance, and security internals
- [CONTRIBUTING.md](CONTRIBUTING.md): workflow and safeguards for human contributors and coding agents
- [SECURITY.md](SECURITY.md): authentication model, deployment requirements, and security verification
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md): completed OWASP/WSTG and container-hardening assessment
- [cli/README.md](cli/README.md): non-interactive CLI, output contract, exit codes, and CI usage

Docker Compose is the recommended installation. For a concise installation path—including native operation without Docker—start with [INSTALL.md](INSTALL.md).

## Phase 1 features

- Read-only mounting and recursive discovery of one or more image directories
- Individual and bulk image selection with scan, additive group assignment, and administrator-only bulk removal actions
- Direct-to-volume `.tar` uploads with sequential browser-side multi-file queues that bound Firefox and Chromium memory use
- Root-validated download of imported `.tar` archives
- Persistent scan-job handler with configurable concurrency (default: 2), restart recovery, duplicate suppression, cancellation, and retry
- Bounded queue admission, storage reserve enforcement, SSE capacity limits, and visible worker/queue/storage/event telemetry
- Transactional bounded upload requests with per-file, per-request, file-count, free-space, and Docker/OCI TAR validation
- Live scan stages and estimated progress using Server-Sent Events (SSE), with polling fallback
- Aggregate severity, image, package, and scan-status dashboard
- Constant-count image/group summary queries, bounded bulk result inserts, and composite SQLite indexes for large saved libraries
- Per-image findings, previous scan history, rescan, and administrator-only raw JSON download
- Severity, package, target, fix-availability, and full-text finding filters
- Consistent severity palette across filters, badges, charts, tables, HTML, and PDF: Critical deep red, High bright red, Medium orange, Low blue, and Unknown gray
- Sortable, resizable columns and virtualized rows
- Click-through vulnerability drawer with full untruncated text
- SQLite normalized result storage and retained raw Trivy JSON
- Strict scan-root path validation and shell-free subprocess execution
- UTF-8 throughout; UI actions use Lucide icons rather than fragile text glyphs
- Centralized, privacy-aware API error formatting for FastAPI validation arrays, nested objects, plain text, proxy failures, and network errors; raw objects are never rendered as `[object Object]`

## Phase 2 features

- Persistent light and dark themes with system-theme detection
- Responsive keyboard-accessible navigation with persistent core destinations, grouped operational and administrative menus, account context, visible focus states, Escape dismissal, reduced-motion support, route-level loading states, and a friendly not-found page
- Consistent status badges, archive-source labels, protected confirmation dialogs, and accessible vulnerability details
- Task-oriented in-app Help center with guided first steps, eight predictable topic areas, role labels, focused workspace links, and private client-side typo-tolerant search
- Path-safe, versioned scan- or image-group report JSON with administrator-only normalized report re-import, standalone HTML, polished landscape PDF, optional one-time PNG/JPEG branding for HTML/PDF, Elastic ECS 9.5.0 Bulk NDJSON, and DefectDojo Generic Findings Import JSON exports
- Upload and report-export progress indicators
- Unified Jobs page with persistent upload progress/history plus scan queue positions, cancellation, retry, and complete status history
- Package inventory with search
- Automatic latest-versus-previous scan comparison
- Debounced server searches, 100-row archive pagination, route/chart code splitting, and SSE-coalesced cache refreshes
- New, resolved, unchanged, and net finding counts
- Persistent Trivy vulnerability database cache
- Fresh vulnerability database bundled into the backend image and copied into persistent storage on first start
- In-app Components page for update checks, explicit database updates, update progress, cancellation, and history
- Optional on-demand Java index database for images containing JAR files
- Network-quiet scans: automatic DB, Java DB, VEX, and telemetry requests are disabled during normal scan jobs
- Diagnostics page with a complete scanner-component inventory—including missing optional components—plus Trivy, SQLite, storage, roots, workers, disk space, both DB caches, and all configured registries
- Explicit GHCR-first vulnerability database repository with public ECR fallback
- Fully local username/password authentication with no external identity dependency
- Mandatory TOTP two-factor enrollment compatible with Aegis, FreeOTP, and RFC 6238 authenticators
- Argon2id password hashes, encrypted TOTP secrets, opaque server-side sessions, CSRF protection, RBAC, audit events, and single-use recovery codes
- Personal API tokens with one-time reveal, hash-only storage, expiration, revocation, last-used metadata, and the same live RBAC enforcement as browser sessions
- Authenticated in-app API documentation with endpoint/search filters, request and response schemas, RBAC metadata, curl/PowerShell examples, and guarded live JSON reads
- Dependency-free Python CLI for streamed uploads, persistent scan-job control, bounded waits, cancellation, findings, exports, and CI vulnerability gates
- Admin-only local user management with viewer, operator, and admin roles
- One-time account activation: administrators create pending accounts, while each user privately chooses their password and enrolls their own TOTP authenticator
- Editable display names, role/access controls, typed-confirmation account removal, and immutable usernames
- Password-preserving 2FA reissue: an administrator issues a hashed, expiring one-time code and the user privately enrolls a new authenticator
- Risk-specific in-app verification dialogs for user removal, disabling, full activation reset, and 2FA reissue—no browser-native prompts
- Session revocation on role or access changes, account unlock, enrollment reset, and last-administrator/self-removal safeguards
- Admin-only Data page for removing individual scans, normalized results, raw JSON, and images
- Administrator-only AES-256-GCM encrypted backup export and staged restore with native large-file downloads, upload progress, SQLite integrity checks, manifest hashes, automatic rollback, restart, and session revocation
- App-styled typed-confirmation dialogs plus select-all and server-prevalidated bulk scan deletion
- Recoverable removal for read-only mounted archives, with permanent TAR deletion limited to dashboard-managed uploads
- Many-to-many image groups with descriptions, color labels, replacement and additive bulk membership management, membership/scanning coverage analytics, aggregate severity totals, highest-risk rankings, and one-click group scans

## Start on Windows

Requirements: Docker Desktop with Linux containers enabled.

### Mount `D:/DockerImages`

In PowerShell:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

If dependencies were previously installed directly inside `frontend`, they are ignored by Docker through `frontend/.dockerignore`; Docker always performs its own lockfile-pinned, Linux-compatible pnpm install during the image build. BuildKit keeps a reusable pnpm package-store cache, so later builds download only packages that are new or changed instead of fetching the full frontend dependency set again.

The included `.env.example` documents every Compose build, resource, path, scanner, authentication, proxy, request-size, storage, discovery, and event-stream option. Its safe checked-in defaults use the repository's sample archive directory:

```dotenv
IMAGE_DIR=./sample-images
HOST_STORAGE_PROBE_DIR=./storage-probe
```

Change `IMAGE_DIR` to `D:/DockerImages` when that is the directory you want LayerScope to scan. Copy the template to `.env`; never commit the populated `.env` file.

Docker Compose mounts that directory at `/images:ro`. Open <http://localhost:8080>. The app discovers `.tar` files recursively when the overview loads or when **Discover** is selected.

`HOST_STORAGE_PROBE_DIR` must point to an empty directory on the host drive that stores Docker Desktop's Linux disk image. The default `./storage-probe` is correct when the project and Docker Desktop data are on the same drive. LayerScope mounts only that empty directory read-only and uses its filesystem statistics to avoid mistaking Docker's sparse virtual-disk capacity for real host free space. Never point it at a drive root or a directory containing private files.

Compose uses the project name `layerscope`, so its containers and network are named accordingly. The data resource remains explicitly mapped to the existing `trivy-dashboard_trivy-data` Docker volume during this compatibility release; this preserves users, scans, uploads, keys, and component databases across the rename. Do not delete that volume.

You can alternatively select **Upload .tar files** in the top navigation. Uploaded archives are saved under `/data/uploads` in the persistent `trivy-data` volume. For very large collections, the read-only directory mount remains the faster option.

You can also set the path just for one invocation:

```powershell
$env:IMAGE_DIR = "D:/DockerImages"
docker compose up --build
```

Avoid backslashes in Compose bind paths on Windows; forward slashes are more portable.

### Mount multiple directories

Add another read-only bind to `backend.volumes` and list both container roots:

```yaml
services:
  backend:
    environment:
      TRIVY_DASHBOARD_SCAN_ROOTS: /images,/more-images
    volumes:
      - trivy-data:/data
      - D:/DockerImages:/images:ro
      - E:/ArchivedImages:/more-images:ro
```

Only files below `TRIVY_DASHBOARD_SCAN_ROOTS` can be scanned. Paths stored in the database are revalidated before every scan.

## Configuration

All backend settings retain the legacy `TRIVY_DASHBOARD_` prefix so existing deployments can upgrade to LayerScope without changing private configuration.

| Variable | Default | Meaning |
|---|---:|---|
| `SCAN_ROOTS` | `/images` | Comma-separated container paths allowed for discovery/scanning |
| `SCAN_CONCURRENCY` | `2` | Concurrent Trivy worker processes |
| `MAX_PENDING_SCANS` | `100` | Maximum combined queued and running scan jobs |
| `TRIVY_TIMEOUT_SECONDS` | `1800` | Per-scan timeout |
| `DATABASE_URL` | `sqlite:////data/trivy.db` | SQLAlchemy database URL |
| `RAW_RESULTS_DIR` | `/data/raw` | Persistent raw Trivy JSON directory |
| `TRIVY_BINARY` | `trivy` | Trivy executable path |
| `TRIVY_CACHE_DIR` | `/data/trivy-cache` | Persistent Trivy database cache |
| `TRIVY_TEMP_DIR` | `/data/trivy-tmp` | Private disk-backed temporary workspace for large layer analysis |
| `TRIVY_DB_REPOSITORIES` | GHCR, then public ECR | Comma-separated DB sources in priority order |
| `TRIVY_JAVA_DB_REPOSITORIES` | GHCR, then public ECR | Comma-separated optional Java DB sources in priority order |
| `TRIVY_SEED_CACHE_DIR` | `/opt/trivy-cache-seed` | Read-only vulnerability DB bundled into the backend image |
| `CORS_ORIGINS` | Local dashboard origins | Explicit comma-separated browser origins |
| `MAX_RAW_RESULT_BYTES` | `268435456` | Maximum accepted raw Trivy result size (256 MiB) |
| `MAX_DISCOVERED_ARCHIVES` | `10000` | Maximum archives retained by one discovery pass |
| `DISCOVERY_INTERVAL_SECONDS` | `30` | Minimum interval between automatic filesystem walks; the Discover button always runs immediately |
| `MAX_JSON_BODY_BYTES` | `1048576` | Default non-upload JSON request-body limit (1 MiB) |
| `MAX_REPORT_IMPORT_BYTES` | `67108864` | Maximum portable JSON report import size (64 MiB) |
| `MAX_UPLOAD_BYTES` | `21474836480` | Maximum bytes per uploaded archive (20 GiB) |
| `MAX_UPLOAD_REQUEST_BYTES` | `42949672960` | Maximum combined bytes in one multi-file upload (40 GiB) |
| `MAX_UPLOAD_FILES` | `20` | Maximum archives accepted in one upload request |
| `STORAGE_RESERVE_BYTES` | `2147483648` | Free space protected against the smaller Docker-volume/host-probe capacity (2 GiB) |
| `MAX_SSE_CLIENTS` | `100` | Maximum simultaneous live-progress streams |
| `SSE_QUEUE_SIZE` | `200` | Per-client live-event buffer before polling recovery is used |
| `MAX_BACKUP_BYTES` | `107374182400` | Maximum encrypted upload and expanded backup size (100 GiB) |
| `AUTH_COOKIE_SECURE` | `false` | Set to `true` whenever HTTPS is enabled |
| `AUTH_IDLE_MINUTES` | `30` | Idle session timeout |
| `AUTH_ABSOLUTE_HOURS` | `8` | Maximum authenticated session lifetime |
| `AUTH_LOGIN_MAX_ATTEMPTS` | `5` | Failed passwords before temporary lockout |
| `AUTH_RATE_LIMIT_ATTEMPTS` | `20` | Expensive authentication requests allowed per route/client/window |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS` | `60` | Authentication throttle window |
| `AUTH_LOCKOUT_MINUTES` | `15` | Temporary account lock duration |
| `AUTH_ACTIVATION_HOURS` | `24` | Lifetime of a one-time admin-issued account activation code |
| `AUTH_MAX_SESSIONS_PER_USER` | `5` | Maximum concurrent server-side sessions retained per user |
| `AUTH_MAX_API_TOKENS_PER_USER` | `20` | Maximum active personal API tokens retained per user |
| `AUTH_BIND_USER_AGENT` | `true` | Revoke a session if its browser user-agent changes |

The dashboard binds to `127.0.0.1` by default. Set `BIND_ADDRESS=0.0.0.0` only when LAN access is intentional, add the exact external origin to `TRIVY_DASHBOARD_CORS_ORIGINS`, terminate TLS, and set `TRIVY_DASHBOARD_AUTH_COOKIE_SECURE=true` before exposing it beyond a trusted host.

### First-run local account

The first browser visit opens a one-time setup flow. Create the local administrator, scan the QR code with Aegis, FreeOTP, or another TOTP authenticator, then verify one code. The app shows ten recovery codes exactly once. Store them offline.

After initial setup, open **Users** as an administrator to create local accounts. The app reveals a random activation code once. Send the username and code to the intended user through a suitable private channel; the user selects **Activate an admin-created account** on the sign-in screen, chooses a password known only to them, and enrolls their own authenticator. Activation codes expire after 24 hours by default, are stored only as hashes, and can be reissued by an administrator. Users cannot self-register, and a pending-account activation cannot create a new account.

Administrators can edit display names, assign viewer/operator/admin roles, unlock or disable accounts, permanently remove eligible users, reissue pending activation, and reissue 2FA without changing the user's password. A 2FA reissue code is shown once, stored only as a hash, and used from **Re-enroll 2FA with an admin code** on the sign-in screen. Starting re-enrollment replaces the old authenticator and produces a new set of recovery codes. Usernames remain immutable identity keys. The server blocks self-removal, self-demotion, self-disable, self-2FA-reissue, and any change that would remove the last active administrator.

If an administrator loses only their password but still has their authenticator or an unused recovery code, use the interactive server-local recovery command. Under Compose, run `docker compose exec backend python -m app.admin_cli reset-admin-password --username admin`. Omit `--username` when exactly one active administrator exists. The command reads the new password and second factor from the terminal without echoing or placing them in process arguments, preserves the existing TOTP enrollment, consumes a supplied recovery code, clears lockout state, revokes every existing session, and records a local-console audit event. It refuses non-interactive input, inactive accounts, and non-administrators. There is deliberately no browser or MFA-bypass reset route.

Passwords, encrypted authenticator secrets, sessions, recovery-code hashes, and audit events are stored locally in the persistent `trivy-data` volume. `/data/auth.key` encrypts TOTP secrets and must be backed up together with `/data/trivy.db`. Losing one while retaining the other prevents account recovery.

The named `trivy-data` Docker volume contains SQLite job/history state, authentication data, raw scan JSON, uploads, and the Trivy cache. UI-only changes never require a rescan. Do not use `docker compose down -v` unless you intentionally want to delete all persistent data.

### API tokens and API calls

Every signed-in user can open **API tokens**, choose a name and lifetime, and create a personal token. Copy it immediately: the complete `lsp_...` secret is displayed once and only its SHA-256 hash is stored. Token requests inherit the owner's current viewer/operator/admin role. Revocation is immediate; expiry, account disablement, role/access changes, activation or 2FA reset, server-local password recovery, account removal, and backup restore also prevent old tokens from retaining access.

Send the token in the standard bearer header. Do not put it in a URL, source file, command argument, or saved shell history. This PowerShell example reads it without echoing, calls the overview API, and removes the temporary variables:

```powershell
$secureToken = Read-Host 'LayerScope API token' -AsSecureString
$plainToken = [Net.NetworkCredential]::new('', $secureToken).Password
try {
    Invoke-RestMethod 'http://localhost:8080/api/overview' -Headers @{ Authorization = "Bearer $plainToken" }
} finally {
    Remove-Variable plainToken, secureToken
}
```

Bearer calls do not use browser cookies or CSRF headers because API clients explicitly supply the credential. A request containing both a LayerScope session cookie and a bearer token is rejected. Token creation, listing, and revocation are intentionally available only through a fully authenticated browser session, so an API token cannot mint replacement credentials. All existing endpoint role rules still apply.

Open **API Docs** after signing in for the searchable endpoint catalog. Each operation documents its authentication mode, required roles, parameters, request body, response schemas, and copyable curl and PowerShell examples. The explorer can execute ordinary JSON `GET` requests with the current browser session. Mutations, event streams, archive/raw evidence, reports, and single-use backup downloads remain examples only so documentation cannot bypass the application's confirmation workflows or accidentally consume a ticket.

Authenticated tools may download the same machine-readable schema from `/api/openapi.json` with either a browser session or personal bearer token. LayerScope intentionally keeps the conventional public `/docs` and `/redoc` routes disabled; the API inventory and internal models are not exposed to unauthenticated visitors.

### CLI and CI/CD automation

The Python 3.12+ client in [`cli/`](cli/) is a thin wrapper around the same authenticated API and persistent jobs used by the browser. It streams TAR uploads from disk, submits scans, polls with a bounded timeout, cancels jobs, reads findings, downloads reports, and can fail a pipeline at a selected severity threshold. It does not run Trivy or access SQLite directly.

Install it from the repository root, then provide a personal operator/admin token without placing the secret in a command argument:

```powershell
python -m pip install ./cli
$secureToken = Read-Host 'LayerScope API token' -AsSecureString
$env:LAYERSCOPE_TOKEN = [Net.NetworkCredential]::new('', $secureToken).Password
try {
    layerscope --url 'http://localhost:8080' whoami
    layerscope --url 'http://localhost:8080' scan --image-id 42 --wait --timeout 3600 --fail-on high
} finally {
    Remove-Item Env:LAYERSCOPE_TOKEN -ErrorAction SilentlyContinue
    Remove-Variable secureToken
}
```

Every result is a versioned JSON envelope. Progress uses standard error, `--quiet` suppresses it, and exit code `12` means the vulnerability gate failed. Upload retry behavior is explicit: `upload --if-absent` skips only an archive whose visible name and byte size already match; ordinary uploads are not assumed idempotent. Active scan requests retain the server's existing duplicate suppression. See [`cli/README.md`](cli/README.md) for all exit codes and [`examples/ci/`](examples/ci/) for a Jenkins workflow using a masked secret-text credential.

### Removing saved data

Administrators can open **Data** to remove a terminal scan or an image. Before deleting results that may be needed later, export the completed scans as **JSON** from Insights and retain that file. The same Data page can import the JSON later as a clearly marked report-only entry, restoring normalized findings, package inventory, scan dates, and coverage notes without restoring the original TAR or raw Trivy evidence. Imported results remain searchable, comparable, and exportable, but cannot be rescanned or downloaded. Importing the same report again is idempotent and skips the duplicate.

Removing a scan deletes its job record, normalized findings, package inventory, and preserved raw Trivy JSON. Removing an image first removes all of its terminal scans. Uploaded archives under `/data/uploads` are then permanently deleted; read-only mounted files cannot be deleted by the container, so they are hidden from discovery and can be restored from the same page. Report-only entries are permanently removed from SQLite, so retain their exported JSON if they may be needed again. Active scans must be cancelled before their scan or image can be removed. Destructive actions require an exact typed confirmation and are recorded in the audit log.

### Encrypted backup and restore

Open **Data** as an administrator and choose **Export encrypted backup**. Enter a unique password of at least 12 characters and store it separately from the downloaded `.tdbackup` file. The app takes an online SQLite snapshot and packages it with `/data/auth.key`, retained raw results, and uploaded TAR archives. AES-256-GCM authenticates and encrypts the complete payload; the password is used only in memory and is never stored.

To restore, select the `.tdbackup` file and enter its password. This first step only stages and validates the backup. Review the displayed creation time and record counts, then type `RESTORE BACKUP`. Restore is blocked while scan or component jobs are active. The backend restarts, atomically replaces the persisted data, revokes every restored session, and returns users to sign-in. If installation fails, the previous database and stored files are rolled back.

Trivy vulnerability and Java database caches are excluded because they are large, reproducible downloads. Reinstall or update them from **Components** after a restore. Read-only host-mounted image TARs are also outside the Docker volume; recreate the same Compose mounts when restoring on another machine.

## Security-data updates

The backend image is pinned to Trivy `0.74.0` and downloads the newest vulnerability database available from the configured OCI repositories while the image is built. On first startup, that bundled database seeds `/data/trivy-cache`. An existing persistent cache is never silently overwritten.

Open **Components** as an administrator to:

- inspect database installation, size, publication time, and next-update deadline;
- check whether the installed data is due for an update and whether a configured registry is reachable;
- update the vulnerability database without rebuilding the app;
- install or update the optional Java index database;
- follow persistent background-job progress and cancel an active download.

The Java database is intentionally not baked into the image because it is large and is only needed for Java archive identification. If it is absent, scans remain offline and complete OS and non-Java language-package analysis while explicitly excluding Java archives; the Jobs page records a coverage warning. Install Java DB from **Components** and rescan for full JAR/WAR/EAR coverage.

Normal scan jobs pass Trivy's skip-update flags and disable VEX repository refreshes and telemetry. This makes network access explicit: updates occur only when an administrator starts them on the Components page. Database maintenance takes an exclusive lock and waits for active scans; concurrent scan workers otherwise share read access safely.

Layer analysis can temporarily materialize very large files even when the final vulnerability report is small. Each scan therefore receives a mode-0700 workspace under `/data/trivy-tmp` on the persistent Docker data filesystem instead of the 1 GiB memory-backed `/tmp`. The workspace is removed after completion, failure, timeout, or cancellation; abandoned `scan-*` workspaces are removed on backend restart. This prevents large model, package, or binary files from failing solely because the hardened `/tmp` tmpfs is small, while normal storage-reserve checks still protect host capacity.

Two build arguments control the embedded tools:

| Build argument | Default | Meaning |
|---|---:|---|
| `GO_IMAGE` | Digest-pinned Go 1.26.8 Alpine image | Toolchain used only to build the scanner |
| `TRIVY_IMAGE` | Digest-pinned Trivy 0.74.0 image | Immutable scanner runtime/build-stage base |
| `TRIVY_VERSION` | `0.74.0` | Checksum-verified Trivy source release |
| `TRIVY_SOURCE_SHA256` | Pinned SHA-256 | Expected release-source archive checksum |
| `TRIVY_GRPC_VERSION` | `1.83.2` | Patched scanner gRPC dependency |
| `TRIVY_DB_SEED_VERSION` | `2026-09-25` | Cache-buster for the database download layer |

To force a newly built image to embed a newer database, change `TRIVY_DB_SEED_VERSION` in `.env` to the current date and rebuild. This is not necessary for ordinary updates performed from the app. The embedded database adds roughly the uncompressed database size to the backend image, while the source-code ZIP remains small.

## Using Insights

After at least one completed scan, open **Insights** to inspect packages or export the latest saved result. Select several images to create a combined LayerScope JSON, HTML, PDF, Elastic, or DefectDojo report. You can also select a group on **Groups** and export a snapshot in any of the same formats. A group snapshot contains the latest completed scan for each visible member, includes an image only once, and clearly records members excluded because they have no completed scan. Empty and entirely unscanned groups cannot be exported. HTML and PDF exports may include a one-time custom PNG or JPEG logo selected immediately before download. The logo is validated, stripped of metadata, re-encoded, embedded in that report, and never saved by LayerScope; JSON, Elastic, and DefectDojo remain unbranded. LayerScope JSON is the portable round-trip format: an administrator can later import it from **Data** to restore normalized dashboard history without image archives. HTML and PDF are presentation formats. Elastic produces ECS 9.5.0 newline-delimited JSON ready for the Elasticsearch Bulk API, and DefectDojo produces Generic Findings Import JSON; these compatibility files are not importable back into LayerScope. Once the same archive has two completed scans, Insights automatically compares the newest scan with the preceding scan.

Elastic export uses `application/x-ndjson`, targets the neutral `layerscope-vulnerabilities` index, ends with the Bulk API's required final newline, and assigns a deterministic SHA-256 document ID to every finding. Submit the file to an authorized Elasticsearch `/_bulk` endpoint with binary-preserving upload semantics. DefectDojo export uses `application/json`; import it with scan type **Generic Findings Import**. LayerScope `UNKNOWN` maps to Elastic `Unknown` and DefectDojo `Info`, with the original value retained in a DefectDojo tag and justification. Both formats omit host paths, archive storage paths, credentials, and raw Trivy evidence.

## Organizing related images

Open **Groups** to organize images by application, environment, team, release, or any other local convention. An image may belong to several groups. Viewers can browse group summaries, export group snapshots, and review a responsive overview of group count, visible memberships, completed-scan coverage, severity distribution, and highest-risk groups. Operators and administrators can create groups, edit their names/descriptions/colors, replace membership, delete a group without deleting its images, and queue all group members for scanning. Analytics and exports use the latest completed scan from each visible member. A member is counted once inside each group, so an image assigned to several groups contributes once to every one of those groups. Group membership is shown alongside archives on Overview.

See [TECHNICAL_README.md](TECHNICAL_README.md) for architecture, API, persistence, security controls, and extension guidance.
See [SECURITY.md](SECURITY.md) for the authentication design, role model, secure-session requirements, and OWASP verification plan.
See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the 1.0.0 OWASP/WSTG review, image-scan results, CIS Docker alignment, and residual risks.

## License

LayerScope is licensed under the [Apache License 2.0](LICENSE). Copyright 2026 LayerScope contributors. See [NOTICE](NOTICE) for attribution.

## Development

Backend:

```powershell
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt
$env:TRIVY_DASHBOARD_SCAN_ROOTS = "D:/DockerImages"
.venv/Scripts/uvicorn app.main:app --reload
```

Frontend:

```powershell
cd frontend
pnpm install --frozen-lockfile
pnpm run dev
```

The Vite development server proxies `/api` to `http://localhost:8000`.

## Verification

```powershell
cd frontend
pnpm run lint
pnpm run build

cd ../backend
.venv/Scripts/python -m pytest -q

cd ..
docker compose config
./scripts/verify-container-hardening.ps1
```

## Operational notes

- Job state is persisted in SQLite while dispatch remains in-process. Do not run multiple backend replicas against the same SQLite file.
- Scan admission is capped before records are created. HTTP 429 includes `Retry-After`; HTTP 507 protects the configured disk reserve. Existing jobs continue unaffected.
- The Jobs page shows queue, worker, storage, and live-event capacity. Diagnostics additionally verifies WAL mode, SQLite busy timeout, foreign keys, storage headroom, and SSE delivery.
- Multi-file upload streams directly into unique partial files on the persistent volume. A rejected, malformed, oversized, or interrupted batch rolls back database rows and removes every partial or completed archive created by that request.
- On a clean or unexpected restart, previously running jobs return to the queue and restart safely; queued jobs retain FIFO order.
- Trivy does not provide a stable item-by-item percentage for image archive scanning. Scan progress is therefore a monotonic stage-based estimate, while upload progress is byte-accurate when the browser provides a total size.
- The first normal scan uses the bundled or persisted vulnerability database and does not download security data. Use **Components** for intentional online updates.
- A missing Java DB never causes Trivy's first-run `--skip-java-db-update` failure: Java archives are excluded while OS, Python, and other non-Java packages are still scanned, and the completed job retains a coverage warning.
- Archive directories are mounted read-only. Only `/data` is writable and persistent.
