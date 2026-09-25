# LayerScope — Technical Guide

This document is the engineering reference for the repository. Installation belongs in [INSTALL.md](INSTALL.md), product behavior and operator workflows belong in [README.md](README.md), contribution rules for humans and coding agents belong in [CONTRIBUTING.md](CONTRIBUTING.md), and the security model belongs in [SECURITY.md](SECURITY.md).

Do not commit runtime data. SQLite files, authentication keys, uploaded archives, raw Trivy JSON, reports, backups, local `.env` files, caches, release archives, and the `work/` directory are intentionally excluded by `.gitignore` because they can contain private data.

## System architecture

The application has two containers and one persistent Docker volume:

```text
Browser                 CLI / CI client
  |
  | HTTP + SSE             | HTTPS + bearer token
  v
Nginx / React frontend
  |
  | /api reverse proxy
  v
FastAPI backend
  |-- persisted SQLite jobs + asyncio dispatcher
  |-- persisted component-maintenance queue + database read/write lock
  |-- Trivy subprocesses
  |-- SQLite normalized data
  |-- raw Trivy JSON
  |-- uploaded TAR archives
  `-- generated LayerScope JSON / HTML / PDF / Elastic NDJSON / DefectDojo JSON responses
```

`frontend` is built with React, TypeScript, Vite, Tailwind, TanStack Query, TanStack Table, TanStack Virtual, React Router, Recharts, and Lucide React. `backend` uses FastAPI, SQLAlchemy, SQLite, ReportLab, and the Trivy binary copied from the official container image.

The Python 3.12+ client under `cli/` is dependency-free and deliberately remains outside both container images. It is a thin HTTP client of the same FastAPI authorization, upload, persistent-job, finding, and export routes; it never invokes Trivy or opens SQLite. Large uploads and report downloads stream in bounded chunks.

The frontend lazy-loads each route and the chart-heavy dashboard module separately, keeps server state in TanStack Query, and uses shared status/source components so the same state has the same label and color everywhere. Scan/component SSE bursts are coalesced before active query invalidation; slow safety polling becomes less frequent when no work is active. Search requests are debounced and the overview renders archives in bounded pages while finding rows remain virtualized. The responsive header keeps Overview, Groups, Jobs, and Insights visible on wide screens, groups lower-frequency destinations by purpose, and exposes the same hierarchy in a compact mobile menu. Administration links are omitted for non-administrators as a usability measure while backend authorization remains authoritative. Menus close on navigation, outside interaction, or Escape; Escape restores focus to the originating control. Light and dark themes use explicit surface, text, border, focus, feedback, and chart overrides; system preference supplies the first default and the user choice is persisted locally. Native browser prompts are not used for protected operations. Dialogs and the finding drawer expose dialog semantics, keyboard dismissal, focus visibility, and background scroll locking. Reduced-motion preferences disable decorative transitions and animations.

## Persistence model

The `trivy-data` volume is mounted at `/data` and contains:

```text
/data/trivy.db       SQLite database
/data/raw/           immutable raw Trivy JSON by scan ID
/data/uploads/       browser-uploaded image archives
/data/trivy-cache/   Trivy vulnerability database cache
/data/trivy-tmp/     private per-scan temporary layer workspaces
```

The backend image also contains `/opt/trivy-cache-seed/`, the read-only vulnerability database used to initialize an empty persistent cache.

The main tables are:

- `images`: discovered or uploaded archive identity and filesystem metadata
- `scans`: persistent job state, progress/stage, timing, errors, and raw JSON location
- `findings`: normalized vulnerability records
- `packages`: normalized package inventory when provided by Trivy
- `maintenance_jobs`: persistent component check/update state, progress, results, and errors
- `upload_jobs`: persistent upload receive/validation progress, timing, archive linkage, and bounded errors
- `image_groups` and `image_group_members`: reusable many-to-many logical organization independent of immutable scan evidence
- `users`: local identities, roles, password hashes, encrypted TOTP seeds, lockout state, and hashed expiring activation/2FA-reissue tokens
- `auth_sessions`, `api_tokens`, `recovery_codes`, and `audit_events`: revocable server-side sessions, hash-only expiring personal API credentials, single-use recovery material, and security event history

Package inventory falls back to the packages represented in vulnerability findings for older scans and Trivy output that omits a full package list.
Trivy package identifiers may be either strings or structured objects depending on the analyzer and Trivy release. The normalization boundary converts every persisted text field deterministically; structured identifiers prefer their PURL, while the unmodified object remains in the retained raw JSON.

Portable report imports reuse the existing normalized schema without a destructive migration. A report-only image has an opaque `report://<sha256>` identity rather than a filesystem path, and an imported scan stores a non-filesystem `report-import:<sha256>` evidence marker for idempotent duplicate detection. Path validation therefore rejects report-only entries from scan, TAR-download, and raw-result routes while normal findings, package, comparison, grouping, and export queries continue to work.

## Scan lifecycle

1. `POST /api/scans` validates every selected archive against configured roots.
2. A `queued` database row is created for each image.
3. The dispatcher suppresses duplicate active scans for the same archive and sends jobs to the configured number of workers.
4. Each worker acquires shared database access and calls Trivy using `asyncio.create_subprocess_exec`; no command shell is involved.
5. Bounded Trivy output is decoded as UTF-8 and mapped to monotonic progress stages; stderr is retained only as a bounded failure tail.
6. Trivy writes JSON directly into `/data/raw`; the backend normalizes findings and packages in one database transaction.
7. SSE publishes status, progress, stage, and message updates. The UI also polls as a recovery fallback.
8. Cancellation terminates an active Trivy child process. Failed/cancelled work can be retried as a new immutable scan record.
9. On startup, persisted `running` records are safely reset to `queued` and dispatched again with their FIFO peers.

Normal scans use `--skip-db-update`, `--skip-java-db-update`, `--skip-vex-repo-update`, and `--disable-telemetry`. A scan never downloads or mutates component data. When Java DB has not been installed, the command excludes Java archive formats so Trivy still analyzes the OS and non-Java ecosystems instead of rejecting `--skip-java-db-update` on first use. The scan persists a coverage warning; after an administrator installs Java DB, rescans automatically restore full Java archive analysis. Component updates acquire exclusive database access, so they wait for active scans and prevent new scans from observing a partially installed database.

Dispatch is intentionally process-local while job state is durable. Run one backend replica while using SQLite. Production multi-replica deployments should use a distributed queue and PostgreSQL with worker leases.

## Quality of service and backpressure

The app admits at most `MAX_PENDING_SCANS` queued plus running scans. Admission is serialized in-process, duplicate active image scans are reused, and capacity is checked before new database rows are committed. A full queue returns HTTP 429 with `Retry-After`; low storage returns HTTP 507 before a scan, upload, export, or restore stage consumes the protected reserve. Under Compose, a dedicated empty host directory is mounted read-only as a capacity probe. Storage enforcement and telemetry use the smaller free-space value from that host filesystem and the Docker data volume, preventing Docker Desktop's sparse virtual-disk maximum from being mistaken for physical host capacity. Upload multipart bodies are parsed incrementally and written directly to unique partial files in managed persistent storage instead of being spooled through container `/tmp`. These responses reject new demand without interrupting admitted work.

Uploads are bounded by archive size, combined request size, file count, disk headroom, and a non-extracting Docker/OCI TAR metadata check. The browser sends a selected multi-file queue as sequential single-file requests so it never owns one enormous multipart batch; weighted progress covers the complete queue, successful earlier files remain saved after a later failure, and the UI reports partial success. Each request creates a persistent upload-job row before reading the body, publishes throttled receive progress, records validation and registration stages, and retains a sanitized success or failure outcome on the unified Jobs page. The API still accepts multi-file clients transactionally: any invalid file, size breach, disk-pressure event, or database error removes all files created by that individual request and rolls back its image rows. Backup export estimates temporary working-space demand; import rechecks headroom while streaming and before expansion.

Trivy may materialize an individual layer file while analyzing it. Scan subprocesses receive explicit `TMPDIR`, `TMP`, and `TEMP` values pointing to a unique mode-0700 workspace under `/data/trivy-tmp`, avoiding the intentionally small memory-backed container `/tmp`. Cleanup runs in the scan `finally` path for success, scanner failure, timeout, cancellation, or service shutdown. Startup deletes only abandoned `scan-*` entries inside the dedicated root before recovered jobs resume. The directory remains outside backup payloads and Diagnostics verifies its writability and real storage headroom.

Each SSE subscriber has a bounded buffer and the service caps simultaneous streams. Slow-client drops and rejected connections are counted; TanStack polling remains the recovery path. The Jobs page polls `/api/service-status` for current queue, worker, storage, and event capacity. Diagnostics includes the same signals plus SQLite WAL, busy timeout, and foreign-key state.

SQLite connections enable WAL, a 15-second busy timeout, foreign keys, `synchronous=NORMAL`, an in-memory temporary store, a bounded page cache, composite hot-path indexes, planner optimization, and periodic WAL checkpoints. Archive discovery is serialized, reuses one archive lookup, and is automatically throttled for 30 seconds while explicit discovery bypasses that interval. Image and group summaries use set-based latest-scan/count queries whose database round trips do not grow per row. Normalized package and finding rows are saved in bounded executemany batches. Nginx adds per-client request/connection shaping, specialized long-lived upload/backup/SSE timeouts, buffered/compressed ordinary APIs, immutable asset caching, and open-file caching. Backend responses include an opaque `X-Request-ID` and `Server-Timing` duration; expensive anonymous authentication routes also have a bounded per-client window in addition to account lockout. Compose uses truthful backend readiness, frontend health checks, init processes, PID limits, and graceful shutdown windows.

## Important API routes

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/health` | Minimal unauthenticated readiness status; no runtime configuration |
| `GET` | `/api/openapi.json` | Authenticated OpenAPI 3 schema with per-operation authentication and RBAC metadata |
| `GET` | `/api/auth/status` | First-run setup state |
| `POST` | `/api/auth/setup` | Atomically create the initial local administrator and TOTP enrollment |
| `POST` | `/api/auth/activate` | Activate an existing admin-created pending account; never creates an identity |
| `POST` | `/api/auth/reenroll-2fa` | Verify current password plus an admin-issued code and privately begin replacement TOTP enrollment |
| `POST` | `/api/auth/login` | Verify Argon2id password and create a short MFA challenge |
| `POST` | `/api/auth/totp/verify` | Verify TOTP/recovery code and rotate into a full session |
| `GET` | `/api/auth/me` | Current user and CSRF value |
| `POST` | `/api/auth/logout` | Revoke the current server-side session |
| `GET` | `/api/api-tokens` | Session-only inventory of the current user's token metadata |
| `POST` | `/api/api-tokens` | Session/CSRF-only one-time personal token issuance |
| `DELETE` | `/api/api-tokens/{id}` | Session/CSRF-only revocation of a token owned by the current user |
| `GET` | `/api/users` | Admin-only local user inventory |
| `POST` | `/api/users` | Admin-only pending-account creation and one-time activation code issuance |
| `POST` | `/api/users/{id}/update` | Admin-only role, display-name, and access-state changes |
| `POST` | `/api/users/{id}/reissue-activation` | Admin-only password/TOTP reset and new one-time activation code |
| `POST` | `/api/users/{id}/reissue-2fa` | Admin-only password-preserving 2FA re-enrollment code issuance |
| `POST` | `/api/users/{id}/unlock` | Admin-only lockout reset |
| `DELETE` | `/api/users/{id}` | Admin-only permanent account removal with self/last-admin safeguards |
| `GET` | `/api/diagnostics` | Active component, storage, queue, and registry checks |
| `GET` | `/api/components` | Installed/bundled component inventory and latest maintenance jobs |
| `POST` | `/api/components/check` | Queue vulnerability and Java database update checks |
| `POST` | `/api/components/{component}/update` | Queue an explicit database download/update |
| `POST` | `/api/component-jobs/{id}/cancel` | Cancel queued or running component maintenance |
| `POST` | `/api/discover` | Rescan configured roots for `.tar` files |
| `POST` | `/api/uploads` | Stream one or more `.tar` files into persistent storage |
| `GET` | `/api/upload-jobs` | Persistent upload progress and terminal history |
| `POST` | `/api/backups/export` | Admin-only encrypted backup creation and one-hour download ticket |
| `GET` | `/api/backups/download/{token}` | Same-admin, single-use native backup download |
| `POST` | `/api/backups/import` | Admin-only streaming upload, decryption, staging, and validation |
| `DELETE` | `/api/backups/{token}` | Discard a validated staged import |
| `POST` | `/api/backups/{token}/restore` | Typed-confirmation atomic restore and controlled restart |
| `GET` | `/api/images` | Archives with latest-scan summary |
| `GET` | `/api/images/removed` | Admin-only hidden mounted-archive inventory |
| `GET` | `/api/images/{id}/archive` | Root-validated original TAR download |
| `DELETE` | `/api/images/{id}` | Admin-only image, scan-history, and managed-upload removal |
| `POST` | `/api/images/bulk-delete` | Admin-only pre-validated removal of up to 500 images |
| `POST` | `/api/images/{id}/restore` | Admin-only restore of a hidden mounted archive |
| `GET` | `/api/groups` | Group summaries using latest completed member scans |
| `GET` | `/api/groups/overview` | Constant-count membership coverage, severity, status, and per-group analytics |
| `GET` | `/api/groups/{id}` | Group details and visible members |
| `POST` | `/api/groups` | Operator/admin group creation |
| `POST` | `/api/groups/{id}/update` | Operator/admin group metadata update |
| `POST` | `/api/groups/{id}/members` | Operator/admin atomic membership replacement |
| `POST` | `/api/groups/{id}/members/add` | Operator/admin additive bulk membership assignment |
| `DELETE` | `/api/groups/{id}` | Operator/admin group removal without deleting images or scans |
| `POST` | `/api/scans` | Queue scans for selected image IDs |
| `DELETE` | `/api/scans/{id}` | Admin-only terminal scan, findings, packages, and raw JSON removal |
| `POST` | `/api/scans/bulk-delete` | Admin-only atomic pre-validation and removal of up to 500 terminal scans |
| `GET` | `/api/jobs` | Filterable persisted job list with progress and queue positions |
| `POST` | `/api/jobs/{id}/cancel` | Cancel queued/running work and terminate an active Trivy process |
| `POST` | `/api/jobs/{id}/retry` | Create a new job from a failed/cancelled scan |
| `GET` | `/api/events` | Live scan events over SSE |
| `GET` | `/api/scans/{id}/findings` | Findings filtered by text, severity, package, target, and fix availability |
| `GET` | `/api/scans/{id}/summary` | Compact job status and grouped severity counts for automation clients |
| `GET` | `/api/scans/{id}/finding-filters` | Distinct package and target options for saved findings |
| `GET` | `/api/scans/{id}/packages` | Package inventory |
| `GET` | `/api/images/{id}/compare` | Latest/previous or explicitly selected scan comparison |
| `GET` | `/api/scans/{id}/raw` | Admin-only original Trivy JSON |
| `GET` | `/api/exports` | Combined unbranded LayerScope JSON, HTML, PDF, Elastic ECS Bulk NDJSON, or DefectDojo Generic Findings JSON report selected by `scan_ids` or `group_ids` |
| `POST` | `/api/exports/branded` | One-time branded HTML/PDF export with a raw PNG/JPEG request body and the same mutually exclusive selection parameters |
| `POST` | `/api/reports/import` | Admin-only bounded import of a LayerScope normalized JSON report |

The frontend route `/api-docs` renders the protected schema as a searchable in-app explorer. It resolves component references into synthetic request examples, provides curl and PowerShell commands, and permits live execution only for ordinary JSON `GET` operations using the existing browser session. Mutations, SSE, archives, raw evidence, report files, and single-use backup downloads are deliberately non-executable in the explorer. FastAPI's public Swagger and ReDoc routes stay disabled. `require_roles(...)` and the session-only dependency annotate their dependency callables so schema generation derives access metadata from the same authorization declarations that protect runtime routes.

Example combined export:

```text
GET /api/exports?scan_ids=12&scan_ids=18&format=pdf
```

Group exports use the mutually exclusive `group_ids` parameter. The backend validates every group, deduplicates overlapping visible members, and resolves each member's latest completed scan with bounded set-based queries. The JSON, HTML, and PDF outputs include snapshot coverage and sampled excluded-member names; Elastic and DefectDojo records carry group context. Empty or entirely unscanned selections return `409`, missing groups return `404`, and selections exceeding 100 completed member reports return `422`.

```http
GET /api/exports?group_ids=4&group_ids=9&format=json
```

Custom branding is deliberately per-export rather than persisted configuration. `POST /api/exports/branded` accepts only raw `image/png` or `image/jpeg` bodies up to 2 MiB and only `format=html` or `format=pdf`. The decoder verifies the encoded container and declared type, rejects trailing payloads, animation, malformed data, dimensions above 2000×1000, or more than 2,000,000 decoded pixels, then removes metadata by re-encoding the image as PNG. The sanitized bytes are embedded as a local data URI or in-memory PDF image and discarded after the response. The route does not accept a path or URL, perform network access, or write temporary files. It retains normal authentication, role, CSRF, origin, request-rate, and audit controls.

All normalized report payloads intentionally omit the archive filesystem path. Downloads of original TAR files resolve the saved path, require a `.tar` suffix, and verify containment below a configured scan root before serving it. LayerScope JSON exports carry the versioned `layerscope-report` marker, a stable opaque image key, normalized findings, package inventory, timestamps, and coverage notes. Legacy LayerScope JSON exports that predate the marker and package inventory remain importable; packages are conservatively reconstructed from finding records.

`format=elastic` returns `application/x-ndjson` for the Elasticsearch Bulk API, pinned to ECS 9.5.0. Each finding is preceded by an `index` action for `layerscope-vulnerabilities`; the action `_id` and ECS `event.id` use the same deterministic SHA-256 identity derived from the portable image key, scan timestamp, vulnerability, package, installed version, and target. Documents use `event.kind=state`, `event.category=[vulnerability]`, `event.type=[info]`, plus ECS container, package, observer, and vulnerability fields. LayerScope-only normalized values live below the non-ECS `layerscope` namespace. The final NDJSON line always ends in a newline as required by the Bulk API.

`format=defectdojo` returns DefectDojo Generic Findings Import JSON with report type `LayerScope`. Each finding carries the stable identity in `unique_id_from_tool`, the scanner identifier in both `vuln_id_from_tool` and `vulnerability_ids`, dependency fields, image name as `service`, target as `file_path`, fix metadata, reference, and conservative active/unverified/static state. `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` map directly; `UNKNOWN` deterministically maps to DefectDojo `Info` with an explicit severity justification and original-severity tag. These are portable files only—LayerScope never receives or stores Elastic/DefectDojo credentials and does not contact either service.

### CLI automation contract

`layerscope` emits a `cli_schema_version: 1` JSON envelope on standard output for completed commands and a matching structured error envelope on standard error. Progress never shares standard output. Exit codes distinguish invocation, authentication, authorization, missing resources, conflicts, capacity, server, network/TLS, failed/cancelled jobs, policy gates, and wait timeouts. Waits always have an explicit finite timeout and optionally request cancellation on expiry.

Bearer secrets are accepted only from `LAYERSCOPE_TOKEN`, standard input, or an explicit secret file; the CLI has no token-value argument. HTTPS uses the platform trust store or a caller-supplied CA bundle and never disables certificate verification or follows redirects. API-token requests keep the owner's live RBAC state, and the server continues to reject bearer access to token-management routes.

Upload bodies use one streamed multipart `files` part per CLI invocation. `upload --if-absent` is an opt-in retry guard based on visible name plus byte size, not content identity; without it, upload submission is not idempotent. Scan submission inherits server-side duplicate suppression for an already active image job. The synthetic HTTP-server tests in `cli/tests/` cover bearer handling, streamed multipart uploads, job completion, severity gates, and overwrite-safe downloads. `examples/ci/Jenkinsfile` demonstrates a masked credential and a bounded `HIGH` gate.

## Backup format and restore lifecycle

`.tdbackup` uses a small versioned JSON header followed by an AES-256-GCM encrypted ZIP64 payload and authentication tag. The encryption key is derived from the administrator-supplied password with scrypt (`N=32768`, `r=8`, `p=1`) and a random 128-bit salt; every export uses a random 96-bit nonce. The password and derived key are never persisted. The payload contains:

- a SQLite online-backup snapshot with an integrity check;
- `auth.key`, required to decrypt restored TOTP secrets and validate recovery-code hashes;
- retained raw Trivy JSON;
- dashboard-managed uploaded TAR files;
- a versioned manifest with per-file sizes and SHA-256 hashes.

Trivy DB and Java DB caches are deliberately excluded as reproducible component downloads. Host bind mounts are outside app-owned storage and are not copied.

Import first streams to private storage with a configured size bound, authenticates and decrypts the complete file, rejects duplicate, absolute, parent-traversal, symlink, unknown, or excessive ZIP entries, verifies the manifest and every hash, runs SQLite schema/integrity checks, and validates the Fernet authentication key. No live file changes occur during staging. Restore requires an exact `RESTORE BACKUP` confirmation and no active scan/component work. A `READY` marker is written, the process exits, and Compose restarts it. Before SQLAlchemy or workers start, the lifespan handler atomically swaps SQLite, the auth key, raw results, and uploads on the same volume. Existing files are held in a rollback directory until validation succeeds, and restored authentication sessions are deleted before accepting traffic.

## Comparison semantics

A finding identity is the tuple:

```text
(vulnerability ID, package name, installed version, target)
```

Keys only in the target scan are **new**. Keys only in the base scan are **resolved**. Shared keys are **unchanged**. A package version change therefore appears as a resolved old finding and a new current finding, which preserves the evidence rather than hiding version transitions.

## Security controls

- `SCAN_ROOTS` is the sole path allowlist.
- Resolved paths must equal an allowed root or be descendants of one.
- Paths are revalidated immediately before scan execution.
- Host archive mounts are read-only.
- Upload filenames are reduced to their basename and restricted to `.tar`.
- Uploads are streamed in 1 MiB chunks and finalized using an atomic rename.
- Existing uploads are never overwritten; a random suffix is added.
- Trivy is executed with an argument vector, never `shell=True`.
- Raw-result downloads are restricted to the configured raw-results directory.
- Raw-result downloads require administrator authorization; ordinary payloads replace internal paths with a source classification.
- Scanner-provided advisory links are accepted only when they are absolute HTTP(S) URLs without credentials.
- Validation failures never reflect submitted values, and unexpected errors return only an opaque correlation ID.
- Unsafe cross-origin mutations and untrusted Host headers are rejected before route handling.
- React escapes rendered API data; HTML exports escape all report values.
- CORS is restricted to configured origins and required methods/headers.
- Nginx applies CSP, clickjacking, MIME-sniffing, referrer, permissions, and cross-origin isolation headers.
- The default published port binds only to `127.0.0.1`.
- Uploads are streamed and subject to per-file size limits.
- Passwords are Argon2id-hashed; TOTP secrets are encrypted with a local persistent key.
- Opaque session tokens are SHA-256-hashed in SQLite and delivered only through HttpOnly SameSite cookies.
- State-changing authenticated requests require a session-bound CSRF value.
- Personal bearer tokens use a fixed `lsp_` format, cryptographic randomness, SHA-256 hash-only storage, a 1–365 day lifetime, per-user active-token cap, throttled last-used writes, ownership-scoped management, and one-time reveal. Bearer requests skip CSRF because clients explicitly set `Authorization`; cookie-plus-bearer ambiguity is rejected. Token-management routes require a full browser session and cannot be called with a bearer token.
- TOTP time steps and recovery codes cannot be reused.
- Scan mutations require `operator` or `admin`; diagnostics require `admin`.
- User inventory and every account-creation or management route require `admin`; first-run setup becomes unavailable once an active user exists.
- Scan/image deletion and mounted-image restoration require `admin`, a valid session-bound CSRF token, and server-side state/path validation. Active work cannot be deleted.
- Only archives resolved below the managed upload directory can be unlinked. Read-only mounted archives are tombstoned in SQLite and remain recoverable.
- Group reads are available to authenticated viewers. Group and membership mutations require operator/admin authorization and CSRF validation; submitted image IDs must reference visible archive records.
- Activation tokens use cryptographically random values, are stored as SHA-256 hashes, expire, and can only activate a pre-existing pending identity.
- Role and access changes revoke the affected user's sessions and API tokens. Token authorization also reads the current user role and active/TOTP state on every request. Server invariants prevent self-demotion/self-disable and removal of the last active administrator.

This is a local administrative tool with local password and mandatory TOTP authentication. Authentication does not make plain HTTP safe; do not expose port 8080 to an untrusted network without TLS and the controls specified in [SECURITY.md](SECURITY.md).

Lost-password recovery is deliberately outside the HTTP surface. `python -m app.admin_cli reset-admin-password` requires an interactive server/container terminal plus the target active administrator's current TOTP or unused recovery code. Secrets are collected with hidden terminal prompts and never accepted as arguments or environment variables. The transaction reuses the normal password policy and Argon2id parameters, prevents password reuse, serializes SQLite mutation, enforces active-admin/TOTP state, applies TOTP replay protection or consumes one recovery code, clears lockout and pending reset tokens, deletes existing sessions, revokes existing API tokens, and appends an `admin_password_recovery` audit event with `local-console` origin. The TOTP secret and remaining recovery codes are preserved. No HTTP endpoint or second-factor bypass exists.

## Diagnostics and database mirrors

The Diagnostics page returns the complete five-item component inventory even when files are absent: vulnerability DB, Java DB, Trivy engine, checks bundle, and VEX Hub. A missing required component is an error; a missing optional component such as the Java DB is informational and does not lower overall health. It also executes bounded, read-only operational checks, except for temporary create/delete probes inside configured writable data directories. It does not download a database or start a scan. Registry checks cover every configured vulnerability and Java DB repository and call its `/v2/` endpoint; HTTP 200 or the standard OCI authentication challenge (401) counts as reachable.

Vulnerability database downloads explicitly prefer `ghcr.io/aquasecurity/trivy-db:2`, with `public.ecr.aws/aquasecurity/trivy-db:2` as fallback. The optional Java database uses the matching `trivy-java-db:1` repositories. This avoids dependence on the Google pull-through mirror that can return HTTP 403 on restricted networks. Override the comma-separated lists with `TRIVY_DASHBOARD_TRIVY_DB_REPOSITORIES` and `TRIVY_DASHBOARD_TRIVY_JAVA_DB_REPOSITORIES`. The Compose project name is `layerscope`. The legacy environment prefix, backup format identifiers, browser-storage keys, and physical data-volume name are intentionally retained across the rename so installed systems remain upgrade-compatible.

## Bundled data and component maintenance

The backend Dockerfile downloads the pinned Trivy release source with Docker's checksum verification, builds it with digest-pinned Go 1.26.8 and patched gRPC 1.83.2, places the version-stamped binary into the digest-pinned official Trivy runtime stage, runs `--download-db-only`, and copies the resulting cache into `/opt/trivy-cache-seed`. Startup copies a seed directory only when the corresponding persistent metadata does not exist. It never rolls back a volume that already contains newer or user-updated data.

The `ComponentManager` is a single persistent background worker. It provides duplicate suppression per component, restart recovery, cancellation, bounded Trivy output, timeouts, SSE events, and polling-compatible state. Checks read local metadata and make a bounded OCI `/v2/` reachability request. Updates use Trivy's official `--download-db-only` or `--download-java-db-only` paths with GHCR-to-ECR fallback and verify installed metadata before completing. Each update receives a mode-0700 temporary workspace under `/data/component-tmp`, so large OCI artifacts use the persistent data volume rather than the memory-backed `/tmp`; the per-job workspace is removed on success, failure, timeout, or cancellation.

The tracked downloadable component inventory is:

- vulnerability database: required and bundled;
- Java index database: optional and downloaded on demand;
- Trivy engine: pinned by image digest and updated by rebuilding with a newer `TRIVY_IMAGE`;
- misconfiguration checks: not downloaded because Phase 2 scans vulnerabilities only; Trivy has an embedded fallback;
- VEX Hub: optional and deliberately disabled for network-predictable scans.

Set `TRIVY_DB_SEED_VERSION` to a new value (normally an ISO date) to invalidate only the Docker database-download layer. In-app DB updates write to the volume and do not require an image rebuild or a rescan. The source archive does not contain the database blob; the reproducible Docker build embeds the freshest artifact available at build time.

## Frontend state

TanStack Query owns server state. The app subscribes once to `/api/events` and invalidates image, overview, scan-job, component-job, finding, package, diagnostic, user, and comparison queries when state changes. Polling recovers from a transient SSE disconnect. Theme choice is stored in browser `localStorage`; it does not affect server data.

All HTTP, upload, export, authentication, query, mutation, and persisted-job failures pass through one error normalizer before rendering. It understands FastAPI/Pydantic `detail` arrays and nested message objects, converts validation locations into readable field paths, handles JSON embedded in strings, deduplicates messages, and falls back safely when details are unavailable. Fields whose names indicate passwords, secrets, tokens, cookies, CSRF values, recovery codes, or one-time codes are excluded from generic object formatting.

The vulnerability grid uses TanStack Table for sorting/resizing and TanStack Virtual to render only visible rows. Details are displayed in a drawer so long descriptions remain accessible without widening every column.

## Report formats

- **JSON**: versioned, normalized UTF-8 with deterministic severity ordering; suitable for automation and administrator-only round-trip import
- **HTML**: standalone UTF-8 document with embedded styling and no remote dependencies
- **PDF**: landscape A4 report generated on demand with ReportLab

Reports read existing SQLite data. Exporting, importing, branding, or changing report presentation never invokes Trivy. Import accepts one LayerScope JSON document directly rather than multipart form data, streams it through a configurable 64 MiB request bound, verifies the declared report/count integrity, allowlisted fields, completed status, bounded timestamps and text, safe advisory URLs, and aggregate limits of 100 reports, 250,000 findings, and 500,000 packages. It writes all normalized rows in one transaction, records an audit event, and skips matching fingerprints. It never writes an archive or raw Trivy JSON. HTML, PDF, Elastic, and DefectDojo files are intentionally not importable.

## Schema evolution

SQLAlchemy `create_all` creates missing tables on startup. A small idempotent additive upgrader adds job-progress columns to existing SQLite volumes without deleting scan data. Use Alembic before introducing destructive or cross-database schema changes.

## Verification commands

```powershell
cd frontend
pnpm install --frozen-lockfile
pnpm run lint
pnpm run build

cd ../backend
python -m pip install -r requirements-dev.txt
python -m pytest -q

cd ..
python -m unittest discover -s cli/tests -v

docker compose config
docker compose build
```

The frontend Docker build separates Corepack setup from dependency metadata and mounts a persistent BuildKit pnpm store. This keeps lockfile-pinned installs reproducible while avoiding full dependency downloads on routine rebuilds; only new or changed packages need network access after the cache is warm.

The backend Dockerfile likewise installs runtime and test dependencies before copying application or test source. Routine Python changes therefore reuse the dependency layers instead of downloading pytest and its support packages again.

## Extension points

Good next integrations include CycloneDX/SARIF export, registry scanning with credential isolation, EPSS and CISA KEV enrichment, scheduled scans, ignore policies with audit history, PostgreSQL, and external queues. Keep external enrichment separate from immutable Trivy evidence so reports remain reproducible.
