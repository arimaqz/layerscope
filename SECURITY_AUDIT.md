# Security Assessment — Release 1.0.0

Assessment date: 2026-09-25

## Scope and method

This review covered the React frontend, authenticated API documentation and tokens, the optional CLI, FastAPI routes and middleware, local authentication and TOTP lifecycle, SQLite persistence, report import/export and branding, uploads and backups, Trivy subprocess handling, Nginx proxy configuration, Dockerfiles, Compose deployment, and the built runtime images. The review used the OWASP Top 10:2025 as the risk taxonomy, the current OWASP Web Security Testing Guide as the web-test catalogue, and CIS Docker Benchmark v1.8.0 as the container-hardening reference.

This is an implementation review and repeatable local verification, not a claim of formal penetration-test coverage or CIS certification. Host-daemon controls cannot be proven from a repository and must be assessed on each target host.

## Outcome

- All 61 backend tests and all 11 CLI tests pass. The backend suite passes inside a non-root, read-only container with all capabilities dropped and `no-new-privileges` enabled.
- Frontend lint and the production TypeScript/Vite build pass.
- A fresh Trivy 0.74.0 database scan dated 2026-09-25 reports **0 fixable Critical or High findings** in both final images.
- Trivy configuration scanning reports **0 High or Critical misconfigurations**.
- The readiness scan initially found 16 fixable High findings: 2 in the bundled Trivy gRPC dependency and 14 in frontend Alpine packages. Trivy 0.74.0 is now rebuilt from its checksum-verified release source with gRPC 1.83.2, the frontend uses the refreshed digest-pinned Nginx image, and Alpine packages are upgraded during the image build.
- The fresh database subsequently exposed 8 additional fixable High findings in the Go 1.26.5 standard library. The scanner build now uses the digest-pinned Go 1.26.8 toolchain; the final rescan reports zero findings in the scanner binary, OS packages, and Python packages at the selected severities.

The JSON files in [`security-evidence`](security-evidence/) are retained historical snapshots from the preceding assessment. The commands below are the acceptance source for this assessment. Results remain point-in-time; rerun them whenever dependencies, base images, or vulnerability databases change.

## OWASP Top 10:2025 coverage

| Category | Implemented controls and review result |
|---|---|
| A01 Broken Access Control | Deny-by-default authenticated API middleware, reusable role dependencies, CSRF on mutations, admin-only raw evidence/backups/deletion/users, operator/admin TAR downloads, self-action and last-admin invariants, audit events for authorization denials, and no internal paths in normal payloads. |
| A02 Security Misconfiguration | Exact trusted hosts and CORS origins, minimal public health response, no API docs in production, defensive headers, generic error responses, localhost-only publication, private backend, non-root/read-only containers, no capabilities, bounded logs/resources, and zero failed Trivy configuration checks. |
| A03 Software Supply Chain Failures | Lockfile/pinned Python dependencies, digest-pinned base images, checksum-verified Trivy release source, a patched and version-stamped scanner build, separated build/test/runtime stages, runtime `pip` removal, explicit database repositories, bundled offline DB snapshot, and image/config scanning gates. Rebuild and rescan remain required for every release. |
| A04 Cryptographic Failures | Argon2id passwords, Fernet-protected TOTP seeds, hashed opaque sessions and one-time codes, single-use recovery codes, AES-256-GCM backups with scrypt-derived unique keys, and documented TLS/Secure-cookie requirement for remote use. |
| A05 Injection | SQLAlchemy parameterization, Pydantic validation with extra-field rejection, shell-free subprocess argument vectors, basename/root path validation, escaped React/HTML output, HTTP(S)-only advisory URLs, and inert-schema checks on imported SQLite files. |
| A06 Insecure Design | Explicit trust boundaries, local-first exposure, bounded queue/SSE/upload/backup/raw-result/discovery flows, two-stage destructive verification, recovery-safe restore, duplicate scan suppression, and offline-by-default normal scans. |
| A07 Authentication Failures | Local mandatory TOTP, Argon2id, short MFA challenges, idle and absolute session bounds, session concurrency cap, user-agent binding, rotation after MFA, account lockout, route/client throttling, activation/reissue expiry, replay prevention, and server-side revocation. |
| A08 Software or Data Integrity Failures | Immutable image digests, retained raw evidence, backup AEAD plus manifest hashes, ZIP member allowlists, measured expanded bytes, SQLite integrity/foreign-key/schema validation, atomic moves, restore rollback, and session revocation after restore. |
| A09 Security Logging and Alerting Failures | Opaque 128-bit request IDs, structured audit events for authentication/authorization and administrative mutations, sanitized scanner errors, query-free Nginx access logging, bounded log rotation, and no secret/session logging. External alert forwarding remains an operator integration. |
| A10 Mishandling of Exceptional Conditions | Central generic exception handling with correlation IDs, safe validation errors, bounded subprocess output/timeouts, transactional upload rollback, capacity errors with retry guidance, restart-safe job recovery, cancelled-child cleanup, and health/readiness checks. |

## WSTG-oriented checks performed

- Configuration: Host-header rejection, origin validation, defensive headers, disabled schema endpoints, path privacy, and minimal health disclosure.
- Identity/authentication: first-admin atomic setup, password/TOTP/recovery flow, failed-login lockout, activation and 2FA reissue boundaries, and no user self-registration.
- Authorization: role-gated routes, CSRF, last-admin/self-action invariants, terminal-job deletion rules, and root-contained downloads/removals.
- Session management: opaque HttpOnly SameSite cookie, idle/absolute expiry, MFA rotation, concurrent-session pruning, logout/revocation, and optional user-agent binding.
- Input validation/injection: Pydantic extra-field rejection, non-reflective validation errors, parameterized persistence, shell-free Trivy, safe filenames, TAR plausibility, traversal/symlink rejection, safe advisory schemes, and escaped reports.
- Error handling and privacy: no submitted values in 422 responses, generic 500 responses with request IDs, scanner error redaction, no host paths in ordinary APIs/reports, and query-free access logs.
- Business logic/availability: bounded scans, uploads, SSE, JSON/raw results, discovery, database backups, expanded archives, timeouts, storage reserve, resource quotas, and retry semantics.

Recommended deployment-time follow-up is an authenticated dynamic test through OWASP ZAP or an intercepting proxy, using dedicated viewer/operator/admin test accounts and a disposable data volume. Test TLS configuration at the real reverse proxy; it is intentionally outside the local Compose stack.

## CIS Docker alignment

Implemented repository/runtime controls include:

- trusted official base images pinned by digest and rebuilt with current OS security updates;
- dedicated non-root numeric users and no backend login shell;
- read-only root filesystems and size-bounded `noexec,nosuid,nodev` temporary filesystems;
- `cap_drop: ALL`, `no-new-privileges`, no privileged mode, no Docker socket, and no host PID/IPC/network namespaces;
- localhost-only frontend publication, no published backend port, and read-only archive mounts;
- CPU, memory, swap, PID, and file-descriptor limits;
- health checks, init processes, graceful stop windows, and bounded rotated logs;
- private persistent data ownership and restrictive runtime umask;
- narrow proxy body/rate/connection/timeout limits, with special handling only where uploads, backup transfer, or SSE require it.

The following host-level benchmark areas are not enforceable by this repository: daemon TLS/authorization, daemon and container audit rules, host filesystem ownership, user-namespace remapping, registry allowlists, image signing/content trust, secret-manager integration, host kernel/Engine patching, and centralized log/alert retention. Review those controls on the Docker Desktop or Linux host. The default `127.0.0.1` binding is deliberate; remote access requires a separately hardened TLS reverse proxy, exact origin configuration, and `AUTH_COOKIE_SECURE=true`.

## Residual risks and operating decisions

1. **Point-in-time dependency status.** The final images are clear of fixable High/Critical findings in the 2026-09-25 database, but advisories and fixed versions change continuously. Rebuild against current OS repositories and rescan immediately before every release.
2. **Untrusted archive analysis.** Trivy still parses attacker-influenced archives inside the backend container. Container restrictions reduce impact but do not create a perfect sandbox. Keep the app local/admin-only and consider a disposable dedicated worker service for hostile public submissions.
3. **Single-node SQLite/worker model.** One backend replica is required. Multi-replica or tenant-facing use needs PostgreSQL, durable worker leases, and stronger object-level tenancy boundaries.
4. **Local HTTP default.** Loopback HTTP is appropriate for the default local workflow. LAN or Internet exposure without TLS would expose authentication traffic; follow the remote-deployment requirements before changing the bind address.
5. **Outbound component updates.** Administrators intentionally initiate vulnerability/Java DB network updates. Egress allowlisting and registry availability are host/network responsibilities; normal scans remain offline. Downloads use private per-job workspaces on the application data volume and clean them after every terminal outcome.
6. **Monitoring integration.** Security events are retained locally, but real-time alert delivery and immutable centralized logs are not bundled because the project remains independent and local-first.

## Reproduction

```powershell
docker compose config --quiet
docker build --target test -t layerscope-backend-test:1.0.0 backend
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges `
  -e TRIVY_DASHBOARD_STORAGE_RESERVE_BYTES=67108864 `
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1g `
  --tmpfs /data:rw,noexec,nosuid,nodev,size=2g,uid=10001,gid=10001 `
  layerscope-backend-test:1.0.0
docker compose build
./scripts/verify-container-hardening.ps1
docker volume create layerscope-readiness-trivy-cache
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock `
  -v layerscope-readiness-trivy-cache:/root/.cache/ aquasec/trivy:0.74.0 image `
  --no-progress --disable-telemetry --scanners vuln --ignore-unfixed `
  --severity HIGH,CRITICAL --exit-code 1 layerscope-backend:latest
docker run --rm -v //var/run/docker.sock:/var/run/docker.sock `
  -v layerscope-readiness-trivy-cache:/root/.cache/ aquasec/trivy:0.74.0 image `
  --skip-db-update --no-progress --disable-telemetry --scanners vuln --ignore-unfixed `
  --severity HIGH,CRITICAL --exit-code 1 layerscope-frontend:latest
```

The image/config evidence files record full Trivy results. Do not use a stale scan as an acceptance gate; update the vulnerability database and reproduce the scan for each release.
