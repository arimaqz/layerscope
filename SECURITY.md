# Security and Authentication Design

## Current security boundary

The dashboard implements independent local authentication with mandatory TOTP enrollment. It does not contact an external identity service. The network listener still defaults to `127.0.0.1:8080`; authentication does not replace TLS, operating-system hardening, backups, or network access control.

The application processes attacker-influenced archives and invokes a security scanner, so it should be treated as an administrative security tool rather than a public upload service.

## Implemented authentication architecture

The browser uses a backend-for-frontend session model, while explicit API clients may use personal bearer tokens:

```text
Browser
  |-- opaque Secure + HttpOnly cookie
  v
FastAPI local authentication/session middleware
  |-- Argon2id password verification
  |-- encrypted RFC 6238 TOTP verification
  |-- opaque bearer-token verification
  `-- SQLite session, token, and audit records
```

The browser persistently stores no password, TOTP secret, recovery code, access token, or session identifier in JavaScript-accessible storage. It receives an opaque HttpOnly session cookie. Recovery codes are held in memory only while their one-time setup screen is visible. A non-secret CSRF value is held in session storage and must match the server-side session record for state-changing requests.

Personal API tokens are created and revoked only from a full browser session protected by CSRF. A token contains cryptographic randomness, is displayed once, and is stored only as a SHA-256 digest plus a short identifying prefix and lifecycle metadata. It expires within at most one year, can be revoked immediately, and is checked against the owner's current active state, TOTP enrollment, and role on every request. API-token calls use `Authorization: Bearer` and do not use cookie CSRF because the client explicitly supplies that header; requests presenting both credential types fail closed. API tokens cannot list, create, or revoke API tokens. Token secrets must never be placed in URLs, logs, source, or command-line arguments.

The optional CLI preserves that boundary. It accepts bearer secrets only through a protected environment variable, standard input, or an explicit restricted secret file and never includes them in JSON output. It uses verified HTTPS for remote deployments, supports a private CA bundle without an insecure verification bypass, rejects credential-bearing URLs and redirects, streams archives from disk, bounds JSON responses and waits, refuses output overwrite unless explicitly requested, and continues to rely on server-side RBAC, limits, path validation, archive validation, and duplicate suppression. CI logs and saved JSON reports can still contain private image or vulnerability metadata and require access controls and retention limits.

The OpenAPI schema at `/api/openapi.json` is protected by the same authentication middleware as application data. The in-app API Docs page does not accept or store token secrets and runs only ordinary JSON `GET` operations through the current browser session. Mutations, streams, evidence/report downloads, and single-use backup tickets are documentation-only. Public Swagger and ReDoc routes remain disabled so unauthenticated visitors cannot inventory internal endpoints, schemas, or administrative capabilities.

Passwords use Argon2id with memory-hard parameters. TOTP seeds use Fernet authenticated encryption with a locally generated `/data/auth.key`. TOTP codes are accepted within a narrow clock window and a successfully used time step cannot be replayed. Recovery codes contain cryptographic randomness, are HMAC-hashed at rest, and are marked used transactionally.

## Session requirements

Local HTTP mode uses a host-only cookie similar to:

```text
trivy_session=<opaque random value>;
HttpOnly; SameSite=Strict; Path=/
```

For any HTTPS deployment, set `AUTH_COOKIE_SECURE=true`; the cookie then includes `Secure`. You may also configure a `__Host-` prefixed cookie name when HTTPS is guaranteed.

- At least 128 bits of cryptographic randomness
- Server-side session record containing user, roles, creation, last activity, and revocation state
- Rotate the session identifier after login, reauthentication, and privilege changes
- Invalidate it server-side on logout
- Enforce idle and absolute lifetimes; a reasonable starting point is 30 minutes idle and 8 hours absolute
- Never include session identifiers in URLs or logs
- Require a synchronizer CSRF token for state-changing requests in addition to SameSite cookies
- Reauthenticate for password, authenticator, recovery-code, role, and other high-impact administrative changes

For a single backend instance, encrypted database-backed sessions are acceptable. Redis is preferable once multiple backend replicas are introduced.

## Authorization model

Authentication alone is insufficient. Enforce authorization in reusable FastAPI dependencies on every API route, deny by default, and never trust roles or object IDs supplied by the frontend.

| Role | Permissions |
|---|---|
| `viewer` | Overview, findings, packages, history, comparisons, and normalized exports |
| `operator` | Viewer permissions plus upload, discovery, scan, rescan, grouping, and validated TAR download |
| `admin` | Operator permissions plus diagnostics, component maintenance, raw evidence, portable report import, backups, deletion, and user management |

Only an authenticated administrator may create an account after the atomic one-time bootstrap. Creation produces a disabled pending identity and a high-entropy activation code that is revealed once and stored only as a hash. Activation can only complete that existing identity: the user privately chooses their password and enrolls TOTP without disclosing either secret to the administrator. Codes expire and reissuing activation revokes the target's sessions, password, authenticator enrollment, and recovery codes.

The separate 2FA reissue flow preserves the user's Argon2id password. The administrator sees only an expiring one-time reissue code, stored at rest as a SHA-256 digest. The user must prove both that code and their current password before a new TOTP secret is generated. The new secret is shown only to the user; consuming the code invalidates it, replaces the old authenticator, revokes sessions and recovery codes, and requires successful TOTP verification before full access. Administrators cannot reissue their own 2FA through this flow.

An active administrator who loses only their password may use the server-local interactive recovery command while proving possession of their current TOTP authenticator or one unused recovery code. The command is not exposed over HTTP, refuses piped/non-interactive secret input, accepts no password or second factor in process arguments, applies the normal password policy and Argon2id parameters, prevents reuse of the existing password, retains TOTP enrollment, applies code replay/consumption rules, clears lockout state, revokes all sessions and API tokens, and records the outcome in the audit log. Access to Docker or the native service account remains a privileged host boundary and must be restricted. The tool has no MFA bypass; loss of both factors requires a valid encrypted backup or another administrator's established recovery workflow.

Account inventory, creation, display-name/role changes, enable/disable, unlock, enrollment reset, 2FA reissue, and permanent removal are all enforced by reusable admin-only backend dependencies; hiding the navigation item is only a usability measure. Usernames remain immutable. Privilege/access changes revoke the affected user's sessions and personal API tokens. Removal also deletes target sessions, API tokens, and recovery-code records while retaining de-identified audit history. Server invariants prevent self-demotion, self-disable, self-removal, and self-2FA-reissue, and prevent disabling, demoting, resetting, or removing the final active administrator.

The interface presents risk-specific, theme-aware verification dialogs before user removal, disablement, full activation reset, or password-preserving 2FA reissue. Each requires an exact account-specific phrase. These confirmations reduce operator mistakes but are not an authorization boundary; the backend independently enforces role, CSRF, self-action, account-state, and last-administrator invariants.

Scan and image removal is also admin-only and CSRF-protected. Single and bulk removal reject queued or running work before mutation, restrict filesystem deletion to `.tar` files resolved below the managed upload directory, and restrict raw-result deletion to the configured raw-results directory. Mounted archives are hidden rather than unlinked because their bind mounts are read-only; the tombstone can be restored. The interface requires exact typed confirmation, while backend authorization and path checks remain authoritative.

Image-group summaries are readable by authenticated viewers. Creating, editing, deleting, or changing membership requires an operator or administrator and the same session-bound CSRF control as scan mutations. Replacement and additive bulk membership operations validate every submitted image ID and exclude hidden records. Deleting a group removes only organizational metadata; it never deletes an archive, scan, finding, package, or raw result.

Original archive downloads require operator/admin access, resolve the stored path, require a `.tar` suffix, and verify that the file remains below a configured scan root. LayerScope JSON, HTML, PDF, Elastic ECS NDJSON, and DefectDojo Generic Findings reports omit internal archive paths entirely. Compatibility exports contain normalized findings only and never contain destination credentials or initiate outbound connections. Raw Trivy JSON is administrator-only because it is deliberate forensic evidence and may contain scanner-originated paths.

Optional HTML/PDF branding is a one-request transformation, not stored configuration. Authenticated viewers, operators, and administrators may send a raw PNG or JPEG body of at most 2 MiB to the branded-export route; browser sessions must also pass CSRF and origin checks. LayerScope verifies the binary container and declared type, rejects trailing payloads, malformed or animated images, oversized dimensions, and excessive decoded pixels, then removes metadata and ancillary content by re-encoding to PNG. The sanitized bytes are embedded locally from memory and discarded after the response. No logo filename, filesystem path, remote URL, temporary file, database record, or backup entry is accepted or created, and branded-export success or rejection is audited without recording image content.

Portable report import is administrator-only, session-authenticated, CSRF-protected, origin-checked, content-type constrained, size-bounded, and audited. Imported JSON is treated as untrusted: the backend allows only the versioned normalized report schema (plus the documented legacy export shape), validates report/count integrity and bounded values, sanitizes advisory URLs, enforces aggregate record ceilings, and commits atomically. It stores no submitted filesystem path, executable content, TAR, or raw Trivy JSON. A stable SHA-256 fingerprint makes repeat import idempotent. Report-only records cannot reach archive download, scan, or raw-evidence paths.

Portable backups contain security-critical material, including password hashes, encrypted TOTP seeds, recovery-code hashes, audit history, raw scan evidence, and uploaded archives. Backup creation, staging, cancellation, and restore are administrator-only and CSRF-protected. Export passwords require at least 12 characters, are processed only in memory, and derive a unique AES-256-GCM key through scrypt with a random salt and nonce. Download tickets are random, expire after one hour, are bound to the creating administrator, and are removed with the exported file after download.

Import treats both encrypted and decompressed content as untrusted. It enforces encrypted and expanded size limits, ZIP64-safe bounded entry counts, an allowlist of member roots, duplicate/path-traversal/symlink rejection, exact manifest membership, per-file SHA-256 verification, SQLite integrity and expected-schema checks, and Fernet-key validation before displaying a restore preview. Applying the restore requires a second typed confirmation, rejects active jobs, uses same-filesystem atomic moves with rollback, revokes all restored sessions and personal API tokens, and restarts before serving the imported state. Trivy component caches and external bind mounts are excluded to reduce backup size and avoid importing executable or independently managed content.

Raw Trivy JSON and diagnostic details may reveal filesystem paths and package inventory. Both are administrator-only; ordinary image, group, and removal payloads expose only a safe `upload`, `mounted`, or `report` source label.

Perform record-level checks as well as route-level checks if teams or tenants are introduced. A user who can view image 10 must not gain access to image 11 by changing an ID in the URL.

## Abuse resistance

- Nginx shapes API request and connection rates; the backend separately throttles expensive authentication routes and retains per-account lockout
- Large layer analysis uses a dedicated mode-0700 per-scan workspace on capacity-monitored persistent storage; scan-finally and startup cleanup prevent abandoned Trivy temporary files from accumulating
- Uploads enforce file-count, per-file, combined-request, storage-reserve, and Docker/OCI TAR plausibility limits before admission
- Multi-file upload rollback removes partial files and rows when any member fails
- Scan and SSE admission have explicit capacity ceilings and retry guidance
- Backup staging and scan/upload output preserve configured free-space headroom
- Portable report imports enforce request, report, finding, package, text, timestamp, and schema bounds before transactional persistence
- Per-export report logos enforce encoded-byte, container, format, animation, dimension, and decoded-pixel bounds before metadata-stripping re-encoding
- Retain the existing root-bound path validation and shell-free Trivy invocation
- Bound scanner process count through worker concurrency and Compose PID limits; size CPU/memory at the Docker host for the archive workload
- Bound concurrent scans and report generation
- Reject unexpected content types and malformed multipart data
- Validate that archives are plausible TAR files before queueing, while treating content as untrusted throughout scanning
- Restrict and back up the local authentication encryption key; Docker secrets may be used when desired but are not required for local operation
- Fail closed if authorization configuration is missing or local credential/session validation fails

## Logging and audit

Record successful and failed authentication, logout, session revocation, authorization denials, uploads, scans, exports, configuration changes, and suppression changes. Include timestamp, request/correlation ID, subject ID, action, object, and outcome.

Do not log passwords, authenticator secrets, one-time codes, recovery codes, tokens, cookies, CSRF values, raw archive content, or sensitive query strings. Encode untrusted log fields and protect logs from ordinary users. Alert on brute-force patterns, repeated authorization failures, unusual export volume, and scan-queue abuse.

## Browser and transport controls

- Terminate TLS before enabling remote access; redirect HTTP to HTTPS
- Preserve the included Content Security Policy and other response headers
- Keep CORS origins exact; never combine credentialed requests with `*`
- Keep dependencies pinned and rebuild images regularly
- Use trusted base images, produce an SBOM, and scan the dashboard's own images
- Add backup, restore, and key-rotation procedures before production use

## Hardened container deployment

The supplied Compose deployment implements the application-scoped CIS Docker controls that can be expressed without changing the Docker host:

- dedicated numeric non-root users (`10001` backend and `101` frontend), with no login shell for the backend account;
- read-only root filesystems, private application networking, and no published backend port;
- `cap_drop: ALL`, `no-new-privileges`, no privileged mode, no host namespaces, and no Docker socket mount;
- bounded memory, CPU, PIDs, open files, request sizes, and rotated local logs;
- writable `/tmp` supplied only as size-bounded `noexec,nosuid,nodev` tmpfs, while persistent `/data` is owned by the backend identity;
- read-only image-directory bind mounts and a localhost-only frontend publication by default;
- immutable digests for Trivy, Python, Node, and Nginx bases, separated build/test/runtime stages, removed runtime `pip`, and health checks in both images and Compose.

Host-level CIS controls—daemon authorization, TLS, audit rules, user namespaces, registry policy, image signing, host patching, and backup protection—remain the deployment operator's responsibility. This project does not claim CIS certification. Verify the actual host against the benchmark version appropriate for its Docker Engine.

## OWASP verification plan

Use OWASP ASVS as acceptance criteria and the latest WSTG as the adversarial test plan. At minimum, test:

- Configuration and deployment management
- Identity lifecycle and account enumeration
- Authentication transport, bypass, brute force, MFA, and recovery
- Authorization bypass, forced browsing, role escalation, and object-ID tampering
- Session fixation, cookie attributes, CSRF, logout, idle timeout, and concurrent sessions
- Injection, stored/reflected XSS, upload handling, path traversal, and command injection
- Error handling and information leakage
- TLS, secret storage, token validation, and cryptographic configuration
- Business-logic abuse of scans, concurrency, exports, quotas, and suppressions
- Client-side storage, CSP, clickjacking, CORS, and browser messaging
- API mass assignment, excessive data exposure, method authorization, and rate limits

Run unit and integration tests for authorization decisions, then test the running Compose deployment with an intercepting proxy and OWASP ZAP. Security tests should be repeatable in CI and should cover both positive and negative role cases.

The completed 1.0.0 assessment and remaining risks are recorded in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

## Official references

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- [OWASP Web Security Testing Guide](https://wstg.owasp.org/latest/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
