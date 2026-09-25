# Contributing to LayerScope

Thank you for improving LayerScope. This guide is written for human contributors and coding agents. Both are expected to preserve local-first operation, saved evidence, security controls, accessibility, and existing functionality.

## Read before changing code

Start with these documents:

- [README.md](README.md) for product behavior and supported workflows
- [INSTALL.md](INSTALL.md) for Docker and native setup
- [TECHNICAL_README.md](TECHNICAL_README.md) for architecture, persistence, APIs, queues, and security boundaries
- [SECURITY.md](SECURITY.md) for authentication, authorization, threat assumptions, and verification guidance
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the latest completed security assessment and residual risks

The codebase has two applications:

- `frontend/`: React, TypeScript, Vite, Tailwind, TanStack Query/Table/Virtual, React Router, Recharts, and Lucide React
- `backend/`: FastAPI, SQLAlchemy, SQLite, persistent queues, Trivy process management, reporting, authentication, and backups

## Contribution workflow

1. Create a focused branch from the current default branch.
2. Describe the user-visible outcome and any security, migration, or compatibility impact.
3. Keep changes scoped. Do not reformat or replace unrelated code.
4. Add or update tests for behavior, security boundaries, migrations, and performance-sensitive queries.
5. Run the verification commands below.
6. Review the complete diff and the privacy checklist before committing.
7. Open a pull request with test evidence and clear manual-verification steps.

Use small, reviewable commits. Do not commit generated dependencies, containers, databases, TAR files, raw Trivy output, backups, local configuration, or release archives.

## Rules for human contributors

- Preserve compatibility with existing SQLite volumes and raw scan history.
- Use additive, idempotent migrations unless a separately reviewed migration plan explicitly permits destructive changes.
- Keep normal scans offline-safe. Downloads must occur only through explicit component-maintenance actions.
- Keep configured scan-root validation on every filesystem operation.
- Invoke subprocesses with argument arrays; never introduce `shell=True` for Trivy or filesystem commands.
- Preserve role checks, cookie-session CSRF protection, API-token ownership/expiry/revocation controls, credential revocation, TOTP replay protection, and audit events.
- Use app-styled dialogs instead of browser-native `alert`, `confirm`, or `prompt` calls.
- Render untrusted values as text. Do not use unsanitized HTML insertion.
- Keep controls keyboard accessible, labeled, responsive, and usable in both themes.
- Use the shared severity, status, progress, error, and source components so behavior remains consistent.
- Avoid new dependencies unless the capability cannot be implemented safely with the existing stack.

## Rules for LLMs and coding agents

Coding agents must follow the same contribution rules plus these safeguards:

1. Read the relevant documentation and nearby tests before editing.
2. Inspect repository status and preserve changes that may belong to another contributor.
3. Treat `.env`, `.local-data/`, `data/`, `work/`, backups, raw JSON, TAR archives, authentication keys, and user-provided screenshots as private. Do not read or reproduce them unless the task explicitly requires it.
4. Never put secrets, real usernames, hostnames, personal paths, tokens, recovery codes, TOTP seeds, vulnerability evidence from private images, or database contents in source, tests, logs, examples, commits, or responses.
5. Use synthetic test fixtures and neutral paths such as `/images/example.tar`.
6. Do not weaken authentication, path validation, output encoding, request limits, container hardening, or security headers to make a test pass.
7. Do not delete or rewrite persisted user data as part of development or verification.
8. Prefer set-based database access, bounded queues/buffers, streaming for large files, and cancellation-aware background work.
9. Verify the smallest relevant checks first, then the full suite in proportion to the change.
10. Report assumptions, tests run, remaining risks, and any check that could not be completed.

An agent-generated pull request must still be reviewed and accepted by a human maintainer.

## Preparing the first Git push

If the source was downloaded as an archive, initialize it locally and inspect exactly what Git will include:

```powershell
git init -b main
git add .
./scripts/check-repository-hygiene.ps1
git diff --cached --check
git status --short
```

Review the staged diff before committing. Then add the repository URL supplied by your Git hosting provider:

```powershell
git commit -m "Initial LayerScope release"
git remote add origin <repository-url>
git push -u origin main
```

Do not paste credentials into the remote URL. Use the operating system credential manager or an SSH agent. Contributions are accepted under the project's Apache License 2.0; see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Privacy and secret-safety checklist

Before every push, confirm that the staged changes contain none of the following:

- `.env` files or environment dumps
- `auth.key`, TLS/private keys, certificates, access tokens, passwords, recovery codes, or TOTP secrets
- SQLite databases, WAL/SHM files, backups, raw Trivy JSON, Docker image TAR files, or report exports
- local paths containing a real account or organization name
- screenshots, logs, stack traces, manifests, or scan evidence that identify private images or infrastructure
- generated `node_modules`, virtual environments, caches, build output, or local work directories

The repository intentionally tracks `.env.example`; it must contain safe defaults and placeholders only. If sensitive data was committed, do not merely delete it in a later commit. Stop, rotate the exposed credential, remove it from history using an appropriate history-rewrite procedure, and notify the maintainer privately.

Optional secret scanning is encouraged before public pushes:

```powershell
gitleaks detect --source . --no-banner
```

The repository also includes a dependency-free candidate-file hygiene check:

```powershell
./scripts/check-repository-hygiene.ps1
```

Do not open a public issue containing a suspected secret or exploitable vulnerability. Use the hosting provider's private security-advisory channel or another private maintainer channel.

## Verification

When adding or changing an API route, keep its FastAPI summary, request/response models, tags, and `require_roles(...)` or session-only dependency accurate. The authenticated `/api/openapi.json` schema and in-app API Docs derive their RBAC display from those runtime dependencies; do not hand-maintain a second authorization map.

Frontend:

```powershell
cd frontend
corepack enable
pnpm install --frozen-lockfile
pnpm run lint
pnpm run build
```

Backend:

```powershell
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest -q
```

CLI and automation contract:

```powershell
python -m unittest discover -s cli/tests -v
python -m pip wheel --no-deps ./cli --wheel-dir ./work/wheels
```

CLI changes must preserve versioned JSON output, documented exit-code meanings, finite wait behavior, streaming transfers, RBAC, and secret input through environment, standard input, or restricted files only. Use the synthetic local test server; never add a real URL, API token, private archive name, or scan result to a fixture or CI example.

Container configuration and hardening:

```powershell
docker compose config
docker compose build
./scripts/verify-container-hardening.ps1
```

For Linux or macOS, activate the virtual environment with `source .venv/bin/activate` and run `python -m pytest -q`.

## Pull request checklist

- [ ] The change has a focused purpose and no unrelated rewrites.
- [ ] Existing data and API compatibility are preserved or the migration is documented.
- [ ] Security and privacy boundaries remain intact.
- [ ] UI changes work with keyboard navigation, narrow layouts, and light/dark themes.
- [ ] CLI/API changes preserve machine-output compatibility, bounded waits, and secret safety.
- [ ] Tests and documentation were updated.
- [ ] Frontend lint/build and backend tests pass.
- [ ] No private or generated data is staged.
- [ ] The pull request explains manual verification and residual risk.
