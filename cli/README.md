# LayerScope CLI

`layerscope` is a dependency-free Python 3.12+ client for LayerScope's authenticated API. It is intended for non-interactive CI/CD jobs and integrations. It submits work to the existing persistent queue; it does not run Trivy or access the application database directly.

## Install

From the repository root:

```powershell
python -m pip install ./cli
layerscope --version
```

Set the server URL and provide an operator or administrator API token through the environment:

```powershell
$env:LAYERSCOPE_URL = "https://layerscope.example.invalid"
$env:LAYERSCOPE_TOKEN = Read-Host -MaskInput "LayerScope API token"
layerscope whoami
```

Tokens can instead be read from standard input or a restricted file with `--token-stdin` or `--token-file`. Tokens are deliberately not accepted as command-line values because process arguments may be visible to other users and captured by CI logs. Use HTTPS for any connection that leaves the local machine. `--ca-file` accepts a private certificate-authority bundle without disabling verification.

## Common workflow

```powershell
layerscope upload --if-absent ./work/example-image.tar
layerscope scan --image-id 42 --wait --timeout 3600 --fail-on high
layerscope findings 101 --severity critical --severity high
layerscope export --scan-id 101 --format json --output ./work/layerscope-report.json
layerscope export --scan-id 101 --format elastic --output ./work/layerscope-findings.ndjson
layerscope export --scan-id 101 --format defectdojo --output ./work/layerscope-defectdojo.json
layerscope export --group-id 7 --format pdf --output ./work/group-snapshot.pdf
layerscope export --group-id 7 --format pdf --logo ./branding/example-logo.png --output ./work/branded-group.pdf
```

Export formats are `json`, `html`, `pdf`, `elastic`, and `defectdojo`. Use one or more `--scan-id` options or one or more `--group-id` options; the two selection modes are mutually exclusive. A group export is a point-in-time snapshot of the latest completed scan for every visible member. Overlapping members appear once, and members without a completed scan are reported as excluded. Add `--logo` only with HTML or PDF to stream a regular PNG/JPEG file of at most 2 MiB for that single export; the server validates, re-encodes, embeds, and discards it. Elastic is an ECS 9.5.0 Bulk API NDJSON file; DefectDojo is Generic Findings Import JSON. They are file downloads only, so the CLI never accepts or transmits Elastic or DefectDojo credentials.

All successful results use a versioned JSON envelope on standard output. Errors use the same schema on standard error. Progress goes only to standard error and can be disabled with `--quiet`; `--compact` produces one-line JSON.

`upload --if-absent` skips only when a visible image has the same file name and byte size. This is a convenience retry guard, not a cryptographic identity check. Uploads without it may create another image record. Scan submission inherits the server's active-job duplicate suppression. Read-only operations may be retried after network failures; do not automatically retry mutating commands unless their documented idempotency behavior is acceptable.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 2 | Invalid invocation or request |
| 3 | Authentication failed |
| 4 | Permission denied |
| 5 | Resource not found |
| 6 | Conflict, including refused overwrite |
| 7 | Queue or storage capacity limit |
| 8 | Server failure |
| 9 | Network or TLS failure |
| 10 | Scan job failed |
| 11 | Scan job was cancelled |
| 12 | Vulnerability policy gate failed |
| 13 | Wait timeout |

Use `layerscope --help` and `layerscope <command> --help` for the full command reference. API tokens cannot create other API tokens, and every command remains subject to the token owner's current RBAC permissions.
