[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Push-Location $repositoryRoot
try {
    git rev-parse --is-inside-work-tree *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'Initialize the repository with git init before running this check.'
    }

    $candidateFiles = @(git ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to enumerate Git candidate files.'
    }

    $blockedPathPatterns = @(
        '(^|/)(\.env|auth\.key)$',
        '(^|/)(data|\.local-data|work|uploads|raw|backups|trivy-cache)/',
        '\.(db|sqlite|sqlite3|tar|zip|pdf|sarif|trivybackup|p12|pfx|pem|key)$',
        '\.db-(wal|shm)$'
    )
    $contentPatterns = [ordered]@{
        'private key material' = '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
        'AWS access-key identifier' = '(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])'
        'GitHub token shape' = '(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{30,}'
        'Slack token shape' = '(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{20,}'
        'personal Windows profile path' = 'C:\\Users\\(?!example(?:\\|$)|user(?:name)?(?:\\|$))[^\r\n]+'
        'personal macOS profile path' = '/Users/(?!example(?:/|$)|user(?:name)?(?:/|$))[^\r\n]+'
        'personal Linux home path' = '/home/(?!example(?:/|$)|user(?:name)?(?:/|$))[^\r\n]+'
    }
    $textExtensions = @('.css','.env','.example','.html','.ini','.js','.json','.md','.ps1','.py','.toml','.ts','.tsx','.txt','.yaml','.yml')
    $findings = [System.Collections.Generic.List[string]]::new()

    foreach ($relativePath in $candidateFiles) {
        $normalized = $relativePath.Replace('\','/')
        foreach ($pattern in $blockedPathPatterns) {
            if ($normalized -match $pattern -and $normalized -ne '.env.example') {
                $findings.Add("Blocked private/generated path: $relativePath")
                break
            }
        }

        # This script necessarily contains the detector expressions themselves.
        if ($normalized -eq 'scripts/check-repository-hygiene.ps1') {
            continue
        }

        $absolutePath = Join-Path $repositoryRoot $relativePath
        if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
            continue
        }
        $file = Get-Item -LiteralPath $absolutePath
        if ($file.Length -gt 5MB -or $textExtensions -notcontains $file.Extension.ToLowerInvariant()) {
            continue
        }
        $content = Get-Content -LiteralPath $absolutePath -Raw
        foreach ($entry in $contentPatterns.GetEnumerator()) {
            if ($content -cmatch $entry.Value) {
                $findings.Add("Possible $($entry.Key): $relativePath")
            }
        }
    }

    if ($findings.Count -gt 0) {
        $findings | Sort-Object -Unique | ForEach-Object { Write-Error $_ }
        throw 'Repository hygiene check failed. Review the reported files before committing.'
    }

    Write-Host "Repository hygiene check passed for $($candidateFiles.Count) Git candidate files."
}
finally {
    Pop-Location
}
