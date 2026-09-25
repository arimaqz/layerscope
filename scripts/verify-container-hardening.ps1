[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot

function Assert-Control {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Hardening check failed: $Message" }
}

Push-Location $projectDirectory
try {
    $backendId = docker compose ps -q backend
    $frontendId = docker compose ps -q frontend
    Assert-Control (-not [string]::IsNullOrWhiteSpace($backendId)) "backend container is not running"
    Assert-Control (-not [string]::IsNullOrWhiteSpace($frontendId)) "frontend container is not running"

    $backend = (docker inspect $backendId | ConvertFrom-Json)[0]
    $frontend = (docker inspect $frontendId | ConvertFrom-Json)[0]

    Assert-Control ($backend.Config.User -eq "10001:10001") "backend must run as 10001:10001"
    Assert-Control ($frontend.Config.User -eq "101:101") "frontend must run as 101:101"

    foreach ($container in @($backend, $frontend)) {
        Assert-Control ([bool]$container.HostConfig.ReadonlyRootfs) "$($container.Name) root filesystem is writable"
        Assert-Control ($container.HostConfig.CapDrop -contains "ALL") "$($container.Name) does not drop all capabilities"
        Assert-Control ($container.HostConfig.SecurityOpt -contains "no-new-privileges:true") "$($container.Name) permits new privileges"
        Assert-Control ($container.HostConfig.PidsLimit -gt 0) "$($container.Name) has no PID limit"
        Assert-Control ($container.HostConfig.Memory -gt 0) "$($container.Name) has no memory limit"
        Assert-Control ($container.HostConfig.Tmpfs."/tmp" -match "noexec" -and
                        $container.HostConfig.Tmpfs."/tmp" -match "nosuid" -and
                        $container.HostConfig.Tmpfs."/tmp" -match "nodev") "$($container.Name) temporary storage is not fully restricted"
        Assert-Control (-not ($container.Mounts | Where-Object Destination -eq "/var/run/docker.sock")) "$($container.Name) mounts the Docker socket"
    }

    $imageMount = $backend.Mounts | Where-Object Destination -eq "/images"
    Assert-Control ($null -ne $imageMount -and -not $imageMount.RW) "image archive mount must be read-only"
    $storageProbeMount = $backend.Mounts | Where-Object Destination -eq "/host-storage-probe"
    Assert-Control ($null -ne $storageProbeMount -and -not $storageProbeMount.RW) "host storage probe must be read-only"
    Assert-Control ($null -eq $backend.NetworkSettings.Ports."8000/tcp") "backend port must not be published"

    $frontendBinding = $frontend.NetworkSettings.Ports."8080/tcp"
    Assert-Control ($frontendBinding.Count -eq 1 -and $frontendBinding[0].HostIp -eq "127.0.0.1") "frontend must bind only to 127.0.0.1 by default"
    Assert-Control ($backend.State.Health.Status -eq "healthy") "backend health check is not healthy"
    Assert-Control ($frontend.State.Health.Status -eq "healthy") "frontend health check is not healthy"

    Write-Host "Container hardening checks passed for backend and frontend."
}
finally {
    Pop-Location
}
