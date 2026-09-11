<#
.SYNOPSIS
    Upgrade an installed EgressDNS: stop the service, replace binaries, restart.

.DESCRIPTION
    Configuration and learned state in ProgramData are left untouched. If the service is
    not installed the binaries are replaced in place and nothing else is attempted.

.EXAMPLE
    .\upgrade.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "upgrading needs administrator rights; re-run from an elevated prompt"
}

$BinDir = "$env:ProgramFiles\egressdns"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Daemon = Join-Path $Here 'egressdnsd.exe'
$Control = Join-Path $Here 'egressdnsctl.exe'
foreach ($exe in @($Daemon, $Control)) {
    if (-not (Test-Path $exe)) {
        throw "required file not found: $exe — run this script from the release archive"
    }
}

$svc = Get-Service -Name 'egressdns' -ErrorAction SilentlyContinue
$wasRunning = $false
if ($svc -and $svc.Status -eq 'Running') {
    Stop-Service -Name 'egressdns' -Force
    $wasRunning = $true
    Write-Host '[ok] service stopped'
}

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Copy-Item -Force $Daemon (Join-Path $BinDir 'egressdnsd.exe')
Copy-Item -Force $Control (Join-Path $BinDir 'egressdnsctl.exe')
Write-Host '[ok] binaries replaced'

& (Join-Path $BinDir 'egressdnsd.exe') --version
if ($svc) {
    if ($wasRunning) {
        Start-Service -Name 'egressdns'
        Start-Sleep -Seconds 1
        $status = (Get-Service -Name 'egressdns').Status
        if ($status -ne 'Running') {
            throw "the service did not reach Running after the upgrade (state: $status)"
        }
        Write-Host '[ok] service restarted'
    } else {
        Write-Host '[ok] service left stopped (it was stopped before the upgrade)'
    }
} else {
    Write-Host '[ok] no service registered; binaries upgraded in place'
}
