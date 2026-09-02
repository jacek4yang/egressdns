<#
.SYNOPSIS
    Remove EgressDNS from this machine.

.DESCRIPTION
    Stops and deletes the service, removes the binaries, and removes the state directory
    only when -PurgeState is given. DNS settings are never modified: if adapters were
    pointed at the local resolver, revert them first with

        Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses

.EXAMPLE
    .\uninstall.ps1 -PurgeState
#>
[CmdletBinding()]
param(
    [switch]$PurgeState
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "uninstallation needs administrator rights; re-run from an elevated prompt"
}

$BinDir = "$env:ProgramFiles\egressdns"
$StateDir = "$env:ProgramData\egressdns"

$svc = Get-Service -Name 'egressdns' -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq 'Running') { Stop-Service -Name 'egressdns' -Force }
    sc.exe delete egressdns | Out-Null
    Write-Host '[ok] service removed'
} else {
    Write-Host '[ok] no service was registered'
}

if (Test-Path $BinDir) {
    Remove-Item -Recurse -Force $BinDir
    Write-Host '[ok] binaries removed'
}

if ($PurgeState) {
    if (Test-Path $StateDir) {
        Remove-Item -Recurse -Force $StateDir
        Write-Host '[ok] state and configuration removed'
    }
} else {
    Write-Host "[ok] configuration and learned state kept in $StateDir (use -PurgeState to remove)"
}

Write-Host "[note] DNS settings were not touched; revert adapters with Set-DnsClientServerAddress -ResetServerAddresses if needed"
