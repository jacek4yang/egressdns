<#
.SYNOPSIS
    Install EgressDNS on Windows: binaries, configuration and (optionally) a Windows
    service.

.DESCRIPTION
    Copies the release binaries to Program Files, writes a default configuration to
    ProgramData when none exists, validates it, and registers a Windows service set to
    start automatically.

    EgressDNS never changes this machine's DNS settings by itself. To direct Windows at
    the local resolver afterwards, run the command this script prints, or re-run with
    -SetDns to have it done explicitly.

    Loopback-only configurations need no firewall change. Serving a LAN requires an
    inbound rule for UDP/TCP 53; -AllowLan creates one.

.PARAMETER ConfigPath
    Where the configuration lives. Default C:\ProgramData\egressdns\config.toml.

.PARAMETER NoService
    Install binaries and configuration only; do not register the service.

.PARAMETER StartAfterInstall
    Start the service immediately after installation.

.PARAMETER SetDns
    Point every online physical adapter's DNS at 127.0.0.1 after a successful start.
    Explicit by design: the resolver does not reconfigure the host silently.

.PARAMETER AllowLan
    Create an inbound firewall rule permitting UDP/TCP 53 from private networks.

.EXAMPLE
    .\install.ps1 -StartAfterInstall
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$env:ProgramData\egressdns\config.toml",
    [switch]$NoService,
    [switch]$StartAfterInstall,
    [switch]$SetDns,
    [switch]$AllowLan
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "installation needs administrator rights; re-run from an elevated prompt"
    }
}

Assert-Administrator

$BinDir = "$env:ProgramFiles\egressdns"
$StateDir = Split-Path -Parent $ConfigPath
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "EgressDNS installation"
Write-Host "  binaries: $BinDir"
Write-Host "  config:   $ConfigPath"

# --- locate the payload -----------------------------------------------------------
$Daemon = Join-Path $Here 'egressdnsd.exe'
$Control = Join-Path $Here 'egressdnsctl.exe'
foreach ($exe in @($Daemon, $Control)) {
    if (-not (Test-Path $exe)) {
        throw "required file not found: $exe — run this script from the release archive"
    }
}
$ExampleConfig = Join-Path $Here 'egressdns.toml'

# --- binaries ---------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Copy-Item -Force $Daemon (Join-Path $BinDir 'egressdnsd.exe')
Copy-Item -Force $Control (Join-Path $BinDir 'egressdnsctl.exe')
Write-Host '[ok] binaries installed'

# --- configuration ----------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
if (Test-Path $ConfigPath) {
    Write-Host "[ok] existing configuration kept: $ConfigPath"
} elseif (Test-Path $ExampleConfig) {
    Copy-Item $ExampleConfig $ConfigPath
    Write-Host "[ok] default configuration written: $ConfigPath"
} else {
    @"
upstreams = ["auto"]

[server]
udp_listen = ["127.0.0.1:53"]
tcp_listen = ["127.0.0.1:53"]
"@ | Out-File -Encoding utf8 $ConfigPath
    Write-Host "[ok] minimal configuration written: $ConfigPath"
}

& (Join-Path $BinDir 'egressdnsd.exe') --config $ConfigPath --check-config
if ($LASTEXITCODE -ne 0) {
    throw "the configuration at $ConfigPath is not valid; fix it and re-run"
}
Write-Host '[ok] configuration validates'

# --- firewall ---------------------------------------------------------------------
if ($AllowLan) {
    New-NetFirewallRule -DisplayName 'EgressDNS (DNS in, private)' -Direction Inbound `
        -Protocol UDP -LocalPort 53 -RemoteAddress LocalSubnet -Action Allow -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName 'EgressDNS (DNS in, private)' -Direction Inbound `
        -Protocol TCP -LocalPort 53 -RemoteAddress LocalSubnet -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Write-Host '[ok] inbound UDP/TCP 53 permitted from the local subnet'
}

# --- service ----------------------------------------------------------------------
if ($NoService) {
    Write-Host '[ok] service registration skipped (-NoService)'
} else {
    $svc = Get-Service -Name 'egressdns' -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running') { Stop-Service -Name 'egressdns' -Force }
        sc.exe config egressdns start= auto | Out-Null
        Write-Host '[ok] existing service updated'
    } else {
        $binPath = '"' + (Join-Path $BinDir 'egressdnsd.exe') + '" --service --config "' + $ConfigPath + '"'
        sc.exe create egressdns binPath= $binPath start= auto DisplayName= "EgressDNS resolver" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE" }
        Write-Host '[ok] service registered'
    }
    sc.exe description egressdns "Adaptive, highly available DNS caching forwarder. Config: $ConfigPath" | Out-Null
    # Restart on failure: after 60s, then 5 minutes, then reboot if it keeps crashing.
    sc.exe failure egressdns reset= 86400 actions= restart/60000/restart/300000/restart/60000 | Out-Null
}

# --- start and verify -------------------------------------------------------------
if ($StartAfterInstall -and -not $NoService) {
    Start-Service -Name 'egressdns'
    Start-Sleep -Seconds 1
    $status = (Get-Service -Name 'egressdns').Status
    if ($status -ne 'Running') {
        throw "the service did not reach Running (state: $status); check the Application event log and the daemon log"
    }
    Write-Host '[ok] service is running'

    # The special-use name `localhost` is answered locally by the daemon itself, so the
    # canary needs no Internet and no upstream.
    $canary = Join-Path $BinDir 'egressdnsctl.exe'
    & $canary query localhost A --server 127.0.0.1 --port 53
    if ($LASTEXITCODE -ne 0) {
        throw "the local canary failed; the daemon is running but did not answer a UDP query on 127.0.0.1:53"
    }
    Write-Host '[ok] local canary answered'
}

# --- explicit DNS cutover ---------------------------------------------------------
if ($SetDns) {
    if (-not $NoService) {
        $status = (Get-Service -Name 'egressdns').Status
        if ($status -ne 'Running') {
            throw "refusing to point DNS at a resolver that is not running (service state: $status)"
        }
    }
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    if (-not $adapters) {
        Write-Host '[warn] no online adapters found; DNS settings were not changed'
    } else {
        # Only physical/up adapters are touched, and only on an explicit flag. The
        # previous settings are recoverable with Set-DnsClientServerAddress -ResetServerAddresses.
        $adapters | Set-DnsClientServerAddress -ServerAddresses 127.0.0.1
        Write-Host '[ok] online adapters now resolve through 127.0.0.1 (revert: Set-DnsClientServerAddress -ResetServerAddresses)'
    }
}

Write-Host ''
Write-Host "Done. EgressDNS does not change this machine's DNS settings on its own."
Write-Host 'To resolve through EgressDNS on this host:'
Write-Host '  - run this script again with -SetDns, or'
Write-Host '  - run:  Get-NetAdapter | Where-Object Status -eq "Up" | Set-DnsClientServerAddress -ServerAddresses 127.0.0.1'
if ($AllowLan) {
    Write-Host "LAN clients may now be pointed at this machine's address; remember the ACL in the config."
}
