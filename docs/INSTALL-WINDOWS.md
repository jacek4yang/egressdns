# Installing EgressDNS on Windows

EgressDNS runs natively on Windows as a console application or as a Windows service. This
document covers installing from a release archive; to build from source you need the Rust
toolchain (`rustup` installs the pinned toolchain from `rust-toolchain.toml`) and the MSVC
build tools, but an installed release needs none of that.

## What the release contains

```
egressdns-v…-windows-x86_64.zip
├── egressdnsd.exe        the resolver
├── egressdnsctl.exe      control and inspection
├── config.toml           an example configuration
├── install.ps1           install: binaries, config, (optionally) the service
├── upgrade.ps1           upgrade an existing installation in place
├── uninstall.ps1         remove it again
└── INSTALL-WINDOWS.md    this file
```

Verify the archive against `SHA256SUMS` in the release before running anything:

```powershell
Get-FileHash .\egressdns-v…-windows-x86_64.zip -Algorithm SHA256
```

## Quick install

From an elevated PowerShell, in the extracted archive directory:

```powershell
.\install.ps1 -StartAfterInstall
```

That copies the binaries to `C:\Program Files\egressdns`, writes a default configuration
to `C:\ProgramData\egressdns\config.toml` if none exists, validates it, registers the
`egressdns` service set to start automatically, starts it, and runs a local canary: a
query for `localhost`, which the daemon answers from its special-use registry, needing no
Internet access.

Loopback-only configurations need no firewall change. To serve a LAN, add
`-AllowLan`, which creates an inbound rule for UDP/TCP 53 from the local subnet, and
widen `server.allow_from` in the configuration.

## What is never done silently

EgressDNS does not change this machine's DNS settings. To resolve through it on this
host, either run the installer again with `-SetDns` (it points online adapters at
`127.0.0.1` and refuses to do so unless the daemon is running) or do it yourself:

```powershell
Get-NetAdapter | Where-Object Status -eq 'Up' |
    Set-DnsClientServerAddress -ServerAddresses 127.0.0.1
```

Revert with `Set-DnsClientServerAddress -ResetServerAddresses`. LAN clients are pointed
at this machine's address by whatever manages them; nothing here rewrites that.

## Console mode

Without the service, run the daemon directly:

```powershell
.\egressdnsd.exe --config .\config.toml --check-config   # validate first
.\egressdnsd.exe --config .\config.toml                  # serve, Ctrl+C to stop
```

Reloading a configuration change without a restart is `egressdnsctl reload` — Windows
has no SIGHUP. Settings listed by `egressdnsctl reload-contract` require a restart.

## Ports and conflicts

Windows has no privileged-port concept: binding port 53 needs no elevation, but it fails
if something else holds it. `egressdnsctl doctor --config <path>` names the holding
process when it can see one, and `netstat -abn` always can. Two common holders of port
53 on Windows are Internet Connection Sharing (`SharedAccess`) and DNS Server on Windows
Server; stop or reconfigure whichever it is rather than making EgressDNS share the port.

Port ranges reserved by Hyper-V/WSL (`netsh int ipv4 show excludedportrange protocol=udp`)
also refuse binds with a permission-shaped error; `doctor` reports those as in use,
which for operational purposes is what they are.

## The control plane

On Windows the administration endpoint is a named pipe, `\\.\pipe\egressdns-admin`,
rather than a Unix socket. `egressdnsctl status`, `upstreams`, `cache-stats`, `network`,
`doctor`, `bench` and the rest work unchanged. The pipe's security descriptor limits
access to the service account, administrators and the running user.

## Where things live

| Path | Purpose |
| --- | --- |
| `C:\Program Files\egressdns\` | binaries |
| `C:\ProgramData\egressdns\config.toml` | configuration |
| `C:\ProgramData\egressdns\state.sqlite3` | learned state (quality rankings, hot domains) |
| `C:\ProgramData\egressdns\egressdnsd.pid` | daemon pid, for `doctor`'s port-ownership report |

Every path is overridable in the configuration file.

## Service lifecycle

```powershell
Start-Service egressdns
Stop-Service egressdns
sc.exe qc egressdns          # inspect the configuration
sc.exe failure egressdns     # restart-on-failure settings
```

The service runs `egressdnsd.exe --service --config <path>`. `sc stop` and a system
shutdown both use the same graceful path as Ctrl+C in console mode.

## Upgrading and removing

```powershell
.\upgrade.ps1              # stop, replace binaries, restart; config and state untouched
.\uninstall.ps1            # stop and remove the service and binaries
.\uninstall.ps1 -PurgeState  # also remove ProgramData\egressdns (config + learned state)
```

`uninstall.ps1` never reverts DNS settings; if adapters were pointed at `127.0.0.1`,
revert them first as shown above.

## Differences from the Linux deployment

* The control plane is a named pipe instead of `/run/egressdns/admin.sock`.
* There is no systemd: restart-on-failure is configured through `sc.exe failure`, the
  readiness protocol (sd_notify) does not exist, and the watchdog setting is accepted
  and ignored.
* `resolv.conf` management does not exist; Windows configures DNS per interface, and
  this deployment does not touch it (see above).
* `doctor`'s `/proc`-based checks degrade honestly: port ownership comes from the IP
  helper API plus the daemon's pidfile, privileged-port capability is not applicable
  (Windows has no privileged ports), and the systemd unit check becomes a service state
  check.

Everything else — the resolver, the cache, the scheduler, DNSSEC policy, quality
learning, the configuration format — behaves the same on both platforms.
