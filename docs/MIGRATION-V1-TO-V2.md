# Migrating from EgressDNS 1.x

EgressDNS 2.0 replaces the configuration format. It is not translated, and the old format
is not accepted: a 1.x file is refused at startup, by name, with a pointer to this page.

That is deliberate. A resolver that quietly accepted half of a file and defaulted the rest
would be running a configuration nobody wrote, and the failure would surface later as a
resolution problem nobody could trace back to the upgrade.

## The short version

Everything under `[[upstream.groups]]` becomes one line per resolver in `upstreams`.

**Before (1.x):**

```toml
version = 2                     # if you were on a late 1.x build

[[upstream.groups]]
name = "default"

[[upstream.groups.servers]]
name = "cloudflare-dot"
transport = "dot"
addresses = ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"]
server_name = "cloudflare-dns.com"
weight = 100

[[upstream.groups.servers]]
name = "quad9-dot"
transport = "dot"
addresses = ["9.9.9.9", "149.112.112.112"]
server_name = "dns.quad9.net"
weight = 100

[upstream.groups.scheduler]
hedge_enabled = true
hedge_min_delay = "20ms"
query_timeout = "1s500ms"
circuit_failure_threshold = 5
emergency_fanout = true
```

**After (2.0):**

```toml
upstreams = [
    "tls://cloudflare-dns.com",
    "tls://dns.quad9.net",
]

proxies = []
```

## What happened to each key

| 1.x key | 2.0 |
| --- | --- |
| `version` | **Removed.** The format is identified by its contents. |
| `[[upstream.groups]]` | **Removed.** One flat `upstreams` list. |
| `upstream.groups.servers.transport` | Implied by the URI scheme, or measured. A bare address gives you Do53 over UDP *and* TCP, and the resolver picks. |
| `upstream.groups.servers.addresses` | Usually unnecessary — a name is resolved at startup. Pin it with `?addr=` when DNS cannot resolve the endpoint yet. |
| `upstream.groups.servers.server_name` | The hostname in the URI. |
| `upstream.groups.servers.port` | The port in the URI. |
| `upstream.groups.servers.path` | The path in the URI. |
| `upstream.groups.servers.weight` | **Removed.** Route preference is measured, not declared. |
| `upstream.groups.servers.enabled` | **Removed.** Delete the line instead. |
| `upstream.groups.scheduler.*` | **Removed.** Hedge timing, exploration, circuit thresholds and fan-out are derived from observed latency and failure history. |
| `upstream.tls.*` | Moved to a top-level `[tls]` table. |
| `server.allow_from` | Unchanged, but *omitting* it now means "admit loopback" on a loopback-only listener, and is refused on a non-loopback listener. |

## Translating each transport

| 1.x server | 2.0 entry |
| --- | --- |
| `transport = "udp"`, `addresses = ["1.1.1.1"]` | `"1.1.1.1"` |
| `transport = "udp"`, `port = 5353` | `"1.1.1.1:5353"` |
| `transport = "tcp"` | `"tcp://1.1.1.1"` |
| `transport = "dot"`, `server_name = "dns.quad9.net"` | `"tls://dns.quad9.net"` |
| `transport = "doq"`, `server_name = "dns.adguard-dns.com"` | `"quic://dns.adguard-dns.com"` |
| `transport = "doh2"` or `"doh3"`, `path = "/dns-query"` | `"https://host/dns-query"` — one entry covers both HTTP versions |

`doh2` and `doh3` collapse into a single `https://` entry on purpose. They are two ways to
reach one resolver, and which is faster on a given network is something the resolver
measures rather than something you should have to predict. Both are tried; the better one
wins; if one path degrades the other takes over without a configuration change.

## Endpoints DNS cannot resolve yet

A 1.x file always carried literal `addresses`, because encrypted upstreams required them.
In 2.0 a name is normally enough. When it is not — a resolver on a private network, one
whose certificate does not match its address, one being stood up before its own record
exists — pin the address:

```toml
upstreams = ["tls://dns.internal.example:8853?addr=10.0.0.53"]
```

`addr` may be repeated. It decides only which socket is opened; the TLS identity is still
the hostname, so a stale hint fails closed rather than reaching a different resolver.

## Checking the result

```sh
egressdnsd --config /etc/egressdns/config.toml --check-config
egressdnsctl doctor --config /etc/egressdns/config.toml
```

`doctor` runs before a cutover and tests the things a config check cannot: whether the
listeners are free, whether the ACL admits the clients you have, and whether the upstreams
you named are reachable from this host.

## Keeping the old daemon

1.x is still published and its tag is not going anywhere. If you are not ready to move,
pin the version:

```sh
curl -fsSL https://raw.githubusercontent.com/jacek4yang/egressdns/main/install.sh \
  | sudo bash -s -- --version v1.0.0
```
