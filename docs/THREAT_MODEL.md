# Threat model

## What this system is

A caching DNS forwarder on a company LAN. Every client is inside one internal network,
every client shares one Internet egress, and the resolver is the only DNS server those
clients see. It is deliberately **not** a public resolver, and it is not an
authoritative server.

## Assets

| Asset | Why it matters |
| ----- | -------------- |
| Answer integrity | A wrong address sends users to the wrong host. This is the primary asset |
| Client query privacy | Query names and client addresses are personal data in most jurisdictions |
| Service availability | DNS failure looks like total network failure to every user |
| The resolver host | Compromise here is compromise of every name lookup on the LAN |
| Upstream relationships | Being seen as an abusive client gets the egress rate-limited or blocked |

## Trust boundaries

```
  UNTRUSTED ─────────────────────────────────────────────────────────────────────
    third-party candidate seeds (cf.090227.xyz)      no authority whatsoever
    DNS answers from upstream                        parsed, validated, never obeyed blindly
    HTTP/TLS responses from probe targets            bounded, verified, size-capped
    anything on a network socket                     hostile until proven otherwise

  SEMI-TRUSTED ──────────────────────────────────────────────────────────────────
    LAN clients                                      ACL-limited, rate-limited
    configured upstream resolvers                    authenticated, but can still lie
    Cloudflare's published prefix lists              authoritative for ownership only

  TRUSTED ───────────────────────────────────────────────────────────────────────
    the configuration file                           root-owned, group-readable
    the local filesystem and clock
    the systemd unit and its capability set
```

---

## Attack surface and controls

### 1. Cache poisoning and answer forgery

*Threat.* An off-path attacker guesses a query ID and source port and injects a forged UDP
answer. An on-path attacker modifies answers in flight.

*Controls.*
- Encrypted upstream transports (DoT, DoH2, DoH3, DoQ) with full certificate chain and
  hostname verification. There is no global switch that disables verification, and
  `deny.toml` bans alternative TLS stacks so there is exactly one code path to audit.
- For plain UDP: randomised query IDs, randomised source ports (`os_port_selection`),
  0x20 case randomisation (RFC 5452), and RFC 7873 DNS Cookies with echo verification.
- Every response is checked for question, ID and opcode match before it is considered.
- Local DNSSEC validation is on by default. Bogus data is never cached and never served.
- The AD bit is never fabricated: it requires the client to have asked, a Secure state, and
  an unmodified answer.

*Residual risk.* A compromised or malicious configured upstream can return whatever it
likes for unsigned zones. DNSSEC mitigates this for signed zones; using two independent
operators limits the blast radius of one of them misbehaving.

### 2. Amplification and reflection

*Threat.* The resolver is used to amplify traffic at a third party by spoofing the source
address of queries.

*Controls.*
- Default-deny ACL. A non-loopback listener with an empty allow list is refused at
  startup — this is a validation error, not a warning.
- Malformed datagrams are dropped, never answered.
- Rate-limited clients receive no response at all, since answering would supply exactly the
  amplification the limit exists to prevent.
- RFC 8482 minimal ANY by default; forwarding ANY from an exposed listener additionally
  requires rate limiting to be enabled.
- EDNS payload capped at 1232 bytes by default; oversized answers set TC and force TCP.
- The shipped nftables example restricts port 53 to the LAN.

### 3. DNS-driven SSRF through the probe engine

*Threat.* This is the most interesting attack on this particular design. A hostile domain
returns `169.254.169.254` or `127.0.0.1`, and the resolver's own probe engine is used to
reach a cloud metadata service or an internal admin interface — from the resolver host,
which is likely to be well-connected.

*Controls.*
- Deny-by-default target policy in `probe::safety`. Loopback, link-local, cloud metadata,
  multicast, unspecified, documentation, benchmarking and reserved ranges are refused.
- Link-local and cloud metadata ranges are refused **even when an operator adds an explicit
  exception**; there is no configuration that makes `169.254.169.254` probeable.
- Only ports declared by the service itself (an HTTPS/SVCB `port` parameter, an SRV record)
  or explicitly listed in `probe.extra_ports` are ever contacted. At most eight extra ports
  may be configured. There is no port-range scanning anywhere in this codebase.
- Redirects are never followed by default: a redirect is a change of authority.
- Response bodies are capped before parsing.
- Per-address, per-prefix and per-domain cooldowns, a global new-connection rate limit, and
  a daily bandwidth budget bound the volume.

*Test coverage.* `probe::safety` unit tests assert every refusal, including the
"exception cannot cover metadata" rule.

### 4. Untrusted candidate sources

*Threat.* A third-party "preferred IP" list is compromised, or simply wrong, and steers
user traffic to an attacker-controlled host.

*Observed reality.* This is not hypothetical. Live samples from `cf.090227.xyz` contained
addresses such as `188.164.248.83`, `91.193.59.179` and `8.35.211.212`, none of which are
inside Cloudflare's published prefixes. Roughly a quarter of one list was outside
Cloudflare's space.

*Controls.*
- The seed source has **no authority**. It can only propose.
- Strict bounded parsing; HTML, JSON, oversized bodies and invalid UTF-8 are rejected.
- Official prefix membership is checked against the *current* snapshot, and again at the
  moment of use.
- Special-use filtering runs before prefix lookup.
- TCP, then TLS with the origin hostname as SNI and full chain verification, then HTTP with
  the origin hostname as authority. HTTP 421 is a definitive rejection.
- Repeated success and a confidence threshold before an address is eligible.
- Even then, `verified-augment` only *prepends*; every original address is retained.
- Retiring a prefix immediately invalidates every candidate inside it.

*Residual risk.* An attacker who controls an address that genuinely is inside Cloudflare's
published space and serves a valid certificate for the target hostname could be selected.
That requires compromising Cloudflare's edge or the hostname's certificate — at which point
the DNS resolver is not the weakest link.

### 5. Resource exhaustion

*Threat.* A client, or a hostile upstream, drives the resolver out of memory, file
descriptors or CPU.

*Controls.* Every queue, cache, pool and worker set is bounded: in-flight queries,
TCP connections globally and per client, pipelining depth, cache entries and bytes, probe
queue, storage queue, candidate pool, hot set, singleflight per shard, validation cache.
The systemd unit sets `LimitNOFILE`, `LimitNPROC` and `TasksMax`. Property tests assert
that the bounded structures stay bounded under adversarial insertion patterns.

### 6. Privacy

*Threat.* Query names and client addresses leak, either into logs and metrics or to third
parties.

*Controls.*
- ECS is disabled by default and a client's LAN address is never forwarded under any mode.
  Fixed-egress mode requires an explicit public prefix, validated to be public and no
  longer than /24 (IPv4) or /56 (IPv6).
- Query logging is off by default and carries an explicit warning; when enabled it is
  sampled.
- Metric labels are compile-time constants or small closed enums. Query names, client
  addresses, candidate addresses and certificate hostnames are **never** labels.
- Hedging duplicates queries to a second upstream, which is a real privacy cost; it is
  bounded by `hedge_max_fraction` and reported through `egressdns_upstream_hedges_total`.
- Only aggregate popularity is persisted. Per-client query histories are never stored.

### 7. Supply chain

*Threat.* A dependency introduces a vulnerability or a licence obligation.

*Controls.* `Cargo.lock` is committed. CI runs `cargo deny check` (advisories, licences,
bans, sources) and `cargo audit`. Only permissive licences are allowed. OpenSSL and
`native-tls` are banned outright. `unknown-git` and `unknown-registry` sources are denied.
The toolchain is pinned.

### 8. Local privilege

*Threat.* Compromise of the daemon becomes compromise of the host.

*Controls.* The service runs as a dedicated unprivileged user. Its only capability is
`CAP_NET_BIND_SERVICE`, in both the ambient and bounding sets, with `NoNewPrivileges`. The
unit applies `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
`ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`,
`ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`,
`LockPersonality`, `MemoryDenyWriteExecute`, `RestrictRealtime`, `RestrictSUIDSGID`,
`RestrictNamespaces`, `SystemCallFilter=@system-service` and a minimal
`RestrictAddressFamilies` set. Writable paths are limited to the state and runtime
directories. The crate is `#![forbid(unsafe_code)]`.

### 9. Administration interface

*Threat.* An unprivileged local user reconfigures or interrogates the resolver.

*Controls.* A Unix domain socket only, with mode validated to grant nothing to "other".
There is no network administration interface at all. Requests are size-bounded, the command
set is a fixed list, argument counts and lengths are bounded, and the effective
configuration dump redacts secret paths.

---

## Explicitly out of scope

- Protecting against a compromised configuration file or a root-level host compromise.
- Content filtering or advertisement blocking. A resolver that lies about some names is a
  resolver whose answers cannot be reasoned about.
- Anonymity. This is not Oblivious DNS.
- Protecting clients from themselves: an operating system or browser may run its own
  resolver or its own DoH, and this daemon cannot and should not prevent that.

---

## Deliberate design refusals

Each of these was considered and rejected. They are listed because "why doesn't it do X?"
deserves an answer.

| Refused | Reason |
| ------- | ------ |
| A global "insecure TLS" switch | It would be found by search engines and used in production within a week |
| QUIC 0-RTT | Early data is replayable; DNS queries are not safe to replay. Setting `quic_zero_rtt = true` is a configuration error |
| `force-any-ip` or address replacement | Returning an address the upstream never offered is indistinguishable from an attack |
| Removing addresses that probe badly | A probe failure is evidence about the probe, not proof the address is unusable for the client |
| Hiding AAAA when IPv6 measures worse | Server-side IPv6 quality says nothing about a client's path; Happy Eyeballs exists precisely so the client can decide |
| Synthetic CNAMEs for TTL control | Mutating third-party data and breaking DNSSEC to gain a scheduling convenience |
| Trusting an upstream AD bit by default | The bit is a claim, not proof, unless the transport is authenticated *and* the operator has said so |
| Persisting live DNS answers | Clock skew, expiry and DNSSEC validity across a restart are subtle. The benefit is a slightly warmer cache; the risk is serving data that should have expired |

---

## Reporting a vulnerability

See `SECURITY.md`.
