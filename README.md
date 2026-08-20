# EgressDNS

An adaptive, highly available DNS caching forwarder for enterprise LANs with a single
Internet egress.

EgressDNS answers DNS for a LAN. It caches aggressively, forwards over encrypted transports
(DoT, DoH2, DoH3, DoQ) as well as plain UDP and TCP, validates DNSSEC, and adapts its
upstream and answer-ordering decisions to what it measures on the actual network. All of
the measuring happens in the background: a client query is never blocked on a probe, a
dataset refresh, or a prediction.

If every adaptive subsystem fails, what is left is a correct caching forwarder. That is the
design contract, and it is tested.

## The whole configuration

```toml
upstreams = ["builtin:recommended"]

proxies = []
```

That is a complete, working file, and it is what the installer writes. `recommended`
expands to five independently operated public resolvers with their plaintext seeds and
their encrypted endpoints; `egressdnsctl builtins recommended` prints exactly what, and
where each endpoint came from. Naming your own resolvers instead — or as well — is equally
fine:

```toml
upstreams = ["1.1.1.1", "https://dns.google/dns-query", "tls://dns.quad9.net"]
```

Listeners default to loopback, so a minimal configuration cannot accidentally become an
open resolver.

You describe *where to ask*. The daemon decides *how*: UDP or TCP, HTTP/2 or HTTP/3, IPv4
or IPv6, direct or through a proxy, which endpoint to prefer, when to hedge, when to break
a circuit and when to try a recovered path again — all from what it measures on your
network, not from constants you had to guess in advance. A single `https://` entry becomes
both an HTTP/3 and an HTTP/2 route candidate for one logical resolver, and the scheduler
picks between them and falls back on its own evidence.

Add proxies and they are used the same way — as paths to measure, not as instructions:

```toml
proxies = ["socks5h://127.0.0.1:1080", "http://127.0.0.1:7890"]
```

Before cutting over, ask what would break:

```sh
egressdnsctl doctor --config /etc/egressdns/config.toml
```

It checks listener ownership (naming the PID that holds the port), forwarding loops, ACL
coverage, `/etc/resolv.conf` management, service-account permissions, privileged-port
capability, address-family egress, and whether your upstreams are actually reachable from
this host — the check that distinguishes "the resolver is broken" from "this network
filters port 853", which otherwise look identical. Every result is `PASS`, `WARNING`,
`FAIL`, `NOT_APPLICABLE` or `NOT_TESTED`; a `FAIL` exits non-zero. A check that could not
look says so rather than reporting success.

There is no configuration version field, and no low-level transport form. Transport,
HTTP version, address family and direct-versus-proxy are not preferences an operator
should have to hold — they are measurements. A file from before 2.0 is refused by name
with a pointer to [the migration guide](docs/MIGRATION-V1-TO-V2.md), never half-applied.

Operational settings that *are* deployment facts — listeners, client ACLs, resource
ceilings, TLS roots — remain in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

```
                    ┌──────────────────────────────────────────┐
   LAN clients ───► │ ingress (UDP/TCP 53, v4+v6)              │
                    │   ACL · rate limit · special-use · cache │
                    └───────────────┬──────────────────────────┘
                                    │ miss
                    ┌───────────────▼──────────────────────────┐
                    │ scheduler: rank · hedge · circuit-break  │──► upstream resolvers
                    │ DNSSEC validate · answer policy          │    (UDP/TCP/DoT/DoH2/
                    └───────────────┬──────────────────────────┘     DoH3/DoQ)
                                    │ snapshots (ArcSwap), never awaited
                    ┌───────────────▼──────────────────────────┐
                    │ background: probe · sample · learn · persist
                    └──────────────────────────────────────────┘
```

## What it does

* **Six upstream transports.** UDP, TCP, DoT, DoH2, DoH3 and DoQ, in one configuration,
  each with its own health, circuit breaker and latency model. All six are verified
  end-to-end in `tests/transports.rs`.
* **DNSSEC that fails closed.** Bogus is SERVFAIL with an extended error, never a served
  answer. The upstream's AD bit is not trusted by default. The CD bit is honoured per
  query.
* **Caching that respects the protocol.** Serve-stale (RFC 8767) only after a refresh has
  actually failed; negative caching (RFC 2308); failure caching with the RFC 9520 bounds;
  cancellation-safe request coalescing; hot-name prefetching under a strict budget.
* **Tail-latency scheduling.** A single bounded hedge, timed from the primary route's own
  p95 rather than a fixed constant. Circuit breakers with a half-open probe. Bounded
  emergency fan-out when everything is failing.
* **Adaptive answer ordering.** A decayed Beta posterior plus latency percentiles per
  address, with hysteresis. Addresses with no evidence score *neutral* — lack of evidence
  is never treated as evidence of failure.
* **Safe Cloudflare optimization.** Reordering by default. Adding an address requires
  official-prefix membership, proven-Insecure DNSSEC, no unvalidatable ECH, a locally
  verified TLS+HTTP handshake, and a measured advantage. See
  [ADR-0010](docs/adr/0010-preserve-before-augment.md).
* **Degradation you can verify.** `scripts/chaos-test.sh` breaks each subsystem in turn and
  asserts DNS still works.

## What it does not do

No iterative resolution. No answer synthesis of any kind — no DNS64, no synthetic CNAMEs,
no AAAA suppression, no SVCB hint rewriting. No filtering or sinkholing. No encrypted ingress. No third-party proxy, relay or intermediary addresses in answers, under
any configuration. The reasoning for each is in [`docs/adr/`](docs/adr/).

## Install

One command, from a GitHub release:

```sh
curl -fsSL https://raw.githubusercontent.com/jacek4yang/egressdns/main/install.sh | sudo bash
```

It asks a few questions on your terminal — who the resolver should serve, what to do about
an existing install, whether this machine should use it for its own lookups — and every
default is the option that changes the least. Pressing Enter throughout gives a
loopback-only resolver and an otherwise untouched system.

Scripted installs answer the same questions with flags:

```sh
curl -fsSL https://raw.githubusercontent.com/jacek4yang/egressdns/main/install.sh \
  | sudo bash -s -- --non-interactive --mode lan --lan-cidr 192.168.1.0/24
```

`--help` lists them all. Pin a version with `--version v2.0.1`, stage without starting with
`--no-start`.

The installer detects the architecture, downloads the matching tarball, verifies its
SHA-256 against the published `SHA256SUMS`, creates a system user, installs the systemd
unit, and writes a configuration for the answers you gave. It will not disable your
existing resolver: it refuses only when something holds an address it actually needs, so
installing alongside systemd-resolved's `127.0.0.53:53` stub works.

Nothing is called successful because systemd says `active`. Before the installer prints a
summary it waits for readiness, then proves the daemon answers over UDP *and* over TCP
using a name answered from local data, resolves real names on the Internet from a quorum of
independent providers, and refuses a DNSSEC-Bogus name with SERVFAIL. Any failure prints
the reason, writes a diagnostic report with secrets redacted, and rolls back — the previous
binary, unit and configuration are snapshotted under `$TMPDIR` first, and the rollback
verifies that the previous version came back rather than assuming it.

Upgrade and uninstall are separate scripts with the same conventions:

```sh
sudo /usr/local/lib/egressdns/upgrade.sh
sudo /usr/local/lib/egressdns/uninstall.sh --purge
```

### From source

```sh
tar -xzf egressdns-v2.0.1-source.tar.gz
cd egressdns
cargo build --release --locked
sudo ./install.sh --local-build
```

Requires Rust 1.88 or newer; the pinned toolchain is in `rust-toolchain.toml`.

## First run

Do not start on port 53. Start on 1053, confirm it behaves, then move.

```sh
egressdnsd --config config/egressdns.toml --check-config
egressdnsd --config config/egressdns.toml --log info

dig @127.0.0.1 -p 1053 example.com A +short
dig @::1       -p 1053 example.com AAAA +short
dig @127.0.0.1 -p 1053 dnssec-failed.org A | grep status:   # must be SERVFAIL
```

`docs/OPERATIONS.md` §1–§6 covers the full path from a test instance to port 53, including
what to do about `systemd-resolved`.

**Exposing the daemon beyond this machine requires naming the client networks.** With
loopback listeners and no `allow_from`, loopback is admitted automatically. With a
non-loopback listener and no `allow_from`, startup is refused rather than guessing — the
guess would be an open resolver. An explicitly empty list is a deliberate deny-all and is
respected as written.

## Operating it

```sh
egressdnsctl status
egressdnsctl upstreams                       # per-route health, latency, circuit state
egressdnsctl network                         # IPv4/IPv6 usability and generation
egressdnsctl cache-stats
egressdnsctl cloudflare status
egressdnsctl cloudflare set-mode off         # neutralise optimization instantly, no restart
egressdnsctl reload                          # atomic; a bad config leaves the old one serving
egressdnsctl reload-contract                 # what needs a restart, and why
```

A reload either applies completely or is refused with the offending field named. There is
no third outcome: a setting is never accepted and quietly ignored. Settings that cannot
take effect live — listening sockets, thread pools, semaphores, fixed-capacity structures
— are listed by `reload-contract` and in
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md#the-reload-contract).

Metrics are Prometheus text format on `/metrics`, with `/healthz` for liveness and
`/readyz` for readiness. Every metric name and label value is a compile-time constant —
query names and client addresses are never used as labels.

## Documentation

| Document | What is in it |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How the pieces fit, and where the foreground/background line is. |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Every key, its default, and every validation rule with its justification. |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Testing, rollout, monitoring, rollback, and seven diagnosis playbooks. |
| [`docs/RFC_COMPLIANCE.md`](docs/RFC_COMPLIANCE.md) | Every standard: what is implemented, where, how it is tested, and what is deliberately not claimed. |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | What this daemon defends against, and what it does not. |
| [`docs/RESEARCH.md`](docs/RESEARCH.md) | What was measured live, including why third-party candidate lists are untrusted. |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Real numbers, real hardware, raw output — microbenchmarks and load tests kept strictly apart. |
| [`STATUS.md`](STATUS.md) | Every claim marked measured, tested, structural, static or unverified. |
| [`docs/adr/`](docs/adr/) | Ten decisions that would be expensive to reverse, and why. |

## Releases

The official repository is [`jacek4yang/egressdns`](https://github.com/jacek4yang/egressdns):

```sh
git clone https://github.com/jacek4yang/egressdns
```

Report issues at <https://github.com/jacek4yang/egressdns/issues>; download release
archives and `SHA256SUMS` from <https://github.com/jacek4yang/egressdns/releases>.

Releases are built by pushing a `v*` tag: `.github/workflows/release.yml` builds x86_64
and aarch64 tarballs, generates `SHA256SUMS`, and attaches them to the release. The
one-command installer above works against every published release. See
[`docs/RELEASING.md`](docs/RELEASING.md) for the full maintainer procedure;
`scripts/publish-first-release.sh` does the first push with pre-flight checks: it refuses
a dirty tree, never force-pushes, and shows you the Actions run.

## Development

```sh
cargo test --workspace --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo deny check && cargo audit
./scripts/check-config-docs.py          # documented keys == real keys
./scripts/pin-github-actions.sh --check # every CI action is a commit SHA
cargo bench                             # in-process microbenchmarks
./scripts/load-test.sh                  # eleven scenarios through a real socket
```

Run the load suite for anything touching the request path. Microbenchmarks measure what
you already suspected; the load harness is what found an O(n log n) per-query eviction, a
circuit breaker that black-holed traffic, and a UDP-only upstream that turned every large
answer into SERVFAIL — none of which moved a Criterion number.

The crate is `#![forbid(unsafe_code)]`. `unwrap`, `expect`, `todo!` and `unimplemented!` do
not appear on any production request path. Fuzz targets for the parsers live in `fuzz/`.

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
