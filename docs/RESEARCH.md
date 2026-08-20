# Research notes

**Research date:** 18 August 2026
**Target platform:** Debian 13 (`x86_64`, `aarch64`)
**Toolchain:** Rust 1.95.0 (pinned in `rust-toolchain.toml`)

This document records what was checked, what was decided, and — importantly — what was
*rejected*. Everything below was verified against primary sources on the research date
rather than recalled; where a widely-repeated assumption turned out to be stale, that is
called out explicitly.

---

## 1. Dependency version matrix

Versions are those resolved in the committed `Cargo.lock`.

| Crate | Version |
| ----- | ------- |
| `hickory-proto` | 0.26.1 |
| `hickory-net` | 0.26.1 |
| `hickory-resolver` | 0.26.1 |
| `hickory-server` (dev only) | 0.26.1 |
| `tokio` | 1.53.1 |
| `rustls` | 0.23.43 |
| `tokio-rustls` | 0.26.4 |
| `quinn` | 0.11.11 |
| `h3` | 0.0.8 |
| `h3-quinn` | 0.0.10 |
| `hyper` | 1.11.0 |
| `hyper-util` | 0.1.20 |
| `moka` | 0.12.16 |
| `arc-swap` | 1.9.2 |
| `rusqlite` (bundled SQLite) | 0.40.2 |
| `serde` | 1.0.229 |
| `toml` | 1.1.4 |
| `clap` | 4.6.6 |
| `tracing` | 0.1.44 |
| `metrics` | 0.24.6 |
| `metrics-exporter-prometheus` | 0.18.3 |
| `ipnet` | 2.12.1 |
| `socket2` | 0.6.5 |
| `governor` | 0.10.4 |
| `tokio-util` | 0.7.19 |
| `thiserror` | 2.0.20 |
| `anyhow` | 1.0.104 |
| `ring` | 0.17.14 |
| `webpki-roots` | 1.0.9 |
| `rustls-native-certs` | 0.8.4 |
| `sd-notify` | 0.5.0 |
| `nix` | 0.31.3 |
| `maxminddb` | 0.30.0 |
| `hyper`/`http` stack (`http`, `http-body-util`) | 1.5.0 / 0.1.5 |
| `proptest` (dev) | 1.11.0 |
| `criterion` (dev) | 0.8.2 |
| `rcgen` (dev) | 0.14.9 |

### A note on the Hickory 0.26 reorganisation

Hickory DNS 0.26 moved the network transports out of `hickory-proto` into a new
`hickory-net` crate. Feature names such as `tls-ring`, `https-ring`, `quic-ring` and
`h3-ring` now live on `hickory-net`, and `hickory-proto` keeps only the wire protocol and
DNSSEC record types. Guides written against 0.24 or 0.25 will not compile. This was
discovered by reading the crate manifests directly, not from documentation.

---

## 2. Standards reviewed

Statuses were checked against the RFC Editor and the IETF Datatracker on the research date.

| Document | Title | Status | How it is used here |
| -------- | ----- | ------ | ------------------- |
| RFC 1034 / 1035 | Domain names — concepts and specification | Internet Standard | Message format, TTL semantics, 512-byte non-EDNS UDP limit |
| RFC 2181 | Clarifications to the DNS specification | Proposed Standard | RRset integrity: an RRset is atomic and is never partially replaced |
| RFC 2308 | Negative caching of DNS queries | Proposed Standard | NXDOMAIN/NODATA TTL taken as `min(SOA.MINIMUM, SOA TTL)`, capped |
| RFC 4033/4034/4035 | DNSSEC | Proposed Standard | Validation states, AD/CD handling, RRSIG lifetime bounds |
| RFC 5452 | Measures against forged answers | Proposed Standard | Query ID and source-port entropy, question matching, 0x20 encoding |
| RFC 6891 | EDNS(0) | Internet Standard | OPT handling, BADVERS, never adding OPT to a non-EDNS client's response |
| RFC 6895 | DNS IANA considerations | Best Current Practice | Extended RCODE 16 is shared by BADVERS and BADSIG |
| RFC 7766 | DNS transport over TCP | Proposed Standard | Pipelining, out-of-order completion, connection reuse |
| RFC 7828 | edns-tcp-keepalive | Proposed Standard | Advertised on TCP responses |
| RFC 7858 | DNS over TLS | Proposed Standard | DoT upstream transport, port 853 |
| RFC 7871 | Client Subnet in DNS queries | Informational | ECS policy; disabled by default, never forwards a client's LAN address |
| RFC 7873 | DNS Cookies | Proposed Standard | Client cookies on UDP/TCP upstreams; echo verification |
| RFC 8305 | Happy Eyeballs v2 | Proposed Standard | Informs why AAAA is never suppressed |
| RFC 8310 | Usage profiles for DNS over TLS/DTLS | Proposed Standard | Strict-privacy profile: authentication is mandatory, never opportunistic |
| RFC 8484 | DNS Queries over HTTPS | Proposed Standard | DoH2 and DoH3 upstream transports, `/dns-query` |
| RFC 8482 | Minimal responses to DNS ANY | Proposed Standard | Default `any_policy = "minimal"` synthesises a HINFO RRset |
| RFC 8767 | Serving stale data | Proposed Standard | Serve-stale, client response timer, max-stale |
| RFC 8914 | Extended DNS Errors | Proposed Standard | EDE codes attached to stale, bogus and network-failure answers |
| RFC 9114 | HTTP/3 | Proposed Standard | Carries DoH3 |
| RFC 9210 | DNS transport over TCP — operational requirements | Best Current Practice | TCP must be supported, not merely tolerated |
| RFC 9250 | DNS over Dedicated QUIC Connections | Proposed Standard | DoQ upstream transport, ALPN `doq`, 0-RTT analysis |
| RFC 9460 | SVCB and HTTPS resource records | Proposed Standard | HTTPS/SVCB pass-through, `port`/`alpn`/`ech` parameters |
| RFC 9499 | DNS terminology | Best Current Practice | Vocabulary used throughout this repository |
| RFC 9520 | Negative caching of DNS resolution failures | Proposed Standard | Failure cache: 1 s minimum, 5 min maximum, ≤ 3 queries per server per transport |
| RFC 9715 | IP fragmentation avoidance in DNS over UDP | Informational | UDP payload sizing |
| RFC 9849 | TLS Encrypted Client Hello | Proposed Standard | ECH; see §6 |
| RFC 6724 | Default address selection for IPv6 | Proposed Standard | Why the server does not attempt client-side address selection |
| draft-ietf-happy-happyeyeballs-v3-04 | Happy Eyeballs v3 | Internet-Draft, not an RFC | Confirms clients, not resolvers, do the racing |

### Findings that changed the design

**RFC 9715 is newer than the number everyone quotes.** Published January 2025 as
Informational, it recommends a **1400-octet** maximum DNS/UDP payload, deriving it from a
typical 1500-byte Ethernet MTU with room for options and tunnel overhead, and explicitly
discusses the older 1232 value (which comes from the IPv6 minimum MTU of 1280). This
project ships **1232** as the default because it is the value that is safe on every path
including IPv6 tunnels, and exposes `server.udp.max_payload` so an operator who has
measured their path MTU can raise it toward 1400. The relevant trade-off is documented in
`config/egressdns.toml` rather than buried in code.

**RFC 9520 puts a hard ceiling on retries.** "Resolvers MUST NOT retry a given query to a
server address over a given DNS transport more than twice (i.e., three queries in total)."

This shipped originally as a validated `scheduler.max_attempts_per_route` between 1 and 3.
That was the wrong shape, and the semantic audit removed it. The scheduler makes at most
*one* attempt per route per resolution — a route being one (server, transport, address)
triple — so a single resolution cannot reach the ceiling no matter what the setting says.
A configuration key that cannot change the behaviour it names is worse than no key: it
invites an operator to tune something that does not exist, and it makes the compliance
claim look like it rests on validation when it actually rests on the control flow.

What bounds *repeated* queries is the failure cache, which is the mechanism RFC 9520 is
actually about. That is still validated, below.

**RFC 9520 also bounds failure caching** to at least 1 second and no more than 5 minutes,
with exponential or linear backoff recommended. `cache.failure_min_ttl` and
`cache.failure_max_ttl` are validated against exactly those bounds.

**ECH is now RFC 9849** (March 2026), no longer `draft-ietf-tls-esni`. This matters because
a great deal of writing still treats ECH as a moving target. It is stable — but the Rust
TLS ecosystem has not caught up, which is why verified-augment degrades to preserve mode
for any domain publishing an `ech` SvcParam (see §6).

**Happy Eyeballs v3 is still a draft** (`-04`, expires January 2027) and updates rather
than obsoletes RFC 8305. Both versions place address racing in the *client*, which is the
reason this resolver never suppresses AAAA: doing so would take a decision away from the
only component that can actually measure the client's path.

---

## 3. Reference implementations examined

Studied for behaviour and architecture only. No code was copied from any of them; the
GPL-licensed projects in particular were read as specification, never as source.

| Project | Licence | What was learned |
| ------- | ------- | ---------------- |
| Unbound | BSD-3-Clause | Serve-stale ergonomics, prefetch trigger points, the value of a hard `infra-cache` separation between name data and host reachability data |
| Knot Resolver | GPL-3.0 | Layered request processing; the discipline of keeping policy out of the packet path |
| dnsdist | GPL-2.0 | Health-checking and route-scoring vocabulary, the idea of an explicit "downstream state" rather than an implicit one |
| SmartDNS | GPL-3.0 | The overall idea of speed-testing answer addresses. Its "pick the fastest IP" behaviour is exactly what this project deliberately *narrows*: it can return an address the upstream never offered |
| smartdns-rs | GPL-3.0 | Rust structuring of the same idea |
| CloudflareSpeedTest | GPL-3.0 | The shape of Cloudflare Anycast measurement: TCP connect latency, then TLS, then a download. Its unrestricted scanning model is not adopted |
| CoreDNS | Apache-2.0 | Plugin-boundary discipline; rejected as a model because per-query plugin dispatch costs more than this workload can afford |

**Licence hygiene.** Reading GPL source and then writing an independent implementation of
the same *idea* is legitimate; copying structure or code is not. The Cloudflare optimizer
here was written from the RFCs, Cloudflare's own documentation and first principles. Its
design differs substantially from the reference projects: it never removes an address, it
never returns an address that has not been validated for the *specific* hostname, and it
treats every external list as untrusted input rather than as configuration.

---

## 4. Cloudflare sources

All four endpoints were fetched and their live responses inspected on the research date.

### `https://api.cloudflare.com/client/v4/ips`

Returns the standard Cloudflare API envelope:

```json
{"result":{"ipv4_cidrs":[...],"ipv6_cidrs":[...],"etag":"..."},"success":true,"errors":[],"messages":[]}
```

Observed: 15 IPv4 prefixes and 7 IPv6 prefixes, served with an `ETag` header and an
`api-version` header. The endpoint requires no authentication. Conditional requests with
`If-None-Match` are supported and are used.

### `https://www.cloudflare.com/ips-v4` and `ips-v6`

Plain text, one CIDR per line, **no trailing newline**. Used as a cross-check: disagreement
with the API is logged for the operator but the API snapshot wins, because the two
endpoints are updated independently and a transient difference is not an error.

### `https://developers.cloudflare.com/fundamentals/reference/network-ports/`

Confirms the proxied ports. Only 443 is relevant to this project: probing anything else
would be a port scan with no defensible purpose.

### `https://cf.090227.xyz/` and its `ct` / `cu` / `cmcc` endpoints

A community-run "preferred Cloudflare IP" site. The root path returns an HTML page; the
data endpoints return `text/plain` with one entry per line in the form
`ADDRESS#comment`, where the comment is Chinese text naming the carrier. `?ips=N` bounds
the number of entries.

**The finding that shapes the entire trust model:** these endpoints regularly return
addresses that do **not** belong to Cloudflare. Two independent samples taken minutes
apart contained, among others:

| Address | In an official Cloudflare prefix? |
| ------- | --------------------------------- |
| `162.159.38.8` | yes |
| `108.162.198.86` | yes |
| `104.26.1.184` | yes |
| `188.164.248.83` | **no** |
| `188.164.248.66` | **no** |
| `91.193.59.179` | **no** |
| `8.35.211.212` | **no** |
| `8.39.125.231` | **no** |

Roughly one in four addresses in the "China Telecom" list was outside Cloudflare's
published space. Whatever those hosts are, they are not Cloudflare edge servers, and
returning one in a DNS answer would send user traffic to an unknown third party.

The captured responses are committed verbatim as `tests/fixtures/seed_*.txt`, and
`tests/cloudflare_security.rs` asserts that every one of those addresses is refused. The
seed provider is therefore modelled as a *hint generator with no authority*: it can only
ever propose an address that must then survive official-prefix membership, special-use
filtering, TCP, TLS-with-correct-SNI, HTTP validation and repeated success before it can
influence any answer.

---

## 5. Cloudflare optimization boundaries

What the optimizer is allowed to do:

- **Reorder** addresses that are already present in a complete A or AAAA RRset.
- **Prepend**, in `verified-augment` mode only, at most two Cloudflare-owned addresses that
  have been validated *for that exact hostname*, while keeping every original address.

What it is never allowed to do, enforced in code and asserted by property tests:

- Remove an address, for any reason, including a failed probe.
- Add an address that is not inside the *current* official prefix snapshot.
- Add an address to a DNSSEC Secure answer, or to one whose DNSSEC state is unknown.
- Merge records from two different upstream responses.
- Alter CNAME, DNAME, MX, SRV, HTTPS, SVCB, DNSKEY, DS, RRSIG, NSEC, NSEC3 or unknown types.
- Use a third-party relay, reverse proxy or intermediary address.
- Decide that a domain is Cloudflare-hosted from its name, its NS records, GeoIP or ASN
  data. Only an address in a valid answer, matched against the official prefix list, can
  establish that.

The candidate admission pipeline is deliberately linear and fail-closed:

```
external seed / local sampling / observed answer / configuration
    -> strict parsing
    -> current official Cloudflare prefix membership
    -> special-use and private-address filtering
    -> bounded pool admission with an hourly budget
    -> TCP 443
    -> TLS 1.3 with the origin hostname as SNI and full chain verification
    -> HTTP with the origin hostname as authority
    -> repeated success and a confidence threshold
    -> eligible for use
```

**Sampling is bounded and reproducible.** Official IPv4 prefixes are divided into buckets;
each round proposes a handful of addresses, preferring never-visited buckets, with a
minority of the budget revisiting historically productive ones. Everything derives from a
configured seed, so a schedule can be replayed during an incident. IPv6 is not sampled by
traversal: `2606:4700::/32` contains 2^96 addresses and random traversal has no defensible
expected yield, so IPv6 candidates come only from real answers, seeds, history and
configuration.

---

## 6. HTTPS/SVCB and ECH compatibility boundaries

HTTPS and SVCB records are passed through byte for byte. No SvcParam is removed, rewritten
or reordered — including `ech`, `alpn`, `port`, `ipv4hint` and `ipv6hint`.

ECH and the DNS transport are independent concepts. ECH does not require DNS-over-HTTPS,
and using DoH does not imply ECH. Conflating them is a common error and would lead to
wrongly "optimizing" a domain whose connection setup depends on a parameter the resolver
does not understand.

The concrete boundary: if a domain publishes an `ech` SvcParam (SvcParamKey 5, RFC 9460
registry, defined by RFC 9849) and this build cannot validate the ECH path end to end —
which, with `rustls` 0.23, it cannot — then `verified-augment` **falls back to preserve
mode** for that domain. Reordering remains safe because the client still receives exactly
the addresses the origin published; adding an address would not be, because the added edge
might not hold the same ECH configuration. Failure to test ECH never removes an HTTPS
record and never removes AAAA.

---

## 7. DNSSEC mutation risks

Any modification of a signed answer is a correctness hazard, so the rules are absolute:

1. **Reordering is safe.** RRset ordering is not covered by RRSIG; canonical ordering is
   computed during validation, not taken from the wire (RFC 4034 §6).
2. **Addition is not safe.** An added address is unsigned. Even with the AD bit cleared, a
   validating stub asking the same question would get a different RRset. Verified-augment
   therefore requires a *proven Insecure* state — not merely "not Secure".
3. **An unknown state is treated as dangerous, not as permission.** `Indeterminate` is what
   you get when validation could not be completed; it is exactly the case where an attacker
   may have stripped the signatures, so it is grouped with Secure for this purpose.
4. **AD is never fabricated.** `may_set_ad()` requires the client to have asked, the state
   to be Secure, and the answer to be unmodified.
5. **Client TTL is bounded by signature lifetime.** Data must never outlive the RRSIG that
   makes it verifiable, so the earliest `sig_expiration` is an upper bound on the TTL.
6. **Bogus never fails open.** Bogus data is never cached and never served, fresh or stale;
   the client gets SERVFAIL with EDE 6.

---

## 8. Rejected dependencies and approaches

| Rejected | Reason |
| -------- | ------ |
| `hickory-server` in the shipped binary | Its `ServerFuture` owns socket handling and request dispatch. This project needs precise control over EDNS sizing, per-connection limits, pipelining depth and ACL evaluation on the hot path. Writing ~400 lines of ingress is cheaper than fighting an opinionated abstraction. It *is* used as a dev-dependency to provide DoT/DoH/DoQ/DoH3 test servers, which is exactly the right use of it |
| `hickory-recursor` | Marked experimental by its own authors. Production correctness must not depend on an experimental iterative resolver; this is a caching *forwarder* by design |
| `openssl` / `native-tls` | Two TLS stacks means two sets of CVEs and two configuration surfaces. `cargo-deny` bans them outright |
| `reqwest` | Brings a second HTTP client and its own DNS resolution path. Probes must dial an *explicit* address while presenting the origin hostname, which a general-purpose client makes awkward. `hyper` over `tokio-rustls` gives exact control with fewer crates |
| `trust-dns-*` | The pre-rename Hickory crates; unmaintained under those names |
| `x509-parser` | Only two facts are needed from an already-verified certificate: the SPKI hash and the issuer CN. A 130-line bounded DER walker with a dedicated fuzz target is a smaller attack surface than a general X.509 parser |
| `rtnetlink` | A full netlink event subscription for a detector that only needs to notice changes within a few seconds. `getifaddrs(3)` via `nix` plus `/proc/net/route` is smaller, has no async-runtime coupling, and is easy to unit-test with fixture files. See ADR-0006 |
| `sha2` | `ring` is already in the tree via `rustls`, and provides SHA-256. Adding a second hash implementation for no functional gain is unjustified |
| A synthetic-CNAME TTL trick | Inserting a resolver-owned CNAME to gain TTL control mutates third-party data and breaks DNSSEC. TTL capping achieves the same goal without touching the answer's shape |
| Machine-learning ranking | An unexplainable model cannot be debugged at 03:00. The cost model here is an explicit sum of named terms, each of which can be read off `egressdnsctl upstreams` |
| io_uring, AF_XDP, custom allocators | No profiling evidence yet justifies them. See `docs/BENCHMARKS.md` for what was measured |

---

## 9. Remaining maturity risks

Recorded honestly, because pretending they do not exist is how they bite.

| Risk | Assessment | Mitigation |
| ---- | ---------- | ---------- |
| `h3` at 0.0.8 | Pre-1.0 and API-unstable. DoH3 is the least battle-tested transport here | DoH3 is never the only configured upstream in the shipped configurations. A DoH3 failure trips the circuit breaker and other routes carry the traffic |
| QUIC on hostile networks | Some middleboxes drop UDP/443 entirely, making every DoQ and DoH3 attempt fail | QUIC/H3 probe failures are classified `Unsupported`, never `ApplicableFailure`, so a UDP-blocking network cannot poison the quality model |
| ECH validation | No Rust TLS stack validates the ECH path end to end today | Verified-augment degrades to preserve mode for any ECH-publishing domain. Revisit when `rustls` ships ECH |
| DNSSEC validation via `hickory-net` | Local validation is comparatively young code | `dnssec.mode = "off"` is a one-line change and leaves a fully working forwarder. Bogus results fail closed |
| `cf.090227.xyz` availability and format | A community endpoint that can change shape or vanish | Disabled by default; strictly bounded parser; endpoint failure is logged and the last good candidate list is retained; the resolver does not depend on it in any way |
| SQLite on unreliable storage | Corruption is possible on abrupt power loss | Corruption is detected with `PRAGMA quick_check`, the file is quarantined, and the daemon starts with neutral in-memory state |
| `maxminddb` | Used only for advisory diagnostics | A missing or broken database is logged and ignored; it can never make a valid address invalid |
| Two-node consistency | Independent caches mean two nodes can briefly return different variants for a CDN name | This is correct behaviour, not a defect: each variant is a complete answer the upstream gave. Documented in `docs/OPERATIONS.md` |

---

## 10. Reproducing this research

```bash
# Cloudflare official sources
curl -sS https://api.cloudflare.com/client/v4/ips | jq .
curl -sS https://www.cloudflare.com/ips-v4
curl -sS https://www.cloudflare.com/ips-v6

# Third-party seed endpoints (untrusted)
curl -sS 'https://cf.090227.xyz/ct?ips=6'
curl -sS 'https://cf.090227.xyz/cu'
curl -sS 'https://cf.090227.xyz/cmcc?ips=8'

# Check which returned addresses are actually Cloudflare's
python3 - <<'PY'
import ipaddress, json, urllib.request
cf = json.load(urllib.request.urlopen("https://api.cloudflare.com/client/v4/ips"))["result"]
nets = [ipaddress.ip_network(n) for n in cf["ipv4_cidrs"]]
for line in urllib.request.urlopen("https://cf.090227.xyz/ct?ips=6").read().decode().splitlines():
    ip = line.split("#")[0].strip()
    if not ip:
        continue
    addr = ipaddress.ip_address(ip)
    print(f"{ip:20s} {'cloudflare' if any(addr in n for n in nets) else 'NOT CLOUDFLARE'}")
PY

# Crate versions
cargo tree --depth 1
```
