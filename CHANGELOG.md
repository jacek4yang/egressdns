# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-08-19

**Breaking: the configuration format is replaced, not translated.** A file from
before 2.0 is refused by name with a pointer to
[the migration guide](docs/MIGRATION-V1-TO-V2.md). See that guide before upgrading.

The theme is that the resolver should decide. Transport, HTTP version, address family,
direct or proxied, which endpoint to prefer, when to hedge and when to corroborate are
measurements, not preferences an operator should have to hold in their head.

### The whole configuration

```toml
upstreams = [
    "1.1.1.1",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "tls://dns.quad9.net",
]

proxies = []
```

Listeners default to loopback, so a minimal file cannot become an open resolver by
accident. There is no configuration version field.

### Added

* **Endpoint URIs.** Bare addresses, provider aliases, `https://`, `tls://`, `quic://`,
  `udp://`, `tcp://`. One `https://` entry becomes *both* an HTTP/3 and an HTTP/2 route
  candidate for one logical resolver, because which is faster on a given network is a
  measurement. `?addr=` pins bootstrap addresses for a name DNS cannot resolve yet.
* **Egress proxies that work.** SOCKS5 (RFC 1928) with optional RFC 1929 authentication,
  and HTTP CONNECT with optional Basic authentication, over cleartext or with TLS to the
  proxy itself. Each proxy is a separate route with its own health; direct is preferred
  while healthy and the proxy takes over on merit when it is not. UDP, DoQ and DoH3 are
  never proxied, because no proxy implemented here carries datagrams.
* **Runtime bootstrap.** An arbitrary named endpoint is resolved at startup from a
  bare-IP upstream or the system resolver. Those supply an *address* only — the TLS
  identity is always the configured name, so a hijacked bootstrap fails closed. Bootstrap
  dependency cycles are refused before any I/O, with the full path.
* **Resolver authority, distinct from route.** Cloudflare over HTTP/3, over HTTP/2, over
  IPv6 and through a proxy are four routes and one authority. Hedges prefer an
  independent authority.
* **Negative corroboration.** An unsigned NXDOMAIN is checked against a different
  authority before it is believed. It can only replace a negative with a positive, never
  the reverse.
* **`egressdnsctl doctor`**, with real protocol canaries — a real Do53 query, a real DoT
  handshake validated against the configured name. Transports whose clients are not
  implemented report `NOT_TESTED`, never `PASS`.
* **`egressdnsctl query`**, a built-in client so health checks never depend on `dig`.

### Fixed

* **The daemon reported ready and answered nothing.** `ProcSubset=pid` hid
  `/proc/net/route`, so the address-family detector found no default route and the
  scheduler had nothing to rank. See
  [the incident report](docs/incidents/2026-08-deployment-failure.md).
* **A detection failure could black-hole all traffic.** Ranking now treats "no family is
  usable" the way it treats "every circuit is open": offer every route rather than none.
* **The ranker penalised routes it had measured.** An untried route scored ~365; one
  measured working at a realistic 250 ms round trip scored ~551, and lower wins — so
  measuring a route demoted it below every untried one and the scheduler cycled forever.
  Invisible on loopback, where the test suite and load harness run.
* **Untried routes were skipped by the emergency fallback** when the hedge was disabled or
  budget-denied.
* **Nested operations each received a fresh copy of the foreground budget.** The
  truncation retry was measured at 4.005 s against a 2.5 s promise; DNSSEC validation,
  including the wait for a validation permit, could spend several budgets. One absolute
  deadline is now established at ingress and carried across everything the request awaits.
* **A sent exchange released its accounting slot on cancellation**, so the ceiling bounded
  waiters rather than exchanges.
* **Runtime policy was published in two steps**, so a query could observe new
  configuration with old policy.
* **Every A and AAAA answer was probed on port 443 and ranked by the result.** An SSH host
  or a mail exchanger was ordered by how well its addresses completed a TLS handshake on a
  port they do not serve, and every address in every answer received an unsolicited
  connection. Port-443 evidence now requires an HTTPS or SVCB record.
* **The systemd unit could stop another resolver.** `Conflicts=` does not refuse to start
  — it stops the other unit.
* **The installer's canary was optional and lenient.** It needed `dig`, which a host may
  not have, and `dig` exits 0 for SERVFAIL and REFUSED alike.
* **Installer rollback restored the files and left DNS down.** The restored configuration
  came back `root:root` and unreadable by the service account, and a unit that had just
  failed repeatedly was rate-limited so the restart was silently declined. Both found by
  exercising a genuinely failed cutover on a real host.
* **The release workflow could not express a release candidate**, and the aarch64 CI job
  was timing out rather than passing.

### Performance

Load harness, this release against the previous one, same host, identical harness:

| scenario | 1.0.0 | 2.0.0 |
| --- | --- | --- |
| cache-hit | 45,726 qps, p99 14.09 ms | 46,445 qps, p99 14.03 ms |
| mixed | 25,158 qps, p99 21.59 ms | 38,011 qps, p99 11.35 ms |
| miss-heavy | 2,799 qps, p99 88.28 ms | 4,657 qps, p99 28.79 ms |
| truncation | 2,908 qps, p99 88.19 ms | 4,410 qps, p99 31.19 ms |

Parity where answers come from cache; 50–66% more throughput at roughly a third of the
tail latency wherever an upstream is involved.

Soak: 90 minutes, 177,250,187 queries, success 1.000, zero errors and zero timeouts. RSS
rose from 12 MB to a 103 MB plateau and then declined to 97 MB; threads flat at 6; file
descriptors ended where they started.

Differential against Unbound 1.22.0 with DNSSEC validation, both forwarding to the same
upstream: 15 cases, 15 agree, 0 differ.

### Known limitations

* No DDR, SVCB/HTTPS resolver discovery, RESINFO, ECH, ODoH or MASQUE.
* SOCKS5 UDP ASSOCIATE is not implemented, so DoQ and DoH3 are direct-only.
* Corroboration covers unsigned negative answers; there is no general multi-authority
  answer-admissibility model.
* No 24-hour soak. aarch64 is verified under emulation, not on native hardware.

## [Unreleased] — production-hardening pass, 2026-08-19

A semantic audit of the 1.0.0 source. The theme is that configuration, documentation and
runtime behaviour must agree; where they did not, the code was changed rather than the
documentation.

### Fixed

* **Hot reload did not reload runtime behaviour.** Every supervised background task copied
  `Config` — and often the resolver and the upstream registry — at spawn time, so a
  successful reload swapped a structure nothing read. Prefetch kept querying the
  pre-reload upstream over a registry whose connections had already been drained. Tasks
  now take a `tasks::Ctx` holding only a `Weak<App>` and re-read the live configuration,
  state and resolver at the top of every iteration.
* **A disabled feature could not be enabled by reload.** Tasks returned early when their
  feature was off at startup, which silently made every `enabled` switch
  restart-required. They now idle and re-check.
* **A UDP-only upstream turned every answer over 512 bytes into SERVFAIL.** Truncated UDP
  answers are never parsed opportunistically, and the stream retry only considered routes
  whose *configured* transport was a stream — so a group with one `transport = "udp"`
  server had nothing to retry over. Every UDP server now gets a companion TCP route to the
  same address and port (RFC 1035 §4.2.1, RFC 7766 §5), excluded from ordinary ranking.
* **`resources.max_inflight_upstream` bounded resolutions, not exchanges.** The semaphore
  was acquired once per `Scheduler::resolve`, but one resolution can run a primary, a hedge
  and emergency fan-out attempts concurrently — the real ceiling was the configured value
  times three. The shared permit is now acquired per physical exchange inside
  `Scheduler::attempt`: primaries and truncation retries queue within the remaining budget,
  hedges and fan-out shed immediately at the ceiling, and a shed attempt records no health
  evidence, so saturation cannot flap a circuit breaker. `tests/bounds.rs` proves the
  ceiling under active hedging and fan-out.
* **The foreground answer path kept the startup Cloudflare configuration after a reload.**
  Background tasks re-read the live configuration, but `CloudflareState` — retained across
  reloads — had captured `cloudflare.enabled` and `cloudflare.mode` at construction, so
  reloads moved the background work while answers kept the old behaviour. Both are now
  atomics updated by `CloudflareState::reconfigure` during `App::reload`, with any admin
  mode override reconciled against the new configured mode. `cloudflare.candidate_pool_max`
  and `cloudflare.sampling.{seed,buckets_per_prefix,exploit_fraction}`, which rebuild would
  discard state for, are classified restart-required instead of being silently ignored.
* **`dnssec.max_concurrent_validations` bounded nothing.** Now a semaphore acquired in
  `Resolver::fetch`; shedding is SERVFAIL plus `dnssec_shed_total`.
* **`dnssec.trust_anchor_file` was decorative.** Anchors are now loaded at resolver
  construction and the setting **fails closed**: a missing, unreadable or empty file
  refuses startup and reload rather than falling back to the built-in IANA anchors.
* **The probe engine created a Tokio task per queued job.** It spawned first and awaited a
  stage semaphore afterwards, making the queue depth the real concurrency limit. The
  worker permit is now acquired before the job leaves the channel.
* **`probe.daily_bandwidth_budget_bytes` was counted but never enforced.** It is now an
  admission gate in `ProbeGuard::admit`.
* **The probe guard's cooldown tables grew without bound.** They are now swept every 30 s
  with a 50,000-entry ceiling.
* **Hyper's connection-driver task was aborted before the response body was read**, and
  leaked on every error path in `probe::fetch`. Replaced with an RAII guard held until the
  body completes, plus an overall fetch deadline.
* **`Storage::flush` blocked a runtime worker** with `thread::sleep`. Now async.
* **Shutdown slept 500 ms and exited** without joining the control plane.
  `App::shutdown_and_join` now cancels, waits, and reports how many tasks had to be
  aborted.
* Blocking filesystem I/O moved off runtime workers (secret reading, prefix-cache reads),
  and the prefix cache file is written atomically.
* **`cache.negative_max_ttl` was accepted on reload but never applied.** The value was
  captured into the retained cache at construction. It is now read from the live
  configuration where the negative TTL is computed, and `tests/reload.rs` proves the
  client-visible TTL follows a reload.
* **`cache.failure_max_ttl` was silently clipped after a reload that raised it.** The
  failures cache's retention bound was sized from the startup value. The per-entry TTL is
  computed from the live configuration; the retention bound is now the RFC 9520 ceiling
  validation enforces (`config::FAILURE_MAX_TTL_CEILING`), which covers every legal value.
* **`resources.systemd_watchdog` claimed to be reloadable.** The watchdog task is spawned
  once at startup, so the field is now classified restart-required and a reload that
  changes it is refused by name.
* **`ResolveError::Overloaded` reported "permits free" while carrying the configured
  ceiling.** The message and the DNSSEC shed site now both pass the configured limit.

### Added

* `src/config/reload.rs` — the reload contract. Every field is reloadable or
  restart-required; a restart-required change is refused **by name** and nothing is
  applied. `catalog()` is derived from the same check that runs, so documentation cannot
  drift from behaviour.
* `egressdnsctl reload-contract` prints the classification without contacting the daemon.
* `tests/reload.rs` — behavioural reload tests, asserting on which upstream answered and
  whether work stopped, never on the contents of the in-memory config. Now includes
  Cloudflare mode/enabled reloads reaching the foreground, restart-required rejection of
  structural Cloudflare changes, and `cache.negative_max_ttl` following a reload.
* `tests/bounds.rs` — resource-ceiling tests that demonstrate limits binding, including
  hedging and emergency fan-out unable to multiply the upstream exchange ceiling, and the
  truncation retry completing at a ceiling of one.
* `scripts/mock_upstream.py`, `scripts/loadtest.py`, `scripts/load-test.sh` — an eleven
  scenario load suite with measured percentiles to p99.9, full rcode accounting, and
  RSS/fd/thread/CPU sampling from `/proc`.
* `scripts/check-config-docs.py` and `scripts/pin-github-actions.sh --check`, both wired
  into CI. The config audit is full-path aware: `prefetch.queue_size` and
  `storage.queue_size` no longer mask each other, and a doc row under the wrong section
  fails the check.
* Every configuration leaf path is classified exactly once — reloadable or
  restart-required — in `src/config/reload.rs`, and the test
  `every_config_path_is_classified_exactly_once` fails the build when a new field is added
  without a classification.
* `cloudflare.augment.min_samples`, `cloudflare.static_candidates`, `logging.query_log`
  and `logging.query_log_sample` now do what they say.
* `prefetch.warm_on_start`, `serve_stale.retry_interval` and `datasets.reload_interval`
  gained real implementations.
* `dnssec.max_validation_depth`, bounding the work one hostile zone can force.
* Metrics: `upstream_shed_total`, `upstream_inflight`, `upstream_last_resort_total`,
  `dnssec_inflight`, `dnssec_shed_total`, `probe_workers_active`, `special_use_total`.

### Changed

* `probe.tcp_concurrency`, `probe.tls_concurrency` and `probe.http_concurrency` are
  replaced by a single `probe.concurrency` (default 8, the tightest of the three old
  defaults). A probe worker holds its slot for the whole TCP → TLS → HTTP exchange, so the
  worker semaphore was already sized from the minimum of the three; two of the three knobs
  were always inert. Every configuration table is `deny_unknown_fields`, so a file still
  carrying an old key fails loudly at startup or reload rather than being silently
  ignored.
* `cache.max_entries` and `cache.variant_max_entries` replaced by byte budgets. An entry
  limit does not bound memory, because a DNS answer can be 200 bytes or 2 kilobytes.
* Hot-set eviction is batched via `select_nth_unstable_by` instead of a full sort per
  query, and the key being inserted is protected from its own eviction pass.
* When every route in a group is circuit-open, all routes are offered rather than none.
  A breaker exists to move traffic somewhere better; when there is nowhere better,
  refusing to send anything converts a degraded upstream into a total outage.
* CI no longer runs any action that cannot be pinned to a verified commit SHA.
  `ludeeus/action-shellcheck@master` — a branch reference, so whatever its maintainer last
  pushed — is gone; ShellCheck is invoked directly. `rustsec/audit-check` and
  `softprops/action-gh-release` are replaced by `cargo audit` and `gh`, so no third party
  ever runs with repository credentials.

### Removed

Fields that were parsed, validated and never read. A field like this is worse than a
missing feature: it tells an operator they have a control they do not have.

`cache.max_entries`, `cache.variant_max_entries`, `upstream.tls.tls_client_cert_file`,
`upstream.tls.tls_client_key_file`, `upstream.groups[].scheduler.max_attempts_per_route`,
`.variant_sample_qps`, `ecs.strip_inbound`, `ecs.ab_test_fraction`,
`probe.throughput_concurrency`, `probe.follow_redirects`, `metrics.unix_socket`,
`cloudflare.sampling.ipv4_enabled`, `cloudflare.sampling.ipv6_enabled`,
`prefetch.queue_size`, `probe.profiles[].port`.

`max_attempts_per_route` is the instructive one. It was validated to be 1–3 in the name of
RFC 9520 §3.2, but the scheduler makes at most one attempt per route per resolution
whatever it says. The compliance claim was true; the mechanism the documentation credited
was not the one providing it.

## [1.0.0] — 2026-08-18

First release.

### Added

**Ingress**

* UDP and TCP listeners on IPv4 and IPv6, with `IPV6_V6ONLY`, path-MTU discovery to avoid
  fragmentation (RFC 9715), optional `SO_REUSEPORT` with a worker per socket, and
  configurable socket buffers.
* Default-deny client ACL with explicit deny rules evaluated first; a non-loopback listener
  without an ACL is a configuration error.
* Per-client token-bucket rate limiting with a bounded two-generation table.
* TCP connection reuse, pipelining, out-of-order responses, idle timeout and a connection
  cap (RFC 7766), with `edns-tcp-keepalive` (RFC 7828).
* RFC 8482 minimal ANY responses by default.
* Special-use domain names (RFC 6761, 6762, 7686, 8375) answered locally rather than
  leaked upstream, with operator configuration taking precedence.

**Resolution**

* Six upstream transports — UDP, TCP, DoT, DoH2, DoH3 and DoQ — configurable per server
  within a group, all verified end-to-end against independent server implementations.
* Adaptive scheduler: per-route latency percentiles, a single bounded hedge timed from the
  primary's own p95, a four-state circuit breaker, and bounded emergency fan-out.
* 0x20 case randomisation with case-insensitive question matching (RFC 5452), DNS cookies
  on unauthenticated transports only (RFC 7873), and strict response validation.
* Truncated UDP answers retried over a stream transport.
* DNSSEC validation that fails closed, with the upstream AD bit untrusted by default and
  the CD bit honoured per query. Validation lookups traverse the same scheduler, cache and
  circuit breakers as ordinary traffic.
* EDNS Client Subnet, disabled by default, restricted to a public operator-configured
  prefix, participating in the cache key.

**Caching**

* Weighed, bounded cache with per-entry TTL enforcement independent of the eviction policy.
* Negative caching (RFC 2308) and resolution-failure caching within the RFC 9520 bounds.
* Serve-stale (RFC 8767) after a refresh attempt has actually failed, with a short client
  TTL and an extended error.
* Cancellation-safe request coalescing with leader-drop wake.
* Hot-name prefetching under a global QPS ceiling and a per-key minimum interval.
* Answer variants tracked per key and never merged.

**Adaptation**

* Decayed Beta posterior plus EWMA and a 16-sample latency window per address, with
  hysteresis and a neutral cost for addresses with no evidence.
* IPv4/IPv6 environment detection with debounced network generations; evidence is demoted
  to a weak prior on change rather than discarded.
* Cloudflare optimization with preserve mode by default; verified-augment requires
  official-prefix membership, proven-Insecure DNSSEC, no unvalidatable ECH, local TLS and
  HTTP validation, and a measured advantage.
* Candidate admission pipeline treating third-party lists as untrusted hints, with strict
  parsing, prefix membership checks, special-use rejection, bounded pool and hourly budget,
  and staged protocol validation.
* Reproducible stratified rotating IPv4 sampler.

**Operations**

* Unix-socket admin protocol and `egressdnsctl`, including a runtime Cloudflare mode
  override that can weaken but never strengthen the configured mode.
* Atomic configuration reload: the new state is built completely before it is swapped in,
  and a failed reload leaves the running configuration serving.
* Prometheus metrics with bounded label cardinality, plus `/healthz` and `/readyz`.
* SQLite persistence of learned state on a dedicated thread behind a bounded queue that
  drops rather than blocking, with quarantine on corruption.
* systemd unit, sysusers and tmpfiles fragments, and an nftables example.
* `install.sh`, `upgrade.sh` and `uninstall.sh` with architecture detection, SHA-256
  verification, automatic snapshot and rollback, and a refusal to displace an existing
  resolver on port 53.
* `scripts/load-test.sh` and `scripts/chaos-test.sh` for pre-promotion validation.

### Security

* `#![forbid(unsafe_code)]`; no `unwrap`, `expect`, `todo!` or `unimplemented!` on
  production request paths.
* Probe safety guard denying special-use, link-local, loopback and cloud-metadata targets
  unconditionally, checked independently in the configuration validator and at call time.
* QUIC 0-RTT refused by configuration validation; TLS early data never sent.
* No TLS verification bypass in any configuration; optional SPKI pinning layered on top of
  verification using a bounded DER walker.
* No query names or client identifiers in metrics labels, logs by default, or the
  persisted database.
* Seven fuzz targets covering the DNS message, seed, prefix, configuration, dataset, admin
  and DER parsers.

### Notes

* Client-facing ingress is cleartext Do53 only; see `docs/adr/0007-do53-only-ingress.md`.
* No answer synthesis of any kind: no DNS64, no synthetic CNAMEs, no AAAA suppression, no
  SVCB hint rewriting.
* No third-party proxy, relay or intermediary addresses can appear in an answer under any
  configuration.
