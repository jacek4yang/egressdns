# Architecture

EgressDNS is a caching **forwarding** resolver, not an iterative one. It is built around a
single organising idea: a strict separation between a foreground data plane that must be
fast and predictable, and a background control plane that gathers evidence which *may*
improve later answers.

If every part of the control plane fails, the process keeps working as a correct caching
DNS forwarder. That is not a fallback bolted on afterwards; it is the shape of the design.

---

## 1. The two planes

```
                    ┌──────────────────────── clients (LAN) ────────────────────────┐
                    │                UDP :53              TCP :53                   │
                    └───────────────────────────┬───────────────────────────────────┘
                                                │
  FOREGROUND ──────────────────────────────────▼──────────────────────────────────────
   dns::server        parse → ACL → rate limit → size limits
   dns::resolver      local zones/hosts → special use → cache → failure cache → singleflight
   upstream::scheduler   route selection → one bounded hedge → first acceptable answer
   policy::dnssec     validation state from record proofs
   policy::answer     A/AAAA ordering → Cloudflare preserve/augment → client TTL cap
   dns::message       truncation-aware serialisation
                                                │
                                                ▼
                                          response to client

     never on this path: disk I/O · database access · TLS/HTTP/QUIC probing ·
                         Cloudflare scanning · dataset parsing · unbounded allocation ·
                         global exclusive locks · high-cardinality metrics

  BACKGROUND ─────────────────────────────────────────────────────────────────────────
   tasks::network            routing/address polling → network generations
   tasks::cloudflare         official prefixes · untrusted seeds · bounded sampler ·
                             candidate prober
   probe::engine             TCP → TLS(SNI) → HTTP stages, subsystem-health detection
   tasks::prefetch           hot-name refresh under a QPS budget
   tasks::maintenance        cache housekeeping · batched SQLite flush · gauges
   admin::server             Unix-socket control
   runtime::observe          Prometheus, liveness, readiness
```

Communication between the planes is deliberately one-directional and lossy:

- Foreground → background: a **bounded, non-blocking** `ProbeQueue`. A full queue drops the
  observation and increments a counter. An observation is optional; a fast answer is not.
- Background → foreground: **immutable snapshots** published through `ArcSwap`
  (prefix set, datasets, network state) and **short-lock reads** of bounded maps (quality
  evidence, candidate pool). A foreground read is an atomic pointer load or a few hundred
  nanoseconds of `parking_lot::Mutex`.

---

## 2. Request lifecycle

```
  ┌─ 1 receive ────────────────────────────────────────────────────────────────┐
  │  UDP datagram or TCP length-prefixed message. Malformed input is dropped    │
  │  (never answered) so the daemon cannot be used as a reflector.              │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ 2 admit ──────────────────────────────────────────────────────────────────┐
  │  Default-deny ACL, then per-client and global rate limits. Refused clients  │
  │  get REFUSED; rate-limited clients get silence, because answering them      │
  │  would defeat the limit.                                                    │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ 3 validate ───────────────────────────────────────────────────────────────┐
  │  Opcode, question count, class, EDNS version. QTYPE=ANY takes the RFC 8482  │
  │  minimal path by default.                                                   │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ 4 local data ─────────────────────────────────────────────────────────────┐
  │  Hosts entries and internal zones answer authoritatively without any        │
  │  upstream contact.                                                          │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ 4b special use ───────────────────────────────────────────────────────────┐
  │  localhost, .local, .invalid, .onion, home.arpa and the private reverse     │
  │  zones are answered here (RFC 6761 and friends) rather than leaked to a     │
  │  public upstream. Step 4 and any suffix rule take precedence, so an         │
  │  operator who really serves one of these keeps serving it.                  │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ 5 cache ──────────────────────────────────────────────────────────────────┐
  │  Failure cache (RFC 9520) → answer cache → stale retention (RFC 8767).      │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ 6 coalesce ───────────────────────────────────────────────────────────────┐
  │  Concurrent identical misses join one flight. Cancellation-safe: a          │
  │  disappearing leader wakes its followers rather than stranding them.        │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ 7 upstream ───────────────────────────────────────────────────────────────┐
  │  Rank healthy routes → send to the best → optionally one hedge after a      │
  │  delay derived from that route's own p95 → first complete acceptable answer │
  │  wins → cancel the rest. Truncated UDP is retried over a stream transport.  │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ 8 validate the answer ────────────────────────────────────────────────────┐
  │  RFC 5452 question/ID/opcode checks, cookie echo check, DNSSEC state from   │
  │  per-record proofs. Bogus is never cached and never served.                 │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ 9 policy ─────────────────────────────────────────────────────────────────┐
  │  Standards-safe A/AAAA ordering → Cloudflare preserve or verified-augment   │
  │  → client TTL cap. Purely functional; see policy::answer.                   │
  └────────────────────────────────────────────────────────────────────────────┘
  ┌─ 10 serialise ─────────────────────────────────────────────────────────────┐
  │  Size-limited encoding. If the answer does not fit, TC is set and the       │
  │  answer section is emptied so the client retries over TCP.                  │
  └────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module map

| Module | Responsibility |
| ------ | -------------- |
| `config` | Strict TOML schema, defaults, and validation that encodes normative requirements |
| `dns::server` | UDP and TCP ingress, socket options, connection limits, pipelining |
| `dns::acl`, `dns::ratelimit` | Default-deny access control and bounded rate limiting |
| `dns::message` | TTL arithmetic, EDNS options (EDE, cookies, keepalive, ECS), truncation-aware serialisation, answer fingerprints |
| `dns::specialuse` | The IANA Special-Use Domain Names registry table and classifier |
| `dns::resolver` | The foreground pipeline |
| `dns::handle` | Adapts the scheduler to hickory's `DnsHandle` so DNSSEC lookups use the same routing |
| `cache` | Answer, negative, failure, variant and stale caches; singleflight; hot set |
| `upstream::pool` | One route per (server, transport, address), connection reuse, cookie state |
| `upstream::health` | Decayed per-route statistics and the circuit breaker |
| `upstream::scheduler` | Ranking, hedging, emergency fan-out, truncation retry, response validation |
| `policy::dnssec` | Validation state, RRSIG lifetime, AD eligibility |
| `policy::ttl` | Client-facing TTL caps |
| `policy::cloudflare` | Eligibility rules and fallback reasons |
| `policy::answer` | The correctness contract, applied |
| `ranking` | Quality model (decayed Beta posterior + EWMA + tail) and ordering with hysteresis |
| `cloudflare::prefixes` | The only authority on what "Cloudflare-owned" means |
| `cloudflare::seeds` | Bounded parser for untrusted candidate lists |
| `cloudflare::candidates` | Admission pipeline and bounded pool |
| `cloudflare::sampler` | Reproducible stratified sampling |
| `cloudflare::state` | Shared snapshots, validations and source health |
| `probe::safety` | Deny-by-default target policy, cooldowns, rate and bandwidth budgets |
| `probe::http`, `probe::quic`, `probe::fetch` | Direct-to-IP HTTP/1.1, HTTP/2, QUIC, HTTP/3 and bounded dataset fetching |
| `probe::engine` | Stage orchestration and subsystem-health detection |
| `network` | IPv4/IPv6 environment state and monotonic generations |
| `datasets` | Hosts, internal zones, suffix routing, categories, advisory GeoIP/ASN |
| `storage` | WAL SQLite for derived state, with quarantine on corruption |
| `tasks` | Supervised background components |
| `admin` | Unix-socket control protocol |
| `runtime` | Process assembly, atomic reload, observability endpoints |

---

## 4. Design decisions worth explaining

### Why a forwarder and not a recursive resolver

An enterprise LAN behind one egress gains almost nothing from iterating from the root, and
loses a great deal: latency on cold names, exposure to every authoritative server's
availability, and a much larger correctness surface. Forwarding to two well-run recursive
resolvers over authenticated transports is both faster and easier to reason about. The
experimental recursor available in the ecosystem is explicitly not depended upon.

### Why answer variants are never merged

Two upstream resolvers may legitimately return different address sets for a CDN name,
because each was answered by a different authoritative view. Each set is *complete and
correct*; a union of the two is neither. The variant cache remembers complete answers by
canonical fingerprint and may switch between them under hysteresis, but never combines
them. This is the difference between "choose a better answer" and "invent an answer".

### Why "no evidence" is not "bad"

The single most damaging failure mode in an adaptive resolver is treating a missing
measurement as a negative one. A newly seen address, an address on a path where probing is
blocked, an address measured while the local CA store was broken — all of these must
score *neutrally*. The quality model encodes this: unknown addresses get
`ranking.neutral_cost_ms`, and only `ApplicableFailure` and `Timeout` observations move the
posterior. Ambiguous failures, unsupported capabilities and policy blocks never do.

### Why the client TTL is capped

LAN DNS latency is a few hundred microseconds. Re-querying is nearly free for the client
and lets the server apply fresher evidence. The cache retains the full authoritative TTL
internally; only the value handed to the client is reduced. Every code path takes a
*minimum*, so no configuration value can extend the life of upstream data — a property
asserted by both unit and property tests.

### Why hedging is bounded to one request

Hedging trades duplicate upstream queries for tail latency. Unbounded hedging turns a slow
upstream into a traffic amplifier and doubles the number of parties who see each query.
One hedge, timed from the primary route's own p95, capped at a configured fraction of
queries, and reported through `egressdns_upstream_hedges_total`, keeps the trade explicit.

### Why the probe engine can be switched off entirely

Everything the optimizer produces is advisory. `probe.enabled = false` leaves a correct,
fast forwarder with neutral ordering. This is the first thing to try when diagnosing
anything, and the operations guide says so.

---

## 5. Failure isolation

Every background component is supervised by `tasks::supervise`, which catches panics,
counts them in `egressdns_task_restarts_total`, and restarts the task with exponential
backoff and jitter. Concretely:

| Failure | Effect on DNS |
| ------- | ------------- |
| Probe engine panics | Restarted; ordering falls back to neutral. No effect on answers |
| Probe queue saturates | Observations are dropped and counted. No effect on answers |
| Cloudflare API unreachable | Last valid prefix snapshot is retained; the on-disk cache survives restarts |
| Seed endpoint returns HTML, garbage or an oversized body | Rejected by the parser, logged with a reason, previous candidates retained |
| Every candidate source fails | Preserve mode still works from addresses seen in real answers; augment simply never triggers |
| SQLite corrupt | Detected by `PRAGMA quick_check`, file quarantined, daemon starts with neutral state |
| SQLite queue full | Batches dropped and counted; DNS never waits for a write |
| Dataset file unreadable or oversized | Previous valid snapshot retained |
| Configuration reload invalid | Running configuration untouched; the error is reported through the admin socket and metrics |
| Network path changes | New generation published; historical evidence demoted to a weak prior; TTL caps shortened while relearning |
| All upstreams down | Stale data served where RFC 8767 allows, otherwise SERVFAIL with an Extended DNS Error |

---

## 6. Concurrency and memory

- One Tokio multi-threaded runtime, worker count defaulting to the core count.
- Blocking work (SQLite, dataset parsing, network polling, secret reading, prefix-cache
  I/O) runs on `spawn_blocking` or on a dedicated thread. No blocking call ever runs on a
  worker thread.
- Cached answers are `Arc<Message>`, shared not copied.
- Configuration and datasets are immutable snapshots; readers never block writers.

### Where every ceiling is enforced

A ceiling that lives only in the configuration struct is not a ceiling. Each of these is
enforced at a specific point in the code, on the single path the work must pass through,
and each has a regression test that demonstrates the limit binding rather than merely
being stored.

| Bound | Setting | Enforced at | Behaviour when reached |
| --- | --- | --- | --- |
| Client queries in flight | `resources.max_inflight_queries` | `App::inflight` semaphore, acquired in `dns::server` before a query is spawned | Query dropped, `rejected_total{reason="inflight_limit"}` |
| Upstream exchanges in flight | `resources.max_inflight_upstream` | `Scheduler::resolve` — the one function every upstream query passes through, including stale refresh, prefetch and DNSSEC auxiliary lookups | Waits up to the caller's budget, then SERVFAIL and `upstream_shed_total` |
| DNSSEC validations in flight | `dnssec.max_concurrent_validations` | `Resolver::fetch`, acquired before the validating handle is used | Waits up to the budget, then SERVFAIL and `dnssec_shed_total` |
| Probe workers | `probe.concurrency` | `ProbeEngine::run`, acquired **before** the job is taken from the channel | Job stays queued; no task is created for it |
| Probe queue depth | `probe.queue_size` | Bounded `mpsc`, `offer()` never awaits | Job dropped and counted |
| Probe bandwidth | `probe.daily_bandwidth_budget_bytes` | `ProbeGuard::admit`, as an admission gate rather than an after-the-fact tally | Probe refused with `Refusal::BandwidthBudget` |
| Probe cooldown state | fixed 50,000 entries | `ProbeGuard::prune`, swept every 30 s | Oldest entries dropped |
| Answer/negative cache | `cache.max_memory_bytes` | moka weighted eviction, weight from `estimate_bytes` | Least-valuable entries evicted |
| Variant cache | `cache.variant_max_memory_bytes` | moka weighted eviction over whole variant sets | Least-valuable sets evicted |
| Hot set | `prefetch.hot_set_size` | `HotSet::evict_locked`, batched `select_nth_unstable_by` rather than a full sort | Lowest-scoring names dropped, never the key just inserted |
| Candidate pool | `cloudflare.candidate_pool_max` | `CandidatePool::admit`, evicting only strictly lower-priority entries | `Rejected(PoolFull)` |
| Stale-refresh attempts | `serve_stale.retry_interval` | `Resolver::stale_refresh_allowed`, per cache key, table capped at 8,192 | Refresh skipped this round |
| TCP connections | `server.tcp.max_connections`, `max_connections_per_client` | Accept loop | Connection closed, `tcp_rejected_total` |
| Persistence queue | `storage.queue_size` | Bounded `mpsc`, non-blocking send | Row dropped; statistics are explicitly droppable |

`tests/bounds.rs` demonstrates the first four plus the cache and the probe guard by
observation — setting a limit low enough that exceeding it would be unmistakable, then
showing that it is not exceeded.

---

## 7. Reload semantics

### The boundary

There are exactly two categories, and the boundary between them is enforced in code, not
by documentation.

**Reloadable** is everything that can be rebuilt into a fresh `RuntimeState`, plus the
feature switches the control plane reads each iteration. `SIGHUP` or `egressdnsctl reload`:

1. Parse and validate the candidate file completely.
2. Compare it against the running configuration with `config::reload::restart_required`.
   If anything restart-required changed, **refuse by name** and stop here — nothing has
   been touched.
3. Build an entire replacement `RuntimeState` — ACL, rate limiter, upstream routes,
   scheduler, resolver, TLS roots.
4. Only if every step succeeded, swap the `ArcSwap` pointer and update the probe and
   prefetch switches.
5. Drain the previous upstream connection pools after a delay.
6. Reload datasets on a blocking thread, keeping the previous snapshot on failure.

**Restart-required** is everything built once at startup: listening sockets, the Tokio
runtime, semaphores, and fixed-capacity structures. `docs/CONFIGURATION.md` lists them,
and `egressdnsctl reload-contract` prints the same list from the same source.

There is deliberately no third category. A configuration change is applied, or it is
refused with the field named — never accepted and ignored.

### Why background tasks do not hold configuration

This is the part that is easy to get wrong, and getting it wrong makes a reload a lie.

A background task that copies `Config` at spawn time keeps serving the startup
configuration for the life of the process. The `ArcSwap` swap succeeds, `reload_count`
increments, the operator sees success — and the prefetcher is still querying the old
upstream, over a connection registry that has already been drained.

So no supervised task receives configuration. Each gets a `tasks::Ctx`, which holds a
`Weak<App>` and nothing else:

```rust
pub struct Ctx { app: Weak<App>, pub cancel: CancellationToken }
```

Every task re-reads `ctx.config()`, `ctx.state()` and `ctx.resolver()` at the top of each
iteration. Three properties follow:

* **A reload reaches the control plane on the next tick.** No restart, no task recycling.
* **A disabled feature idles rather than exiting**, so enabling it by reload starts it
  working again — a task that returned early at startup would have made its own `enabled`
  switch restart-required without saying so.
* **The reference is weak**, so a detached task cannot keep process state alive after
  shutdown. `ctx.app()` returning `None` *is* the shutdown signal.

Tasks live in a `tasks::Supervisor` (`JoinSet`), so `App::shutdown_and_join` can cancel
them and actually wait, reporting how many had to be aborted. `tests/reload.rs` asserts on
observable behaviour — which upstream answered, whether probing stopped, whether queries
kept being served through twenty reloads under load — rather than on the contents of the
in-memory configuration, which proves nothing.

Caches, quality evidence, network generation and the candidate pool survive a reload,
because they describe the world rather than the configuration.

---

## 8. Two-node deployment

```
                    ┌─────────────┐        ┌─────────────┐
        DHCP ──────▶│  DNS-A      │        │  DNS-B      │◀────── DHCP
     10.0.0.53      │  EgressDNS  │        │  EgressDNS  │      10.0.0.54
                    └──────┬──────┘        └──────┬──────┘
                           │                      │
                           └──────── shared egress ┘
                                       │
                             upstream resolvers (DoT/DoH)
```

The nodes are independent: same validated configuration, separate live caches, separate
quality databases, no synchronous shared state. Either can be rebooted without affecting
the other. Because each keeps its own evidence, they can briefly return different
(individually complete and correct) variants for a CDN name — which is exactly what two
independent recursive resolvers would do.
