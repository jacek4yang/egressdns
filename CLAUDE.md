# Working on EgressDNS

Notes for anyone — human or agent — making changes to this repository. Read this before
the first edit; it will save you from re-deriving constraints that are load-bearing.

## The one rule

**A client query must never wait on anything that is not required to answer it.**

Probing, dataset refreshes, sampling, persistence, prediction and metric aggregation are
background work. If a change makes the request path `await` any of them, take a lock any of
them can hold, or share a budget with any of them, the change is wrong regardless of how
good the feature is. See [ADR-0004](docs/adr/0004-foreground-background-split.md).

Concretely, on the request path:

* Read shared state through `ArcSwap` snapshots — one load per request, then work from the
  snapshot.
* Offer work to background queues with non-blocking `offer()`, which returns `false` when
  full. Never `send().await`.
* Do not allocate unboundedly, do not take a `Mutex` a background task also takes, do not
  touch the filesystem.

## Priority order

When two desirable properties conflict, this is the tie-break, and it is not negotiable:

1. DNS and DNSSEC correctness
2. Availability and graceful degradation
3. Security and bounded resource use
4. Tail latency and cache-hit performance
5. Optimization quality
6. Average throughput
7. Feature breadth

A change that improves 5 at the cost of 1 is a regression. Say so in review.

## The reload contract

Every configuration field is exactly one of two things, and there is no third option:

* **Reloadable** — it takes effect on the next `systemctl reload`, including in background
  tasks. A background task must therefore never copy `Config` at spawn time; it takes a
  `tasks::Ctx` and re-reads `ctx.config()`, `ctx.state()` and `ctx.resolver()` at the top
  of every iteration. A disabled feature **idles rather than returning**, so that enabling
  it by reload starts it working without a restart.
* **Restart-required** — it is listed in `src/config/reload.rs`, and changing it makes the
  reload fail with the field named. Nothing is applied.

If you add a configuration field, you must do one of three things before the change is
complete, and "leave it for later" is not one of them:

1. **Implement it** — a production consumer outside `src/config/`, plus a regression test
   that demonstrates the observable behaviour changing.
2. **Classify it restart-required** — add it to `restart_required` *and* to `MUTATIONS` in
   the same file, so `catalog()` covers it and the documentation cannot drift.
3. **Remove it.** A field that is parsed, validated and never read is worse than a missing
   feature: it tells an operator they have a control they do not have.

`scripts/check-config-docs.py` fails CI when a field is undocumented or a documented key is
not a real field. `egressdnsctl reload-contract` prints the classification.

## Invariants that must not be broken

These are asserted by tests. If a test that covers one of these starts failing, the change
is wrong — do not adjust the test to match.

* Never merge RRsets from two different upstream responses into one answer.
* Preserve mode is a **permutation** of a single complete A or AAAA RRset. Nothing added,
  nothing removed, nothing moved between RRsets, no other record type touched.
* The original upstream order is the final tie-breaker in ranking. Equal scores must not
  reorder.
* An address with no evidence scores **neutral**, never bad. Lack of probe evidence is not
  evidence of failure.
* A TCP 443 failure says nothing about whether an address is usable for DNS.
* DNSSEC Bogus is SERVFAIL. There is no path that turns it into an answer.
* The upstream AD bit is not trusted unless explicitly configured per-server.
* A truncated UDP answer is retried over a stream transport, never parsed opportunistically.
* AAAA is never suppressed, filtered, or synthesised.
* The client TTL never exceeds the remaining authoritative TTL. TTL policy only ever
  *reduces*.
* No synthetic CNAMEs. No answer synthesis at all outside the bounded augment path.
* An address with no quality samples may be *reordered* on neutral evidence, but may never
  be *added* to an answer on it. Adding requires `cloudflare.augment.min_samples` real
  observations.

## Absolute exclusions

* No third-party reverse-proxy, proxy-IP-service, relay, tunnel or intermediary addresses may
  appear in a DNS answer, under any configuration. There is a repository-wide test that
  scans for the concept.
* Cloudflare optimization may only use: addresses inside officially published Cloudflare
  prefixes; Cloudflare-owned addresses seen in normal DNS answers; and candidates from a
  third-party list **after** verifying official-prefix membership and passing local
  protocol validation.
* Do not add `unwrap`, `expect`, `todo!` or `unimplemented!` to a production path. Tests
  and benches may use them.
* The crate is `#![forbid(unsafe_code)]`. Do not add `unsafe`.
* Do not hand-write DNS wire format, TLS, HTTP/2, HTTP/3 or QUIC. Use the vendored crates.
* Do not copy GPL source from other resolver or speed-test projects.

## Layout

```
src/
  dns/        ingress, resolver pipeline, message helpers, ACL, rate limit, special-use
  cache/      main cache, singleflight, hot set
  upstream/   routes, pool, health, scheduler (hedging, circuit breaking)
  policy/     the correctness contract: dnssec, ttl, cloudflare eligibility, answer shaping
  ranking/    quality model and address ordering
  probe/      probe engine, safety guard, HTTP/QUIC probes, bounded fetch
  cloudflare/ prefixes, seeds, candidate admission, sampler, shared state
  network/    IPv4/IPv6 detection and generations
  tasks/      supervised background tasks
  storage/    SQLite persistence
  runtime/    App assembly, atomic reload, observability endpoints
  admin/      control socket protocol, server and client
```

`src/policy/` is where the invariants above live. Changes there need more care and more
tests than changes anywhere else.

## Before you commit

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
./scripts/check-config-docs.py
./scripts/pin-github-actions.sh --check
```

All must be clean. For anything touching the request path, also run `cargo bench` and
compare against `docs/BENCHMARKS.md` — and, more importantly, run `./scripts/load-test.sh`.
Microbenchmarks cannot find the defects that matter here. The load harness has found an
O(n log n) per-query eviction, a circuit breaker that black-holed traffic, and a UDP-only
upstream that turned every large answer into SERVFAIL; none of those moved a Criterion
number at all.

For anything touching a parser, add a case to the relevant fuzz target in `fuzz/`.

## Testing conventions

* Integration tests use `tests/common/mod.rs`, which starts real upstream servers built on
  `hickory-server` — not hand-written mocks. If a transport test passes, the transport
  actually works against an independent implementation.
* Time-dependent tests use `#[tokio::test(start_paused = true)]` and an injected `Clock`.
  Do not `sleep` in tests.
* Reload tests assert on **behaviour**, never on the contents of `app.config()`. Checking
  that a struct was replaced proves only that a struct was replaced; it says nothing about
  whether anything reads it. See `tests/reload.rs`.
* Resource-bound tests set the limit low enough that exceeding it would be unmistakable,
  then demonstrate that it binds. See `tests/bounds.rs`.
* Property tests in `tests/properties.rs` cover the "permutation, not mutation" invariants.
  Add to them rather than adding another example-based test when the property is general.
* Names in tests use `.test` or `example.com`. Note that `.test` is deliberately *not*
  blocked by the special-use registry — see `src/dns/specialuse.rs`.

## Things that look like bugs but are not

* `cloudflare_candidate_rejected_total` being very large. Third-party lists are mostly not
  Cloudflare addresses; rejecting them is the point.
* `cloudflare_augment_total` being near zero. Augmentation requires six conditions to hold
  simultaneously. Rarely firing is correct.
* Storage writes being dropped under load. Persisted statistics are an optimisation and are
  explicitly droppable rather than blocking.
* Two DNS-A/DNS-B nodes returning different address *orders* for the same name. They have
  different measurements. Different address *sets* is also normal if their upstreams
  differ. Different rcodes is not.

## Where to look first

* Something is wrong with an answer → `src/policy/`
* Something is slow → `src/dns/resolver.rs`, then `src/upstream/scheduler.rs`
* Something is unbounded → `src/probe/safety.rs`, `src/cache/`, `src/admin/mod.rs`
* Something about Cloudflare is surprising → `src/cloudflare/candidates.rs` and
  [ADR-0005](docs/adr/0005-untrusted-seed-trust-model.md)
