# Benchmarks

Two kinds of measurement live here, and they are kept strictly apart because they answer
different questions and mixing them produces claims that are not true:

* **Microbenchmarks** (Criterion) measure the daemon's own in-process work. They are
  precise and reproducible, and they cannot tell you what a deployment will do.
* **Load tests** (`scripts/load-test.sh`) drive real UDP sockets against a real upstream
  under real impairment. They are the only numbers here that describe behaviour.

A throughput claim derived from a microbenchmark is a fabrication — `path_cache_hit_full`
at 2.26 µs does not mean 442,000 qps, because it excludes the kernel, the sockets, the
scheduler and every other query competing for the same cores. Nothing in this document
makes that leap.

Everything below was produced on the machine described, by the commands shown, from the
tree at commit `c70f468`. Nothing is estimated, extrapolated, or carried over from another
machine or another version. The unedited Criterion output is in
[`benchmarks/raw-2026-08-19.txt`](benchmarks/raw-2026-08-19.txt); the only edit is
substituting the build directory with `<source-tree>` so no absolute local path is
published. Raw load-test JSON is written to `target/loadtest/` and is not committed,
because it is a property of the machine that produced it.

## Environment

| | |
| --- | --- |
| CPU | Intel Xeon @ 2.80 GHz, **2 vCPU**, 1 thread per core |
| Memory | 7.8 GiB |
| Kernel | Linux 6.18.5 x86_64 |
| Distribution | Ubuntu 24.04.4 LTS, glibc 2.39 |
| Rust | rustc 1.95.0 (59807616e 2026-04-14) |
| Profile | `[profile.release]` — `lto = "thin"`, `codegen-units = 1`, `panic = "unwind"`, `strip = "debuginfo"` |
| Criterion | 0.8, default sampling (50 samples per benchmark) |
| Date | 2026-08-19 |

This is a shared two-core virtual machine. Three consequences, stated rather than hidden:

1. **Outliers are frequent.** On dedicated hardware the outlier rate is normally low single
   digits.
2. **Anything that would benefit from parallelism is understated.**
3. **The load generator competes with the daemon for the same two cores.** See the
   saturation note below — it is the single most important caveat in this document.

---

# Part 1 — Load tests

These are the numbers that describe behaviour. Reproduce with:

```sh
./scripts/load-test.sh --duration 45 --sustained 480 --clients 8 --inflight 8
```

The harness starts `scripts/mock_upstream.py` (a scriptable DNS upstream with delay,
jitter, loss, SERVFAIL, NXDOMAIN and truncation knobs), starts a release build against it,
and drives it with `scripts/loadtest.py`.

## Two rules that make these numbers honest

**A reply is not a success.** Counting any DNS response as a completed query lets a
failing upstream be reported as throughput. In the `servfail` scenario the two numbers
differ by 16%:

```
qps=5665.5   useful=4754.4   success=0.839
rcodes={'noerror': 118909, 'servfail': 22786}
```

`useful qps` counts NOERROR responses **that contain an answer record** — the thing a
client actually wanted — and the full rcode distribution is printed alongside, so the gap
between "answered" and "answered usefully" is never invisible.

**The generator saturated before the daemon did.** The generator is closed-loop: each
client keeps `--inflight` queries outstanding, so throughput is bounded by
`clients × inflight ÷ latency` by construction. Every run records `harness_ceiling_qps`,
and in **every scenario below `qps` is within 0.5% of it**. That means these figures are
**floors on the daemon's capacity, not measurements of it** — the Python generator and the
daemon are sharing two cores, and the daemon used 36–73% of one of them. On real hardware,
drive the load from a separate machine.

## Results

45 s per scenario (480 s for `sustained`), 8 clients × 8 in flight.

| Scenario | qps | useful qps | success | p50 | p99 | p99.9 | RSS | CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `cache-hit` | 30,031 | 30,031 | 100% | 0.49 ms | 13.9 ms | 21.8 ms | 14 MB | 57% |
| `mixed` | 35,058 | 35,058 | 100% | 0.71 ms | 14.4 ms | 22.6 ms | 24 MB | 69% |
| `miss-heavy` | 7,208 | 7,208 | 100% | 5.05 ms | 28.8 ms | 33.1 ms | 225 MB | 71% |
| `elevated-rtt` | 1,886 | 1,886 | 100% | 38.0 ms | 56.8 ms | 75.9 ms | 119 MB | 36% |
| `packet-loss` | 7,231 | 7,231 | 100% | 2.93 ms | 37.1 ms | 351 ms | 225 MB | 69% |
| `timeouts` | 2,059 | 2,057 | 99.9% | 0.63 ms | 337 ms | 671 ms | 124 MB | 42% |
| `servfail` | 7,004 | 6,154 | 87.9% | 9.22 ms | 26.0 ms | 34.2 ms | 214 MB | 70% |
| `truncation` | 6,323 | 6,323 | 100% | 12.1 ms | 27.8 ms | 33.8 ms | 215 MB | 70% |
| `ipv6-mixed` | 34,417 | 34,417 | 100% | 0.75 ms | 14.6 ms | 27.0 ms | 33 MB | 71% |
| `dnssec-closed` | 24,285 | **0** | **0%** | 0.61 ms | 28.0 ms | 64.7 ms | 20 MB | 71% |
| `sustained` (7 min) | 22,278 | 22,278 | 100% | 1.89 ms | 20.9 ms | 38.1 ms | 96 MB | 73% |

File descriptors peaked at 75 and threads at 4 in every scenario. Total queries completed
across the suite: **17.4 million**.

### What each impaired scenario demonstrates

**`packet-loss` (2% of upstream queries never answered) — 100% success.** Two upstream
queries in a hundred vanishing is completely invisible to clients. The cost shows up in
the tail: p99.9 of 351 ms against a p50 of 2.9 ms is the retry.

**`timeouts` (10% loss) — 99.9% success.** 84 SERVFAILs out of 92,787. Retries absorb a
one-in-ten loss rate almost entirely, at the price of a 671 ms p99.9.

**`servfail` (20% of upstream answers are SERVFAIL) — 87.9% success.** This is a
regression test as much as a measurement. An upstream failing 20% of queries sets a natural
ceiling near 80%; 87.9% means retries recovered some of them. The failure this guards
against is the opposite: a result *far below* 80% would mean the circuit breaker had opened
every route in the group and was refusing to send anything, turning a partially working
upstream into a total outage. When no route is usable, all routes are now offered anyway,
worst-scored last — availability outranks the breaker's own policy. Watch
`upstream_last_resort_total` to see it happen.

**`truncation` (15% of UDP answers set TC) — 100% success.** This scenario found a defect
during the hardening pass. Run against the unfixed tree it reported 90.9% success with
26,738 SERVFAILs, because the stream retry only considered routes whose *configured*
transport was a stream — and the harness upstream, like many real ones, is declared
`transport = "udp"`. Every UDP server now gets a companion TCP route (RFC 1035 §4.2.1,
RFC 7766 §5). Zero SERVFAILs across 284,588 queries.

**`dnssec-closed` — 0% useful, and that is the correct result.** Validation is enabled
against an upstream that supplies no chain of trust, so every answer is unvalidatable.
DNSSEC must fail closed: 1,093,126 queries, 1,093,126 SERVFAILs, no exceptions. **A single
NOERROR in this scenario would be a serious security defect.** The 24,285 qps figure is the
cost of the fail-closed path — failing is not slower than succeeding here, which matters,
because a slow failure path is a denial-of-service amplifier.

## Memory: no leak, and a usable sizing rule

An 8-minute soak — **9,256,227 queries at 19,283 qps** — sampling RSS once per second:

```
11.5 → 65.9 → 85.9 → 88.4 → 93.3 → 94.8 → 95.5 → 95.8 → 95.8 → 95.8 → …
                                                        ↑ flat from here to the end
```

`rss_mb_growth_last_third = 0.0 MB`. Threads flat at 4. RSS climbs while the cache fills,
then is **completely flat for the final five minutes across roughly six million queries**.
A cache filling to its budget plateaus; a leak does not. `scripts/loadtest.py` reports
`rss_mb_series` and `rss_mb_growth_last_third` on every run so this is checkable rather
than asserted.

Across scenarios with different working sets and cache budgets, steady-state resident
memory fits:

```
RSS ≈ 15 MB + 1.6 × cache.max_memory_bytes
```

The 1.6 factor covers per-entry keys and metadata, the negative and variant caches, and
allocator fragmentation. The 15 MB floor is the runtime, connection pools and the metric
registry. **Plan capacity from this relationship, not from the budget alone**: a 1 GiB
cache budget is a ~1.7 GB process.

## What the load tests are not

* Not a measurement of peak throughput — see the saturation note above.
* Not a LAN measurement. Loopback has no NIC, no driver and no switch.
* Not representative of real traffic mixes. `--names` is uniform; real DNS traffic is
  heavily Zipf-distributed, so a real deployment sees a *better* hit ratio than
  `miss-heavy` and often better than `mixed`.
* Not a multi-core scaling result. Two vCPUs cannot say anything credible about scaling.

---

# Part 2 — Microbenchmarks

In-process work only. Useful for spotting a regression in a specific function; useless for
predicting deployment throughput.

```sh
cargo bench                                    # everything
cargo bench --bench hot_path                   # request-path
cargo bench --bench cloudflare_and_ranking     # classification and ranking
```

No environment variables, CPU pinning, governor changes or `nice` levels were used. The
machine was otherwise idle.

### Request path

| Benchmark | Mean | 95% CI | What it measures |
| --- | --- | --- | --- |
| `path/cache_hit_full` | **2.26 µs** | 2.21 – 2.32 µs | The full in-process pipeline for a cache hit: ACL, rate limit, cache key, lookup, TTL rewrite, response build, serialise. |
| `cache/hit` | 215.6 ns | 213.1 – 218.5 ns | Cache lookup returning a fresh entry. |
| `cache/miss` | 173.6 ns | 172.1 – 175.2 ns | Cache lookup that misses. |
| `cache/key_construction` | 135.9 ns | 134.4 – 138.2 ns | `CacheKey` from question, policy view and DNSSEC mode. |
| `cache/size_estimate` | 1.93 µs | 1.89 – 1.97 µs | Weighing a cached message for the byte budget. |
| `acl/allow` | 13.0 ns | 12.97 – 13.12 ns | Client ACL check, permitted. |
| `acl/deny` | 19.5 ns | 19.44 – 19.62 ns | Client ACL check, refused. |
| `ratelimit/check` | 67.2 ns | 66.6 – 67.9 ns | Per-client token bucket. |
| `singleflight/uncontended` | 528.2 ns | 519.3 – 538.7 ns | Uncontended acquire and release. |

### Message handling

| Benchmark | Mean | 95% CI |
| --- | --- | --- |
| `message/parse/1_records` | 482.2 ns | 474.3 – 490.3 ns |
| `message/parse/4_records` | 1.06 µs | 1.04 – 1.09 µs |
| `message/parse/16_records` | 3.03 µs | 2.99 – 3.06 µs |
| `message/serialize/1_records` | 752.3 ns | 738.3 – 771.7 ns |
| `message/serialize/4_records` | 1.32 µs | 1.28 – 1.38 µs |
| `message/serialize/16_records` | 3.28 µs | 3.25 – 3.32 µs |
| `message/ttl_rewrite` | 319.6 ns | 287.7 – 348.2 ns |
| `message/fingerprint` | 3.79 µs | 3.76 – 3.81 µs |

### Ranking

| Benchmark | Mean | 95% CI |
| --- | --- | --- |
| `ranking/order/2_addresses` | 319.2 ns | 315.9 – 322.7 ns |
| `ranking/order/4_addresses` | 581.0 ns | 574.9 – 588.5 ns |
| `ranking/order/8_addresses` | 957.2 ns | 944.2 – 972.5 ns |
| `ranking/order/16_addresses` | 1.77 µs | 1.74 – 1.82 µs |
| `ranking/expected_cost` | 67.7 ns | 67.0 – 68.4 ns |
| `ranking/record_observation` | 19.4 ns | 18.8 – 20.1 ns |

### Cloudflare classification

| Benchmark | Mean | 95% CI |
| --- | --- | --- |
| `cloudflare/prefix_hit_v4` | 5.50 ns | 5.30 – 5.77 ns |
| `cloudflare/prefix_miss_v4` | 13.7 ns | 13.5 – 14.0 ns |
| `cloudflare/prefix_hit_v6` | 11.7 ns | 11.6 – 11.8 ns |
| `cloudflare/prefix_json_parse` | 19.6 µs | 19.5 – 19.8 µs |
| `cloudflare/seed_parse_small` | 1.02 µs | 0.99 – 1.06 µs |
| `cloudflare/seed_parse_1000` | 76.2 µs | 75.1 – 77.5 µs |
| `cloudflare/sample_round_32` | 431.3 µs | 425.8 – 438.4 µs |

### Utility and storage

| Benchmark | Mean | 95% CI |
| --- | --- | --- |
| `util/ipclass_private` | 69.9 ns | 66.8 – 73.3 ns |
| `util/ipclass_global` | 504.5 ns | 501.1 – 508.3 ns |
| `storage/enqueue_500_rows` | 61.7 µs | 60.7 – 62.8 µs |

## Reading the microbenchmarks

`path/cache_hit_full` at **2.26 µs** is the entire in-process cost of answering a cached
query. The load tests show p50 of **0.49 ms** for the same query through a real socket — so
the daemon's own work is roughly **0.5% of the latency a client observes**, and the other
99.5% is the kernel, the socket and the loopback path. On a LAN, network transit dominates
further still. That ratio is the design target: the resolver should disappear into the
network's noise floor.

Two structural properties worth pointing out:

* **Ranking scales linearly.** 8 addresses cost 957 ns and 16 cost 1.77 µs — almost exactly
  double, with no super-linear term. Real RRsets are 2–8 addresses, at 319–957 ns.
* **Cloudflare classification is effectively free.** 5.5 ns for IPv4, 11.7 ns for IPv6,
  because the snapshot precomputes masks and the lookup is a bounded scan over a sorted
  array. That is what makes it acceptable to classify every address in every answer on the
  request path.

Everything expensive is background work and absent from the request path: parsing the
official prefix API (19.6 µs), a 1000-line seed list (76.2 µs), a sampling round
(431.3 µs). Even the slowest is half a millisecond; the reason they are off the request
path is availability, not speed — see [`adr/0004`](adr/0004-foreground-background-split.md).

## Performance regression policy

A change touching the request path (`src/dns/`, `src/cache/`, `src/policy/`,
`src/ranking/`) must be benchmarked before and after **on the same machine, in the same
session** — comparing against the numbers in this document from different hardware tells
you about the hardware.

It must **also** be load-tested. This is not optional and it is not interchangeable with
`cargo bench`. Every defect the load harness has found — an O(n log n) per-query hot-set
eviction, a circuit breaker that black-holed traffic, a UDP-only upstream that turned every
large answer into SERVFAIL — was invisible to Criterion. Two of them made the daemon
*faster* by microbenchmark, because failing early is quick.

A regression that buys correctness is acceptable and should say so in the commit message.
A regression that buys nothing is not.
