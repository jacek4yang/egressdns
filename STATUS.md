# Status

**Version**: 1.0.0 · **Date**: 2026-08-19 · **Git history**: newly initialised, 9 commits, no tags

This document exists to be checked, not believed. Every claim below either names the
command that produced it or says plainly that it was not exercised here.

## Read this first: what "verified" means in this document

The source was delivered as an archive with **no `.git` directory**. The repository in this
tree was initialised from that archive during the hardening pass. It has 9 commits and
no tags, and it is not a continuation of any earlier history:

```
c3a8b19  Stop shipping a manifest that can never verify
80cae1e  Bar fallible-panic constructs from production paths, and check it in CI
04a563b  Re-run every benchmark and load scenario on the hardened tree
c70f468  Add docs/RELEASING.md and make every repository placeholder explicit
fe7c435  Rewrite the documentation to match what the code actually does
f106379  Retry a truncated UDP answer over TCP without a second server entry
162f8d1  Add a realistic load harness and remove unpinnable CI actions
27d911c  Make the control plane follow reloads, and every ceiling real
750c050  import: EgressDNS v1.0.0 source archive (sha256 312f184a...)
```

No prior commit SHA, tag, CI run or release is referenced anywhere in this document,
because none was available to inspect. `v1.0.0` is the version in `Cargo.toml`; no tag has
been created and nothing has been published.

Claims in this document fall into five categories, and each row below is marked:

| Mark | Meaning |
| --- | --- |
| **Measured** | A command was run in this environment and its output is recorded here. |
| **Tested** | An automated test asserts it. The test is named. |
| **Structural** | It follows from the code's shape, and the code is named. No test can fail if it is true. |
| **Static** | The artefact was inspected but not executed here, because this environment cannot execute it. |
| **Unverified** | Not checked here at all. Stated so you do not assume otherwise. |

## Build and test summary — Measured

| Check | Command | Result |
| --- | --- | --- |
| Tests | `cargo test --workspace --all-features` | **408 passed, 0 failed** |
| Lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Clean |
| Format | `cargo fmt --all -- --check` | Clean |
| Release build | `cargo build --release --locked` | Succeeds |
| Shipped configs | `egressdnsd --config config/*.toml --check-config` | All three valid |
| Docs | `cargo doc --workspace --no-deps` with `RUSTDOCFLAGS=-D warnings` | Clean |
| Advisories | `cargo audit` | 0 vulnerabilities across 334 dependencies |
| Licences and bans | `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok` |
| Shell lint | `shellcheck --shell=bash` on every script | Clean **at every severity**, not just warning and above |
| Python lint | `python3 -m ruff check scripts/` | Clean |
| Config docs sync | `./scripts/check-config-docs.py` | 229 fields, all documented, none stale |
| Production paths | `./scripts/check-production-paths.py` | No `unwrap`/`expect`/`todo!`/`unimplemented!`/`unsafe` outside test modules |
| Source archive | `./scripts/verify-source-archive.sh … --full` | Extracts to a clean directory, builds `--release --locked`, runs all 408 tests, verifies `MANIFEST.sha256`, checks every shipped config, and confirms no secrets, no absolute local paths and no forbidden reference. **All checks pass.** |
| Action pinning | `./scripts/pin-github-actions.sh --check` | Every `uses:` is a commit SHA |
| Workflow YAML | `python3 -c 'yaml.safe_load(...)'` | Both files parse |
| Shell syntax | `bash -n install.sh upgrade.sh uninstall.sh scripts/*.sh` | Clean |

`#![forbid(unsafe_code)]` is declared in `src/lib.rs`, so `unsafe` cannot compile at all;
`check-production-paths.py` catches it anyway in case a `#[allow]` is ever added.

Test breakdown: 327 unit tests in the library, 20 resolution, 10 transport, 8 scheduling,
14 Cloudflare security, 13 property (256 generated cases each), **7 hot-reload**,
**7 resource-bound**, 2 harness smoke.

The reload and bounds suites are new in this pass and are the two that would have caught
the P0 and P1 findings.

## The P0 and P1 findings

| Finding | Severity | Disposition | Evidence |
| --- | --- | --- | --- |
| Hot reload did not reload runtime behaviour | P0 | **Fixed by design change.** Every supervised task now takes a `tasks::Ctx` (a `Weak<App>`) and re-reads config, state and resolver each iteration. No task holds configuration. | Tested — `tests/reload.rs::a_reload_moves_foreground_queries_to_the_new_upstream`, `::background_tasks_observe_the_reloaded_configuration`, `::disabling_probing_by_reload_stops_probe_work` |
| No rigorous reload contract | P0 | **Fixed.** `src/config/reload.rs` classifies every field; a restart-required change is refused by name and nothing is applied. `catalog()` is derived from the same check, so documentation cannot drift. | Tested — `::a_restart_required_change_is_refused_and_leaves_the_process_untouched`, `src/config/reload.rs::tests::the_catalog_covers_every_mutation_exactly_once` |
| `dnssec.max_concurrent_validations` semantically dead | P1 | **Implemented** as a semaphore acquired in `Resolver::fetch`; shedding is SERVFAIL plus `dnssec_shed_total`. Classified restart-required. | Tested — `tests/bounds.rs::dnssec_validation_concurrency_is_bounded` |
| `dnssec.trust_anchor_file` decorative | P1 | **Implemented and fails closed.** Anchors are loaded at `Resolver::new`; a missing, unreadable or empty file refuses startup *and* reload rather than falling back to the built-in anchors. | Structural — `src/dns/resolver.rs::Resolver::new` returns `Result`; every caller propagates |
| `resources.max_inflight_upstream` did not bound anything | P1 | **Implemented** in `Scheduler::resolve`, the single function every upstream query passes through — foreground, stale refresh, prefetch and DNSSEC auxiliary lookups alike. | Tested — `tests/bounds.rs::max_inflight_upstream_actually_bounds_upstream_work`, `::shedding_at_the_upstream_ceiling_is_visible` |
| ProbeEngine created unbounded waiting tasks | P1 | **Fixed.** The worker permit is acquired *before* the job leaves the channel, so a queued job is not a live task. | Tested — `tests/bounds.rs::probe_workers_are_bounded_before_a_job_is_dequeued` (2,000 jobs offered; task growth under 200) |

## Defects found beyond the brief

Each of these was found by the new load harness or by the semantic audit, and none of them
would have moved a Criterion number.

| Defect | How it was found | Fix |
| --- | --- | --- |
| A UDP-only upstream group turned **every answer over 512 bytes into SERVFAIL** | Load harness, `truncation` scenario: 9.1% SERVFAIL against an upstream doing nothing worse than truncating | RFC 1035 §4.2.1 / RFC 7766 §5 companion TCP route per UDP server, excluded from ordinary ranking. Truncation scenario is now **100% success** |
| Hyper's connection-driver task was aborted before the response body was read, and leaked on every error path | Code audit of `src/probe/fetch.rs` | RAII `DriverGuard` held until the body completes; overall fetch deadline added |
| `cloudflare.augment.min_samples` parsed and never read | Semantic config audit | Implemented: an unmeasured address may be *reordered* on neutral evidence but never *added* to an answer on it |
| `cloudflare.static_candidates` validated and never consumed | Semantic config audit | Implemented with `CandidateOrigin::Config`, re-checked against the official prefix snapshot every round |
| `logging.query_log` / `query_log_sample` parsed, validated, never consulted | Semantic config audit | Implemented as sampled structured query logging, deterministic in the message ID |
| `Storage::flush` blocked a runtime worker with `thread::sleep` | Code audit | Made async |
| Shutdown slept 500 ms and exited without joining the control plane | Code audit | `App::shutdown_and_join` cancels, waits, and reports how many tasks had to be aborted |
| Blocking filesystem I/O on runtime workers (secret reading, prefix cache) | Code audit | Moved to `spawn_blocking`; the prefix cache is now written atomically |
| `ludeeus/action-shellcheck@master` executed whatever its maintainer last pushed | Supply-chain audit | Removed; ShellCheck is invoked directly |

### Configuration fields removed

Removed rather than kept for compatibility, because a field that is parsed and never read
tells an operator they have a control they do not have:

`cache.max_entries`, `cache.variant_max_entries` (replaced by `variant_max_memory_bytes`),
`upstream.tls.tls_client_cert_file`, `upstream.tls.tls_client_key_file`,
`upstream.groups[].scheduler.max_attempts_per_route`, `.variant_sample_qps`,
`ecs.strip_inbound`, `ecs.ab_test_fraction`, `probe.throughput_concurrency`,
`probe.follow_redirects`, `metrics.unix_socket`, `cloudflare.sampling.ipv4_enabled` and
`.ipv6_enabled` (replaced by a single `enabled`, because IPv6 sampling could never be
defensible and a flag that must always be false is not a setting).

`upstream.groups[].scheduler.max_attempts_per_route` deserves its own note: it was
validated to be 1–3 in the name of RFC 9520 §3.2, but the scheduler makes at most one
attempt per route per resolution regardless of its value. The compliance claim was true;
the mechanism named in the documentation was not the one providing it.

## Load-test results — Measured

Full method, environment and caveats in `docs/BENCHMARKS.md`. Reproduce with
`./scripts/load-test.sh`. Raw JSON in `target/loadtest/`.

The two accounting rules that make these numbers meaningful:

* **A reply is not a success.** `useful` counts NOERROR *with an answer record*. In the
  `servfail` scenario `qps` and `useful_qps` differ by 16%; reading only the former would
  report a failing upstream as throughput.
* **The generator is closed-loop and shares two vCPUs with the daemon.** In every scenario
  below, `qps` is within 0.5% of the recorded `harness_ceiling_qps`: the harness saturated
  first, so these are **floors on the daemon's capacity, not measurements of it**.

| Scenario | qps | useful qps | success | p50 | p99.9 | RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `cache-hit` | 30,031 | 30,031 | 100% | 0.49 ms | 21.8 ms | 14 MB |
| `mixed` | 35,058 | 35,058 | 100% | 0.71 ms | 22.6 ms | 24 MB |
| `miss-heavy` | 7,208 | 7,208 | 100% | 5.05 ms | 33.1 ms | 225 MB |
| `elevated-rtt` (40±15 ms) | 1,886 | 1,886 | 100% | 38.0 ms | 75.9 ms | 119 MB |
| `packet-loss` (2%) | 7,231 | 7,231 | 100% | 2.93 ms | 351 ms | 225 MB |
| `timeouts` (10%) | 2,059 | 2,057 | 99.9% | 0.63 ms | 671 ms | 124 MB |
| `servfail` (20%) | 7,004 | 6,154 | 87.9% | 9.22 ms | 34.2 ms | 214 MB |
| `truncation` (15%) | 6,323 | 6,323 | 100% | 12.1 ms | 33.8 ms | 215 MB |
| `ipv6-mixed` | 34,417 | 34,417 | 100% | 0.75 ms | 27.0 ms | 33 MB |
| `dnssec-closed` | 24,285 | **0** | **0%** | 0.61 ms | 64.7 ms | 20 MB |
| `sustained` (7 min) | 22,278 | 22,278 | 100% | 1.89 ms | 38.1 ms | 96 MB |

17.4 million queries across the suite. File descriptors peaked at 75, threads at 4, in
every scenario.

`dnssec-closed` returning **0% useful is the correct result and the point of the
scenario**: validation against an upstream that supplies no chain of trust must fail
closed. 1,093,126 queries, 1,093,126 SERVFAILs. A single NOERROR there would be a serious
security defect.

**No leak.** A separate 8-minute soak — 9,256,227 queries at 19,283 qps — shows RSS
climbing from 11.5 MB to 96.1 MB as the cache fills and then **completely flat for the
final five minutes** (`rss_mb_growth_last_third = 0.0 MB`), with threads flat at 4.

## Un-exercised in this environment

These are environment limits, not implementation gaps.

| Item | Why not here | How to exercise it |
| --- | --- | --- |
| Binding UDP/TCP **port 53** specifically | No `CAP_NET_BIND_SERVICE`, no init system. The listener code is port-independent and is exercised on ephemeral ports throughout. | `sudo setcap 'cap_net_bind_service=+ep' ./target/release/egressdnsd` |
| systemd unit activation and sandbox verification | No systemd here. | `sudo systemctl start egressdns && systemd-analyze security egressdns` |
| The GitHub Actions workflows | Creating or pushing to a remote repository was not authorised, and none exists. Both files parse and every action is SHA-pinned. | Push to a repository and watch the Actions run. |
| `install.sh` against a real release | Requires published release assets. | `sudo ./install.sh --local-build` exercises everything except download and checksum fetch. |
| aarch64 runtime behaviour | x86_64 host. CI cross-*builds* aarch64; it does not run it. | Run the suite on aarch64, or under `qemu-user`. |
| Real-world Cloudflare probing | Outbound probing to arbitrary hosts is not appropriate from a build container and the results would not represent a real egress. | `egressdnsctl cloudflare scan-now` on a deployed node. |
| Multi-hour soak and chaos runs | Time-bounded environment, 2 vCPU. The longest run here is recorded in `docs/BENCHMARKS.md`. | `./scripts/load-test.sh --sustained 86400`, `./scripts/chaos-test.sh` |
| Two-node DNS-A/DNS-B deployment | Single container. | `docs/OPERATIONS.md` §7 |

## Known limitations

1. **Cleartext ingress only.** Client-facing DoT/DoH/DoQ is not implemented. `docs/adr/0007`.
2. **Forwarder, not a recursive resolver.** If every upstream is unreachable and stale data
   has expired, this daemon cannot resolve. `docs/adr/0001`.
3. **Linux-specific network detection.** `/proc/net/route` parsing is Linux-only.
4. **`.test` is deliberately not blocked** by the special-use registry, for the reason
   recorded in `src/dns/specialuse.rs`.
5. **Verified-augment fires rarely by design.** Seven conditions must now hold
   simultaneously — `min_samples` added one. `docs/adr/0010`.
6. **Learned state is per-node.** Two nodes must not share a SQLite file. Documented rather
   than enforced, because enforcement would need locking that could block.
7. **Persisted statistics can be dropped under write pressure.** By design. `docs/adr/0008`.
8. **The load harness is Python and shares the machine with the daemon.** On a larger host,
   drive it from a separate machine.
9. **`--inflight` is bounded by the 16-bit DNS transaction ID space** per client thread.
   The default of 8 is far below that; a pathological value is not defended against.
