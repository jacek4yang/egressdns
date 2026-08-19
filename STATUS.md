# Status

**Version**: 2.0.0 · **Date**: 2026-08-19 · **Published**: <https://github.com/jacek4yang/egressdns>, branch `feat/v2-autonomous-adaptive-resolver`

## 2.0.0 summary

Seven defects fixed, two features added. Three of the defects were found by running the
software rather than by reading it: two by installing it on a real host and watching it
report perfect health while answering nothing, one by the load harness after a change the
entire test suite accepted.

| Claim | Evidence |
| --- | --- |
| A `version = 2` file of two keys starts and answers | **Tested** — `tests/config_v2.rs::a_minimal_v2_configuration_starts_and_answers` |
| One `https://` entry yields H3 and H2 candidates | **Tested** — `tests/config_v2.rs::one_https_upstream_becomes_both_http_versions` |
| `proxies` is refused, never silently ignored | **Tested** — `tests/config_v2.rs::declaring_a_proxy_is_refused_rather_than_ignored` |
| `doctor` detects port conflicts, forwarding loops and ACL gaps | **Tested** — 20 tests in `src/doctor/` |
| `doctor` runs correctly on a real host | **Measured** — run under `sudo` against the live deployment; found and then confirmed the fix for two of its own misdiagnoses |
| `ProcSubset=pid` broke all resolution | **Measured** — reproduced under `systemd-run`; see `docs/incidents/2026-08-deployment-failure.md` |
| A blind address-family detector still resolves | **Tested** — `tests/deployment.rs::a_failed_address_family_detection_still_resolves` |
| The packaged unit does not hide `/proc/net` | **Tested** — `tests/deployment.rs::the_systemd_unit_does_not_hide_proc_net_from_the_detector` |
| A proven route outranks untried routes | **Tested** — `src/upstream/scheduler.rs::a_proven_route_outranks_routes_that_have_never_been_tried`, fails before the fix |
| The ranking fix changes real behaviour | **Measured** — same host, same ten real names, back to back: 0/30 answered before, 9/30 after |
| No untried ranked route is skipped by fallback | **Tested** — three tests in `tests/scheduler_contract.rs` |
| One absolute deadline covers the truncation retry | **Tested** — `tests/scheduler_contract.rs::truncation_retry_cannot_exceed_the_foreground_deadline`, measured 4.005s against a 2.5s budget before the fix |
| Cancelled exchanges keep their slot, bounded | **Measured** — unbounded retention took truncation from 15,285 qps at 100% to 1,187 at 0%; capped at 100ms it is 16,336 qps at 100% |
| Reload publishes one coherent policy generation | **Structural** — the request path reads config-derived policy from the `Config` the `ArcSwap` publishes; plus **Tested** by `effective_mode_ignores_an_override_stronger_than_the_live_configuration` |
| Real DNSSEC validation works end to end | **Measured** — `dig +dnssec @127.0.0.1 cloudflare.com A` returns NOERROR with the `ad` flag set, against real upstreams on port 53 |
| systemd lifecycle is clean | **Measured** — two `reload`s under continuous traffic with zero failed queries; `stop`/`start` cycle clean; `systemd-analyze security` **1.7 OK** |
| Proxy egress | **Not implemented.** Declaring one is a hard error. |
| DDR, SVCB/HTTPS discovery, RESINFO, ECH, ODoH, MASQUE | **Not implemented.** |

Original 1.0.0 status follows.

This document exists to be checked, not believed. Every claim below either names the
command that produced it or says plainly that it was not exercised here.

## Read this first: provenance and what "verified" means

The source arrived as an archive with **no `.git` directory**. The Git history in this
repository was initialised from that archive, so it is short and honest rather than long
and reconstructed:

```
d10740c  fix: make install.sh --local-build work under sudo and in a test prefix
d1a4916  test: prove a DNSSEC mode reload fails closed on the data plane
2e63f54  test: make the config audit full-path aware and force classification
9966f74  fix: eliminate dead config and unify the probe concurrency ceiling
ad2b67d  docs: hard-code the real GitHub repository in install and release metadata
0404d55  docs: record cloudflare restart-required fields and per-exchange ceiling
2563236  fix: bound physical upstream exchanges, not resolutions
564fcc6  fix: make cloudflare enabled/mode reload-consistent in foreground state
ff2410e  import: EgressDNS v1.0.0 source archive (hardening baseline)
```

The archive itself was the product of an earlier hardening pass whose findings are
recorded in `CHANGELOG.md`; that pass's commit history was not recoverable and is not
reconstructed here.

Claims in this document fall into five categories, and each row below is marked:

| Mark | Meaning |
| --- | --- |
| **Measured** | A command was run in this environment and its output is recorded here. |
| **Tested** | An automated test asserts it. The test is named. |
| **Structural** | It follows from the code's shape, and the code is named. No test can fail if it is true. |
| **Static** | The artefact was inspected but not executed here, because this environment cannot execute it. |
| **Unverified** | Not checked here at all. Stated so you do not assume otherwise. |

Environment: Intel Core i3-8100 (4 cores), 15 GiB RAM, Debian 13, kernel 6.12,
rustc 1.95.0. Details in `docs/BENCHMARKS.md`.

## Build and test summary — Measured

| Check | Command | Result |
| --- | --- | --- |
| Tests | `cargo test --workspace --all-features` | **482 passed, 0 failed** (2.0.0) |
| Lint | `cargo clippy --all-targets --all-features -- -D warnings` | Clean |
| Format | `cargo fmt --all -- --check` | Clean |
| Release build | `cargo build --release --locked` | Succeeds |
| Shipped configs | `egressdnsd --config config/*.toml --check-config` (release binary) | All three valid |
| Docs | `cargo doc --workspace --all-features --no-deps` with `RUSTDOCFLAGS=-D warnings` | Clean |
| Advisories | `cargo audit` | 0 vulnerabilities across 334 dependencies |
| Licences and bans | `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok` |
| Python lint | `ruff check scripts/` | Clean |
| Config docs sync | `./scripts/check-config-docs.py` | **224 fields across 39 tables**, all documented, none stale — now full-path aware |
| Reload classification | `cargo test --all-features config::reload` | Every one of the 224 leaf paths is classified exactly once: reloadable or restart-required |
| Production paths | `./scripts/check-production-paths.py` | No `unwrap`/`expect`/`todo!`/`unimplemented!`/`unsafe` outside test modules |
| Action pinning | `./scripts/pin-github-actions.sh --check` | Every `uses:` is a commit SHA |
| Workflow YAML | parsed with a real YAML parser (see below) | Both workflows parse |
| Shell syntax | `bash -n install.sh upgrade.sh uninstall.sh scripts/*.sh` | Clean |
| Installer smoke | `sudo EGRESSDNS_TEST_ROOT=<prefix> ./install.sh --local-build`, run twice | Installs binaries, unit and config; validates config; second run is an idempotent in-place upgrade |

`#![forbid(unsafe_code)]` is declared in `src/lib.rs`, so `unsafe` cannot compile at all;
`check-production-paths.py` catches it anyway in case a `#[allow]` is ever added.

**ShellCheck is not installed in this environment and could not be run here.** `bash -n`
passes on every script, and CI runs ShellCheck directly (`--severity=warning`); the
workflows are SHA-pinned and were not modified in this pass. **PyYAML is not installed and
PyPI is unreachable from this environment**, so the workflow YAML check used the YAML
parser bundled with Prettier instead of `yaml.safe_load`; both files parse. The same
restriction is why the installer smoke used `--local-build` (no release download) — see
the un-exercised table below.

## The P0 and P1 findings — this pass

| Finding | Severity | Disposition | Evidence |
| --- | --- | --- | --- |
| Foreground answers used the **startup** Cloudflare config after a reload | P0 | **Fixed.** `CloudflareState.enabled`/`mode` are now atomics updated by `reconfigure()` during `App::reload`; admin mode overrides are reconciled against the new configured mode. `cloudflare.candidate_pool_max` and `cloudflare.sampling.{seed,buckets_per_prefix,exploit_fraction}` are classified restart-required instead of silently ignored. | Tested — `tests/reload.rs::reloading_the_cloudflare_mode_reaches_the_foreground_state`, `::toggling_cloudflare_enabled_by_reload_reaches_the_foreground_state`, `::cloudflare_structural_changes_are_refused_as_restart_required` |
| `resources.max_inflight_upstream` bounded **resolutions**, not exchanges — hedging and emergency fan-out multiplied the real ceiling up to 3× | P0 | **Fixed.** The shared permit is acquired per physical exchange inside `Scheduler::attempt`, after the hedge delay, around `route.send`. Primaries and truncation retries queue within budget; hedges and fan-out shed immediately at the ceiling. Shed attempts record no health evidence, so saturation cannot flap circuit breakers. | Tested — `tests/bounds.rs::hedging_cannot_multiply_the_upstream_ceiling`, `::emergency_fanout_cannot_multiply_the_upstream_ceiling`, `::truncation_retry_does_not_deadlock_at_a_ceiling_of_one` |
| Config audit collapsed fields to leaf names (`queue_size` × 3, `enabled` × 14, …) | P1 | **Fixed.** `scripts/check-config-docs.py` is full-path aware on both sides; `src/config/reload.rs` now has an explicit `RELOADABLE` list and `every_config_path_is_classified_exactly_once` fails the build when a new field is added without classification. | Measured — the rewrite caught three real doc gaps (a nonexistent `[upstream.scheduler]` section, undocumented `probe.profiles.required_header`, undocumented per-server ECS overrides), all fixed |
| `prefetch.queue_size` parsed, validated, documented, never read | P1 | **Removed** (config, validation, docs, examples). The prefetcher bounds work with its QPS semaphore; there is no queue to size. | Structural — no reference remains |
| `probe.profiles[].port` parsed, validated, never read | P1 | **Removed.** The engine probes the job's port. | Structural — no reference remains |
| `probe.{tcp,tls,http}_concurrency` collapsed to `min()` — two knobs always inert | P1 | **Replaced** by one truthful `probe.concurrency` (default 8 = the old effective ceiling; range preserves every previously reachable value). Old keys fail loudly at parse (`deny_unknown_fields`). | Tested — `tests/bounds.rs::probe_workers_are_bounded_before_a_job_is_dequeued` uses the new knob |
| `cache.negative_max_ttl` captured at startup, misclassified reloadable | P1 | **Fixed** — read from the live configuration where the negative TTL is computed. | Tested — `tests/reload.rs::negative_max_ttl_follows_a_reload` |

## Defects found beyond the brief — this pass

| Defect | How it was found | Fix |
| --- | --- | --- |
| `cache.failure_max_ttl` silently clipped after a reload that raised it | Semantic audit of cache construction | The failures cache's retention bound is now the validation ceiling (`FAILURE_MAX_TTL_CEILING`), which covers every legal value; per-entry TTLs were already live |
| `resources.systemd_watchdog` claimed reloadable but read once at startup | Classification audit | Restart-required; a reload changing it is refused by name |
| `ResolveError::Overloaded` reported "permits free" while carrying the configured ceiling; the DNSSEC shed site passed `available_permits()` | Review of the limiter change | Both sites report the configured ceiling |
| `sudo ./install.sh --local-build` failed: sudo drops the user's rustup cargo from PATH | Executing the documented install path | `build_locally` falls back to the invoking user's `~/.cargo/bin` and builds as that user, so `target/` is not left root-owned |
| The systemd unit directory was assumed to exist | Installer smoke under `EGRESSDNS_TEST_ROOT` | Created before the unit is installed |

The earlier pass's findings (reload redesign, UDP truncation/TCP companion, probe worker
bounds, DNSSEC ceilings, and the rest) are recorded in `CHANGELOG.md`; their regression
tests all still run and pass.

## Load-test results — Measured

Full method, environment and caveats in `docs/BENCHMARKS.md`. Reproduce with
`./scripts/load-test.sh`. Raw JSON in `target/loadtest/` (not committed).

15 s per scenario (120 s for `sustained`), 8 clients × 8 in flight, against
`scripts/mock_upstream.py` on loopback:

| Scenario | qps | useful qps | success | p50 | p99.9 | RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `cache-hit` | 38,319 | 38,319 | 100% | 1.63 ms | 5.60 ms | 14 MB |
| `mixed` | 37,347 | 37,347 | 100% | 1.66 ms | 6.51 ms | 24 MB |
| `miss-heavy` | 18,409 | 18,409 | 100% | 5.57 ms | 13.2 ms | 207 MB |
| `elevated-rtt` (40±15 ms) | 1,680 | 1,680 | 100% | 39.5 ms | 55.5 ms | 62 MB |
| `packet-loss` (2%) | 9,852 | 9,852 | 100% | 0.48 ms | 356 ms | 166 MB |
| `timeouts` (10%) | 1,824 | 1,822 | 99.9% | 0.28 ms | 2,000 ms | 65 MB |
| `servfail` (20%) | 16,222 | 13,854 | 85.4% | 5.76 ms | 15.6 ms | 188 MB |
| `truncation` (15%) | 15,969 | 15,969 | 100% | 6.12 ms | 16.0 ms | 196 MB |
| `ipv6-mixed` | 36,798 | 36,798 | 100% | 1.66 ms | 6.96 ms | 34 MB |
| `dnssec-closed` | 32,605 | **0** | **0%** | 1.77 ms | 22.5 ms | 21 MB |
| `sustained` (2 min) | 37,018 | 37,018 | 100% | 1.64 ms | 11.5 ms | 97 MB |

7.6 million queries across the suite. File descriptors peaked at 78, threads at 6, in
every scenario. In every scenario `qps` is within 2% of the recorded
`harness_ceiling_qps` — the generator saturated first, so these are **floors on the
daemon's capacity, not measurements of it**.

`dnssec-closed` returning **0% useful is the correct result and the point of the
scenario**: validation against an upstream that supplies no chain of trust must fail
closed. 489,183 queries, 489,183 SERVFAILs. A single NOERROR there would be a serious
security defect.

**No leak.** The `sustained` run — 4,442,251 queries at 37,018 qps — shows RSS climbing
from 12.1 MB to 97.4 MB as the cache fills and then **completely flat for the final ninety
seconds** (`rss_mb_growth_last_third = 0.0 MB`), threads flat at 6.

The per-exchange upstream limiter introduced this pass was exercised by every scenario
above — hedging (loss/timeout scenarios), emergency fan-out (`servfail`), and truncation
retries all pass through it. No contention or deadlock was observed; the bounds tests
(`tests/bounds.rs`) prove the ceiling itself.

## Un-exercised in this environment

These are environment limits, not implementation gaps.

| Item | Why not here | How to exercise it |
| --- | --- | --- |
| ShellCheck | Not installed; no package network access. `bash -n` passes; CI runs ShellCheck directly and **passed** on `main` (run 32261285237). | — done in CI |
| The GitHub Actions workflows | ~~Had not run at the time of writing~~ **Now executed**: CI green on `main`; the Release workflow green on `v1.0.0` and published a non-draft release with `egressdns-v1.0.0-linux-x86_64.tar.gz`, `-aarch64.tar.gz` and `SHA256SUMS`. The GitHub-stored asset digests (via `gh api …/releases/tags/v1.0.0`) match `SHA256SUMS` exactly. | — done |
| The download path of `install.sh` | Release assets now exist, but this environment's route to the GitHub asset CDN is throttled to the point a 7.9 MB asset does not complete; the asset bytes were instead verified by comparing GitHub's stored SHA-256 digests against the published `SHA256SUMS`. A deliberately truncated download **fails** `sha256sum -c` — the checksum gate fails closed. The remainder of the installer (build, install, config validation, idempotent upgrade) was executed via `--local-build`. | From a network with normal GitHub access: `curl -fsSL https://raw.githubusercontent.com/jacek4yang/egressdns/main/install.sh \| sudo bash` |
| Binding UDP/TCP **port 53** specifically | No init system here; the listener code is port-independent and is exercised on ephemeral ports throughout. | `sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/egressdnsd` |
| systemd unit activation and sandbox verification | No systemd here. | `sudo systemctl start egressdns && systemd-analyze security egressdns` |
| aarch64 runtime behaviour | x86_64 host. CI cross-*builds* aarch64; it does not run it. | Run the suite on aarch64, or under `qemu-user` |
| Real-world Cloudflare probing | Outbound probing to arbitrary hosts is not appropriate from a build machine and the results would not represent a real egress. | `egressdnsctl cloudflare scan-now` on a deployed node |
| Multi-hour soak and chaos runs | Time-bounded environment. The longest run here is recorded in `docs/BENCHMARKS.md`. | `./scripts/load-test.sh --sustained 86400`, `./scripts/chaos-test.sh` |
| Two-node DNS-A/DNS-B deployment | Single machine. | `docs/OPERATIONS.md` §7 |

## Known limitations

1. **Cleartext ingress only.** Client-facing DoT/DoH/DoQ is not implemented. `docs/adr/0007`.
2. **Forwarder, not a recursive resolver.** If every upstream is unreachable and stale data
   has expired, this daemon cannot resolve. `docs/adr/0001`.
3. **Linux-specific network detection.** `/proc/net/route` parsing is Linux-only.
4. **`.test` is deliberately not blocked** by the special-use registry, for the reason
   recorded in `src/dns/specialuse.rs`.
5. **Verified-augment fires rarely by design.** Seven conditions must hold simultaneously —
   `min_samples` added one. `docs/adr/0010`.
6. **Learned state is per-node.** Two nodes must not share a SQLite file. Documented rather
   than enforced, because enforcement would need locking that could block.
7. **Persisted statistics can be dropped under write pressure.** By design. `docs/adr/0008`.
8. **The load harness is Python and shares the machine with the daemon.** On a larger host,
   drive it from a separate machine.
9. **`--inflight` is bounded by the 16-bit DNS transaction ID space** per client thread.
   The default of 8 is far below that; a pathological value is not defended against.
10. **A cancelled hedge can leave one zombie upstream exchange.** When a hedge loses the
    race its permit is released immediately, but the datagram already sent is still
    processed by the upstream. The observed in-flight count at the upstream can therefore
    exceed the configured ceiling by at most one momentarily; the permit ceiling itself is
    strict. This is inherent to cancelling UDP — the wire cannot be unsent.
