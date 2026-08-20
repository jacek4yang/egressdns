# Configuration reference

EgressDNS reads exactly one TOML file. The path is given with `--config` and defaults to
`/etc/egressdns/config.toml`.

Three rules govern the whole file:

1. **Unknown keys are a hard error.** Every table is `deny_unknown_fields`. A typo in a key
   name fails the config rather than silently taking the default — a resolver that
   quietly ignores `allow_from` because you wrote `allowed_from` is a resolver that is open
   to the Internet.
2. **Validation is normative, not advisory.** `Config::validate()` encodes rules from the
   RFCs and from this project's threat model: the RFC 9520 attempt ceiling, the failure-TTL
   bounds, the requirement that a non-loopback listener declares an ACL, the refusal of
   QUIC 0-RTT, the requirement that an ECS prefix is public. A configuration that violates
   one of these is rejected at load and at reload; see [Validation rules](#validation-rules).
3. **A rejected reload changes nothing.** The daemon builds the new state completely before
   swapping it in. If the new configuration fails to parse, fails validation, or fails to
   bind, the running configuration keeps serving and the failure is logged.

Check a file without starting the daemon:

```sh
egressdnsd --config /etc/egressdns/config.toml --check-config
```

Print the effective configuration, with every default made explicit:

```sh
egressdnsd --config /etc/egressdns/config.toml --dump-config
```

Two annotated files ship with the source:

| File | Use |
| --- | --- |
| `config/egressdns.toml` | The default. A complete working file; start here. |
| `config/egressdns.lan.example.toml` | Serving a LAN. **Edit `server.allow_from` before use.** |

## Durations

Any key documented as a *duration* accepts a humantime string: `500ms`, `2s`, `2s500ms`,
`5m`, `1h`, `1d`. Bare numbers are not accepted, because `timeout = 5` is ambiguous.

## Sizes

Byte counts are plain integers. Where a key is a count of entries rather than bytes the
type column says `integer` and the description says what is counted.

---

## The reload contract

`systemctl reload egressdns` (or `egressdnsctl reload`) re-reads this file and applies it
atomically. Not every setting can take effect that way, and the difference is not a
detail: a resolver that accepts a change, reports success and keeps running the old value
is worse than one that refuses, because the operator now believes something that is not
true.

So the contract is explicit:

* **Reloadable** — the default. The new configuration is parsed, validated, and used to
  build a complete replacement runtime state *before* anything is swapped. Background
  tasks re-read the live configuration at the top of every iteration, so the next tick
  after a reload uses the new upstreams, the new intervals and the new feature switches.
  Turning a feature off by reload actually stops the work; turning it back on starts it
  again without a restart.
* **Restart-required** — a listening socket, a thread pool, a semaphore or a fixed-capacity
  structure that is built once at startup. Changing one of these is **refused by name**.
  The reload fails, the running configuration is untouched, `egressdnsctl status` reports
  the refusal, and `config_reloads_total{outcome="restart_required"}` is incremented.

There is deliberately no third category. A setting is never silently ignored.

To see the classification without reading this document:

```sh
egressdnsctl reload-contract
```

### Settings that require a restart

Everything not in this table applies on reload.

| Setting | Why a restart is required |
| --- | --- |
| `server.udp_listen` | listening sockets are bound once at startup; rebinding could drop queries and may need CAP_NET_BIND_SERVICE |
| `server.tcp_listen` | listening sockets are bound once at startup |
| `server.udp.reuse_port` | SO_REUSEPORT changes the socket topology, which is fixed at bind time |
| `server.udp.workers_per_socket` | receive workers are spawned per socket at bind time |
| `server.udp.recv_buffer_bytes` | SO_RCVBUF is applied to the socket at bind time |
| `server.udp.send_buffer_bytes` | SO_SNDBUF is applied to the socket at bind time |
| `metrics.enabled` / `metrics.listen` | the metrics listener is bound once at startup |
| `admin.enabled` / `admin.socket` / `admin.socket_mode` | the admin socket is created once at startup; recreating it would break connected clients and race on the path |
| `resources.worker_threads` | the Tokio runtime is built once at startup |
| `resources.max_blocking_threads` | the Tokio blocking pool is sized once at startup |
| `resources.max_inflight_queries` | the ingress semaphore is sized once at startup |
| `resources.max_inflight_upstream` | the upstream semaphore is sized once at startup |
| `resources.systemd_watchdog` | the watchdog task is spawned once at startup |
| `cache.max_memory_bytes` / `cache.failure_max_entries` / `cache.variant_max_memory_bytes` | cache capacity is fixed at construction; resizing would mean discarding the cache |
| `cache.quality_max_entries` | the quality store is sized once at startup |
| `serve_stale.enabled` / `serve_stale.max_stale` / `cache.internal_max_ttl` | these determine cache retention, which is fixed when the cache is built |
| `prefetch.hot_set_size` / `prefetch.transition_table_size` / `prefetch.transition_prediction` | the hot set is sized once at startup |
| `probe.queue_size` | the probe channel capacity is fixed at construction |
| `dnssec.max_concurrent_validations` | the validation semaphore is sized once at startup |
| `cloudflare.candidate_pool_max` | the candidate pool capacity is fixed at construction; resizing would mean discarding validated candidates |
| `cloudflare.sampling.seed` / `cloudflare.sampling.buckets_per_prefix` / `cloudflare.sampling.exploit_fraction` | the sampler is built once at startup; rebuilding it would discard per-bucket history |
| `storage.enabled` / `storage.path` / `storage.queue_size` | the database connection and its write queue are opened once at startup |
| `logging.level` / `logging.json` | the tracing subscriber is installed once at startup |

A refused reload looks like this, and nothing has changed when you see it:

```
reload refused: these fields require a restart:
  - server.udp_listen: listening sockets are bound once at startup; rebinding could drop
    queries and may need CAP_NET_BIND_SERVICE
Revert them, or restart the service to apply them.
```

### Why some of these could be made reloadable and are not

`cache.max_memory_bytes` is the clearest example. The cache could be rebuilt at the new
size on reload — but doing so discards every cached answer, which turns a routine
configuration change into a latency and upstream-load event at an unpredictable moment.
Requiring a restart makes the cost visible and lets the operator schedule it. The same
reasoning applies to the quality store and the hot set: the data in them is *earned*, and
silently throwing it away during a reload would be a worse surprise than a refusal.

## Memory sizing

The cache is bounded by **bytes, not entries**. An entry limit does not bound memory,
because a DNS answer can be 200 bytes or 2 kilobytes depending on the RRset.

Measured on x86_64 with the load harness in `scripts/`, steady-state resident memory is
approximately:

```
RSS ≈ 15 MB + 1.6 × cache.max_memory_bytes
```

The 1.6 factor covers per-entry keys and metadata, the negative and variant caches, and
allocator fragmentation; the 15 MB floor is the runtime, the upstream connection pools and
the metric registry. Plan capacity from this relationship rather than from the budget
alone: a 1 GiB budget is a ~1.7 GB process.

See `docs/BENCHMARKS.md` for the measurements this is derived from, including the control
experiment that varied only the budget.

---

## Section reference

Generated from the field documentation in `src/config/mod.rs`; the source is authoritative
if the two ever disagree.

### Top-level keys

These sit at the root of the file, before any table. Together they are a complete,
working configuration.

```toml
upstreams = ["auto"]

proxies = []
```

There is no configuration version field. The format is identified by its contents, and a
file from before 2.0 is refused by name with a pointer to
[the migration guide](MIGRATION-V1-TO-V2.md) rather than half-applied.

`auto` is worked out on the host at startup rather than guessed in a file: the local
gateway when it answers DNS and does not forward back here, the regional resolvers that
answer fastest, and independent encrypted resolvers so that not every source shares a
jurisdiction. Every entry it produces is a literal address or a name with its addresses
pinned, so nothing needs DNS to reach DNS. `egressdnsctl upstreams` prints the result.

The gateway is adopted as a **local forwarder**, not an authority. It is usually the
fastest source on the network and the only one that answers for local names, but it
forwards to somebody else — so agreeing with it proves only that it and we asked the same
upstream. It therefore cannot corroborate an NXDOMAIN and is never used as a DNSSEC
oracle. It is refused outright when it is one of this resolver's own listeners, or when it
answers a per-instance probe that only an EgressDNS instance can answer, which means the
query came home.

Each `upstreams` entry may be `auto`, a built-in profile (`builtin:recommended`), a bare address
(`1.1.1.1`, `1.1.1.1:5353`, `2606:4700:4700::1111`, `[2606:4700:4700::1111]:5353`), a
provider alias (`cloudflare`, `google`, `quad9`, `adguard`), or a URI:

| Form | Becomes | Default port |
| --- | --- | --- |
| bare address | Do53 over UDP, with the TCP companion RFC 7766 truncation retries need | 53 |
| `https://host/path` | **both** an HTTP/3 and an HTTP/2 candidate for one logical DoH resolver | 443 |
| `tls://host` | DoT | 853 |
| `quic://host` | DoQ | 853 |
| `udp://host`, `tcp://host` | Do53 over that transport specifically | 53 |

An `https://` entry deliberately produces two route candidates rather than one. Whether
HTTP/3 or HTTP/2 is better on a given network is a measurement, not a configuration
choice: the scheduler ranks both from observed latency and failure history, prefers the
better one, and falls back to the other when a path degrades — without an operator having
to predict which will work. The same applies to UDP against TCP, IPv4 against IPv6, and
direct against proxied.

`http://` is refused: it has the privacy cost of DoH and none of its integrity. An
encrypted transport pointed at a literal address is also refused, because there would be
no name to authenticate the certificate against.

**Built-in profiles.** `builtin:<name>` expands to a curated set of independently operated
public resolvers, each contributing its plaintext seeds *and* its encrypted endpoints. Every
endpoint is taken from the operator's own documentation, with the source and the date it was
last checked recorded alongside it. `egressdnsctl builtins` lists the profiles and
`egressdnsctl builtins <name>` prints one in full — a set of resolvers you did not choose by
hand is still one you can audit.

| Profile | For |
| --- | --- |
| `builtin:recommended` | The default. Five independent operators, general-purpose, none filtering. |
| `builtin:global` | Wider reach, still unfiltered. |
| `builtin:china` | Reachable with low latency from mainland China. |
| `builtin:privacy` | Operators with an explicit no-logging policy. |
| `builtin:security-filtered` | Withhold known-malicious names. |
| `builtin:ad-blocking` | Withhold advertising and tracking names. |

`recommended` deliberately contains no filtering resolver. A filtering resolver's omissions
are indistinguishable from ordinary GeoDNS variation once mixed into one pool, and
corroboration counts *authorities* — so mixing policies would let one operator's editorial
decision look like a consensus. Choose a filtering profile if you want filtering; do not mix
one into an unfiltered pool.

Profiles compose with everything else, so a private resolver alongside the built-in set is
just another entry:

```toml
upstreams = ["builtin:recommended", "tls://dns.internal.example?addr=10.0.0.53"]
```

> On a network where some of a profile's endpoints are blocked, see the
> [DNSSEC downgrade note](incidents/2026-08-dnssec-downgrade-on-blocked-routes.md): a
> blocked route can cause a signed name to be answered without its AD bit. Listing only the
> reachable providers avoids it.

**Naming an endpoint DNS cannot resolve yet.** A named endpoint needs an address before it
can be reached. Well-known providers carry published bootstrap addresses; any other name
is resolved at startup by the bootstrap resolver. When neither is possible — a resolver on
a private network, one whose certificate does not match its address, one being stood up
before its own record exists — pin the address with `?addr=`:

```toml
upstreams = ["tls://dns.internal.example:8853?addr=10.0.0.53"]
```

`addr` may be repeated. It changes only which socket is opened: the TLS identity is still
the hostname, so a stale or wrong hint fails closed rather than quietly reaching somebody
else. It is the same information SVCB carries as `ipv4hint`.

`proxies` entries are `socks5://`, `socks5h://`, `http://` or `https://`, with optional
`user:password@` credentials. Whether a proxy is used, and which one, is decided from
measured path health rather than configured.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `upstreams` | `auto`, endpoint URI, or `builtin:` profile | `[]` (empty) | Where to ask. At least one is required. |
| `proxies` | list of proxy URI | `[]` (empty) | Egress proxies, tried when the direct path is unhealthy. |

### `[server]`

Inbound DNS service: listeners, access control and the foreground budget.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `udp_listen` | list of address:port | `["127.0.0.1:53", "[::1]:53"]` | UDP listen addresses. |
| `tcp_listen` | list of address:port | `["127.0.0.1:53", "[::1]:53"]` | TCP listen addresses. |
| `allow_from` | list of CIDR prefix | `[]` (empty) | Client networks permitted to use the resolver. Default-deny: an empty list refuses every client. |
| `deny_from` | list of CIDR prefix | `[]` (empty) | Client networks explicitly refused, evaluated before `allow_from`. |
| `foreground_budget` | duration | `2500ms` | Maximum time the foreground path may spend before returning something to the client. Background work is never included in this budget. |
| `any_policy` | string: `"minimal"` \| `"forward"` \| `"refuse"` | `minimal` | Handling of `QTYPE=ANY` queries (RFC 8482). |
| `special_use` | string: `"local"` \| `"forward"` | `local` | Handling of names in the IANA Special-Use Domain Names registry (RFC 6761 and friends). Locally configured zones and hosts are always consulted first, so this only affects names the operator has not claimed. |
| `udp` | sub-table `[server.udp]` | see below | UDP-specific settings. |
| `tcp` | sub-table `[server.tcp]` | see below | TCP-specific settings. |
| `rate_limit` | sub-table `[server.rate_limit]` | see below | Inbound rate limiting. |

### `[server.udp]`

UDP-specific ingress settings.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `max_payload` | integer | `1232` | Maximum EDNS(0) UDP payload this server will emit. Defaults to 1232, the DNS Flag Day 2020 value derived from the IPv6 minimum MTU. RFC 9715 discusses 1400 as an alternative for networks known to have a 1500-byte path MTU. |
| `non_edns_max_payload` | integer | `512` | Response size limit for clients that did not send an OPT record (RFC 1035). |
| `recv_buffer_bytes` | integer (optional) | `4194304` | Optional `SO_RCVBUF` override in bytes. |
| `send_buffer_bytes` | integer (optional) | `4194304` | Optional `SO_SNDBUF` override in bytes. |
| `reuse_port` | boolean | `false` | Enable `SO_REUSEPORT` and open one socket per worker. Keep disabled until benchmarked on the target host. |
| `workers_per_socket` | integer | `1` | Number of receive workers per UDP listen address when `reuse_port` is enabled. |

### `[server.tcp]`

TCP-specific ingress settings.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `idle_timeout` | duration | `10s` | Idle timeout for an established DNS-over-TCP connection (RFC 7766 section 6.2.3). |
| `max_connection_lifetime` | duration | `300s` | Hard ceiling on connection lifetime regardless of activity. |
| `max_connections` | integer | `4096` | Global concurrent connection limit. |
| `max_connections_per_client` | integer | `64` | Per-client-address concurrent connection limit. |
| `max_pipelined_queries` | integer | `256` | Maximum number of in-flight queries per connection (pipelining depth). |
| `max_message_bytes` | integer | `65535` | Maximum accepted DNS message size on TCP. |
| `advertise_edns_keepalive` | boolean | `true` | Advertise EDNS TCP Keepalive (RFC 7828) in responses over TCP. |

### `[server.rate_limit]`

Per-client inbound rate limiting.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master switch. |
| `per_client_qps` | integer | `2000` | Sustained queries per second permitted per client address. |
| `per_client_burst` | integer | `4000` | Burst allowance per client address. |
| `global_qps` | integer | `200000` | Sustained queries per second permitted across all clients. |
| `global_burst` | integer | `400000` | Burst allowance across all clients. |
| `client_table_size` | integer | `65536` | Bound on the per-client rate limiter table. |

### `[cache]`

Cache sizing and admission.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `max_memory_bytes` | integer | `268435456` | Approximate memory ceiling for cached answers, in bytes. |
| `failure_max_entries` | integer | `20000` | Maximum number of cached resolution-failure entries (RFC 9520). |
| `variant_max_memory_bytes` | integer | `33554432` | Byte budget for retained alternate answer variants. Must be at least 1 MiB and no larger than `max_memory_bytes`: variants are a diagnostic aid and must never outweigh the answers themselves. |
| `quality_max_entries` | integer | `100000` | Maximum number of tracked IP quality records held in memory. |
| `internal_max_ttl` | integer | `86400` | Upper bound applied to any authoritative TTL before it is stored (RFC 2181 caps TTLs at 2^31-1; a shorter internal cap bounds memory and staleness). |
| `negative_max_ttl` | integer | `3600` | Upper bound applied to negative TTLs derived from the SOA (RFC 2308). |
| `failure_min_ttl` | duration | `1s` | Minimum resolution-failure cache duration (RFC 9520 recommends >= 1 second). |
| `failure_max_ttl` | duration | `300s` | Maximum resolution-failure cache duration (RFC 9520 recommends <= 5 minutes). |

### `[ttl]`

Client-facing TTL ceilings. Every value here is a *cap*: it can only ever shorten a TTL.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `cap_default` | integer | `300` | Cap for single-address or non-optimized answers. |
| `cap_optimized_multi` | integer | `90` | Cap for optimized multi-address answers that are not Cloudflare-specific. |
| `cap_cloudflare_preserve` | integer | `60` | Cap applied when a Cloudflare answer was reordered in preserve mode. |
| `cap_cloudflare_augment` | integer | `25` | Cap applied when verified Cloudflare addresses were prepended. |
| `cap_network_change` | integer | `15` | Cap applied for a period after a network-generation change. |
| `cap_serve_stale` | integer | `30` | Cap applied to answers served from the stale cache. |
| `network_change_window` | duration | `300s` | How long the reduced network-change cap remains in force. |

### `[ranking]`

Address quality model and ordering policy.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Enable evidence-based ordering. When disabled the original upstream order is always preserved. |
| `neutral_cost_ms` | float | `120.0` | Neutral cost in milliseconds assigned to an address with no applicable evidence. Lack of evidence is not evidence of failure. |
| `failure_penalty_ms` | float | `400.0` | Penalty in milliseconds applied for a full connection failure. |
| `tail_weight` | float | `0.35` | Weight applied to the recent tail latency estimate. |
| `jitter_weight` | float | `0.25` | Weight applied to observed jitter. |
| `uncertainty_penalty_ms` | float | `60.0` | Penalty in milliseconds scaled by the width of the success-probability confidence interval; a wide interval means the estimate is not yet trustworthy. |
| `stale_sample_penalty_ms` | float | `40.0` | Penalty in milliseconds applied when the newest sample is older than `sample_max_age`. |
| `sample_max_age` | duration | `1800s` | Age beyond which samples are considered stale. |
| `evidence_half_life` | duration | `3600s` | Half-life applied to the success/failure posterior. |
| `hysteresis` | float | `0.12` | Required relative improvement before the leading address may be replaced. |
| `min_successes_to_lead` | integer | `3` | Minimum number of successful observations before an address may be promoted to first position. |
| `exploration_rate` | float | `0.02` | Fraction of decisions that deliberately keep a lower-ranked address first so that addresses can recover from a bad streak. |
| `consecutive_failure_base` | float | `1.8` | Base penalty multiplier applied per consecutive failure, compounded. |

### `[serve_stale]`

RFC 8767 serve-stale policy.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master switch. |
| `max_stale` | duration | `86400s` | Maximum age past expiry for which stale data may be served. |
| `client_timeout` | duration | `1800ms` | How long the resolver attempts a live refresh before falling back to stale data. |
| `retry_interval` | duration | `30s` | Minimum interval between background refresh attempts for one stale name. Enforced per cache key in the resolver, so a name whose upstream is down is retried on this schedule rather than on every client query that hits the stale entry. |
| `include_ede` | boolean | `true` | Attach RFC 8914 Extended DNS Error 3 (Stale Answer) to stale responses. |

### `[prefetch]`

Hot-name prefetching.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master switch. |
| `trigger_fraction` | float | `0.15` | Refresh when the remaining TTL fraction drops below this value. |
| `min_hits` | integer | `3` | Minimum observed hit count before a name is eligible. |
| `hot_set_size` | integer | `20000` | Bound on the tracked hot set. |
| `global_qps` | integer | `50` | Global prefetch query budget in queries per second. |
| `per_key_min_interval` | duration | `5s` | Minimum interval between prefetches of the same cache key. |
| `warm_on_start` | integer | `200` | Persisted hot names re-resolved at startup, so a restarted process does not begin with an empty cache. Warming runs in a bounded task set with a 30 s drain, is skipped when persistence is disabled, and never delays the listeners: queries are answered from the moment the sockets are bound. `0` disables it. |
| `transition_prediction` | boolean | `false` | Enable the bounded aggregate transition table (query-sequence prediction). Disabled by default; see `docs/BENCHMARKS.md` for the evidence requirement. |
| `transition_table_size` | integer | `20000` | Bound on the transition table. |

### `[tls]`

TLS trust for encrypted upstreams. Which roots to trust is a deployment fact rather than
something the resolver can measure its way to, so it stays configurable; how to *use* an
encrypted upstream does not.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `use_system_roots` | boolean | `true` | Use the platform trust store in addition to the compiled-in Mozilla root set. |
| `extra_ca_files` | list of path | `[]` (empty) | Additional PEM bundles containing corporate or private roots. |
| `session_resumption` | boolean | `true` | Enable TLS session resumption for DoT, DoH and DoQ. |
| `quic_zero_rtt` | boolean | `false` | QUIC 0-RTT. Early data is replayable and DNS queries are not idempotent from a privacy standpoint, so this is refused if enabled; see `docs/THREAT_MODEL.md`. |

### `[dnssec]`

DNSSEC validation policy.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | string: `"background"` \| `"strict"` \| `"off"` | `background` | When validation happens relative to the client. See below. |
| `trust_anchor_file` | path (optional) | unset | Replacement for the compiled-in IANA root anchors, in DNS presentation format — the same shape as the `root.key` written by `unbound-anchor`. **Fails closed**: if the file is missing, unreadable, or contains no usable DS or DNSKEY record, startup and reload are refused rather than silently falling back to the built-in anchors. Leave unset to use the compiled-in anchors. |
| `trust_upstream_ad` | boolean | `false` | Trust an upstream's AD bit. Only honoured for servers that also set `trust_ad` and use an authenticated transport. |
| `max_concurrent_validations` | integer | `256` | Global ceiling on DNSSEC validations running at once, enforced by a semaphore the resolver acquires before validating. A query that cannot get a permit inside the foreground budget is shed as SERVFAIL and counted in `dnssec_shed_total` rather than queueing without bound. **Restart-required**: the semaphore is created once at startup and shared by every resolver generation. |
| `max_validation_depth` | integer | `12` | Maximum delegation depth followed while building a validation chain, which bounds the work one hostile zone can force. Applied as the request depth limit on every validating lookup. |
| `validation_cache_entries` | integer | `10000` | Bound on the validation result cache. |
| `proof_completion_timeout` | duration | `20s` | How long a background proof completion may run. When a chain cannot be proved inside `server.foreground_budget` the answer is served with AD cleared and the proof is finished afterwards, so the next query for that zone validates normally. Nothing waits on this, which is why it is far larger than the foreground budget. |
| `corroborate_negative` | boolean | `true` | Ask a second, independent resolver authority before believing an unsigned NXDOMAIN. A forged negative is how a name is made to disappear and, unlike a forged address, leaves no evidence in the answer itself. Corroboration can only ever replace a negative with a positive, never the reverse, so it cannot be used to erase a name. Costs one extra query on cold unsigned NXDOMAINs only. |
| `extended_errors` | boolean | `true` | Attach RFC 8914 Extended DNS Errors describing DNSSEC outcomes. |

**`background` (default)** — a client gets the fastest admissible answer and validation
follows in the evidence plane, where nobody is waiting. What it finds decides what happens
to that answer *next*: a variant proven Bogus is evicted, so it is served at most once and
never again; a variant proven Secure is promoted, and the next client to ask gets AD. A
proof that could not be completed changes nothing, because "I could not check this" is not
a statement about the answer.

This is the default because synchronous validation could not keep the promise the
foreground budget makes. Proving a name at the end of a four-zone CNAME chain —
`www.bing.com` is the case that forced it — needs more sequential DS and DNSKEY lookups
than 2.5 seconds holds. The lookups were cut off, the library reports a cut-off lookup as
Bogus, and the resolver refused a name it could resolve perfectly well.

**`strict`** — validate before answering, and fail closed. Honest about its cost: a name
whose chain does not fit the validation deadline is refused. Correct for some deployments,
wrong for most. Accepts the 2.x name `validate` as an alias, because somebody who wrote
that chose fail-closed deliberately.

**`off`** — no local validation.

In every mode a confirmed Bogus verdict is refused; the modes differ in *when* the verdict
is available, not in whether it is honoured.

### `[ecs]`

EDNS Client Subnet. Disabled by default.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | string: `"disabled"` \| `"fixed-egress"` | `disabled` | Global mode. |
| `egress` | sub-table `[ecs.egress]` | see below | Fixed public egress prefixes advertised upstream when `mode = "fixed-egress"`. |

### `[ecs.egress]`

The prefix advertised when ECS is enabled.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ipv4` | IPv4 CIDR (optional) | — | IPv4 prefix advertised upstream. Must be a public prefix. |
| `ipv6` | IPv6 CIDR (optional) | — | IPv6 prefix advertised upstream. Must be a public prefix. |

### `[probe]`

Active probe engine: budgets, safety and profiles. Everything here is background work.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master switch. When disabled the resolver never opens a probe connection and all candidates keep neutral scores. |
| `queue_size` | integer | `8192` | Bounded probe work queue. |
| `concurrency` | integer | `8` | Single ceiling on concurrent probe exchanges, across all stages: a worker holds its slot for the whole TCP → TLS → HTTP pipeline. Must be between 1 and 256. |
| `global_connections_per_second` | integer | `64` | Global ceiling on new probe connections per second. |
| `tcp_timeout` | duration | `1500ms` | Stage 1 timeout. |
| `tls_timeout` | duration | `3000ms` | Stage 2 timeout. |
| `http_timeout` | duration | `5000ms` | Stage 3 timeout. |
| `per_ip_cooldown` | duration | `300s` | Minimum interval between probes of the same address. |
| `per_prefix_cooldown` | duration | `30s` | Minimum interval between probes inside the same prefix. |
| `per_domain_cooldown` | duration | `600s` | Minimum interval between domain-level validations of the same hostname. |
| `max_candidates_per_rrset` | integer | `4` | Maximum number of addresses scheduled from a single observed RRset. |
| `extra_ports` | list of integer | `vec![443]` | Ports probed in addition to those declared by HTTPS/SVCB or SRV records. |
| `max_response_bytes` | integer | `16384` | Response body cap for HTTP probes. |
| `enable_http3` | boolean | `true` | Attempt a QUIC/HTTP-3 probe when the target advertises `h3`. A path that blocks UDP produces an `Unsupported` observation, never a failure, so a QUIC-hostile network cannot make an otherwise healthy address look bad. |
| `daily_bandwidth_budget_bytes` | integer | `67108864` | Daily budget for throughput measurement, in bytes. |
| `allow_special_use_targets` | list of CIDR prefix | `[]` (empty) | Networks that may be probed even though they are private or otherwise special-use. Empty by default; probing special-use space is refused unless listed here. |
| `profiles` | array of `[[probe.profiles]]` | `[]` (empty) | Named validation profiles. |

### `[[probe.profiles]]`

One probe profile.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | `String::new()` | Profile name. |
| `domains` | list of string | `[]` (empty) | Domains this profile applies to. A leading `.` matches the suffix. |
| `path` | string | `"/".to_string()` | Health-check path. |
| `method` | string | `"HEAD".to_string()` | HTTP method; only `HEAD` and `GET` are permitted. |
| `allowed_status` | list of integer | `vec![200, 204, 301, 302, 400, 403, 404, 405]` | Status codes considered a successful validation. |
| `required_header` | sub-table `[probe.profiles.required_header]` (optional) | unset | A response header that must be present, and optionally its exact value. |
| `body_sha256` | string (optional) | unset | Hex-encoded SHA-256 of the expected (small) response body. |
| `spki_sha256` | list of string | `[]` (empty) | Permitted hex-encoded SHA-256 values of the server certificate SPKI. |
| `required_issuer_cn` | string (optional) | unset | Required issuer common name substring. |
| `alpn` | list of string | `vec!["h2".to_string(), "http/1.1".to_string()]` | ALPN protocols offered, in preference order. |

### `[probe.profiles.required_header]`

The response header a profile requires, set by `required_header` in `[[probe.profiles]]`.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | — | Header name, compared case-insensitively. |
| `value` | string (optional) | unset | Exact value the header must carry; unset means only presence is required. |

### `[network]`

IPv4/IPv6 environment detection.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master switch for network-generation tracking. |
| `poll_interval` | duration | `5s` | Polling interval for route and address state. |
| `debounce` | duration | `3s` | Debounce window; changes must be stable for this long before a new generation is published. |
| `reference_v4` | IP address | `IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))` | Reference IPv4 destination used only to ask the kernel which source address and route would be selected. No packets are sent. |
| `reference_v6` | IP address | — | Reference IPv6 destination used the same way. |
| `confidence_decay_on_change` | float | `0.25` | Multiplier applied to historical confidence after a generation change. |
| `relearn_window` | duration | `600s` | Duration of accelerated relearning after a generation change. |

### `[cloudflare]`

Cloudflare answer optimization.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Master switch for the whole subsystem. |
| `mode` | string: `"off"` \| `"preserve"` \| `"verified-augment"` | `preserve` | Response mode. |
| `official` | sub-table `[cloudflare.official]` | see below | Official prefix sources. |
| `seeds` | sub-table `[cloudflare.seeds]` | see below | Untrusted third-party candidate seed endpoints. |
| `sampling` | sub-table `[cloudflare.sampling]` | see below | Bounded sampling of official IPv4 prefixes. |
| `augment` | sub-table `[cloudflare.augment]` | see below | Verified-augment specific limits. |
| `probe_hosts` | list of string | `vec!["speed.cloudflare.com".to_string()]` | Hostnames used for generic Cloudflare reachability probing. |
| `allow_domains` | list of string | `[]` (empty) | Domains eligible for optimization; empty means "all eligible domains". |
| `deny_domains` | list of string | `[]` (empty) | Domains never optimized, evaluated first. |
| `candidate_pool_max` | integer | `4096` | Bound on the candidate pool. |
| `static_candidates` | list of IP address | `[]` (empty) | Administrator-supplied candidate addresses, admitted with origin `config` and no hourly budget. Re-checked against the official prefix snapshot on every refresh round: administrator intent does not make an address Cloudflare-owned, so an address outside every current official prefix is refused and logged. |

### `[cloudflare.official]`

Official Cloudflare prefix sources. These are the only source of truth for what counts as a Cloudflare address.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `api_url` | string | `"https://api.cloudflare.com/client/v4/ips".to_string()` | Primary JSON API endpoint. |
| `ipv4_url` | string | `"https://www.cloudflare.com/ips-v4".to_string()` | Plain-text IPv4 list used as a cross-check. |
| `ipv6_url` | string | `"https://www.cloudflare.com/ips-v6".to_string()` | Plain-text IPv6 list used as a cross-check. |
| `refresh_interval` | duration | `86400s` | Refresh interval. |
| `timeout` | duration | `10s` | Per-request timeout. |
| `max_response_bytes` | integer | `262144` | Maximum accepted response size. |
| `min_ipv4_prefixes` | integer | `8` | Minimum number of IPv4 prefixes a snapshot must contain to be accepted. |
| `min_ipv6_prefixes` | integer | `4` | Minimum number of IPv6 prefixes a snapshot must contain to be accepted. |
| `api_token_file` | path (optional) | unset | Optional file containing a Cloudflare API token. The token is never required: the IP endpoint is public. |
| `api_token_env` | string (optional) | unset | Optional environment variable holding a Cloudflare API token. |
| `cache_file` | path (optional) | `PathBuf::from("/var/lib/egressdns/cloudflare-prefixes.json")` | Path where the last valid snapshot is cached on disk. |

### `[cloudflare.seeds]`

Untrusted third-party candidate lists.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Master switch for third-party seeds. |
| `endpoints` | array of `[[cloudflare.seeds.endpoints]]` | three endpoints, all disabled unless `enabled = true` | Endpoints to poll. |
| `refresh_interval` | duration | `2400s` | Refresh interval. |
| `timeout` | duration | `10s` | Per-request timeout. |
| `max_response_bytes` | integer | `131072` | Maximum accepted response size for any single endpoint. |
| `max_addresses_per_response` | integer | `256` | Maximum number of addresses accepted from a single endpoint response. |
| `resolve_hostnames` | boolean | `true` | Resolve hostnames returned by a seed endpoint through the local resolver and then filter the resulting addresses against the official prefix snapshot. |

### `[[cloudflare.seeds.endpoints]]`

One untrusted seed endpoint.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | `String::new()` | Short name used as a bounded metrics label. |
| `url` | string | `String::new()` | Absolute HTTPS URL. |
| `enabled` | boolean | `true` | Enable or disable this endpoint independently. |

### `[cloudflare.sampling]`

Reproducible stratified sampling of official prefixes.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Enable stratified rotating sampling of official prefixes. Sampling is IPv4-only by construction: random traversal of the official IPv6 space has no defensible expected yield, so there is deliberately no IPv6 switch. IPv6 candidates come from observed answers and from seed lists instead. |
| `round_interval` | duration | `300s` | Interval between sampling rounds. |
| `addresses_per_round` | integer | `32` | Addresses proposed per round across all prefixes. |
| `max_new_candidates_per_hour` | integer | `512` | Ceiling on newly proposed IPv4 candidates per hour. |
| `buckets_per_prefix` | integer | `64` | Number of sampling buckets each prefix is divided into. |
| `exploit_fraction` | float | `0.3` | Extra budget share given to historically productive buckets, in `[0, 1]`. |
| `seed` | integer | `0x5eed_0cf0_0000_0001` | Deterministic seed so that a sampling schedule is reproducible. |

### `[cloudflare.augment]`

Conditions under which verified-augment mode may add an address.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `max_added` | integer | `2` | Maximum number of verified addresses prepended to an eligible answer. |
| `min_validations` | integer | `3` | Minimum number of successful domain-level validations before an address may be added for that domain. |
| `validation_ttl` | duration | `3600s` | Validity window of a domain-level validation result. |
| `min_advantage` | float | `0.12` | Required confidence-adjusted improvement over the best original address, as a fraction. Acts as hysteresis. |
| `min_samples` | integer | `8` | Quality observations a candidate must have before it may be *added* to an answer. An address with no measurements scores neutral rather than bad, which is correct for ranking but would otherwise let an entirely unmeasured address outrank a genuinely slow original one. Reordering is unaffected; this gates addition only. |

### `[datasets]`

Optional offline dataset files.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `hosts_files` | list of path | `[]` (empty) | Hosts-format files. |
| `domain_category_files` | list of path | `[]` (empty) | GeoSite-compatible domain category files (`category:domain` per line). |
| `geoip_mmdb` | path (optional) | unset | Optional GeoIP MMDB used only as advisory diagnostic metadata. |
| `asn_mmdb` | path (optional) | unset | Optional ASN MMDB used only as advisory diagnostic metadata. |
| `reload_interval` | duration | `3600s` | Interval at which dataset files are re-read by the background dataset task. A rebuild that produces byte-identical content is not republished, so an unchanged file costs one hash and no snapshot swap. Files are also re-read on configuration reload. |
| `max_file_bytes` | integer | `67108864` | Maximum accepted size of any single dataset file. |
| `max_records` | integer | `2000000` | Maximum accepted number of records per dataset. |

### `[local]`

Static local data.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `hosts` | array of `[[local.hosts]]` | `[]` (empty) | Inline hosts-style entries. |
| `zones` | array of `[[local.zones]]` | `[]` (empty) | Internal zones served authoritatively from configuration. |
| `suffix_rules` | array of `[[local.suffix_rules]]` | `[]` (empty) | Suffix-based upstream routing rules. |
| `local_ttl` | integer | `60` | TTL used for locally served records. |

### `[[local.hosts]]`

One hosts-style mapping.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | — | Fully qualified name. |
| `addresses` | list of IP address | — | Addresses returned for A/AAAA queries. |

### `[[local.zones]]`

One internal zone served from configuration.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | `String::new()` | Zone apex. |
| `records` | array of `[[local.zones.records]]` | `[]` (empty) | Records in presentation-like form. |
| `authoritative` | boolean | `true` | Answer NXDOMAIN for names inside the zone that have no record. |

### `[[local.zones.records]]`

One record inside an internal zone.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | `"@".to_string()` | Owner name, relative to the zone apex or fully qualified when ending in a dot. |
| `rtype` | string | `"A".to_string()` | Record type: `A`, `AAAA`, `CNAME`, `TXT`, `PTR`, `MX`, `SRV` or `NS`. |
| `value` | string | `String::new()` | Presentation-format RDATA. |
| `ttl` | integer (optional) | unset | TTL override for this record. |

### `[[local.suffix_rules]]`

Route a DNS suffix to a named upstream group.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `suffix` | string | — | Domain suffix, matched on label boundaries. |
| `group` | string | — | Target upstream group name. |

### `[storage]`

SQLite persistence of learned state.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master switch. When disabled the resolver runs with purely in-memory state. |
| `path` | path | `PathBuf::from("/var/lib/egressdns/state.sqlite3")` | Database path. |
| `flush_interval` | duration | `30s` | Interval between batched flushes. |
| `queue_size` | integer | `8192` | Bounded write queue. |
| `max_quality_rows` | integer | `50000` | Maximum number of persisted IP quality rows. |
| `max_hot_rows` | integer | `20000` | Maximum number of persisted hot-domain rows. |
| `max_candidate_rows` | integer | `20000` | Maximum number of persisted Cloudflare candidate rows. |
| `row_max_age` | duration | `Duration::from_secs(30 * 86_400)` | Rows unused for longer than this are pruned. |

### `[metrics]`

Prometheus exposition and health endpoints.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master switch. |
| `listen` | address:port | — | Listen address. Must be a loopback address unless `allow_non_loopback` is set. |
| `allow_non_loopback` | boolean | `false` | Permit binding a non-loopback address. Strongly discouraged. |

### `[logging]`

Structured logging.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `level` | string | `"info".to_string()` | Log filter directive, `tracing-subscriber` syntax. |
| `json` | boolean | `false` | Emit newline-delimited JSON instead of human-readable text. |
| `query_log` | boolean | `false` | Emit one structured line per sampled query, at `info`, with the client address, name, type, rcode, answer origin and elapsed time. Off by default: this records client addresses and query names, which is personal data in most jurisdictions. Reloadable. |
| `query_log_sample` | float | `0.01` | Fraction of queries logged when `query_log` is enabled, in `[0, 1]`. Sampling is deterministic in the DNS message ID rather than random, so the same query is not logged twice by two processes. `0.0` logs nothing; `1.0` logs everything. |

### `[admin]`

Local administration socket.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Master switch. |
| `socket` | path | `PathBuf::from("/run/egressdns/admin.sock")` | Unix domain socket path. |
| `socket_mode` | integer | `0o660` | Socket file mode. |
| `max_request_bytes` | integer | `65536` | Maximum accepted request size. |

### `[resources]`

Process-wide ceilings.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `worker_threads` | integer (optional) | unset | Tokio worker threads; `None` means one per available core. |
| `max_inflight_queries` | integer | `20000` | Maximum concurrent in-flight client queries. |
| `max_inflight_upstream` | integer | `4000` | Global ceiling on upstream exchanges in flight, across *every* path that issues one — foreground resolution, stale refresh, prefetch and probe-driven lookups alike. The permit is acquired per physical exchange in the scheduler, the single point every upstream exchange passes through, so hedges and emergency fan-out count against the same ceiling; a hedge or fan-out attempt that cannot start immediately is shed rather than queued. A query that cannot get one inside its budget is shed as SERVFAIL and counted in `upstream_shed_total`. **Restart-required**: the semaphore is sized once at startup. |
| `max_blocking_threads` | integer | `4` | Maximum number of blocking threads used for storage and dataset parsing. |
| `systemd_watchdog` | boolean | `true` | Enable the systemd watchdog when `WATCHDOG_USEC` is present. **Restart-required**: the watchdog task is spawned once at startup. |


---

## Validation rules

These are enforced by `Config::validate()` (`src/config/validate.rs`) at startup, at
`--check-config`, and on every reload. Each one exists because the alternative is a
resolver that is quietly wrong.

| Rule | Why |
| --- | --- |
| At least one UDP or TCP listener must be configured, with no duplicate addresses. | A resolver with no listener is a process that burns memory; a duplicated listen address fails at bind time with a much less obvious message. |
| A listener on any address other than loopback requires a non-empty `server.allow_from`. | Default-deny. An open resolver on a LAN is an amplification reflector. |
| `server.allow_from` entries may not be multicast ranges. | A multicast prefix cannot identify a client, so such a rule can only ever be a mistake. |
| `server.udp.max_payload` must be between 512 and 4096. | RFC 1035 fixes the floor; RFC 9715 explains why anything above the path MTU causes fragmentation. The shipped default is 1232, and `config/egressdns.toml` notes 1400 as the only sane larger value. |
| `server.udp.non_edns_max_payload` must be exactly 512. | RFC 1035. The key exists so the value is visible, not so it can be changed. |
| `server.udp.workers_per_socket > 1` requires `reuse_port = true`. | Multiple workers on one socket without `SO_REUSEPORT` is just contention. |
| `serve_stale.client_timeout` must be below `server.foreground_budget`, and at most 1800ms. | Otherwise serve-stale can never fire and the client just times out. RFC 8767 §5 recommends ≤1.8s. |
| `serve_stale.max_stale` must be non-zero and at most 7 days. | RFC 8767 §6. |
| `cache.failure_min_ttl` must be at least 1s; `cache.failure_max_ttl` at most 300s and not below the minimum. | RFC 9520 §4. |
| `cache.internal_max_ttl` must be non-zero and at most 86400s. | An unbounded internal TTL turns the cache into a memory leak with a DNS interface. |
| Every group named by `upstream.default_group` or by a suffix rule must exist, group names must be unique, and every group must have at least one server. | A dangling or duplicated group name silently sends traffic nowhere. |
| An encrypted transport (`dot`, `doh2`, `doh3`, `doq`) requires a non-empty `server_name`. | Without an authentication name, TLS verification is meaningless. |
| An upstream address must be a literal IP, and must be global, private, shared-address-space or loopback. | Documentation, benchmarking, multicast and metadata ranges are never a real resolver. Using a hostname would require resolving it with the resolver being configured. |
| `enable_cookies = true` is rejected on `dot`, `doh2`, `doh3` and `doq`. | RFC 7873 cookies protect an unauthenticated datagram path. On an authenticated transport they add nothing and act as a stable client identifier. Leave the key unset to get the correct per-transport default. |
| The RFC 9520 ceiling of three queries per server address per transport is satisfied structurally: one resolution makes at most one attempt per route. | RFC 9520 §3.2. There is no setting, because there is nothing a setting could change. |
| `upstream.tls.quic_zero_rtt = true` is always rejected. | 0-RTT data is replayable. A replayable DNS query is a cache-poisoning primitive. |
| `ecs.egress` prefixes must be public, with prefix length ≤ 24 (v4) and ≤ 56 (v6). | RFC 7871 §2 and §11.1. Sending a private prefix leaks the LAN and is useless to the upstream. |
| A `probe.allow_special_use_targets` entry may not cover a link-local, loopback, multicast or cloud-metadata range. | The probe engine is an outbound HTTP client running as a daemon; letting configuration point it at `169.254.169.254` turns a config file into an SSRF primitive. This is re-checked at call time in `src/probe/safety.rs`, so a bug in the validator is not sufficient to reach one. |
| `cloudflare.mode = "verified-augment"` requires `probe.enabled = true`. | Augmentation without probe evidence would be guessing, and this daemon does not guess about answers. |
| Every probe profile needs a unique non-empty name, at least one domain, a path starting with `/`, and valid HTTP status codes in `allowed_status`. | A malformed profile would otherwise fail silently at probe time, which looks identical to "the address is bad". |
| Every seed endpoint URL must be an absolute `https://` URL. | A cleartext candidate list is an on-path attacker's input to your answers. |
| `admin.socket` must be an absolute path and `admin.socket_mode` must grant nothing to "other". | The admin socket can flush the cache and change Cloudflare modes; it is not a public interface. |
| `admin.max_request_bytes` must be between 1 and 1 MiB. | The admin protocol is line-oriented; an unbounded line is an OOM. |
| `storage.path` must be absolute; `resources.worker_threads` must be 1–512. | An ambiguous relative path under a `systemd` unit with `ProtectSystem=strict` is a confusing failure; an absurd thread count is a resource-exhaustion foot-gun. |

## Precedence

When more than one mechanism could answer a name, the order is fixed:

1. `[[local.hosts]]` — exact name match.
2. `[[local.zones]]` — most specific zone apex wins.
3. Special-use registry (`server.special_use = "local"`), unless a `[[local.suffix_rules]]`
   entry covers the name.
4. Cache (fresh).
5. `[[local.suffix_rules]]` — chooses the upstream group.
6. `upstream.default_group`.
7. Cache (stale), only if every upstream failed and `serve_stale.enabled` is true.

## What is deliberately not configurable

* **The DNSSEC fail-closed rule.** There is no key that turns a Bogus answer into a served
  answer. `dnssec.mode = "off"` disables validation entirely, which is honest; there is no
  setting that validates and then ignores the result.
* **Answer synthesis.** No key adds a CNAME, rewrites an address that the upstream did not
  send (outside the strictly bounded verified-augment path), filters AAAA, or applies
  DNS64.
* **The special-use metadata ranges.** `probe.exceptions` cannot re-enable
  `169.254.169.254` and friends; this is checked in the config validator *and* again in the
  probe guard at call time.
* **TLS verification.** There is no `insecure_skip_verify`. Pinning can be added on top of
  verification, never instead of it.
