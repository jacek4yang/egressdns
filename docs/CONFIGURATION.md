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

Three annotated files ship with the source:

| File | Use |
| --- | --- |
| `config/egressdns.minimal.toml` | The smallest file that starts and serves. |
| `config/egressdns.example.toml` | Every key, with commentary. Start here. |
| `config/egressdns.production.toml` | A hardened LAN deployment. **Edit `server.allow_from` before use.** |

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

These sit at the root of the file, before any table.

`version = 2` selects the intent-oriented front-end, where `upstreams` describes *where to
ask* and the daemon derives the transports, address families and route candidates. Omitting
`version` selects the advanced form, where every upstream is declared in full under
`[[upstream.groups]]`. The two are mutually exclusive: a file that used both would leave an
operator guessing which one was in force, so combining them is a hard error.

```toml
version = 2
upstreams = [
    "1.1.1.1",
    "2606:4700:4700::1111",
    "https://cloudflare-dns.com/dns-query",
    "tls://dns.quad9.net",
]
```

Each entry may be a bare address (`1.1.1.1`, `1.1.1.1:5353`, `2606:4700:4700::1111`,
`[2606:4700:4700::1111]:5353`), a provider alias (`cloudflare`, `google`, `quad9`,
`adguard`), or a URI:

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
to predict which will work.

`http://` is refused: it has the privacy cost of DoH and none of its integrity. An
encrypted transport pointed at a literal address is also refused, because there would be
no name to authenticate the certificate against.

A named endpoint needs bootstrap addresses before DNS works. They come from a small
built-in provider registry (`cloudflare-dns.com`, `dns.google`, `dns.quad9.net`,
`dns.adguard-dns.com`). The addresses are only a way to open a connection — the TLS
identity is always the configured name, so a stale bootstrap address fails closed rather
than quietly reaching a different resolver. For any other name, declare the server in the
advanced `[[upstream.groups.servers]]` form with explicit `addresses`.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `version` | integer | unset | Configuration format version. `2` selects the intent-oriented front-end; omitting it selects the advanced form. |
| `upstreams` | list of endpoint URI | `[]` (empty) | Where to ask. Requires `version = 2`. |
| `proxies` | list of proxy URI | `[]` (empty) | Reserved. **Not implemented in this release**: a non-empty list is refused rather than ignored, because a proxy that is accepted and not used would send traffic the operator believes is tunnelled straight out of the host. |

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

### `[upstream]`

Upstream groups and shared transport settings.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `default_group` | string | `"default".to_string()` | Group used when no suffix rule matches. |
| `groups` | array of `[[upstream.groups]]` | `vec![UpstreamGroupConfig::default()]` | Configured upstream groups. |
| `tls` | sub-table `[upstream.tls]` | see below | TLS trust configuration shared by encrypted transports. |

### `[upstream.tls]`

TLS material shared by every encrypted upstream transport.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `use_system_roots` | boolean | `true` | Use the platform trust store in addition to the compiled-in Mozilla root set. |
| `extra_ca_files` | list of path | `[]` (empty) | Additional PEM bundles containing corporate roots. |
| `session_resumption` | boolean | `true` | Enable TLS session resumption for DoT/DoH/DoQ. |
| `quic_zero_rtt` | boolean | `false` | QUIC 0-RTT is disabled: early data is replayable and DNS queries are not idempotent from a privacy standpoint. See `docs/THREAT_MODEL.md`. |

### `[[upstream.groups]]`

One named group of upstream servers. At least one group must exist and one must match `upstream.default_group`.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | `"default".to_string()` | Group name referenced by suffix rules and by `upstream.default_group`. |
| `servers` | array of `[[upstream.groups.servers]]` | two public resolvers over DoT (see `[[upstream.groups]]` below) | Members of the group. |
| `scheduler` | sub-table `[upstream.groups.scheduler]` | see below | Scheduling policy for this group. |

### `[[upstream.groups.servers]]`

One upstream server inside a group.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | `String::new()` | Operator-facing name; also used as the bounded metrics label. |
| `transport` | string: `"udp"` \| `"tcp"` \| `"dot"` \| `"doh2"` \| `"doh3"` \| `"doq"` | `udp` | Transport used to reach the server. |
| `addresses` | list of IP address | `[]` (empty) | Literal addresses of the server. Encrypted transports require these as bootstrap addresses so that the resolver never needs to resolve its own upstream. |
| `port` | integer (optional) | unset | Port override; defaults to the IANA port for the transport. |
| `server_name` | string (optional) | unset | TLS server name (SNI and certificate hostname) for encrypted transports. |
| `path` | string (optional) | unset | HTTP path for DoH transports. |
| `bind_addr` | address:port (optional) | unset | Optional local source address to bind. |
| `weight` | integer | `100` | Static preference weight used to break ties between equally healthy routes. |
| `enabled` | boolean | `true` | Disable without deleting. |
| `enable_cookies` | boolean (optional) | unset | Send RFC 7873 DNS Cookies. `None` means "automatic": enabled for UDP and TCP, disabled for encrypted transports where they add nothing. Setting `true` explicitly on an encrypted transport is a configuration error. |
| `trust_ad` | boolean | `false` | Trust this upstream's AD bit when local validation is disabled. Requires an authenticated transport. |
| `ecs` | sub-table `[upstream.groups.servers.ecs]` (optional) | unset | Per-server ECS override; `None` inherits the global policy. |

### `[upstream.groups.servers.ecs]`

A per-server ECS prefix override, with the same shape and rules as `[ecs.egress]`; it applies to this upstream server only.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ipv4` | IPv4 CIDR (optional) | — | IPv4 prefix advertised to this server. Must be a public prefix. |
| `ipv6` | IPv6 CIDR (optional) | — | IPv6 prefix advertised to this server. Must be a public prefix. |

### `[upstream.groups.scheduler]`

Hedging, circuit breaking and failure-cache behaviour.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `hedge_enabled` | boolean | `true` | Enable a single bounded hedge request. |
| `hedge_percentile` | float | `0.95` | Latency percentile of the primary route used to time the hedge. |
| `hedge_min_delay` | duration | `20ms` | Lower bound on the hedge delay. |
| `hedge_max_delay` | duration | `400ms` | Upper bound on the hedge delay. |
| `hedge_max_fraction` | float | `0.15` | Maximum fraction of queries that may be hedged, as a privacy and load control. |
| `query_timeout` | duration | `1500ms` | Per-attempt upstream timeout. |
| `explore_rate` | float | `0.02` | Fraction of queries deliberately routed to a non-optimal healthy route so that recovered upstreams can regain rank. |
| `circuit_failure_threshold` | integer | `5` | Consecutive failures before the circuit opens. |
| `circuit_open_duration` | duration | `20s` | How long the circuit stays open before a half-open probe is allowed. |
| `circuit_half_open_successes` | integer | `2` | Successful half-open probes required to close the circuit. |
| `emergency_fanout` | boolean | `true` | Permit a bounded emergency fan-out when every route is unhealthy. |
| `emergency_fanout_max` | integer | `3` | Maximum number of routes contacted during an emergency fan-out. |

### `[dnssec]`

DNSSEC validation policy.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | string: `"validate"` \| `"passthrough"` \| `"off"` | `validate` | Validation mode. |
| `trust_anchor_file` | path (optional) | unset | Replacement for the compiled-in IANA root anchors, in DNS presentation format — the same shape as the `root.key` written by `unbound-anchor`. **Fails closed**: if the file is missing, unreadable, or contains no usable DS or DNSKEY record, startup and reload are refused rather than silently falling back to the built-in anchors. Leave unset to use the compiled-in anchors. |
| `trust_upstream_ad` | boolean | `false` | Trust an upstream's AD bit. Only honoured for servers that also set `trust_ad` and use an authenticated transport. |
| `max_concurrent_validations` | integer | `256` | Global ceiling on DNSSEC validations running at once, enforced by a semaphore the resolver acquires before validating. A query that cannot get a permit inside the foreground budget is shed as SERVFAIL and counted in `dnssec_shed_total` rather than queueing without bound. **Restart-required**: the semaphore is created once at startup and shared by every resolver generation. |
| `max_validation_depth` | integer | `12` | Maximum delegation depth followed while building a validation chain, which bounds the work one hostile zone can force. Applied as the request depth limit on every validating lookup. |
| `validation_cache_entries` | integer | `10000` | Bound on the validation result cache. |
| `extended_errors` | boolean | `true` | Attach RFC 8914 Extended DNS Errors describing DNSSEC outcomes. |

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
| `server.udp.max_payload` must be between 512 and 4096. | RFC 1035 fixes the floor; RFC 9715 explains why anything above the path MTU causes fragmentation. The shipped default is 1232, and `config/egressdns.example.toml` documents 1400 as the only sane larger value. |
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
