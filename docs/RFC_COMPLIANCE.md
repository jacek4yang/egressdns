# RFC compliance matrix

This document records, for every standard EgressDNS implements or deliberately
declines to implement, **what** the requirement is, **where** it is realised in the
tree, and **how** it is tested. "Delegated" means the behaviour is provided by a
vendored crate (Hickory DNS, rustls, quinn, h3, hyper) rather than by code in this
repository; EgressDNS still owns the configuration and the failure semantics around
it, and those are listed.

Legend for **Status**:

| Symbol | Meaning |
| --- | --- |
| Full | Implemented in this repository and exercised by tests. |
| Delegated | Provided by a dependency; EgressDNS configures and constrains it. |
| Partial | Implemented for the subset that a forwarding cache needs; the excluded part is stated. |
| N/A | Out of scope for a forwarder; the reason is stated. |

---

## 1. Core protocol

### RFC 1034 / RFC 1035 — Domain names, concepts and specification

* **Status**: Delegated (wire format) + Full (server semantics).
* **Where**: message encode/decode is `hickory-proto`. EgressDNS owns
  `src/dns/message.rs` (`serialize_limited`, `question_matches`,
  `answer_fingerprint`), `src/dns/resolver.rs` (the query pipeline), and
  `src/dns/server.rs` (UDP/TCP ingress).
* **Notes**: EgressDNS never hand-writes wire format — no manual label parsing,
  no manual compression pointers. `serialize_limited` uses
  `BinEncoder::set_max_size` and re-encodes with the TC bit set when the answer
  does not fit, so compression pointer correctness stays inside the library.
* **Tests**: `tests/resolution.rs::forwards_and_caches_a_records`,
  `::large_answers_set_tc_on_udp_and_fit_on_tcp`, and
  `src/dns/message.rs::tests::serialize_sets_tc_when_too_large`,
  `::serialize_keeps_small_messages_intact`,
  `::fingerprint_is_order_independent`.

### RFC 2181 — Clarifications to the DNS specification

* **Status**: Full.
* **Where**: `src/policy/ttl.rs`, `src/policy/answer.rs`, `src/cache/mod.rs`.
* **Requirements honoured**:
  * §5.2 — TTLs within an RRset are treated as a unit. The cache stores one TTL
    per cached message and `effective_client_ttl()` takes the **minimum** across
    the answer, so an RRset can never be served with inconsistent TTLs.
  * §5.4 — ranking of data. EgressDNS never merges records from two upstream
    responses into one answer; a cached entry always originates from exactly one
    response (`CacheEntry.source` records which server and transport produced it).
  * §9 — the TC bit means the *message* was truncated, so a truncated UDP reply is
    retried over a stream transport rather than parsed opportunistically
    (`src/upstream/scheduler.rs::stream_retry`).
* **Tests**: `tests/resolution.rs::truncated_udp_answers_are_retried_over_tcp`,
  `::client_ttl_is_capped_but_never_extended`,
  `src/policy/ttl.rs::tests::never_exceeds_remaining_authoritative_ttl`,
  `tests/properties.rs::client_ttl_never_exceeds_the_authoritative_remainder`,
  `tests/properties.rs::per_record_ttls_are_only_ever_reduced`.

### RFC 2308 — Negative caching of DNS queries

* **Status**: Full.
* **Where**: `src/policy/ttl.rs::negative_ttl`, `src/cache/mod.rs`
  (`EntryKind::NegativeNoData`, `EntryKind::NegativeNxDomain`).
* **Requirements honoured**: NXDOMAIN and NODATA are cached; the negative TTL is
  `min(SOA.MINIMUM, SOA record TTL, configured negative ceiling)`. A negative answer
  with no SOA is cached only for the configured floor.
* **Tests**: `tests/resolution.rs::negative_answers_are_cached` (covers both NXDOMAIN and
  NODATA), plus `src/policy/ttl.rs::tests::caps_follow_the_documented_ordering`.

### RFC 3596 — DNS extensions to support IPv6

* **Status**: Full. AAAA is a first-class type throughout; there is **no** AAAA
  filtering, AAAA synthesis, or AAAA suppression anywhere in the tree.
* **Where**: `src/policy/answer.rs` treats A and AAAA RRsets symmetrically.
* **Tests**: `tests/resolution.rs::a_and_aaaa_are_independent`,
  `tests/properties.rs::ipv6_answers_are_also_permutations`,
  `tests/properties.rs::unknown_addresses_are_never_dropped`.

### RFC 6891 — Extension mechanisms for DNS (EDNS(0))

* **Status**: Full.
* **Where**: `src/dns/message.rs` (OPT handling), `src/config/validate.rs`
  (payload bounds), `src/dns/resolver.rs` (response OPT construction).
* **Requirements honoured**: the OPT pseudo-RR is never cached as an RR; the
  advertised payload size is a configured value, not echoed from the client; the
  EDNS version is 0 and a client advertising a higher version receives BADVERS.
* **Tests**: `tests/resolution.rs::unsupported_edns_version_yields_badvers`,
  `tests/resolution.rs::a_client_without_edns_never_receives_an_opt_record`.

---

## 2. Transports

### RFC 7766 — DNS transport over TCP, implementation requirements

* **Status**: Full.
* **Where**: `src/dns/server.rs` (TCP listener), `src/upstream/pool.rs`
  (upstream TCP).
* **Requirements honoured**: two-octet length prefix; connection reuse; multiple
  queries may be in flight on one connection and responses may be returned out of
  order; per-connection idle timeout; a bounded number of concurrent connections
  with the oldest idle connection closed first under pressure.
* **Truncation retry (§5, and RFC 1035 §4.2.1)**: a truncated UDP answer is retried
  over a stream transport **to the same server**, never parsed opportunistically.
  Because that retry has to be possible from any configuration, every server declared
  as `transport = "udp"` is given a companion TCP route to the same address and port,
  built automatically in `src/upstream/pool.rs`. The companion is used for truncation
  retries only and is excluded from ordinary route ranking, so an operator who asked
  for UDP does not silently get a share of their traffic over TCP. Without it, a
  UDP-only upstream group — an entirely reasonable configuration — turned every answer
  over 512 bytes into SERVFAIL.
* **Tests**: `tests/transports.rs::upstream_over_tcp`,
  `tests/resolution.rs::tcp_pipelining_answers_every_query`,
  `tests/resolution.rs::out_of_order_completion_is_permitted_on_tcp`,
  `tests/resolution.rs::truncated_udp_answers_are_retried_over_tcp`,
  `tests/resolution.rs::a_udp_only_upstream_still_retries_a_truncated_answer_over_tcp`,
  `src/upstream/pool.rs::tests::a_udp_only_server_gets_a_tcp_companion_for_truncation_retries`.

### RFC 7828 — The edns-tcp-keepalive EDNS(0) option

* **Status**: Full.
* **Where**: `src/dns/message.rs::keepalive_option`, `src/dns/server.rs`.
* **Requirements honoured**: the option is only ever sent on TCP-family transports,
  never on UDP; the advertised timeout matches the idle timeout the server will
  actually enforce; a client that sends the option receives it back with the
  server's value.
* **Tests**: `src/dns/message.rs::tests` option-encoding cases, and the
  `src/dns/server.rs` TCP idle-timeout unit tests.

### RFC 7858 — Specification for DNS over TLS (DoT)

* **Status**: Delegated to `hickory-net` + `tokio-rustls`; Full for policy.
* **Where**: `src/tls.rs` (roots, verifier, ALPN, no early data),
  `src/upstream/pool.rs` (route construction).
* **Requirements honoured**: strict privacy profile — the authentication domain
  name is always verified; a certificate failure is a hard route failure, never a
  silent downgrade to cleartext. Optional SPKI pinning is layered on top via
  `CapturingClientConfig` and the bounded DER walker in `src/util/der.rs`.
* **Tests**: `tests/transports.rs::upstream_over_dns_over_tls`,
  `::an_untrusted_upstream_certificate_is_refused`,
  `::a_wrong_server_name_is_refused`.

### RFC 8310 — Usage profiles for DNS over TLS and DTLS

* **Status**: Partial (TLS profiles only; DTLS is not implemented and is not
  required for any deployment target).
* **Where**: `src/tls.rs`, `src/config/validate.rs`.
* **Notes**: only the *strict* profile is offered. There is no opportunistic mode,
  because an opportunistic encrypted transport that silently falls back is worse
  than a cleartext transport that is honest about being cleartext.

### RFC 8484 — DNS queries over HTTPS (DoH)

* **Status**: Delegated to `hickory-net` + `hyper`; Full for policy.
* **Where**: `src/upstream/pool.rs`, `src/config/mod.rs` (`DohPath`).
* **Requirements honoured**: POST is used for upstream queries so that the DNS
  message is not reflected in a URL; the media type is
  `application/dns-message`; HTTP status codes other than 200 are route failures,
  and a 421 is never treated as a usable answer.
* **Tests**: `tests/transports.rs::upstream_over_dns_over_https_h2`;
  the 421 rule is asserted by
  `tests/cloudflare_security.rs::http_421_prevents_promotion_while_403_and_404_do_not`.

### RFC 9114 / RFC 9250 — HTTP/3 and DNS over QUIC (DoQ)

* **Status**: Delegated to `quinn` + `h3`; Full for policy.
* **Where**: `src/upstream/pool.rs`, `src/probe/quic.rs`, `src/config/validate.rs`.
* **Requirements honoured**: ALPN is `doq` for DoQ and `h3` for DoH3; the DoQ
  message ID is zero on the wire; QUIC 0-RTT is **refused by configuration** —
  `validate()` rejects `quic_zero_rtt = true` — because a replayable DNS query is
  a cache-poisoning primitive, and rustls is additionally configured to never
  send early data.
* **Tests**: `tests/transports.rs::upstream_over_dns_over_quic`,
  `::upstream_over_dns_over_https_h3`,
  `::every_transport_answers_from_one_configuration`, and
  `src/config/validate.rs::tests::quic_zero_rtt_cannot_be_enabled`.

### RFC 9715 — IP fragmentation avoidance in DNS over UDP

* **Status**: Full.
* **Where**: `src/config/defaults.rs`, `src/config/validate.rs`, `src/dns/server.rs`.
* **Requirements honoured**: the default advertised EDNS payload size is **1232**
  octets, and the configured ceiling may not exceed **1400**. `IP_MTU_DISCOVER` /
  `IPV6_MTU_DISCOVER` are set so the kernel does not fragment on send. Anything
  larger than the advertised size is truncated with TC set and retried over TCP.
* **Tests**: `src/config/validate.rs::tests::the_shipped_defaults_are_valid` (the shipped
  default is 1232) and
  `tests/resolution.rs::large_answers_set_tc_on_udp_and_fit_on_tcp`.

---

## 3. Security and integrity

### RFC 4033 / RFC 4034 / RFC 4035 — DNSSEC

* **Status**: Delegated validation (`hickory-net::dnssec::DnssecDnsHandle` with
  `dnssec-ring`); Full for state machine and policy.
* **Where**: `src/policy/dnssec.rs`, `src/dns/handle.rs` (`SchedulerHandle`
  implements `DnsHandle` so DNSKEY/DS lookups traverse the same scheduler,
  circuit breakers and cache as ordinary traffic).
* **Requirements honoured**:
  * A **Bogus** result is returned as SERVFAIL with EDE 6 (DNSSEC Bogus). It is
    never converted into an unvalidated answer. DNSSEC never fails open.
  * The AD bit from an upstream is **not** trusted by default
    (`trust_upstream_ad = false`); AD is only set on a response when this resolver
    itself proved Secure, or when the operator has explicitly opted in for a
    specific upstream over an authenticated channel.
  * The CD bit is honoured: a client that sets CD receives unvalidated data and
    the resolver does not apply its own bogus-suppression to that response.
  * Cached entries are keyed on the DNSSEC mode (`dnssec_ok`, `checking_disabled`)
    so a CD=1 answer can never be served to a CD=0 client.
* **Deliberate non-goal**: EgressDNS is a forwarder, not an iterative resolver, so
  it does not build a chain of trust from the root by itself when the upstream
  refuses to supply the necessary records; in that case the result is Indeterminate,
  which is treated as "no proof", not as "proof of failure".
* **Tests**: `src/policy/dnssec.rs::tests` covers every `Proof` value
  (`all_secure_is_secure`, `one_bogus_record_makes_the_answer_bogus`,
  `one_indeterminate_record_makes_the_answer_indeterminate`,
  `validation_disabled_is_indeterminate_not_secure`), the AD-trust switch
  (`upstream_ad_is_only_trusted_when_explicitly_configured`,
  `ad_is_never_claimed_for_modified_data`), and
  `src/cache/mod.rs::tests::bogus_is_never_cached_or_served`;
  `tests/cloudflare_security.rs::signed_or_unknown_answers_never_gain_addresses`
  asserts that a Secure or Indeterminate answer is never augmented;
  `src/cache/mod.rs::tests` asserts DnssecMode participates in the cache key.

### RFC 5452 — Measures for making DNS more resilient against forged answers

* **Status**: Full.
* **Where**: `src/upstream/scheduler.rs::validate_response`, `src/dns/message.rs`.
* **Requirements honoured**: cryptographically random message IDs and source
  ports (delegated to the OS and Hickory); **0x20 case randomisation** on outgoing
  QNAMEs with a case-insensitive comparison of the echoed question on return; a
  response is accepted only if the ID, source address, source port, and question
  all match the outstanding query. Mismatches increment a metric and are dropped
  rather than answered.
* **Tests**: `src/dns/message.rs::tests::question_matching_is_case_insensitive` and
  `::question_mismatch_is_detected` (the comparison used by
  `scheduler::validate_response`); `tests/transports.rs::a_wrong_server_name_is_refused`.
  Case randomisation itself is switched on in `src/dns/resolver.rs` and
  `src/upstream/pool.rs` via `DnsRequestOptions::case_randomization`.

### RFC 7873 / RFC 9018 — DNS cookies

* **Status**: Full for the client side; server side accepts and echoes.
* **Where**: `src/dns/message.rs` (cookie option), `src/config/mod.rs`
  (`enable_cookies` tri-state).
* **Requirements honoured**: cookies are offered on **UDP and TCP only**. On an
  already-authenticated transport (DoT, DoH2, DoH3, DoQ) they add nothing and are a
  stable client identifier, so the tri-state default resolves to *off* there; the
  configuration validator rejects an explicit `enable_cookies = true` on those
  transports.
* **Tests**: `src/config/validate.rs::tests` cookie/transport interaction cases, and the
  `cookie_round_trip` / `cookie_rejects_short_server_cookie` cases in
  `src/dns/message.rs::tests`.

### RFC 7871 — Client subnet in DNS queries (ECS)

* **Status**: Full, and **off by default**.
* **Where**: `src/dns/message.rs`, `src/config/validate.rs`, `src/cache/mod.rs`
  (`PolicyView` participates in the cache key).
* **Requirements honoured**: ECS is never enabled implicitly. When enabled, only
  an operator-configured **public** prefix is sent (the validator rejects private,
  loopback, link-local and special-use ranges), the source prefix length is capped,
  and the scope returned by the upstream participates in the cache key so a
  scoped answer is never served to a client outside that scope.
* **Tests**: `src/config/validate.rs::tests::ecs_rejects_private_prefixes` and the
  `src/cache/mod.rs::tests` keying cases
  (`keys_are_case_insensitive_but_type_sensitive`,
  `variants_are_bounded_and_never_merged`).

### RFC 8482 — Providing minimal-sized responses to DNS queries with QTYPE=ANY

* **Status**: Full.
* **Where**: `src/dns/resolver.rs`.
* **Requirements honoured**: QTYPE=ANY is answered with a single HINFO RR
  ("RFC8482") rather than an amplification-friendly dump of the cache. The
  behaviour is configurable but defaults to minimal.
* **Tests**: `tests/resolution.rs::any_queries_get_a_minimal_answer_by_default`.

### RFC 8914 — Extended DNS errors (EDE)

* **Status**: Full.
* **Where**: `src/dns/message.rs::push_ede`, used across `src/dns/resolver.rs`.
* **Codes emitted** (the complete set — `grep ExtendedError:: src/` is
  authoritative and short by design):

  | Code | Name | Emitted when |
  | --- | --- | --- |
  | 0 | Other | Generic fallback, only from the message helper's default path. |
  | 3 | Stale Answer | A positive answer was served from expired cache data. |
  | 6 | DNSSEC Bogus | Validation failed; the response is SERVFAIL. |
  | 19 | Stale NXDOMAIN Answer | An expired negative answer was served. |
  | 22 | No Reachable Authority | Every eligible upstream failed. |
  | 23 | Network Error | The answer came from the RFC 9520 failure cache. |

* **Notes**: EDE is informational — it is attached to the response, never used to
  change the RCODE, and never populated with text that could echo attacker input.
  The extra-text field is a fixed, bounded, compiled-in string
  (`src/dns/message.rs::encode_ede` truncates it), so a malicious name cannot be
  reflected into another resolver's logs through this daemon. EDE is emitted only
  when `dnssec.extended_errors` is true (the default); it can be switched off
  wholesale for deployments that consider it a fingerprinting surface.
* **Tests**: `tests/scheduling.rs::stale_data_is_served_when_every_upstream_fails`
  (EDE 19 on the stale reply), `tests/resolution.rs::clients_outside_the_acl_are_refused`,
  and `src/dns/message.rs::tests::ede_round_trip` / `::ede_text_is_bounded`.

### RFC 9520 — Negative caching of DNS resolution failures

* **Status**: Full.
* **Where**: `src/cache/mod.rs::FailureEntry`, `src/upstream/health.rs`,
  `src/config/validate.rs`.
* **Requirements honoured**: a resolution *failure* (timeout, network error,
  SERVFAIL) is cached for at least **1 second** and at most **5 minutes**; the
  validator enforces both bounds. Failure caching is keyed separately from positive
  caching so it cannot displace good data.
* **The ≤3 attempts ceiling (§3.2)** is satisfied *structurally* rather than by a
  setting. One resolution makes at most **one** attempt per route, and a route is one
  (server, transport, address) triple, so a single resolution can never reach the
  ceiling. There used to be a `max_attempts_per_route` key; it was removed, because a
  configuration knob that cannot change the behaviour it names is worse than no knob —
  it invites an operator to believe they are tuning something. Repeated *client*
  queries are bounded by the failure cache instead, which is the mechanism the RFC
  actually asks for.
* **Tests**: `tests/resolution.rs::resolution_failures_are_suppressed_and_do_not_hammer_the_upstream`
  (asserts the upstream sees a bounded number of attempts) and
  `src/cache/mod.rs::tests::failure_cache_expires`.

### RFC 8767 — Serving stale data to improve DNS resiliency

* **Status**: Full.
* **Where**: `src/cache/mod.rs` (`Lookup::Stale`), `src/dns/resolver.rs`.
* **Requirements honoured**: stale data is served **only** after an attempt to
  refresh has failed or exceeded the client timeout (default 1.8 s, spec suggests
  ≤1.8 s); the stale TTL handed to the client is a small fixed value (default 30 s),
  never the original TTL; the maximum stale age is bounded (default 24 h, spec
  ceiling 7 days); a stale answer carries EDE 19. The refresh task is detached and
  races the client timeout, so the client is never blocked on a dead upstream.
* **Tests**: `tests/scheduling.rs::stale_data_is_served_when_every_upstream_fails`,
  `::all_upstreams_failing_without_stale_data_returns_servfail`,
  `tests/transports.rs::a_dead_upstream_does_not_stall_the_client`, and
  `src/cache/mod.rs::tests::fresh_then_stale_then_gone`.

### RFC 9460 — SVCB and HTTPS resource records

* **Status**: Full (as data). SVCB/HTTPS RRs are cached and returned unmodified.
* **Where**: `src/policy/answer.rs` explicitly excludes SVCB/HTTPS from any
  reordering or augmentation.
* **Notes**: EgressDNS does **not** rewrite `ipv4hint`/`ipv6hint`, does not
  synthesise HTTPS records, and does not strip them. Rewriting a hint would be
  indistinguishable from an on-path attacker doing the same thing.
* **Tests**: `tests/resolution.rs::record_types_other_than_a_and_aaaa_pass_through_unchanged`,
  `tests/properties.rs::only_address_records_move`,
  `src/policy/answer.rs::tests::other_record_types_are_untouched`.

### RFC 9849 — Encrypted ClientHello (ECH) configuration in SVCB/HTTPS

* **Status**: Partial — pass-through and preservation, no ECH client.
* **Where**: `src/policy/answer.rs`, `src/policy/cloudflare.rs`.
* **Notes**: the `ech` SvcParam is preserved byte-for-byte. Critically, an HTTPS
  RRset that carries an `ech` parameter is **excluded from Cloudflare address
  augmentation** entirely: prepending an address that was not covered by the
  published ECH configuration would break the very handshake the record exists to
  protect. Published March 2026; see `docs/RESEARCH.md` §4.
* **Tests**: `src/policy/cloudflare.rs::tests::unvalidatable_ech_falls_back_to_preserve`
  (an answer carrying SvcParamKey 5 forces `Mode::Preserve` with
  `FallbackReason::EchUnvalidatable`, so no address is ever added).

---

## 4. Operational and adjacent standards

### RFC 6761 / RFC 6762 / RFC 7686 / RFC 8375 — Special-use domain names

* **Status**: Full, with one documented deviation (`test.`, below).
* **Where**: `src/dns/specialuse.rs` (the registry table and classifier),
  `src/dns/resolver.rs::special_use_answer`, `src/datasets/zones.rs`.
* **Requirements honoured**:

  | Name | RFC | Behaviour |
  | --- | --- | --- |
  | `localhost.` and descendants | 6761 §6.3 | A → `127.0.0.1`, AAAA → `::1`, every other type NODATA. Never forwarded. |
  | `invalid.` | 6761 §6.4 | NXDOMAIN, never forwarded. |
  | `local.` | 6762 §22 | NXDOMAIN, never forwarded — mDNS names are not DNS names. |
  | `home.arpa.` | 8375 | NXDOMAIN unless the operator has configured it. |
  | `onion.` | 7686 §2 | NXDOMAIN, never forwarded. |
  | `10.in-addr.arpa.`, `16–31.172.in-addr.arpa.`, `168.192.in-addr.arpa.`, `254.169.in-addr.arpa.`, `8/9/a/b.e.f.ip6.arpa.`, `c/d.f.ip6.arpa.` | 6761 §6.1, 6890 | NXDOMAIN, never forwarded — a reverse lookup for a LAN address is a map of the LAN. |

* **Precedence**: configured hosts and local zones are consulted *first*, and an
  explicit `[[local.suffix_rules]]` entry covering a registry name disables the
  registry default for that subtree. That is the supported way to point
  `home.arpa.` at an internal resolver. The whole mechanism is switchable with
  `server.special_use = "forward"`.
* **Matching**: whole labels only. `notlocal.` is not `local.`,
  `local.example.com.` is not `.local`, and `1.2.15.172.in-addr.arpa.` is not
  inside `172.16/12`.
* **Documented deviation**: `test.` (RFC 6761 §6.2) is classified but **not**
  blocked. §6.2 instructs caching servers not to query *authoritative* servers for
  test names; this daemon is a forwarder and never contacts an authoritative
  server. `.test` is simultaneously the TLD the IETF recommends for local
  development, whose resolver is normally exactly the configured upstream, so
  returning NXDOMAIN would break more deployments than it protects. The rationale
  is recorded in `src/dns/specialuse.rs` next to the table.
* **Tests**: `src/dns/specialuse.rs::tests` (all four cases, including the
  label-boundary and "ordinary names are forwarded" sets),
  `tests/resolution.rs::special_use_names_are_answered_locally_and_never_forwarded`
  (asserts the upstream query count stays at zero),
  `::a_configured_local_zone_overrides_the_special_use_registry`,
  `tests/scheduling.rs::local_zones_and_hosts_answer_without_any_upstream`,
  `src/datasets/zones.rs::tests::more_specific_zone_wins`.

### RFC 6890 / RFC 5735 / RFC 4193 / RFC 3927 — Special-purpose address registries

* **Status**: Full.
* **Where**: `src/util/ipclass.rs`.
* **Notes**: the tables include the IANA special-purpose registries **plus** the
  cloud instance-metadata addresses (`169.254.169.254`, `fd00:ec2::254`,
  `100.100.100.200`, `192.0.0.192`) which are not in any RFC registry but are the
  highest-value SSRF target on any cloud host. The probe safety guard refuses these
  unconditionally — an operator-supplied exception cannot re-enable them.
* **Tests**: `src/util/ipclass.rs::tests::metadata_is_blocked`,
  `::private_and_loopback_blocked`, `::documentation_and_benchmarking_blocked`,
  `::ipv4_mapped_v6_is_special`;
  `src/probe/safety.rs::tests::explicit_exception_allows_private_but_never_link_local`
  and `::special_use_targets_are_refused`;
  `src/config/validate.rs::tests::probe_exceptions_can_never_cover_metadata_ranges`; and
  `tests/cloudflare_security.rs::private_and_metadata_addresses_from_an_external_source_are_rejected`.

### RFC 7626 — DNS privacy considerations

* **Status**: Full, as design constraints rather than a wire feature.
* **Notes**: QNAME and client address are never written to disk; the SQLite store
  holds only aggregate address-quality statistics keyed by
  `(addr, port, profile)` — no names, no client identifiers. Query logging is
  off by default and, when on, is rate-limited and sampled.

### RFC 8020 — NXDOMAIN really means there is nothing underneath

* **Status**: N/A for a forwarder. EgressDNS does not synthesise NXDOMAIN for
  child names from a cached parent NXDOMAIN, because it does not know the zone cuts
  the upstream is using and a wrong synthesis is unrecoverable for the client.

### RFC 5011 — Automated updates of DNSSEC trust anchors

* **Status**: N/A. A forwarder that validates uses the compiled-in root trust
  anchor set from `hickory-proto`. Rolling the root KSK is a package update, which
  is auditable, rather than a silently self-modifying on-disk anchor.

### RFC 1996 / RFC 2136 / RFC 5936 — NOTIFY, dynamic update, AXFR

* **Status**: N/A. EgressDNS is not authoritative. These opcodes/types are
  answered with NOTIMP or REFUSED and are never forwarded.
* **Tests**: `tests/resolution.rs::unsupported_opcode_and_class_are_rejected_cleanly`.

---

## 5. Where compliance is *not* claimed

Stating this plainly is part of the contract:

1. **No iterative resolution.** EgressDNS never queries a root or TLD server. Every
   answer comes from a configured upstream. RFC 1034 §5.3.3 resolution algorithm is
   therefore out of scope.
2. **No DNS64/NAT64 (RFC 6147).** Synthesising AAAA from A is address forgery from
   the client's point of view, and the spec for this project forbids synthetic
   answers.
3. **No DTLS (RFC 8094).** Not deployed anywhere that matters; adding an
   under-tested encrypted transport enlarges the attack surface for no gain.
4. **No DNS over HTTP/1.1 for ingress.** The server side of this daemon speaks
   Do53 (UDP/TCP) only. Encrypted ingress is a documented non-goal for v1.0.0 — see
   `docs/adr/0007-do53-only-ingress.md`.
5. **No EDNS Padding (RFC 7830) on ingress**, because ingress is cleartext Do53 on
   a LAN and padding there is theatre. Padding on *upstream* encrypted transports is
   whatever the negotiated transport does.
