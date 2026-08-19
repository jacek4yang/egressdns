# ADR-0001: A forwarding cache, not an iterative resolver

**Status**: Accepted · **Date**: 2026-08 · **Supersedes**: nothing

## Context

The deployment target is an enterprise LAN with a single Internet egress. Something has to
answer DNS for the LAN. There are two shapes it could take:

1. An **iterative resolver** that starts at the root, follows delegations, and talks
   directly to authoritative servers.
2. A **forwarding cache** that sends every query to one or more configured upstream
   resolvers and caches what comes back.

## Decision

EgressDNS is a forwarding cache. It never queries a root or TLD server, and it has no
delegation-following logic.

## Rationale

* **The egress is single and shared.** An iterative resolver on a LAN generates a long tail
  of connections to thousands of authoritative servers, each a new NAT entry and a new
  cold path. A forwarder makes a handful of long-lived, warm, encrypted connections. On a
  single-egress network the second pattern is dramatically better for tail latency, which
  is priority 4 in this project's ordering.
* **Encrypted transport is available upstream, and only upstream.** DoT, DoH2, DoH3 and
  DoQ exist between a client and a resolver. Authoritative servers overwhelmingly speak
  cleartext Do53. An iterative resolver on this network would send the entire query stream
  over the shared egress in cleartext. A forwarder sends it inside TLS.
* **The optimization the project actually exists for needs a forwarder.** Cloudflare answer
  optimization compares what different vantage points return for the same name. That
  presupposes an upstream that has a vantage point. An iterative resolver would receive one
  authoritative answer and have nothing to compare.
* **Correctness surface is much smaller.** Delegation following, glue handling, zone-cut
  discovery, QNAME minimisation, and negative-trust-anchor logic are all places to be
  subtly wrong. Priority 1 is DNS correctness; the cheapest way to be correct is to not
  implement the hard part at all.

## Consequences

* The upstream resolver is trusted for *data* unless DNSSEC proves otherwise. This is why
  DNSSEC validation is on by default and why the AD bit from upstream is not trusted:
  the forwarder must be able to check the upstream's work.
* RFC 8020 (NXDOMAIN cut synthesis) and RFC 5011 (trust-anchor rollover) are out of scope,
  as recorded in `docs/RFC_COMPLIANCE.md` §5.
* If every configured upstream fails, this daemon cannot resolve at all. That is the
  motivation for serve-stale, the circuit breaker, and the multi-group configuration in
  `docs/OPERATIONS.md` §7.

## Revisit when

The deployment stops being single-egress — for example if the LAN gains diverse transit and
the operator wants independence from any external resolver operator. At that point the
right move is a separate iterative mode, not a bolt-on: the caching, policy and ranking
layers would be reusable, but the resolution core would not.
