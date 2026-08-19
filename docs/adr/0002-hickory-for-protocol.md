# ADR-0002: Hickory DNS for wire protocol and encrypted transports

**Status**: Accepted · **Date**: 2026-08

## Context

The daemon needs to encode and decode DNS messages and to speak UDP, TCP, DoT, DoH2, DoH3
and DoQ upstream. The project brief forbids hand-writing the DNS wire protocol, TLS,
HTTP/2, HTTP/3 or QUIC — and that prohibition matches good sense: each of those is a
decade of other people's security bugs.

## Decision

Use `hickory-proto` for message encode/decode and `hickory-net` for transports, on top of
`rustls` (ring), `quinn`, `h3` and `hyper`. Use `hickory-resolver` for connection pooling
and `hickory-net::dnssec` for validation. Pin to the 0.26 line.

## Alternatives considered

| Option | Why not |
| --- | --- |
| `domain` crate | Excellent message handling, but at the time of writing its transport story for DoH3/DoQ is thinner, and this project needs all six transports first-class. |
| `trust-dns` (pre-rename) | Same project, older name. Using the current name avoids a migration. |
| `simple-dns` + own transports | Puts the forbidden work back on us. |
| Bindings to `getdns`/`unbound` | A C dependency with its own memory-safety surface, and it would make `#![forbid(unsafe_code)]` meaningless. |

## Consequences

* Hickory's API shape leaks into ours in places — `Message`, `Record`, `Proof`,
  `DnsHandle`. This is accepted deliberately: wrapping every type would add a translation
  layer with its own bugs and no benefit.
* The 0.26 line moved transports out of `hickory-proto` into a new `hickory-net` crate.
  That churn is the cost of tracking a pre-1.0 dependency; the alternative is being stuck
  on a version that does not have DoH3.
* DNSSEC validation happens inside `DnssecDnsHandle`. To make it use our scheduler, cache
  and circuit breakers rather than opening its own connections, `src/dns/handle.rs`
  implements `DnsHandle` over our `Scheduler`. That adapter is the single integration
  point and is worth reading before changing anything in the DNSSEC path.
* `unsafe` is confined to dependencies. The crate itself is `#![forbid(unsafe_code)]`.

## Revisit when

Hickory reaches 1.0 (pin can relax), or if a transport we need stops being maintained
there. `cargo deny` is configured to fail on unmaintained advisories so this surfaces
early.
