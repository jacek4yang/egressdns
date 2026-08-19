# ADR-0005: Third-party candidate lists are untrusted input, not data

**Status**: Accepted · **Date**: 2026-08

## Context

Community-maintained lists of "fast Cloudflare IPs" exist and are widely used. During
research for this project three such endpoints were fetched live
(`cf.090227.xyz/ct?ips=6`, `/cu`, `/cmcc?ips=8`) and their contents examined. Roughly a
quarter of the addresses in one list were **not** in any Cloudflare-published prefix. The
captured responses are preserved as fixtures under `tests/fixtures/`.

An address from such a list, inserted into a DNS answer, is an address the operator did not
choose, serving traffic for a name the operator does not control. If it is not actually
Cloudflare's, it is somebody's proxy.

## Decision

A third-party list is treated as an **untrusted hint about which addresses to test**, never
as an answer. Every candidate must pass, in order:

1. **Strict parsing.** The parser accepts only documented forms and rejects HTML, JSON, and
   hostnames whose final label is numeric. A list that starts returning a login page must
   not be silently interpreted.
2. **Official prefix membership.** The address must fall inside a prefix published by
   Cloudflare itself. This is the definition of "is a Cloudflare address"; nothing else
   counts, and the check is against a snapshot fetched from Cloudflare, not against
   anything the list supplied.
3. **Special-use rejection.** Private, loopback, link-local, multicast, documentation and
   cloud-metadata addresses are refused unconditionally.
4. **Bounded admission.** The pool has a hard size cap and an hourly admission budget, so a
   hostile list cannot flood it.
5. **Local protocol validation.** TCP 443, then a TLS handshake with the *origin's* SNI
   verified against the public root store, then an HTTP exchange, then repeated success
   over time before the address is eligible for anything.

Only after all five does an address become a candidate — and even then it can only be used
under the conditions in ADR-0010.

## Explicitly excluded

Per the project brief, and independently correct: no reverse-proxy IPs, no proxy-IP
services, no relay servers, no anonymous proxies, no Workers relays, no VLESS nodes, no
tunnel relays, and no unrelated intermediary servers may ever appear as a DNS answer
address. There is no configuration that enables this, and
`tests/cloudflare_security.rs::the_repository_contains_no_third_party_relay_data_source`
scans the whole tree to assert that no such concept exists in the source.

## Consequences

* Most of what a seed list offers is discarded. `cloudflare_candidate_rejected_total`
  being large is the system working, and `docs/OPERATIONS.md` §16 says so explicitly, so an
  operator does not "fix" it.
* Seed endpoints are optional. All of them failing degrades to sampling official prefixes
  directly; that failing degrades to preserve mode; that failing degrades to plain
  forwarding.
* The verification pipeline costs bandwidth and time. Both are budgeted and both are
  background work (ADR-0004).

## Revisit when

Never for the trust direction. The admission pipeline's *stages* can change — for example
if Cloudflare publishes a signed endpoint list — but "an address is Cloudflare's because
Cloudflare says so, not because a list says so" is not negotiable.
