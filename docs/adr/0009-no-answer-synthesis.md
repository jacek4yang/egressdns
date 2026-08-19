# ADR-0009: No answer synthesis, ever

**Status**: Accepted · **Date**: 2026-08

## Context

Resolvers are frequently asked to invent records. DNS64 synthesises AAAA from A. Split-horizon
setups synthesise CNAMEs. Filtering resolvers synthesise NXDOMAIN or a sinkhole address.
"Optimising" resolvers rewrite the `ipv4hint` in an HTTPS record. Each has a plausible local
justification.

## Decision

EgressDNS returns records that an upstream actually sent, or records the operator explicitly
configured as local data. It does not invent records. Specifically:

* No DNS64/NAT64 synthesis.
* No synthetic CNAMEs, ever, for any reason.
* No AAAA filtering, even when IPv6 egress is measured to be broken.
* No rewriting of SVCB/HTTPS parameters, including `ipv4hint`, `ipv6hint` and `ech`.
* No sinkholing or answer replacement as a feature.
* The one bounded exception — verified-augment mode — may *prepend* at most two addresses
  to an A or AAAA RRset, retains every original address, and only under the conditions in
  ADR-0010.

## Rationale

* **A synthesised record is indistinguishable from an attack.** From the client's seat, a
  resolver that returns an address the authoritative server did not publish and a
  successful on-path attacker are the same event. The only defence a client has is DNSSEC,
  and synthesis breaks it — which is precisely why the augment path requires a *proven*
  Insecure state before it may add anything.
* **The failure is silent and remote.** A wrong synthesis produces a connection to the
  wrong place, at some other layer, minutes later, on someone else's machine. It is the
  hardest class of bug to attribute back to the resolver.
* **AAAA suppression specifically.** It is tempting when IPv6 egress is bad: hide AAAA and
  clients "just work". But the resolver is answering for *clients*, whose connectivity may
  differ from its own, and clients already implement Happy Eyeballs, which solves this
  problem correctly at the layer that has the information. Hiding AAAA takes a decision
  away from the only component qualified to make it.
* **ECH makes hint rewriting actively dangerous.** An HTTPS record carrying an `ech`
  parameter describes a specific configuration; substituting an address that the published
  ECH config does not cover breaks the handshake the record exists to protect. So an
  ECH-bearing answer is excluded from augmentation entirely
  (`FallbackReason::EchUnvalidatable`).

## Consequences

* Operators who want filtering, sinkholing or DNS64 need a different or additional
  component. That is the right place for it: those are policy decisions with local
  justification, and they should be visible as their own thing rather than hidden inside a
  cache.
* `tests/properties.rs` asserts the invariant as a property, not just an example: the
  address set of an answer after policy is a permutation of the set before it, for every
  generated input, except in the explicitly bounded augment case.

## Revisit when

Never. If a future requirement seems to need synthesis, it needs a different component.
