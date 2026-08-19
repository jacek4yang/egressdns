# ADR-0007: Cleartext Do53 ingress only in v1.0.0

**Status**: Accepted · **Date**: 2026-08

## Context

The daemon speaks six transports *upstream* — UDP, TCP, DoT, DoH2, DoH3, DoQ. It would be
natural to offer the encrypted ones to clients too, and several comparable projects do.

## Decision

v1.0.0 accepts client queries over cleartext UDP and TCP on port 53 only. There is no DoT,
DoH or DoQ listener.

## Rationale

* **The threat this would address is not the threat that exists here.** Encrypted ingress
  protects the LAN segment between a client and the resolver. On a managed enterprise LAN
  that segment is already the operator's; the segment that is not theirs is the one to the
  Internet, and that one *is* encrypted, by default, in this design.
* **Every client on the target network already speaks Do53** and finds the resolver by
  DHCP/RA. An encrypted ingress that no client is configured to use is attack surface with
  no users.
* **The surface is not small.** Encrypted ingress means terminating TLS with a server
  certificate the operator has to obtain, renew and protect; an HTTP server on the request
  path; per-connection state that is attacker-controlled; and a new set of resource limits
  to get right. Priority 3 is bounded resources and priority 2 is availability. This is a
  large, uncompensated bet against both.
* **Doing it badly is worse than not doing it.** A DoH listener with a self-signed
  certificate that clients are told to trust is a downgrade, not an upgrade.

## Consequences

* Client queries on the LAN are visible to anyone who can see the LAN. This is stated
  plainly in `docs/THREAT_MODEL.md` rather than papered over, and the mitigation offered
  is a network-layer one (`packaging/nftables/egressdns.nft` restricts who can reach port
  53 at all).
* A client that wants encrypted DNS to *this* resolver cannot have it. A client that wants
  encrypted DNS in general can be pointed at an upstream directly, at which point this
  daemon is not in the path.
* Access control is therefore load-bearing. `server.allow_from` is default-deny and a
  non-loopback listener without an ACL is a configuration error, not a warning.

## Revisit when

Client platforms start defaulting to encrypted DNS *discovery* on the LAN — DDR
(RFC 9462) / DNR (RFC 9463) adoption reaching the point where a Do53-only resolver is
being bypassed by clients that would otherwise use it. At that point encrypted ingress
stops being unused surface and starts being the way clients find you.
