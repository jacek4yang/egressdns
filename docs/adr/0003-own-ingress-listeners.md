# ADR-0003: Own UDP/TCP ingress instead of `hickory-server::ServerFuture`

**Status**: Accepted · **Date**: 2026-08

## Context

`hickory-server` provides `ServerFuture`, which binds sockets, parses requests, and calls a
`RequestHandler`. Using it would have removed a few hundred lines from this project.

## Decision

Implement the UDP and TCP listeners directly in `src/dns/server.rs`, using `socket2` for
socket options and Tokio for the event loop. Keep `hickory-server` as a **dev-dependency**
only, where it provides DoT/DoH2/DoH3/DoQ *test servers*.

## Rationale

The foreground path is priority 4 (tail latency) and priority 3 (bounded resources), and
both need control that `ServerFuture` does not expose:

1. **Per-socket options.** `IP_MTU_DISCOVER` / `IPV6_MTU_DISCOVER` to avoid fragmentation
   (RFC 9715), `IPV6_V6ONLY` so a v6 listener does not silently swallow v4,
   `SO_REUSEPORT` with a worker per socket, and explicit `SO_RCVBUF`/`SO_SNDBUF`. Getting
   fragmentation avoidance right is a correctness requirement, not a tuning preference.
2. **Explicit inflight accounting.** The ingress owns a bounded inflight counter and a
   cancellation token, so shutdown drains rather than drops, and overload sheds load at a
   defined point instead of growing a queue.
3. **Response size policy.** The maximum response size depends on the client's advertised
   EDNS payload, our configured ceiling, and the transport. `serialize_limited` re-encodes
   with TC set when the answer does not fit. Doing this above a generic server abstraction
   means computing the limit twice and hoping the two agree.
4. **Reading state per request.** Every request reads an `ArcSwap` snapshot of runtime
   state exactly once, so a configuration reload is atomic from the request's point of
   view. That is a property of our ingress loop, not of the handler.

## Consequences

* We own the accept loop, the TCP length-prefix framing, the idle timeout, the connection
  cap, and out-of-order response support on TCP (RFC 7766). All of these are tested
  directly.
* Using `hickory-server` in tests means the six upstream transports are verified against a
  real independent implementation rather than a mock we wrote to match our own
  assumptions. This turned out to be the highest-value use of the crate.

## Revisit when

`hickory-server` grows the socket-option and inflight-accounting hooks this needs. The
handler logic is already separate (`Resolver::handle`), so switching would be a change to
one file.
