# ADR-0004: Strict separation of the foreground data plane from the background control plane

**Status**: Accepted · **Date**: 2026-08

## Context

This daemon does two very different kinds of work. It answers DNS queries, where the budget
is microseconds for a cache hit and a few milliseconds for a miss. And it measures the
network — probing addresses, fetching prefix lists, sampling, computing quality statistics
— where the budget is minutes and the work is inherently unreliable.

The failure mode to avoid is the one every "smart" resolver eventually hits: a client query
waits on a measurement, and a slow measurement becomes a slow answer.

## Decision

The foreground path never performs, awaits, or is scheduled behind background work. The
boundary is enforced structurally, not by convention:

* **Immutable snapshots.** Background tasks publish results by building a new value and
  `ArcSwap`-ing it in. The foreground path does one atomic load per request and reads a
  consistent snapshot. It never takes a lock that a background task can hold.
* **Bounded non-blocking queues.** When the foreground path wants to *suggest* a
  measurement, it calls `ProbeQueue::offer`, which returns `false` immediately if the queue
  is full. There is no `send().await` anywhere on the request path.
* **Separate task supervision.** Every background task runs under `tasks::supervise`, which
  isolates panics and restarts with backoff. A background task that dies does not take the
  listener with it.
* **No shared budget.** `server.foreground_budget` bounds the request path. Probe
  bandwidth, rate and concurrency budgets are entirely separate, so exhausting one cannot
  starve the other.

## Rationale

Priorities 2 (availability) and 4 (tail latency) both fail the same way if this boundary is
soft. A p99 that occasionally includes "we happened to be fetching a prefix list" is
indistinguishable, from a user's seat, from a broken resolver.

It also makes the degradation story provable rather than aspirational: if every background
subsystem is dead, the foreground path still has a valid (if stale) snapshot, the queue
`offer`s all return `false`, and resolution continues. `tests/cloudflare_security.rs`
asserts exactly this.

## Consequences

* Background results are always slightly stale from the foreground's point of view. That is
  the correct trade: an answer ordered by 30-second-old evidence is fine; an answer that
  arrives 300 ms late is not.
* `ArcSwap` snapshots mean a reload allocates a whole new state tree. This costs a few
  hundred kilobytes at reload time and buys atomicity — a request either sees the entire
  old configuration or the entire new one.
* Some information the foreground path would like (has this exact address been probed since
  the last network change?) is only available as of the last snapshot. The ranking model
  handles this by treating unknown as *neutral* rather than bad, per ADR-0010.

## Revisit when

Never, in this shape of daemon. If a future feature seems to need synchronous background
work on the request path, that is a signal the feature is wrong, not the boundary.
