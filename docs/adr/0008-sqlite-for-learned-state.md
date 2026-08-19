# ADR-0008: SQLite for learned state, dropped rather than allowed to block

**Status**: Accepted · **Date**: 2026-08

## Context

The daemon accumulates state worth keeping across restarts: per-address quality statistics,
the candidate pool and its verification stages, the last good official prefix snapshot, and
domain validation results. Losing it on restart means re-learning from scratch, which means
a window after every restart where ordering decisions have no evidence behind them.

## Decision

Persist to a single SQLite database in WAL mode, written from a **dedicated thread** fed by
a **bounded channel**. When the channel is full, writes are **dropped** and a counter is
incremented. Reads happen at startup only. If the file is corrupt, it is quarantined and a
fresh one is created.

## Rationale

* **SQLite over a flat file**: schema migrations, atomic transactions, and `PRAGMA
  quick_check` for corruption detection, none of which is worth reimplementing. `rusqlite`
  with the bundled build removes a system-library dependency.
* **Dedicated thread over async**: SQLite is synchronous. Calling it from an async task
  either blocks a runtime worker or needs `spawn_blocking` per write. A single owned thread
  with a channel is simpler and makes the concurrency story trivial: exactly one writer,
  ever.
* **Bounded and dropping, not bounded and blocking**: this is the important one. Persisted
  state is an *optimisation*. If the disk is slow, or full, or the queue is backed up, the
  correct behaviour is to lose statistics, not to slow down DNS. A blocking write on a full
  queue would reintroduce exactly the coupling ADR-0004 exists to prevent.
  `egressdns_storage_queue_depth` and `egressdns_storage_healthy` make the loss visible.
* **Quarantine over repair**: a corrupt state file is not worth heroics. Rename it aside,
  log loudly, start clean. Resolution never stops, and the operator has the artifact if
  they want to look at it.

## Consequences

* Under sustained write pressure, some quality samples are lost. The model is designed for
  this: it is a decayed posterior over many observations, not an exact ledger.
* The database is not a source of truth for anything correctness-critical. Deleting it is a
  supported operation (`docs/OPERATIONS.md` §10) and costs only warm-up time.
* Two daemons must not share a file. This is documented in the DNS-A/DNS-B section rather
  than enforced, because enforcing it would need locking that could itself block.

## Revisit when

Write volume grows enough that dropping becomes routine rather than exceptional. The fix
then is to sample harder before the queue, not to make the queue blocking.
