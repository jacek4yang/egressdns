# ADR-0010: Preserve is the default; augmentation must earn its place

**Status**: Accepted · **Date**: 2026-08

## Context

The optimization this project exists for can act on an answer in two ways:

* **Preserve mode** — reorder addresses *within* a single complete A or AAAA RRset. No
  address is added, removed, or moved between RRsets. The set the client receives is
  exactly the set the upstream sent.
* **Verified-augment mode** — prepend at most two verified Cloudflare addresses to the
  RRset, retaining every original address.

Reordering is nearly free in risk terms; adding an address is not.

## Decision

* Preserve is the default mode, and the mode the production example ships with commented
  guidance about.
* Verified-augment requires **every** one of the following, checked per answer:
  1. The answer is already a Cloudflare answer — the existing addresses are inside official
     Cloudflare prefixes. The daemon does not introduce Cloudflare into an answer that had
     nothing to do with it.
  2. DNSSEC status is **proven Insecure**. Not "unsigned as far as we can tell" —
     Indeterminate is not sufficient, and Secure is disqualifying, because adding a record
     to a signed RRset invalidates the signature.
  3. The answer publishes no ECH parameters this build cannot validate end to end.
  4. The candidate is currently verified: in the official prefixes as of the *current*
     snapshot, past every admission stage, with recent repeated success, and matching the
     query's address family.
  5. There is a measured advantage over the existing baseline for that domain, beyond a
     hysteresis margin. Equal-looking is not better.
  6. The network generation has not changed since the evidence was gathered.
* If any condition fails, the mode falls back to preserve, and
  `cloudflare_fallback_total{reason}` records which one. Failing closed to a *weaker* mode
  is always available, because preserve cannot be wrong about content.
* A runtime override may weaken the mode instantly through the admin socket, but may never
  strengthen it — strengthening is a configuration change so that it goes through
  validation and stays reviewable.

## Rationale

Reordering has a bounded worst case: the client tries a slower address first. Every address
in the answer was published by the zone owner, so no reordering can send a client somewhere
the owner did not point it. This is why preserve mode needs no probe evidence to be safe,
and why "unknown" addresses are given a *neutral* score rather than a bad one — lack of
evidence is not evidence of failure.

Adding an address has an unbounded worst case if any premise is wrong. Hence the six
conditions, hence the requirement for *proof* of Insecure rather than absence of proof of
Secure, and hence the two-address cap: even in the best case, the client should be one
retry away from the answer the upstream actually gave.

## Consequences

* Verified-augment fires rarely. That is intended. `cloudflare_augment_total` staying low
  relative to `cloudflare_preserve_total` is a healthy system, not an underperforming one.
* The condition list is long and each condition needs its own test. `src/policy/cloudflare.rs`
  has one test per condition plus `augment_requires_every_condition`.
* An operator who wants aggressive behaviour cannot get it. There is no configuration that
  relaxes conditions 1–3.

## Revisit when

Condition 5's advantage threshold could become adaptive rather than a fixed hysteresis
margin. That is a tuning change inside an already-safe envelope, and it does not touch
conditions 1–4.
