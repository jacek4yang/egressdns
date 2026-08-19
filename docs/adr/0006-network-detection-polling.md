# ADR-0006: Poll `/proc` and `getifaddrs` rather than subscribe to netlink

**Status**: Accepted · **Date**: 2026-08

## Context

The daemon needs to know whether IPv4 and IPv6 egress are usable, and to notice when that
changes — a laptop docking, a WAN failover, an IPv6 prefix being withdrawn. A network
change invalidates accumulated per-address evidence, so noticing it matters for
correctness of the ranking model, not just for tidiness.

Linux offers `rtnetlink` for event subscription. The `rtnetlink`/`netlink-packet-route`
crates make this workable from Rust.

## Decision

Poll. Every few seconds, read `/proc/net/route` and `/proc/net/ipv6_route`, call
`getifaddrs(3)` through `nix`, and derive a source address per family by `connect()`ing an
unbound UDP socket to a well-known address (which selects a source without sending a
packet). Hash the result into a fingerprint; a changed fingerprint, after a debounce
interval, becomes a new network generation.

## Rationale

* **The requirement is "within a few seconds", not "immediately".** Nothing in the design
  needs sub-second notification. Evidence is demoted on generation change, and demoting it
  two seconds later than theoretically possible changes nothing an operator can observe.
* **Netlink is a socket that can go wrong.** Buffer overruns require a full resync;
  multicast group membership is one more thing to get wrong at startup; and an event
  stream that silently stops is much harder to detect than a poll that returns the same
  fingerprint. A poll has exactly one failure mode: the read fails, and the previous state
  is retained.
* **`RestrictAddressFamilies` stays honest either way.** The unit allows `AF_NETLINK`
  because `getifaddrs(3)` uses it internally, so netlink would not have widened the
  sandbox. But an event subscription is a long-lived netlink socket versus a short syscall,
  which is a meaningfully larger surface.
* **Testability.** `/proc` parsers take a `&str`, so the route-table tests are fixture
  files covering default routes, ULA-only environments, and malformed lines. An event
  subscription would need a much heavier harness for much weaker assertions.
* **Cost is negligible.** Two small file reads and one `getifaddrs` every few seconds does
  not register against a daemon that is handling thousands of queries per second.

## Consequences

* Worst-case detection latency is one poll interval plus the debounce. Both are configurable
  and both are documented in `docs/CONFIGURATION.md`.
* A flapping interface is handled by the debounce rather than by event coalescing;
  `egressdns_network_generation_changes_total` exposes flapping to the operator
  (`docs/OPERATIONS.md` §14).
* The implementation is Linux-specific in its `/proc` parsing. `getifaddrs` is portable;
  the route tables are not. Since the deployment target and the systemd packaging are
  Linux, this is not currently a constraint.

## Revisit when

A requirement appears for sub-second reaction — for example if the daemon ever manages its
own connections to a failing-over egress and wants to tear them down instantly rather than
letting them time out.
