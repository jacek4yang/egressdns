# Architecture decision records

Each record states a decision that was expensive to make and would be expensive to reverse,
the alternatives that were actually considered, and what would have to be true for the
decision to be revisited. They are written so that a future maintainer can disagree with
them from an informed position rather than rediscovering the constraints.

| # | Decision | Status |
| --- | --- | --- |
| [0001](0001-forwarder-not-recursive.md) | Forwarding cache, not an iterative resolver | Accepted |
| [0002](0002-hickory-for-protocol.md) | Hickory DNS for wire protocol and transports | Accepted |
| [0003](0003-own-ingress-listeners.md) | Own UDP/TCP ingress instead of `hickory-server` | Accepted |
| [0004](0004-foreground-background-split.md) | Strict foreground/background separation | Accepted |
| [0005](0005-untrusted-seed-trust-model.md) | Third-party candidate lists are untrusted input | Accepted |
| [0006](0006-network-detection-polling.md) | Poll `/proc` and `getifaddrs` instead of netlink | Accepted |
| [0007](0007-do53-only-ingress.md) | Cleartext Do53 ingress only in v1.0.0 | Accepted |
| [0008](0008-sqlite-for-learned-state.md) | SQLite for learned state, dropped rather than blocking | Accepted |
| [0009](0009-no-answer-synthesis.md) | No answer synthesis, ever | Accepted |
| [0010](0010-preserve-before-augment.md) | Preserve is the default; augment must earn its place | Accepted |
