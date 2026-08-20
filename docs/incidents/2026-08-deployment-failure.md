# Deployment failure: healthy on every signal, answering nothing

**Date:** 2026-08-19
**Severity:** release-blocking
**Status:** fixed, with regression coverage
**Affected:** every systemd deployment of 1.0.0 on a host where `/proc` is restricted

## Summary

EgressDNS 1.0.0 installs cleanly, starts, binds port 53, passes the installer's UDP and TCP
health checks, reports `ready: true`, and feeds its systemd watchdog — while returning
SERVFAIL to every single client query.

The daemon's own signals all say it is healthy, which is what makes this class of failure
expensive: there is nothing to page on and nothing in the log. The only symptom is that DNS
does not work.

## Scope note on the source of this report

The task that prompted this work referenced a shared ChatGPT conversation as the source of
a reported deployment defect. That transcript was **not** used: retrieval was abandoned at
the user's explicit instruction before any content was read. Nothing in this document is
derived from it, and no claim here should be read as describing the failure that transcript
reports.

Everything below was found independently, by installing this build on a real Debian host
and looking at why it did not answer. If the reported incident has a different root cause,
that root cause remains uninvestigated.

## Environment

* Debian 13, kernel 6.12.100
* systemd unit as shipped in `packaging/systemd/egressdns.service`
* Service account `egressdns`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`
* Listeners `0.0.0.0:53` and `[::]:53`, UDP and TCP
* Host has a working IPv4 default route (`192.168.31.204` via `192.168.31.1`) and global
  IPv6 addresses

## Timeline

1. `sudo ./install.sh --local-build` completes. The installer's own canary passes:
   `UDP health check against 127.0.0.1:53` and the TCP equivalent both succeed.
2. `systemctl is-active egressdns` reports `active`. `egressdnsctl status` reports
   `"ready": true`.
3. Every client query fails:

   ```
   $ dig +short @127.0.0.1 example.com A
   $ dig @127.0.0.1 example.com A | grep -E 'status:|EDE'
   ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 4480
   ; EDE: 22 (No Reachable Authority): (all upstreams failed: no upstream route available in group ...)
   ```

4. `egressdnsctl network` shows the contradiction:

   ```json
   {
     "default_interface_v4": null,
     "gateway_v4": null,
     "default_interface_v6": null,
     "gateway_v6": null,
     "ipv4": "unusable",
     "ipv6": "unusable",
     "source_v4": "192.168.31.204",
     "source_v6": "240e:390:9abb:15c0:...",
     "global_addresses": ["192.168.31.204%enp2s0", "..."]
   }
   ```

   Both families are `unusable`, yet the source addresses were detected correctly and the
   host demonstrably has connectivity.

## Root cause

`ProcSubset=pid` in the systemd unit.

The directive mounts `/proc` with only the per-PID directories visible. Every non-PID file
disappears, including `/proc/net/route` and `/proc/net/ipv6_route`. Confirmed directly:

```
$ systemd-run --property=ProtectProc=invisible --property=ProcSubset=pid \
    /bin/sh -c 'test -r /proc/net/route && echo YES || echo NO'
NO
$ systemd-run --property=ProtectProc=invisible \
    /bin/sh -c 'test -r /proc/net/route && echo YES || echo NO'
YES
```

The chain from there:

1. `network::detect` reads `/proc/net/route`; the file is absent, so it parses an empty
   string and finds no default route.
2. `RawNetworkState::v4_state` requires `default_iface_v4.is_some()`, so it returns
   `Unusable`. Same for IPv6.
3. `Scheduler::rank_inner` skipped every route whose family was `Unusable`.
4. With no family usable, the ranked list was empty.
5. `Scheduler::resolve` returned `ResolveError::NoRoute`, which the resolver maps to
   SERVFAIL with EDE 22.

Startup masks it. The first published snapshot is `NetworkSnapshot::unknown()`, whose
families are `Unknown` rather than `Unusable`, and `Unknown` is treated as usable. The
detector task runs a few seconds later and flips both families to `Unusable`. So the
installer's canary, which queries immediately after start, passes — and the resolver dies
seconds after the installer reports success.

## The second, larger defect

Fixing the unit alone would have left the more serious problem in place: **a detection
failure could black-hole all traffic.**

Address-family usability is *derived from the host routing table*. It therefore reports on
our ability to measure the network at least as much as on the network itself. An unfamiliar
container, a platform whose route file moved, a future sandbox change — each produces
`Unusable` on a host whose networking is fine.

The circuit breaker in the same function already refuses to make this mistake. Its comment
reads: when every route's circuit is open, "refusing to send anything converts a partially
working upstream into a total outage", so every route is offered anyway, worst-scored last.
The family filter had no such guard.

## Fix

Two changes, in `packaging/systemd/egressdns.service` and `src/upstream/scheduler.rs`.

* `ProcSubset=pid` removed, with a comment recording why it must not come back.
  `ProtectProc=invisible` — the directive that hides *other processes* — is kept, as is the
  rest of the sandbox. `systemd-analyze security` still rates the unit **1.7 OK**.
* `rank_inner` now treats "no family reads as usable" the way it treats "every circuit is
  open": the filter has produced nothing actionable, so every route is offered rather than
  none. Counted by `egressdns_upstream_family_fallback_total`. A genuine single-family
  outage is unaffected, because the working family still populates the ranked set and the
  dead family is still skipped.

## Regression coverage

`tests/deployment.rs`, both failing before the fix and passing after:

* `a_failed_address_family_detection_still_resolves` — publishes exactly the snapshot a
  blind detector produces (`RawNetworkState::default()`, both families `Unusable`) onto a
  running daemon and asserts a client still gets `NOERROR` and the right address. Before
  the fix this returned SERVFAIL, reproducing production exactly.
* `the_systemd_unit_does_not_hide_proc_net_from_the_detector` — asserts the packaged unit
  carries no `ProcSubset` directive that would hide `/proc/net`, and that the hardening
  which does not break detection is still present.

## Verification on the real host

After the fix, on the same machine:

* `egressdnsctl network` reports `ipv4: usable`, `ipv6: usable`, with the correct default
  interface (`enp2s0`) and gateways.
* `dig @127.0.0.1 example.com A` and `AAAA` both answer.
* `dig +dnssec @127.0.0.1 cloudflare.com A` returns NOERROR with the **`ad` flag set** —
  local DNSSEC validation completing end to end.
* `dig +tcp @127.0.0.1 www.google.com A` answers.
* `dig @127.0.0.1 nothing.invalid-tld-zzz A` returns NXDOMAIN, matching the upstream.
* `systemctl reload` twice under continuous traffic: zero failed queries, `reloads: 2`.
* `systemctl stop` / `start` cycle clean; queries answer afterwards.

## What else the investigation surfaced

Chasing this failure exposed three further defects, each fixed with its own coverage:

* **`doctor` reported phantom port conflicts.** An unprivileged bind of port 53 fails with
  `EACCES`, not `EADDRINUSE`; treating every bind error as a conflict sent the operator
  hunting for a resolver that was not running. Bind results are now classified, and a
  privilege failure reports `NOT_TESTED` because ownership is genuinely unknown.
* **`doctor` reported the running daemon as a conflict**, and attributed an IPv4 wildcard
  socket as the owner of an IPv6 address — turning one healthy listener into four phantom
  failures on a dual-stack host. Owner matching is now family-aware, and a listener held by
  our own `egressdnsd` reports PASS.
* **The route ranker penalised routes it had measured.** An unmeasured route scored better
  than a proven one, so the scheduler cycled through its route list forever preferring
  whatever it knew least about. Invisible on loopback, where both the test suite and the
  load harness run. See the commit `fix: stop the route ranker from penalising routes it
  has measured` for the measurement.

## Lessons

* **A green health check is not a working resolver.** The installer canary ran inside the
  window where the network snapshot was still `Unknown`. A canary that runs once,
  immediately, cannot see a failure that arrives on the detector's first tick.
* **Sandbox hardening is a functional dependency.** `ProcSubset=pid` looks like pure
  hardening and is in fact a hard dependency of the address-family detector. The unit and
  the code that reads the filesystem have to be reviewed together, which is what the new
  unit test enforces.
* **Derived signals must fail open, not closed.** Anything computed from an observation of
  the local system can fail because the observation failed. When it does, the safe answer
  is to stop filtering rather than to filter everything away.
* **Localhost hides the defects that matter.** Three of the four problems here are
  invisible at sub-millisecond RTT with an unrestricted `/proc`. The load harness is not a
  substitute for installing the thing on a real host and querying it.
