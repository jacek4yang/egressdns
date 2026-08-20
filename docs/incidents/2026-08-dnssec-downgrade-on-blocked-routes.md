# DNSSEC silently downgraded to Insecure when a route is blocked

**Date:** 2026-08-20
**Severity:** high — correctness, priority 1 in `CLAUDE.md`
**Status:** characterised and reproducible; **not fixed**
**Affects:** 2.0.0, and 2.0.1 more often than 2.0.0

## Summary

On a network where some upstream routes are unreachable, a DNSSEC-signed name can be
answered with `authenticated: false` and no AD bit, instead of either validating or
failing. The answer looks completely normal. A client that trusts the AD bit concludes the
zone is unsigned.

The verdict is then cached for the answer's TTL, so one unlucky moment sticks.

This is not new in 2.0.1, but 2.0.1 makes it more likely: `builtin:recommended` puts
encrypted endpoints in the pool by default, and on a network that blocks them, there are
now failing routes where before there were none.

## Reproduction

On a host where DoH/DoT to the public providers is blocked but plaintext Do53 works — the
test host is behind such a network — the same daemon build, same version, differing only
in the upstream list:

```
upstreams = ["builtin:recommended"]
  example.com     authenticated=false      <-- signed zone, reported unsigned
  cloudflare.com  authenticated=true
  paypal.com      authenticated=true
  isc.org         authenticated=true

upstreams = ["1.1.1.1","8.8.8.8","9.9.9.10","185.222.222.222","194.242.2.2"]
  example.com     authenticated=true
  cloudflare.com  authenticated=true
  paypal.com      authenticated=true
  isc.org         authenticated=true
```

Both runs started from an empty state database. The second list is the plaintext subset of
the first: removing the *blocked* routes is what fixes the verdict.

The data is available and correct on this network — the upstreams are fine:

```
$ dig +dnssec DS example.com @1.1.1.1
;; flags: qr rd ra ad; ANSWER: 2
example.com. 86400 IN DS 2371 13 2 C988EC42...
example.com. 86400 IN RRSIG DS 13 2 86400 ... com.

$ dig +dnssec example.com A @1.1.1.1
;; flags: qr rd ra ad          <-- an external validator authenticates it
```

An all-encrypted configuration SERVFAILs everything on this host, confirming those
endpoints are genuinely blocked rather than slow.

## Mechanism

Validation needs auxiliary lookups — DS and DNSKEY at each level of the chain. A client
query that fails on one route is retried on another by the scheduler. The validator's
auxiliary lookups do not get the same treatment: when one fails, the chain cannot be
built, and the library reports the answer as **Insecure** rather than as an error.

`policy::dnssec::dnssec_status` then faithfully reports what it was given. Its logic is
correct — it takes the weakest proof in the message — but "Insecure" arriving for two
completely different reasons is what makes the failure invisible:

* the zone is genuinely unsigned, proven by an NSEC/NSEC3 denial of DS at the parent — an
  answer that should be served; and
* the chain could not be fetched — an answer that should not be served as authentic.

Only the first is Insecure in RFC 4035 terms. The second is Indeterminate, which fails
closed. The distinction is lost before our code sees the message.

## Why this was not fixed here

The obvious patch — "an answer containing RRSIGs must not be reported Insecure" — breaks a
legitimate case. A zone can sign its data and still have no DS at its parent (an island of
security). Its answers carry RRSIGs and are correctly Insecure, and turning those into
SERVFAIL would make names disappear that resolve everywhere else. Trading a silent
downgrade for a silent outage is not an improvement, and by the priority order in
`CLAUDE.md` availability sits directly below correctness rather than far below it.

A correct fix has to preserve the distinction the library is discarding: either give the
validator a resolver handle that retries across healthy routes the way client queries do,
or capture Indeterminate separately from Insecure at the point validation fails. Both are
real changes to the validation path and deserve their own work, their own tests against
`hickory-server` instances that serve islands of security, and their own load run.

## What holds in the meantime

* **Bogus is still SERVFAIL.** The fail-closed gate is unaffected: a deliberately bogus
  name is refused, which the installer checks on every install and treats as fatal.
  Verified on the test host: `dnssec-failed.org` → SERVFAIL, EDE 6.
* **Validation works when routes work.** With a reachable route set, signed zones
  validate and set AD — `www.isc.org`, `nic.cz`, `afnic.fr`, `iana.org`, `ietf.org` and
  others all authenticate on the affected host.
* The failure needs a *blocked* route to trigger. On a network without egress
  restrictions, the default configuration has none.

## Operator workaround

Where some providers are unreachable, list only the reachable ones rather than taking the
whole built-in profile:

```toml
upstreams = ["1.1.1.1", "8.8.8.8", "9.9.9.10"]
```

`egressdnsctl builtins recommended` prints what the profile expands to, so the reachable
subset can be copied out of it.

## A note on how this was found

Not by a test. The suite passes, and it passes because every route in it works: the
integration harness starts `hickory-server` instances on loopback, and loopback does not
block anything. It surfaced from querying a real host on a restricted network and noticing
that `dig +dnssec cloudflare.com` came back without an `ad` flag that a public validator
sets.

The first hypothesis — `dnssec.max_validation_depth = 12`, below the library's default of
26 — was **wrong**, and looked right for a while: raising it to 26 appeared to fix
`example.com`. Re-running with a cleared state database showed depth 12 validating
perfectly well, and the earlier result to have been route-selection luck. The lesson is the
ordinary one: a fix that is not reproducible from a clean state has not been demonstrated.
