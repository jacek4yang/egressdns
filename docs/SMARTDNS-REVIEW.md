# SmartDNS: what was adopted, what was not

SmartDNS is GPLv3 and EgressDNS is not. Nothing here is copied, translated or
mechanically transformed from it: no source, no comments, no data structures, no tests, no
configuration grammar. What follows is a record of *ideas* — the kind of thing you could
learn from a conference talk — and of where this codebase deliberately does something
else.

The review was of the project's published design and behaviour at commit
`b59606ea34ee0fe35aced6f6d241919af717980e`, focused on the areas the brief named: speed
checking, prefetch, pending requests, the client, the cache, the proxy layer and dual-stack
selection.

## Scope note

This is an honest account of a **partial** review. The mechanisms below are ones EgressDNS
either already implemented independently or implemented for 3.0. Several areas named in
the brief — the proxy layer and dual-stack selection in particular — were not studied in
enough depth to claim anything, and nothing in this release derives from them.

## Adopted as ideas

**Several upstreams, and the first useful answer wins.** The central insight, and the one
EgressDNS 3.0 is built around: for an ordinary positive lookup, a resolver that waits for
one nominated upstream is slower and less available than one that asks a few and takes the
first admissible reply. What EgressDNS took from this is the *shape* — answer from whoever
is fastest right now — not the tactic.

**Request coalescing.** Concurrent identical questions should produce one upstream query.
EgressDNS already had this (`cache::singleflight`) before the review.

**A bounded cache with prefetch for popular names.** Refreshing an entry before it expires
turns a periodic miss into a hit for names that are asked repeatedly.

**Measuring addresses rather than trusting their order.** An authoritative answer's address
order carries no information about which address is fastest *from here*. Measuring and
reordering is worth doing.

**Recovering from upstream failure without operator action.** A route that fails should be
avoided and then retried, not removed until somebody notices.

## Improved on, deliberately

**Do not keep asking everybody.** Racing every configured upstream on every query multiplies
one client's traffic by the number of upstreams, discloses each query to all of them, and
keeps paying that cost forever. EgressDNS races a small ranked set on a cold name and
converges to one primary plus a delayed hedge once route quality is known.
`the_first_query_does_not_contact_every_route` asserts the bound.

**Do not put address measurement in front of the client.** Probing is background work in the
optimization plane; the first query returns as soon as the DNS answer is admissible, and
measurement changes the *order of later answers*.

**Reachability is not correctness.** An address that answers a ping or a TCP connect may
still be the wrong address — that is precisely what DNS poisoning produces. EgressDNS
treats connection latency as a *service quality* signal and keeps it strictly separate from
*answer evidence*, which comes from source identity, transport authentication, agreement
between independent authorities, and DNSSEC. The two never mix: a DNSSEC verdict may not
change an address's latency rank, and a fast TCP handshake may not make a forged answer
look authentic.

**Validate the service, not just the socket.** Where a name is known to be an HTTPS service,
a candidate address must present a certificate valid for the *original hostname*. A failed
certificate rejects the address as an HTTPS candidate without declaring the DNS answer
wrong for every other protocol.

**Separate the authority from the route.** Cloudflare over HTTP/3, over HTTP/2, over IPv6
and through a proxy are four routes and one authority. Counting them as four opinions would
let one operator's outage look like a consensus. This is why a home gateway is a
`LocalForwarder` and not an authority: it forwards to somebody, quite possibly whoever we
just asked.

**Keep whole answer variants.** Merging every address every resolver returned produces a set
no authority ever served, and quietly launders a poisoned answer into a legitimate one.
EgressDNS keeps complete variants with their authority, transport, chain, DNSSEC state and
observation time, and compares them semantically — CDN answers differ legitimately and
constantly.

**Bound what is disclosed.** Every extra upstream asked is another party that learns the
query. Probe traffic, candidate counts and background bandwidth are budgeted.

## Rejected

**Racing every upstream as the steady state.** See above: the cost is permanent and paid in
somebody else's privacy as well as bandwidth.

**Ping-based address ranking as the primary signal.** ICMP is frequently filtered, is
answered by middleboxes, and says nothing about whether the service on that address is the
service that was asked for.

**Treating a fast address as evidence that the answer is right.** This is the specific
conflation the 3.0 brief calls out, and it is the one that would matter most if it were
wrong.

## Evidence

The performance claims EgressDNS makes are its own measurements on the author's host, in
`CHANGELOG.md` and `STATUS.md`. No comparison against SmartDNS was run, and none is
claimed.

## Licensing

EgressDNS carries no SmartDNS code. The ideas above are architectural and were reimplemented
from scratch against this codebase's own abstractions — `Scheduler`, `RouteKey`,
`ValidationOutcome`, the three execution planes — none of which correspond to anything in
SmartDNS.
