# Operations guide

This document is written to be followed in order the first time, and used as a lookup
table afterwards. Sections 1–5 are validation before anything touches production;
sections 6–8 are the rollout; section 9 is what to watch; section 10 is how to get out;
sections 11–17 are diagnosis.

Throughout, `$CTL` means `egressdnsctl` and `$SOCK` means the admin socket, which is
`/run/egressdns/admin.sock` under the packaged unit and whatever you set in `admin.socket`
otherwise. Commands that need root are shown with `sudo`.

---

## 1. Testing on UDP and TCP port 1053

**Never** validate a new build on port 53 of a machine that anything depends on. Port 1053
is unprivileged, so the daemon needs no capabilities and cannot collide with an existing
resolver.

Create a throwaway configuration:

```sh
mkdir -p /tmp/egressdns-test
cat > /tmp/egressdns-test/config.toml <<'TOML'
[server]
udp_listen = ["127.0.0.1:1053", "[::1]:1053"]
tcp_listen = ["127.0.0.1:1053", "[::1]:1053"]
allow_from = ["127.0.0.0/8", "::1/128"]

[admin]
enabled = true
socket = "/tmp/egressdns-test/admin.sock"

[metrics]
enabled = true
listen = "127.0.0.1:9153"

[storage]
path = "/tmp/egressdns-test/state.sqlite"

[cloudflare]
mode = "preserve"
TOML

egressdnsd --config /tmp/egressdns-test/config.toml --log info
```

Both address families must be tested, because a resolver that works on IPv4 and silently
fails on IPv6 looks healthy on every dashboard:

```sh
dig @127.0.0.1 -p 1053 example.com A     +short
dig @::1       -p 1053 example.com AAAA  +short
dig @127.0.0.1 -p 1053 example.com A     +tcp +short
dig @::1       -p 1053 example.com AAAA  +tcp +short
```

Confirm the daemon actually bound what you asked for:

```sh
ss -lunp 'sport = :1053'
ss -ltnp 'sport = :1053'
```

You should see four rows in total: UDP and TCP, on `127.0.0.1` and `::1`. If a row is
missing, the daemon logged the bind failure at startup — read that log rather than
guessing.

**Leave this test instance running** for sections 3, 4 and 5.

## 2. Running `egressdnsctl check-config`

Configuration is validated in three places, and all three run the same code:

```sh
# Before the daemon exists at all — parse + validate, exit non-zero on failure.
egressdnsd --config /etc/egressdns/config.toml --check-config

# Same validation, via the CLI, when you prefer one tool.
egressdnsctl --config /etc/egressdns/config.toml check-config

# Against a *running* daemon: also reports whether a reload would succeed.
egressdnsctl --socket "$SOCK" check-config
```

Print the effective configuration with every default made explicit and secrets redacted —
this is what to attach to a bug report:

```sh
egressdnsctl --socket "$SOCK" dump-effective-config > /tmp/effective.toml
```

Make `check-config` part of your configuration-management run, before the file is copied
into place. A rejected reload leaves the old configuration serving, but a rejected
*startup* leaves you with no resolver at all.

## 3. Query validation with `dig`

Work through this list against the port-1053 instance. Each line checks a behaviour that
has silently regressed in other resolvers.

```sh
D="dig @127.0.0.1 -p 1053"

# 3.1 Basic forwarding and caching. The second TTL must be lower than the first.
$D example.com A | grep -E '^example\.com\.'
sleep 2
$D example.com A | grep -E '^example\.com\.'

# 3.2 IPv6 answers are never suppressed.
$D example.com AAAA +short

# 3.3 NXDOMAIN is negative-cached and reports SOA-derived TTLs.
$D nx-$$.example.com A | grep -E 'status:|SOA'

# 3.4 Truncation and TCP retry: a large answer over UDP must set TC or fit.
$D +bufsize=512 +ignore dnssec-failed.org TXT | grep -E 'flags:|MSG SIZE'

# 3.5 DNSSEC: a signed zone validates and sets AD.
$D +dnssec cloudflare.com A | grep -E 'flags:|RRSIG'

# 3.6 DNSSEC: a deliberately broken zone must be SERVFAIL with EDE 6, never an answer.
$D dnssec-failed.org A | grep -E 'status:|EDE'

# 3.7 The same broken zone with CD=1 must return data, because the client opted out.
$D +cdflag dnssec-failed.org A | grep -E 'status:'

# 3.8 RFC 8482 minimal ANY.
$D example.com ANY | grep -E 'HINFO|status:'

# 3.9 Special-use names never reach an upstream.
$D localhost A +short                    # expect 127.0.0.1
$D printer.local A | grep 'status:'      # expect NXDOMAIN
$D 1.0.168.192.in-addr.arpa PTR | grep 'status:'   # expect NXDOMAIN

# 3.10 EDNS payload size is 1232 by default.
$D example.com A +edns=0 | grep -E 'udp:'

# 3.11 Access control: a client outside allow_from is REFUSED, not ignored.
#      Run from another host on the LAN.
```

The two answers that matter most are 3.6 and 3.7. If 3.6 returns an address, validation is
not actually happening; if 3.7 returns SERVFAIL, the CD bit is being ignored and clients
that do their own validation are broken.

## 4. Load testing

The suite starts a scriptable mock upstream, starts a release build against it, and runs
eleven scenarios:

```sh
./scripts/load-test.sh                          # full suite, ~10 minutes
./scripts/load-test.sh --duration 10            # quick pass
./scripts/load-test.sh --only cache-hit,servfail
./scripts/load-test.sh --sustained 3600         # one-hour soak
```

Each scenario writes JSON to `target/loadtest/`. To point the generator at an already
running instance instead:

```sh
./scripts/loadtest.py --port 1053 --duration 60 --clients 8 --inflight 8 \
    --names 10000 --daemon-pid "$(pidof egressdnsd)" --json result.json
```

### Reading the output honestly

Two things will mislead you if you do not check them, and the harness reports both so you
do not have to remember:

* **`qps` counts replies. `useful_qps` counts NOERROR answers that contain a record.** If
  those two numbers differ, the difference is failures being reported as throughput. Always
  read `useful_qps` and the `rcodes` map together.
* **`harness_ceiling_qps` is `clients x inflight / mean-latency`** — what the generator
  could achieve at the observed latency. When `qps` is close to it, *the generator*
  saturated, and the result is a floor on the daemon's capacity rather than a measurement
  of it. Raise `--clients` and `--inflight`, or drive the load from a separate machine.

### What to look for, in order of importance

1. **p99 within a small multiple of p50 on `cache-hit`.** A cache hit does no I/O, so a p99
   far above p50 means contention or background work on the foreground path. That is a bug,
   not a tuning problem. File it.
2. **`rss_mb_growth_last_third` near zero on a sustained run.** A cache filling to its
   budget grows and then plateaus; a leak keeps climbing. The `rss_mb_series` field shows
   the shape directly. Expect steady-state RSS around `15 MB + 1.6 x cache.max_memory_bytes`.
3. **`fds_end` and `threads_end` back near their starting values.** A file descriptor or
   thread count that ratchets upward across a soak is a leak regardless of what RSS does.
4. **`abandoned_at_end` small.** Queries still outstanding when the clock stopped. A large
   number means the daemon was not keeping up and the latency figures understate the tail.
5. **`egressdns_inflight_queries` back to zero** within a second of the run ending. If not,
   a permit is leaking.

### The impaired scenarios and what they prove

| Scenario | What it demonstrates |
| --- | --- |
| `packet-loss`, `timeouts` | Retries recover almost everything: 2% upstream loss is invisible to clients, 10% costs well under 1%. The p99.9 shows the retry cost. |
| `servfail` | A 20%-SERVFAIL upstream must still answer roughly 80% of queries. A number far *below* 80% means the circuit breaker is black-holing traffic instead of routing around it. |
| `truncation` | Truncated UDP answers must be retried over a stream transport and reach 100%. Anything less means a stream route is missing — see RFC 7766 in `docs/RFC_COMPLIANCE.md`. |
| `dnssec-closed` | Validation against an upstream that supplies no chain of trust must yield **100% SERVFAIL**. That is the correct result: DNSSEC must fail closed, never degrade to unvalidated answers. A single NOERROR here is a serious security defect. |

Compare against `docs/BENCHMARKS.md`, which records what this build achieved and on what
hardware. Do not compare against numbers from a different machine.

Increase load until something degrades, then check *which* thing degraded. The intended
failure mode under overload is rate-limited REFUSED to new clients with existing clients
still served, and `upstream_shed_total` rising — not latency growing without bound.

## 5. Fault testing

```sh
./scripts/chaos-test.sh --host 127.0.0.1 --port 1053 --socket /tmp/egressdns-test/admin.sock
```

Each scenario breaks something and asserts that DNS still works, or fails in the documented
way. Run it before promoting any node. The scenarios are:

| Scenario | Required behaviour |
| --- | --- |
| Every upstream unreachable | Stale answers served with EDE 3/19 while `serve_stale.max_stale` lasts, then SERVFAIL. Never a wrong answer. |
| Primary upstream slow (not dead) | A hedge fires after the primary's own p95; the client sees roughly the secondary's latency. |
| Upstream returns SERVFAIL repeatedly | The circuit opens; queries move to other routes; the failure is cached per RFC 9520 rather than retried in a loop. |
| Candidate source unreachable | Cloudflare optimization degrades to preserve mode; ordinary forwarding is unaffected. |
| Probe target refuses TCP 443 | The address keeps its DNS answer position; a TCP 443 failure is not evidence the address is unusable for anything else. |
| SQLite file corrupted | The store is quarantined, a fresh one is opened, and resolution never stops. |
| Config replaced with an invalid file, then reloaded | The reload is rejected and the running configuration keeps serving. |
| `SIGHUP` during load | No dropped queries, no listener gap. |

Manual additions worth doing once on real hardware:

```sh
# Pull the IPv6 default route and confirm the daemon notices and degrades, not fails.
sudo ip -6 route del default
sleep 20 && egressdnsctl -s "$SOCK" network
sudo ip -6 route add default via <gw> dev <if>

# Kill the process hard and confirm systemd restarts it and state is restored.
sudo systemctl kill -s SIGKILL egressdns && sleep 3
egressdnsctl -s "$SOCK" status
```

## 6. Binding port 53

Port 53 is privileged. There are exactly two supported ways to bind it, and neither
involves running as root.

**Packaged deployment (recommended).** The shipped unit grants one capability and nothing
else:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
User=egressdns
```

**Manual binaries.** Grant the capability to the file:

```sh
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/egressdnsd
getcap /usr/local/bin/egressdnsd
```

Note that `setcap` is lost on every binary replacement — the upgrade script re-applies it;
if you copy a binary by hand, re-apply it by hand.

Before switching a machine to port 53, stop whatever already owns it. On most modern Linux
systems that is `systemd-resolved`:

```sh
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
# Point local resolution at EgressDNS. /etc/resolv.conf is often a symlink into
# /run/systemd/resolve; replace it deliberately rather than editing through the symlink.
sudo rm -f /etc/resolv.conf
printf 'nameserver 127.0.0.1\nnameserver ::1\noptions edns0 trust-ad\n' | sudo tee /etc/resolv.conf
```

`install.sh` **refuses** to proceed when port 53 is occupied rather than stopping the
incumbent for you. Silently disabling a machine's resolver is not a decision an installer
gets to make.

Then set the real listeners and restart:

```toml
[server]
udp_listen = ["0.0.0.0:53", "[::]:53"]
tcp_listen = ["0.0.0.0:53", "[::]:53"]
allow_from = ["192.0.2.0/24", "2001:db8:1::/48"]   # your LAN, not this example
```

```sh
sudo egressdnsctl check-config -c /etc/egressdns/config.toml
sudo systemctl restart egressdns
```

## 7. Deploying DNS-A and DNS-B

Run two independent instances. The point is that a mistake on one does not become an outage.

| | DNS-A | DNS-B |
| --- | --- | --- |
| Address | e.g. `192.0.2.10` / `2001:db8:1::10` | e.g. `192.0.2.11` / `2001:db8:1::11` |
| Upstream group | Primary set | **Deliberately different** primary order |
| Cloudflare mode | Upgrade here first | Stays on the previous mode for a week |
| Upgrade order | Second | First |

Rules that make the pair worth having:

1. **Never upgrade both at once.** Upgrade B, watch for at least a full business day, then
   upgrade A.
2. **Give them different upstream orderings.** If a single upstream provider serves a bad
   answer or goes down, the two nodes do not fail identically.
3. **Do not share the SQLite file.** Each node learns its own quality statistics; sharing
   the file couples their failure modes and the store is not designed for concurrent
   writers from separate hosts.
4. **Verify both from a client**, not from the node itself:
   ```sh
   for s in 192.0.2.10 192.0.2.11 2001:db8:1::10 2001:db8:1::11; do
     echo "== $s"; dig @"$s" example.com A +short +time=2 +tries=1
   done
   ```
5. **Check the pair disagrees only in ordering.** Two nodes returning different *sets* of
   addresses for the same name is expected (upstreams differ); two nodes returning
   different *rcodes* is a problem worth understanding before rollout continues.

## 8. Updating DHCP DNS addresses

Change DHCP only after both nodes answer correctly from a client machine.

**ISC DHCP / `dhcpd.conf`:**

```
option domain-name-servers 192.0.2.10, 192.0.2.11;
default-lease-time 600;    # shorten temporarily so a rollback propagates quickly
```

**Kea:**

```json
{ "name": "domain-name-servers", "data": "192.0.2.10, 192.0.2.11" }
```

**IPv6 (RDNSS in Router Advertisements)** — do not forget this one; a dual-stack client
that still learns the old resolver over RA will keep using it and your change will look
like it did nothing:

```
# radvd.conf
RDNSS 2001:db8:1::10 2001:db8:1::11 { AdvRDNSSLifetime 600; };
```

Sequence that keeps the blast radius small:

1. Shorten the DHCP lease time **first**, and wait one full old-lease interval. This is the
   step people skip, and it is the step that makes a rollback take minutes instead of a day.
2. Change the resolver addresses; reload the DHCP server.
3. Watch `egressdns_queries_total` climb on both nodes and the old resolver's rate fall.
4. Leave the old resolver **running** for at least 24 hours after the last query. Do not
   decommission it in the same change window.
5. Restore the original lease time once the rate on the old resolver reaches zero.

## 9. Monitoring

Scrape `http://<node>:9153/metrics`. `/healthz` is liveness (the event loop responds);
`/readyz` is readiness (ingress bound and a resolution path available). Point your load
balancer or monitoring at `/readyz`, not `/healthz`.

### Cache

| Metric | Watch for |
| --- | --- |
| `egressdns_cache_lookups_total{outcome}` | Hit ratio: `fresh / total`. A LAN resolver should settle well above 0.8. A sudden drop means either a cache flush or an upstream shortening TTLs. |
| `egressdns_cache_entries`, `egressdns_cache_bytes` | Both flat near the configured ceiling is normal. Both *growing* toward it for hours after start is normal warm-up; growing again after a steady period means the working set changed. |
| `egressdns_cache_evictions_total` | Non-zero and rising continuously means the cache is too small for the working set — see §15. |
| `egressdns_singleflight_coalesced_total` | Should be a meaningful fraction of misses. Zero here with a high miss rate means duplicate upstream work. |
| `egressdns_prefetch_total{outcome}` | `failed` climbing means prefetch is spending budget on names that no longer resolve. |

### Upstream

| Metric | Watch for |
| --- | --- |
| `egressdns_upstream_queries_total{server,transport,outcome}` | Per-route error rate. One route with a rising error rate is normal and handled; *all* routes rising is an egress problem. |
| `egressdns_upstream_duration_seconds{server,transport}` | p95 per route. This is the input to hedging, so a rising p95 also raises the hedge delay. |
| `egressdns_upstream_circuit_state{server,transport}` | 0 closed, 1 suspect, 2 open, 3 half-open. Any route sitting at 2 for more than a few minutes deserves §12 or §13. |
| `egressdns_upstream_hedges_total` | A small percentage of queries is healthy. More than ~5% means a primary is chronically slow. |
| `egressdns_upstream_duplicate_queries_total` | The cost of hedging and emergency fan-out. Should track hedges, not exceed them by a lot. |
| `egressdns_upstream_tcp_retry_total` | Truncation retries. A step change means an upstream started returning larger answers. |

### Stale and errors

| Metric | Watch for |
| --- | --- |
| `egressdns_serve_stale_total` | **Any** non-zero value is an incident signal: it means every upstream failed for that name. Alert on the rate, not the total. |
| `egressdns_extended_errors_total` | Which EDE codes clients are seeing. |
| `egressdns_dnssec_results_total{proof}` | `bogus` climbing is §13. |
| `egressdns_responses_total{rcode}` | SERVFAIL rate is the headline user-visible failure metric. |

### IPv4 / IPv6

| Metric | Watch for |
| --- | --- |
| `egressdns_network_family_state{family}` | 1 usable, 0 not. A flap here is §14. |
| `egressdns_network_generation` | Increments on a real network change. |
| `egressdns_network_generation_changes_total` | Rapid increments mean the debounce is being defeated by a flapping interface. |

### Cloudflare optimization

| Metric | Watch for |
| --- | --- |
| `egressdns_cloudflare_prefixes{family}` | Should be non-zero and stable. Zero means the official prefix list failed to load and optimization is inert — see §16. |
| `egressdns_cloudflare_candidates{family}` | Size of the verified pool. |
| `egressdns_cloudflare_source_updates_total{source,outcome}` | `failed` for the official source is serious; `failed` for a seed endpoint is routine. |
| `egressdns_cloudflare_candidate_rejected_total{reason}` | Expected to be large. `not_in_official_prefix` dominating is normal and is the filter doing its job. |
| `egressdns_cloudflare_preserve_total` / `_augment_total` | Which mode answers are actually taking. |
| `egressdns_cloudflare_fallback_total{reason}` | Why a stronger mode was not used. |
| `egressdns_probe_subsystem_healthy` | 0 means every optimization input is stale; baseline DNS is unaffected. |

### A minimal alert set

```
# Users are seeing failures.
rate(egressdns_responses_total{rcode="SERVFAIL"}[5m]) > 1

# Every upstream failed for at least one name.
rate(egressdns_serve_stale_total[5m]) > 0

# Not ready to serve.
egressdns_ready == 0

# A route has been broken for 10 minutes.
avg_over_time(egressdns_upstream_circuit_state[10m]) >= 2

# Validation is failing, not merely absent.
rate(egressdns_dnssec_results_total{proof="bogus"}[15m]) > 0.1
```

## 10. Rolling back to the previous resolver

Rollback is a DHCP change plus a service stop, in that order. Practise it before you need it.

**Fast path (minutes, no client changes):** if the old resolver is still running on its old
address, revert the DHCP/RA option and reload the DHCP server. Clients pick it up within one
lease interval — which is why §8 says to shorten the lease first.

**Same-address path:** if EgressDNS took over the address the old resolver used:

```sh
sudo systemctl stop egressdns
sudo systemctl start <previous-resolver>       # e.g. unbound, dnsmasq, systemd-resolved
dig @<address> example.com A +short            # confirm before walking away
```

**Package rollback:**

```sh
sudo /usr/local/lib/egressdns/upgrade.sh --version v0.9.0   # previous release
# or, from the installer:
curl -fsSL https://raw.githubusercontent.com/jacek4yang/egressdns/main/install.sh \
  | sudo bash -s -- --version v0.9.0
```

`install.sh` snapshots the binary, the unit and `config.toml` into a temporary backup
directory under `$TMPDIR` before touching anything — the exact path is printed in the
install log — and restores that snapshot automatically if the new version fails its
post-install health check. `upgrade.sh` additionally keeps a persistent snapshot in
`/var/lib/egressdns/rollback/`; restore it at any time with:

```sh
sudo /usr/local/lib/egressdns/upgrade.sh --rollback
```

To restore the installer's snapshot by hand, use the backup path from the install log:

```sh
sudo systemctl stop egressdns
sudo install -m 0755 <backup-dir>/egressdnsd /usr/local/bin/egressdnsd
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/egressdnsd
sudo install -m 0640 <backup-dir>/config.toml /etc/egressdns/config.toml
sudo systemctl start egressdns
```

The learned-state database is forward-compatible within a major version and is quarantined
rather than migrated if it cannot be read, so a rollback never needs the database deleted.
If you want to start clean anyway: `sudo rm /var/lib/egressdns/state.sqlite*` with the
service stopped. Nothing in it is required for correct resolution.

---

## Diagnosis

## 11. Port conflicts

Symptom: the daemon exits at startup, or `systemctl start` fails immediately, with an
address-in-use error naming the listener.

```sh
sudo ss -lunp 'sport = :53'
sudo ss -ltnp 'sport = :53'
sudo systemctl status systemd-resolved dnsmasq unbound named 2>/dev/null | grep -E 'Active|●'
journalctl -u egressdns -n 50 --no-pager
```

| Finding | Action |
| --- | --- |
| `systemd-resolved` holds `127.0.0.53:53` | Either stop and disable it (§6), or set `DNSStubListener=no` in `/etc/systemd/resolved.conf` and restart it. |
| Another resolver holds `0.0.0.0:53` | Decide which one owns the machine. Do not run both. |
| Only the IPv6 listener fails | Something else holds `[::]:53`, or IPv6 is disabled in the kernel. The daemon binds v6 sockets `IPV6_V6ONLY`, so a v4 wildcard listener is not the cause. |
| Bind succeeds as root, fails as `egressdns` | The capability is missing: re-apply `setcap`, or check `AmbientCapabilities` in the unit. |
| Nothing shown by `ss`, bind still fails | A network namespace or a container without `NET_ADMIN`. Check `systemd-analyze security egressdns`. |

## 12. Upstream TLS errors

```sh
egressdnsctl -s "$SOCK" upstreams
journalctl -u egressdns --since '15 min ago' | grep -iE 'tls|certificate|handshake'
```

| Log detail | Cause | Fix |
| --- | --- | --- |
| `invalid peer certificate: UnknownIssuer` | The system root store is missing or stale, or a middlebox is intercepting TLS. | Install `ca-certificates`; if a middlebox is intended, add its CA to `upstream.tls.extra_ca_files`. |
| `invalid peer certificate: NotValidForName` | `server_name` does not match the certificate — a typo, or the IP belongs to a different service. | Fix `server_name`. **Do not** work around it; there is no verification bypass and there will not be one. |
| `invalid peer certificate: Expired` | Upstream's problem, or this host's clock is wrong. | Check `timedatectl`. A wrong clock breaks TLS *and* DNSSEC simultaneously — see §13. |
| `spki pin mismatch` | The upstream rotated its key. | Update `spki_sha256`, or remove the pin. Pinning a third-party resolver you do not control is a scheduled outage. |
| Handshake timeout on `doq`/`doh3` only | UDP/443 is blocked or rate-limited on the path. | Confirm with `nc -zu <ip> 443`; fall back to `dot` for that route. |
| Everything fails at once after a network change | The daemon is using a source address that no longer exists. | `egressdnsctl network`; a generation bump should have happened. If it did not, file a bug with the output. |

A TLS failure is a **route** failure, never a downgrade. The scheduler moves to another
route and the client still gets an answer; that is why this can be diagnosed calmly.

## 13. DNSSEC failures

```sh
egressdnsctl -s "$SOCK" status | grep -i dnssec
dig @<node> +dnssec dnssec-failed.org A     # must be SERVFAIL + EDE 6
dig @<node> +dnssec cloudflare.com A        # must be NOERROR with AD set
```

| Symptom | Likely cause | Check |
| --- | --- | --- |
| One zone SERVFAILs, others fine | Genuinely broken zone. This is EgressDNS working. | `dig +cd <name>` returns data; `delv <name>` or `dnsviz` confirms. Report to the zone owner. |
| *Everything* signed SERVFAILs | System clock skew — expired-signature and not-yet-valid both look like bogus. | `timedatectl status`; fix NTP, then `egressdnsctl flush-all`. |
| Bogus only via one upstream | That upstream is mangling responses (a "DNS optimiser" middlebox). | Compare with another upstream directly; drop the offender from the group. |
| AD never set on anything | `dnssec.mode` is not `validate`, or the upstream strips RRSIGs. | `dump-effective-config \| grep -A4 '\[dnssec\]'`; query the upstream directly with `+dnssec`. |
| AD set on things you did not validate | `trust_upstream_ad` was enabled. | Turn it off unless the upstream is yours and reached over an authenticated transport. |

EgressDNS never fails open. If validation cannot complete, the answer is SERVFAIL with an
EDE, not an unvalidated answer. The escape hatch for a client that wants raw data is the CD
bit, which is honoured per query — not a server-side setting that silently degrades everyone.

## 14. IPv6 degradation

```sh
egressdnsctl -s "$SOCK" network
ip -6 route show default
ping -6 -c2 2606:4700:4700::1111
```

| `network` output | Meaning | Action |
| --- | --- | --- |
| `ipv6: usable=false, reason=no_default_route` | No IPv6 egress. | Expected on IPv4-only networks. AAAA records are still served to clients — the daemon does not filter them just because *it* cannot reach them. |
| `ipv6: usable=false, reason=probe_failed` | Route exists, egress broken (common with broken 6to4 or a firewall). | Fix upstream or accept it; IPv6 upstream routes are deprioritised, not deleted. |
| `usable=true` but IPv6 upstream routes still fail | Path MTU black hole. | Test with `ping -6 -s 1400`; then check `server.udp.max_payload` and any tunnel MTU. |
| `generation` incrementing every few seconds | A flapping interface is defeating the debounce. | Find the flapping link. Every generation change demotes accumulated probe evidence to a weak prior, so a flapping link means the daemon is permanently re-learning. |

Two things EgressDNS deliberately does **not** do when IPv6 is degraded: it does not
suppress AAAA records, and it does not synthesise A records. Clients implement Happy
Eyeballs; hiding AAAA from them is a decision that belongs to the client, not the resolver.

## 15. Cache pressure

```sh
egressdnsctl -s "$SOCK" cache-stats
```

| Signal | Meaning | Action |
| --- | --- | --- |
| `evictions` rising continuously, hit ratio falling | Working set exceeds `cache.max_memory_bytes`. | Raise it. Memory is cheaper than upstream latency; a LAN resolver for a few hundred clients is comfortable at 256–512 MiB. |
| Hit ratio low, evictions near zero | Upstream TTLs are very short, or the working set is genuinely huge and unique (malware beaconing, telemetry). | Check the hottest names in `cache-stats`. Consider `ttl.cap_default` — but note it can only *shorten*, never lengthen, so it cannot fix short upstream TTLs. |
| `cache_bytes` far below the ceiling but evictions non-zero | Entry-count ceiling reached before the byte ceiling. | Raise `cache.max_entries`. |
| Memory grows without bound | Not the DNS cache — it is weighed and capped. | Look at `egressdns_storage_queue_depth` and connection counts; attach the process to `heaptrack` and file a bug. |
| Hit ratio drops to zero abruptly | Something flushed the cache, or a reload replaced it. | `egressdns_config_reloads_total`, and check who has access to the admin socket. |

Targeted flushes are cheap; `flush-all` is not — it guarantees a stampede of upstream
queries:

```sh
egressdnsctl -s "$SOCK" flush-name www.example.com
egressdnsctl -s "$SOCK" flush-all           # last resort
```

## 16. Candidate-source failures

```sh
egressdnsctl -s "$SOCK" cloudflare status
egressdnsctl -s "$SOCK" cloudflare sources
egressdnsctl -s "$SOCK" cloudflare candidates --limit 20
```

| Finding | Meaning | Action |
| --- | --- | --- |
| `official: last_success` is old, `prefixes` non-zero | The published prefix list could not be refreshed; the last known-good snapshot is still in use. | Usually transient. The snapshot is retained deliberately — an unreachable API must not erase the definition of "Cloudflare address". |
| `prefixes: 0` | No official prefix data at all, including the compiled-in fallback. | Optimization is inert and answers are untouched. Check egress to `api.cloudflare.com` and `www.cloudflare.com`. |
| A seed endpoint permanently failing | An untrusted third-party list is unreachable. | Ignore it, or set `enabled = false`. These lists are optional inputs, never a dependency. |
| `candidate_rejected_total{reason="not_in_official_prefix"}` very high | A seed list is mostly non-Cloudflare addresses. | **Working as designed.** Measured live during development: roughly a quarter of one such list was not Cloudflare space. See `docs/RESEARCH.md` §5. |
| `rejected{reason="special_use"}` non-zero | A seed list contained private or metadata addresses. | Also working as designed, and a good reason to distrust that list. Consider disabling it. |
| `probe_subsystem_healthy = 0` | Every optimization input is stale or the probe budget is exhausted. | Baseline DNS is unaffected. Check `probe_dropped_total{reason}` and `probe_bandwidth_bytes_total` against the daily budget. |
| Candidates exist but are never used | The domain is not eligible: not a Cloudflare answer, DNSSEC not proven Insecure, ECH published, or no measured advantage. | `cloudflare_fallback_total{reason}` names the exact condition. |

No failure in this section can make DNS resolution fail. The worst case is that answers are
returned exactly as the upstream sent them, which is what a plain forwarder does.

## 17. Disabling Cloudflare optimization without stopping baseline DNS

Three levels, from softest to hardest. None of them interrupts resolution.

**1. Runtime, no restart, no configuration change** — takes effect on the next query:

```sh
egressdnsctl -s "$SOCK" cloudflare set-mode preserve   # stop adding addresses
egressdnsctl -s "$SOCK" cloudflare set-mode off        # stop touching answers entirely
egressdnsctl -s "$SOCK" cloudflare status              # confirm
```

This is the button to press during an incident. `off` means answers are returned in exactly
the order the upstream sent them.

**2. Persist it** so a restart does not undo the change:

```toml
[cloudflare]
mode = "off"      # or "preserve"
```

```sh
sudo egressdnsctl check-config -c /etc/egressdns/config.toml
sudo egressdnsctl -s "$SOCK" reload
```

**3. Stop the background work as well**, when you want zero outbound probe traffic:

```toml
[cloudflare]
mode = "off"

[cloudflare.seeds]
enabled = false

[probe]
enabled = false
```

After a reload the daemon is a plain caching forwarder: no probing, no candidate lists, no
sampling, no reordering. Everything in sections 1–15 still applies, and every test in §3
still passes. That is the design contract — the optimization is a strictly additive layer,
and removing it leaves a correct resolver behind.

To confirm nothing is left running:

```sh
egressdnsctl -s "$SOCK" status | grep -E 'probe|cloudflare'
# egressdns_probe_queue_depth and egressdns_cloudflare_candidates should both be 0
curl -s localhost:9153/metrics | grep -E 'probe_queue_depth|cloudflare_candidates'
```
