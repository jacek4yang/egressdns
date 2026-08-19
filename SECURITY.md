# Security policy

## Reporting a vulnerability

Report privately. Do not open a public issue for a security problem.

* Preferred: GitHub Security Advisories — *Security* → *Report a vulnerability* on the
  repository.
* Alternative: contact the repository owner directly through the address on their GitHub
  profile.

Please include the version (`egressdnsd --version`), the configuration with secrets
removed (`egressdnsctl dump-effective-config` redacts them), what you observed, and a
reproduction if you have one. If you have a patch, say so and we will coordinate.

Expect an acknowledgement within a few days and an assessment within two weeks. If the
report is confirmed, we will agree a disclosure timeline with you; 90 days is the default
and we will move faster for anything being exploited.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No |

## What counts as a vulnerability

In scope, in rough order of severity:

* **Cache poisoning or answer forgery.** Anything that causes a client to receive an
  address the upstream did not send, outside the documented verified-augment path.
* **DNSSEC bypass.** Any input that causes a Bogus result to be served as an answer, or the
  AD bit to be set on data this resolver did not validate.
* **Remote crash or hang.** A crafted DNS message, admin request, dataset file, seed
  response or configuration that panics the daemon or wedges the request path.
* **Unbounded resource use.** Any input that grows memory, file descriptors, connections,
  goroutine-equivalents or metric cardinality without bound.
* **SSRF through the probe engine.** Any path that gets the probe engine to connect to a
  link-local, loopback or cloud-metadata address. This is defended in two independent
  places — the config validator and the runtime guard — and a bypass of either is a valid
  report even if the other still holds.
* **Privilege issues.** Anything that escapes the systemd sandbox, or that needs more than
  `CAP_NET_BIND_SERVICE`.
* **Admin socket exposure.** Any path that lets a user without socket access flush the
  cache, change modes, or read the configuration.
* **Information disclosure.** Query names, client addresses or configuration secrets
  appearing in logs, metrics labels or the persisted database. None of these are supposed
  to be there at all.

## What does not count

* **A client on the LAN seeing another client's cleartext DNS.** Ingress is unencrypted
  Do53 by design in v1.0.0; see [ADR-0007](docs/adr/0007-do53-only-ingress.md). Restrict
  access at the network layer.
* **An operator with admin-socket access doing operator things.** The socket is a control
  interface. It is mode 0600 and owned by the service account.
* **An operator configuring something harmful to themselves**, where the daemon warned or
  the documentation says not to. Configuration that could compromise *clients* is in scope;
  configuration that only degrades the operator's own service is not.
* **A trusted upstream returning bad data that DNSSEC cannot detect.** Choosing an upstream
  is a trust decision the operator makes. Failing to *validate* what a signed zone says is
  in scope; an unsigned zone being wrong at the source is not.
* **Denial of service from an unauthenticated client that the ACL should have refused.**
  `server.allow_from` is default-deny for this reason. A bypass of the ACL is in scope.
* **Findings in dependencies with no exploitable path through this code.** Report them
  upstream. `cargo audit` and `cargo deny` run in CI and we will pick them up.

## Design commitments

These are properties the project commits to, and breaking one is a vulnerability:

* DNSSEC never fails open. There is no configuration that validates and then serves a
  Bogus answer.
* There is no TLS verification bypass. No `insecure_skip_verify`, no opportunistic
  downgrade, no "accept any certificate" mode. Pinning layers on top of verification, never
  instead of it.
* QUIC 0-RTT is refused by configuration validation, because replayable DNS queries are a
  cache-poisoning primitive.
* Cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`,
  `192.0.0.192`) can never be probed. An operator exception cannot re-enable them.
* Metrics label values are compile-time constants or small closed enums. Query names and
  client addresses are never labels.
* The persisted database contains no query names and no client identifiers.
* Extended DNS Error text is a fixed bounded compiled-in string, so a hostile name cannot
  be reflected through this daemon into another operator's logs.
* The crate is `#![forbid(unsafe_code)]`.

## Hardening the deployment

The shipped systemd unit runs as a dedicated system account with
`AmbientCapabilities=CAP_NET_BIND_SERVICE` and nothing else, `ProtectSystem=strict`,
`PrivateTmp`, `NoNewPrivileges`, a restricted syscall filter, and
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`. Verify it on your host:

```sh
systemd-analyze security egressdns
```

`packaging/nftables/egressdns.nft` restricts which sources can reach port 53 at the
network layer, which is the right place to enforce it given cleartext ingress.
