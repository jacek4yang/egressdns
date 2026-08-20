# The post-install TCP canary failed under proxychains

**Date:** 2026-08-20
**Severity:** release-blocking — installation always rolled back
**Affected:** any install run through `proxychains` without a loopback bypass

## Symptom

```
[egressdns] UDP canary against 127.0.0.1:53
[egressdns] TCP canary against 127.0.0.1:53
[egressdns] warning: tcp canary against 127.0.0.1:53 did not return a usable answer
[egressdns] error: post-install TCP canary failed
[egressdns] warning: rolling back to the previous installation
```

UDP passes, TCP fails, every time. The installer then correctly rolls back, so the user
ends with no new installation and no explanation.

## Root cause

`proxychains` hooks `connect(2)` through `LD_PRELOAD`. Every TCP connection the process
makes is redirected to the configured SOCKS proxy — **including connections to
127.0.0.1**, unless the configuration carries a `localnet` bypass.

The host's `/etc/proxychains4.conf`:

```
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 192.168.31.105 10808
```

There is no `localnet` line. So when the installer runs

```sh
egressdnsctl query example.com --server 127.0.0.1 --port 53 --tcp
```

under `sudo proxychains -q bash`, the TCP connection to the resolver *we just installed on
this machine* is sent to 192.168.31.105:10808 and asked to reach 127.0.0.1:53 — which,
from the proxy's point of view, is the proxy's own loopback. The stream closes without the
RFC 7766 two-octet length prefix.

UDP is untouched: proxychains intercepts TCP `connect`, not datagram sends. That is the
whole reason the failure is UDP-passes-TCP-fails rather than everything failing, and it is
what makes the symptom look like a TCP ingress defect in the daemon.

**The daemon's TCP ingress was never broken.**

## Reproduction

Against a healthy running daemon on this host, same binary, same listener:

```
$ proxychains -q egressdnsctl query example.com --server 127.0.0.1 --port 53 --json
{ "result": "answered", "rcode": "NOERROR", "answer_records": 2, ... }        # exit 0

$ proxychains -q egressdnsctl query example.com --server 127.0.0.1 --port 53 --tcp --json
{ "result": "failed", "reason": "no length prefix from 127.0.0.1:53: early eof" }
                                                                              # exit 2
```

And with the interception removed for that one command:

```
$ proxychains -q env -u LD_PRELOAD egressdnsctl query example.com \
    --server 127.0.0.1 --port 53 --tcp --json
{ "result": "answered", "rcode": "NOERROR", "answer_records": 2, ... }        # exit 0
```

## Fix

A health check against a loopback listener must never traverse a proxy. That is true
regardless of proxychains: the question a local canary asks is "is the resolver on *this
machine* answering", and routing it through an intermediary answers a different question.

The installer now runs every local canary with the interception cleared —
`LD_PRELOAD`, `LD_LIBRARY_PATH` and the `*_PROXY` variables are unset for the canary
command only. Artifact downloads keep the proxy, because those genuinely do need to leave
the host.

## What this exposed

Two further defects, both fixed alongside it:

* **The local canary needed the Internet.** It resolved `example.com`, so a listener test
  could fail because of upstream trouble rather than the listener. Local ingress is now
  proven with `localhost`, which EgressDNS answers itself, and forwarding is a separate
  check with its own quorum.
* **The failure reason was discarded.** The canary redirected output to `/dev/null`, so the
  operator saw "did not return a usable answer" and nothing else. The rcode, answer count,
  elapsed time and recent daemon logs are now printed and preserved in a diagnostic bundle
  that survives rollback.
