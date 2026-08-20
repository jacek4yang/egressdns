# EgressDNS binary release

This archive contains statically-linkable Linux binaries, a systemd unit, a production
configuration template and the installation scripts.

## Verify what you downloaded

Do this before running anything. `SHA256SUMS` is published alongside the archives on the
release page.

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

If the check does not print `OK` for your archive, stop.

## Install

The scripted path:

```sh
sudo ./install.sh --local-build
```

Or by hand, which is the same thing written out:

```sh
sudo install -m 0755 egressdnsd egressdnsctl /usr/local/bin/
sudo install -d -m 0750 /etc/egressdns /var/lib/egressdns
sudo install -m 0640 egressdns.toml /etc/egressdns/config.toml
sudo install -m 0644 egressdns.service /etc/systemd/system/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin egressdns || true
sudo chown -R egressdns:egressdns /var/lib/egressdns
```

## Configure

The shipped `egressdns.toml` is a complete working file. It has two keys that matter:

* `upstreams` — where queries are forwarded, as addresses or URIs. The shipped list names
  public resolvers as an example, not as a recommendation.
* `proxies` — egress proxies, tried when the direct path is unhealthy. Empty by default.

Listeners default to loopback, so the resolver serves this machine and nothing else until
you say otherwise. Serving a LAN means adding a `[server]` table with non-loopback
listeners *and* an explicit `allow_from`: with one and not the other, startup is refused
rather than guessing, because the guess would be an open resolver. See
`egressdns.lan.example.toml`.

Then validate the file before asking systemd to start anything. A configuration error at
this point is a message on your terminal; the same error at start time is a failed unit:

```sh
sudo egressdnsd --config /etc/egressdns/config.toml --check-config
```

## Start

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now egressdns
systemctl status egressdns
```

Confirm it answers:

```sh
dig @127.0.0.1 -p 53 example.com A +short
```

## Reload

Most settings apply live:

```sh
sudo systemctl reload egressdns
```

Some cannot — listening sockets, thread counts, cache budgets and other structures that
are built once at startup. Those changes are **refused by name** rather than silently
accepted, so a reload that prints a list of restart-required fields has changed nothing.
Apply them with `systemctl restart` instead. The complete classification is in
`docs/CONFIGURATION.md`.

## Upgrade and removal

```sh
sudo ./upgrade.sh --local-build     # replaces the binaries and restarts
sudo ./uninstall.sh                 # removes the unit, binaries and optionally state
```

## Where things live

| Path | Contents |
| --- | --- |
| `/usr/local/bin/egressdnsd` | the daemon |
| `/usr/local/bin/egressdnsctl` | the control client |
| `/etc/egressdns/config.toml` | configuration |
| `/var/lib/egressdns/` | persisted measurement state |
| `/run/egressdns/admin.sock` | administration socket, when enabled |

Operational guidance — metrics, alerting, capacity planning and failure modes — is in
`docs/OPERATIONS.md`.
