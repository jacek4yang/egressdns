# Debian packaging

These files build a `.deb` from a source checkout. They are provided for operators who
prefer distribution packaging over the tarball installer; the release workflow produces
tarballs, not `.deb` files.

```sh
sudo apt install devscripts debhelper build-essential
cp -r packaging/debian ./debian
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../egressdns_1.0.0-1_amd64.deb
```

The `debian/` directory must be at the top of the source tree for `dpkg-buildpackage`,
which is why it is kept under `packaging/` here and copied into place — having a top-level
`debian/` in the repository would make every tarball look like a Debian source package.

## Deliberate behaviours

* **The service is not started or enabled on install.** Port 53 is normally already owned
  by `systemd-resolved`. Taking it over silently would break the machine's own name
  resolution during a package install, which is an unacceptable thing for a package to do.
  The postinst prints what to do next.
* **`setcap` is applied to `/usr/bin/egressdnsd`** so the daemon can bind port 53 without
  running as root. It is re-applied on every upgrade because replacing the binary clears
  it.
* **The config file is `root:egressdns` mode 0640.** The daemon reads it; it cannot write
  it.
* **`purge` removes state and configuration**; `remove` does not.
* **`Conflicts:` lists the common resolvers** rather than silently coexisting with them.
