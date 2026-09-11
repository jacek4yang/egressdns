# Releasing

## Repository identity

The official repository is [`jacek4yang/egressdns`](https://github.com/jacek4yang/egressdns),
and that identity is hard-coded throughout the tree: `Cargo.toml` (`repository`,
`homepage`), `README.md`, `install.sh` and `upgrade.sh` (default `--repo`),
`scripts/publish-first-release.sh`, `docs/OPERATIONS.md`, and the packaging metadata in
`packaging/`. There is nothing to substitute before a release.

`.github/workflows/release.yml` derives the repository from `GITHUB_REPOSITORY` at run
time, so it also works unchanged on a fork.

## Preconditions

Everything in this list must actually pass. A release built from a tree where one of them
was skipped is a release whose provenance you cannot describe later.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --release --locked
cargo deny check
cargo audit
shellcheck --shell=bash install.sh upgrade.sh uninstall.sh scripts/*.sh
./scripts/check-config-docs.py
./scripts/pin-github-actions.sh --check
for f in config/*.toml; do ./target/release/egressdnsd --config "$f" --check-config; done
```

For a release that changes the request path, also run the load suite and update
`docs/BENCHMARKS.md` with the numbers *from that run*:

```sh
./scripts/load-test.sh --duration 45 --sustained 480
```

## Versioning

The tag must be `v` plus the exact `version` in `Cargo.toml`. `release.yml` checks this and
fails the run if they disagree, because an archive that advertises a version the binary
does not report is impossible to reason about after the fact.

Update in this order:

1. `Cargo.toml` — `version`
2. `Cargo.lock` — `cargo update -p egressdns` (or any build; it is committed)
3. `CHANGELOG.md` — move `[Unreleased]` to the new version with today's date
4. `STATUS.md` — re-run the verification commands and update the numbers
5. Commit, then tag

## Publishing

```sh
git tag -a v1.2.3 -m "EgressDNS v1.2.3"
git push origin v1.2.3
```

The tag push triggers `.github/workflows/release.yml`, which:

1. Verifies the tag matches `Cargo.toml`, on every build job independently.
2. Builds `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` **in one job**, so
   those artefacts never leave the runner until they are complete archives, and
   `x86_64-pc-windows-msvc` on a Windows runner — every artifact built natively.
3. Verifies each built binary reports the tagged version, on its own platform. The
   Windows job also runs `--check-config` against the shipped example before it is
   allowed to ship.
4. Produces reproducible Linux tarballs — fixed ownership, sorted entries, the tag
   commit's date as the mtime — a Windows zip, and a `SHA256SUMS` covering every archive,
   generated from the bytes that are about to be published.
5. Creates the release as a **draft**, uploads everything, then publishes. A partially
   uploaded release is never visible.

No third-party action runs in that workflow. `gh` is preinstalled on the runner, so the
token is never handed to code outside GitHub's own tooling.

`scripts/publish-first-release.sh` does the first push with pre-flight checks: it refuses
a dirty tree and never force-pushes.

## Verifying a published release

From a clean machine, as a user would:

```sh
gh release download v1.2.3 --repo jacek4yang/egressdns
sha256sum -c SHA256SUMS --ignore-missing
tar -tzf egressdns-v1.2.3-linux-x86_64.tar.gz | head
./egressdns/egressdnsd --version
```

## If something goes wrong

**Do not force-push a tag.** A tag that moves means two different builds claim the same
version, and anyone who already downloaded the first one has no way to find out. Delete
the release, delete the tag, and publish the next patch version instead:

```sh
gh release delete v1.2.3 --repo jacek4yang/egressdns --yes
git push --delete origin v1.2.3
git tag -d v1.2.3
```

Then fix, bump to `v1.2.4`, and tag again.

## Updating pinned actions

Action references are commit SHAs, so Dependabot updates them like any other dependency.
To refresh them by hand:

```sh
GITHUB_TOKEN=... ./scripts/pin-github-actions.sh
./scripts/pin-github-actions.sh --check
```

Read the diff before committing. The trailing `# vX` comment records what the SHA was
resolved from; a SHA that changes without the comment changing means the tag moved, which
is exactly the situation pinning exists to make visible.
