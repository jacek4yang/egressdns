#!/usr/bin/env bash
#
# Build the distributable source archive and its internal manifest.
#
#   ./scripts/build-source-archive.sh [output-directory]
#
# Produces egressdns-v<version>-source.tar.gz containing exactly one top-level directory,
# `egressdns/`, with no build artefacts, VCS metadata, caches or credentials.

set -Eeuo pipefail

# Derived from Cargo.toml rather than hard-coded: an archive named for a version the
# tree is not is worse than no archive at all.
VERSION="v$(sed -n '0,/^version = /s/^version = "\(.*\)"/\1/p' \
    "$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml")"
readonly VERSION
readonly NAME="egressdns"

root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="${1:-$root/dist}"
mkdir -p "$out_dir"

work="$(mktemp -d "${TMPDIR:-/tmp}/egressdns-archive.XXXXXX")"
trap 'rm -rf "$work"' EXIT
stage="$work/$NAME"
mkdir -p "$stage"

printf '[archive] staging the source tree\n' >&2
# `git archive` guarantees only tracked files are included, which is the strongest possible
# statement about what is and is not in the archive.
if git -C "$root" rev-parse --git-dir >/dev/null 2>&1 && [ -z "$(git -C "$root" status --porcelain)" ]; then
    git -C "$root" archive --format=tar HEAD | tar -x -C "$stage"
else
    printf '[archive] working tree is dirty or not a repository; copying with exclusions\n' >&2
    tar -C "$root" \
        --exclude='./.git' \
        --exclude='./target' \
        --exclude='./dist' \
        --exclude='./fuzz/target' \
        --exclude='./fuzz/corpus' \
        --exclude='./fuzz/artifacts' \
        --exclude='*.sqlite3' \
        --exclude='*.sqlite3-wal' \
        --exclude='*.sqlite3-shm' \
        --exclude='*.corrupt-*' \
        -cf - . | tar -x -C "$stage"
fi

# Belt and braces: remove anything that must never ship even if it was tracked by mistake.
rm -rf "$stage/.git" "$stage/target" "$stage/dist" \
       "$stage/fuzz/target" "$stage/fuzz/corpus" "$stage/fuzz/artifacts"
find "$stage" -name '*.sqlite3*' -delete
find "$stage" -name '*.corrupt-*' -delete

printf '[archive] generating MANIFEST.sha256\n' >&2
# A manifest cannot record its own digest: writing the file changes the thing being
# hashed. So any manifest carried in from the source tree is removed first, the new one is
# written outside the staging directory, and `find` is told to skip it either way. A
# committed MANIFEST.sha256 is guaranteed to be stale, which is why it is gitignored.
rm -f "$stage/MANIFEST.sha256"
(
    cd "$stage"
    find . -type f ! -name MANIFEST.sha256 -print0 |
        LC_ALL=C sort -z |
        xargs -0 sha256sum > "$work/MANIFEST.sha256"
)
mv "$work/MANIFEST.sha256" "$stage/MANIFEST.sha256"

archive="$out_dir/${NAME}-${VERSION}-source.tar.gz"
rm -f "$archive"
printf '[archive] writing %s\n' "$archive" >&2
# --sort=name and a fixed mtime, owner and group make the archive byte-reproducible from
# the same source tree.
tar --owner=0 --group=0 --numeric-owner \
    --sort=name \
    --mtime='2026-01-01 00:00:00 UTC' \
    -czf "$archive" -C "$work" "$NAME"

sha256sum "$archive" | tee "$archive.sha256"
printf '[archive] %s files, %s\n' \
    "$(tar -tzf "$archive" | grep -vc '/$' || true)" \
    "$(du -h "$archive" | cut -f1)" >&2
