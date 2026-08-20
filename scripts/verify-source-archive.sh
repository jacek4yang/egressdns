#!/usr/bin/env bash
#
# Validate a source archive exactly the way a user would consume it.
#
#   ./scripts/verify-source-archive.sh dist/egressdns-v1.0.0-source.tar.gz [--full]
#
# Without --full it performs the structural checks. With --full it also extracts into a
# temporary directory and runs a release build and the whole test suite.

set -Eeuo pipefail

FAILURES=0
FULL=0

pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
info() { printf '\n=== %s\n' "$*"; }

archive="${1:-}"
[ -n "$archive" ] || { printf 'usage: %s <archive.tar.gz> [--full]\n' "$0" >&2; exit 1; }
[ -f "$archive" ] || { printf 'no such archive: %s\n' "$archive" >&2; exit 1; }
[ "${2:-}" = "--full" ] && FULL=1

info "listing the archive"
listing="$(tar -tzf "$archive")"
printf '%s\n' "$listing" | head -20
printf '  ... %s entries\n' "$(printf '%s\n' "$listing" | wc -l)"

info "top-level directory"
tops="$(printf '%s\n' "$listing" | cut -d/ -f1 | sort -u)"
if [ "$tops" = "egressdns" ]; then
    pass "exactly one top-level directory: egressdns/"
else
    fail "expected a single top-level directory 'egressdns', found: $tops"
fi

info "excluded content"
for pattern in '^egressdns/\.git/' '^egressdns/target/' '\.sqlite3' '\.corrupt-' 'fuzz/corpus/' 'fuzz/artifacts/'; do
    if printf '%s\n' "$listing" | grep -Eq "$pattern"; then
        fail "archive contains $pattern"
    else
        pass "no $pattern"
    fi
done

info "required content"
for required in \
    egressdns/Cargo.toml \
    egressdns/Cargo.lock \
    egressdns/rust-toolchain.toml \
    egressdns/README.md \
    egressdns/CHANGELOG.md \
    egressdns/SECURITY.md \
    egressdns/CLAUDE.md \
    egressdns/STATUS.md \
    egressdns/LICENSE-MIT \
    egressdns/LICENSE-APACHE \
    egressdns/MANIFEST.sha256 \
    egressdns/install.sh \
    egressdns/upgrade.sh \
    egressdns/uninstall.sh \
    egressdns/src/lib.rs \
    egressdns/src/bin/egressdnsd.rs \
    egressdns/src/bin/egressdnsctl.rs \
    egressdns/config/egressdns.lan.example.toml \
    egressdns/config/egressdns.toml \
    egressdns/config/egressdns.toml \
    egressdns/packaging/systemd/egressdns.service \
    egressdns/.github/workflows/ci.yml \
    egressdns/.github/workflows/release.yml \
    egressdns/docs/RESEARCH.md \
    egressdns/docs/ARCHITECTURE.md \
    egressdns/docs/THREAT_MODEL.md \
    egressdns/docs/RFC_COMPLIANCE.md \
    egressdns/docs/OPERATIONS.md \
    egressdns/docs/CONFIGURATION.md \
    egressdns/docs/BENCHMARKS.md \
    egressdns/docs/adr/README.md \
    egressdns/docs/adr/0001-forwarder-not-recursive.md \
    egressdns/docs/adr/0010-preserve-before-augment.md \
    egressdns/packaging/debian/control \
    egressdns/packaging/nftables/egressdns.nft \
    egressdns/fuzz/Cargo.toml \
    egressdns/tests/properties.rs \
    egressdns/benches/hot_path.rs \
    egressdns/scripts/load-test.sh \
    egressdns/scripts/chaos-test.sh
do
    if printf '%s\n' "$listing" | grep -Fxq "$required"; then
        pass "$required"
    else
        fail "missing $required"
    fi
done

info "secrets and absolute paths"
# A --full run compiles the whole workspace and links every test binary inside this
# directory. On a distribution whose /tmp is a RAM-backed tmpfs that competes with the
# linker for memory, and the failure it produces is "ld terminated with signal 7 [Bus
# error]" — which reads like a compiler bug rather than a full disk. Prefer a
# disk-backed directory beside the archive when the caller has not chosen one.
if [ "${FULL:-0}" = "1" ] && [ -z "${TMPDIR:-}" ] &&
    [ "$(stat -f -c %T /tmp 2>/dev/null || echo unknown)" = "tmpfs" ]; then
    TMPDIR="$(cd "$(dirname "$archive")" && pwd)"
    export TMPDIR
    info "using $TMPDIR for the build: /tmp is a tmpfs and --full needs real disk"
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar -xzf "$archive" -C "$work"
tree="$work/egressdns"

if grep -rIlE 'BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY' "$tree" >/dev/null 2>&1; then
    fail "a private key is present"
else
    pass "no private keys"
fi

if grep -rIlE '(gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})' "$tree" >/dev/null 2>&1; then
    fail "an API token is present"
else
    pass "no API tokens"
fi

if grep -rIl --exclude-dir=.github -E '/home/[a-z0-9_-]+/|/Users/[a-z0-9_-]+/' "$tree" >/dev/null 2>&1; then
    grep -rIl --exclude-dir=.github -E '/home/[a-z0-9_-]+/|/Users/[a-z0-9_-]+/' "$tree" | head -5
    fail "an absolute local path is present"
else
    pass "no absolute local paths"
fi

# The needles are assembled from fragments so that this script, which ships inside the
# archive it verifies, does not itself contain the strings it is checking for. That means
# the check can cover the whole tree with no exclusions.
forbidden_a="zip.cm.$(printf 'edu').kg"
forbidden_b="all.$(printf 'json')"
for needle in "$forbidden_a" "$forbidden_b"; do
    if grep -rIl -F "$needle" "$tree" >/dev/null 2>&1; then
        grep -rIl -F "$needle" "$tree" | head -5
        fail "the forbidden reference '$needle' is present"
    else
        pass "no reference to '$needle'"
    fi
done

info "MANIFEST.sha256"
if [ -f "$tree/MANIFEST.sha256" ]; then
    # The manifest deliberately does not list itself — writing it would change the thing
    # being hashed — so every entry it does list must match exactly.
    if grep -q ' \./MANIFEST.sha256$' "$tree/MANIFEST.sha256"; then
        fail "the manifest lists itself, which can never verify"
    elif (cd "$tree" && sha256sum --quiet --check MANIFEST.sha256); then
        pass "every file matches its recorded digest"
    else
        fail "manifest verification failed"
    fi
else
    fail "MANIFEST.sha256 is missing"
fi

info "shell scripts"
if (cd "$tree" && bash -n install.sh upgrade.sh uninstall.sh scripts/*.sh); then
    pass "bash -n"
else
    fail "bash -n reported a syntax error"
fi
if command -v shellcheck >/dev/null 2>&1; then
    if (cd "$tree" && shellcheck --severity=warning install.sh upgrade.sh uninstall.sh scripts/*.sh); then
        pass "shellcheck"
    else
        fail "shellcheck reported findings"
    fi
else
    printf '  SKIP  shellcheck is not installed\n'
fi

info "workflow YAML"
if command -v python3 >/dev/null 2>&1; then
    if python3 - "$tree" <<'PY'
import pathlib, sys
try:
    import yaml
except ImportError:
    print("  SKIP  PyYAML is not installed")
    sys.exit(0)
root = pathlib.Path(sys.argv[1])
bad = False
for path in sorted((root / ".github/workflows").glob("*.yml")):
    try:
        yaml.safe_load(path.read_text())
    except Exception as exc:
        print(f"  invalid {path.name}: {exc}")
        bad = True
sys.exit(1 if bad else 0)
PY
    then
        pass "workflow YAML parses"
    else
        fail "a workflow file is not valid YAML"
    fi
fi

if [ "$FULL" -eq 1 ]; then
    info "release build from the extracted archive"
    if (cd "$tree" && cargo build --release --locked); then
        pass "cargo build --release --locked"
    else
        fail "the release build failed"
    fi

    info "test suite"
    if (cd "$tree" && cargo test --workspace --all-features); then
        pass "cargo test --workspace --all-features"
    else
        fail "the test suite failed"
    fi

    info "shipped configurations"
    for cfg in "$tree"/config/*.toml; do
        if (cd "$tree" && ./target/release/egressdnsd --config "$cfg" --check-config >/dev/null); then
            pass "$(basename "$cfg")"
        else
            fail "$(basename "$cfg") is not valid"
        fi
    done
fi

info "summary"
if [ "$FAILURES" -eq 0 ]; then
    printf 'archive validation passed\n'
    exit 0
fi
printf '%d check(s) failed\n' "$FAILURES"
exit 1
