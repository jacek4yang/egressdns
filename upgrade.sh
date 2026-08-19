#!/usr/bin/env bash
#
# EgressDNS upgrade and rollback helper.
#
#   sudo ./upgrade.sh [--version v1.0.1]                 # upgrade from the official repo
#                                                          (jacek4yang/egressdns)
#   sudo ./upgrade.sh --repo <owner>/<name>              # upgrade from a fork (advanced)
#   sudo ./upgrade.sh --local-build                      # upgrade from the source tree
#   sudo ./upgrade.sh --rollback                         # restore the previous binaries
#
# An upgrade keeps your configuration untouched, snapshots the current binaries, and
# restores them automatically if the new version fails to start or fails its health check.

set -Eeuo pipefail

readonly PROGRAM="egressdns"
readonly BIN_DIR="/usr/local/bin"
readonly CONF_DIR="/etc/egressdns"
readonly ROLLBACK_DIR="/var/lib/egressdns/rollback"
readonly DAEMON="egressdnsd"
readonly CONTROL="egressdnsctl"

log()  { printf '[%s] %s\n' "$PROGRAM" "$*" >&2; }
warn() { printf '[%s] warning: %s\n' "$PROGRAM" "$*" >&2; }
die()  { printf '[%s] error: %s\n' "$PROGRAM" "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
Usage: upgrade.sh [options]

  --repo <owner/name>   GitHub repository to download release assets from
                        (default: jacek4yang/egressdns). Advanced override,
                        intended for development and testing forks.
  --version <tag>       Release tag to install (default: latest).
  --local-build         Build from the current source tree instead of downloading.
  --rollback            Restore the snapshot taken by the previous upgrade and exit.
  --help                Show this help.
USAGE
}

REPO="jacek4yang/egressdns"
VERSION="latest"
LOCAL_BUILD=0
ROLLBACK=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --repo)        REPO="${2:-}";    shift 2 ;;
        --version)     VERSION="${2:-}"; shift 2 ;;
        --local-build) LOCAL_BUILD=1;    shift ;;
        --rollback)    ROLLBACK=1;       shift ;;
        --help|-h)     usage; exit 0 ;;
        *)             die "unknown option '$1' (try --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"

snapshot() {
    install -d -m 0750 "$ROLLBACK_DIR"
    for binary in "$DAEMON" "$CONTROL"; do
        if [ -f "$BIN_DIR/$binary" ]; then
            cp -p "$BIN_DIR/$binary" "$ROLLBACK_DIR/$binary"
        fi
    done
    if [ -f "$CONF_DIR/config.toml" ]; then
        cp -p "$CONF_DIR/config.toml" "$ROLLBACK_DIR/config.toml"
    fi
    if [ -f /etc/systemd/system/egressdns.service ]; then
        cp -p /etc/systemd/system/egressdns.service "$ROLLBACK_DIR/egressdns.service"
    fi
    "$BIN_DIR/$DAEMON" --version > "$ROLLBACK_DIR/version.txt" 2>/dev/null || true
    log "snapshot stored in $ROLLBACK_DIR"
}

restore() {
    [ -d "$ROLLBACK_DIR" ] || die "no rollback snapshot found in $ROLLBACK_DIR"
    local restored=0
    for binary in "$DAEMON" "$CONTROL"; do
        if [ -f "$ROLLBACK_DIR/$binary" ]; then
            install -m 0755 "$ROLLBACK_DIR/$binary" "$BIN_DIR/$binary"
            restored=1
        fi
    done
    [ "$restored" -eq 1 ] || die "the snapshot contains no binaries to restore"
    if [ -f "$ROLLBACK_DIR/egressdns.service" ]; then
        install -m 0644 "$ROLLBACK_DIR/egressdns.service" /etc/systemd/system/egressdns.service
    fi
    systemctl daemon-reload 2>/dev/null || true
    if ! "$BIN_DIR/$DAEMON" --config "$CONF_DIR/config.toml" --check-config; then
        warn "the current configuration is not valid for the restored binary"
        if [ -f "$ROLLBACK_DIR/config.toml" ]; then
            log "restoring the snapshotted configuration as well"
            install -m 0640 "$ROLLBACK_DIR/config.toml" "$CONF_DIR/config.toml"
        fi
    fi
    systemctl restart egressdns.service 2>/dev/null || true
    log "rollback complete: $("$BIN_DIR/$DAEMON" --version 2>/dev/null || echo unknown)"
}

health() {
    command -v systemctl >/dev/null 2>&1 || return 0
    sleep 1
    systemctl is-active --quiet egressdns.service || return 1
    command -v "$BIN_DIR/$CONTROL" >/dev/null 2>&1 || return 0
    "$BIN_DIR/$CONTROL" status >/dev/null 2>&1 || return 1
    return 0
}

if [ "$ROLLBACK" -eq 1 ]; then
    restore
    exit 0
fi

[ -f "$BIN_DIR/$DAEMON" ] || die "EgressDNS is not installed; run install.sh first"

log "current version: $("$BIN_DIR/$DAEMON" --version 2>/dev/null || echo unknown)"
snapshot

installer=""
for candidate in "$(dirname "$0")/install.sh" "./install.sh" "/usr/local/share/egressdns/install.sh"; do
    if [ -f "$candidate" ]; then installer="$candidate"; break; fi
done
[ -n "$installer" ] || die "install.sh was not found next to upgrade.sh"

args=()
if [ "$LOCAL_BUILD" -eq 1 ]; then
    args+=(--local-build)
else
    args+=(--repo "$REPO" --version "$VERSION")
fi

if ! bash "$installer" "${args[@]}"; then
    warn "the upgrade failed; restoring the snapshot"
    restore
    exit 1
fi

if ! health; then
    warn "the upgraded service is unhealthy; restoring the snapshot"
    restore
    exit 1
fi

log "upgrade complete: $("$BIN_DIR/$DAEMON" --version 2>/dev/null || echo unknown)"
log "roll back at any time with: sudo ./upgrade.sh --rollback"
