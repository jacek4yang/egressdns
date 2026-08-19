#!/usr/bin/env bash
#
# EgressDNS uninstaller.
#
#   sudo ./uninstall.sh                 # remove binaries and the unit, keep configuration and state
#   sudo ./uninstall.sh --purge         # also remove configuration, state and the service account
#
# Removing EgressDNS does not restore whatever resolver you were using before. The final
# message tells you exactly what to re-enable.

set -Eeuo pipefail

readonly PROGRAM="egressdns"
readonly BIN_DIR="/usr/local/bin"
readonly CONF_DIR="/etc/egressdns"
readonly STATE_DIR="/var/lib/egressdns"
readonly RUN_DIR="/run/egressdns"
readonly UNIT_PATH="/etc/systemd/system/egressdns.service"
readonly SERVICE_USER="egressdns"

PURGE=0
ASSUME_YES=0

log()  { printf '[%s] %s\n' "$PROGRAM" "$*" >&2; }
die()  { printf '[%s] error: %s\n' "$PROGRAM" "$*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --purge) PURGE=1;      shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --help|-h)
            cat <<'USAGE'
Usage: uninstall.sh [--purge] [--yes]

  --purge   Also remove /etc/egressdns, /var/lib/egressdns and the service account.
  --yes     Do not ask for confirmation.
USAGE
            exit 0 ;;
        *) die "unknown option '$1' (try --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"

if [ "$PURGE" -eq 1 ] && [ "$ASSUME_YES" -eq 0 ]; then
    printf 'This will delete %s and %s. Continue? [y/N] ' "$CONF_DIR" "$STATE_DIR" >&2
    read -r reply
    case "$reply" in
        y|Y|yes|YES) : ;;
        *) die "aborted" ;;
    esac
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet egressdns.service 2>/dev/null; then
        log "stopping egressdns.service"
        systemctl stop egressdns.service || true
    fi
    if systemctl is-enabled --quiet egressdns.service 2>/dev/null; then
        systemctl disable egressdns.service || true
    fi
fi

rm -f "$UNIT_PATH"
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

for binary in egressdnsd egressdnsctl; do
    if [ -f "$BIN_DIR/$binary" ]; then
        rm -f "$BIN_DIR/$binary"
        log "removed $BIN_DIR/$binary"
    fi
done

rm -rf "$RUN_DIR"

if [ "$PURGE" -eq 1 ]; then
    rm -rf "$CONF_DIR" "$STATE_DIR"
    log "removed $CONF_DIR and $STATE_DIR"
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        userdel "$SERVICE_USER" 2>/dev/null || true
        log "removed the service account '$SERVICE_USER'"
    fi
else
    log "kept $CONF_DIR and $STATE_DIR (use --purge to remove them)"
fi

cat >&2 <<'MSG'

EgressDNS has been removed. Nothing else was changed, so this host currently has no local
resolver. Re-enable whichever one you were using before, for example:

    sudo systemctl enable --now systemd-resolved
    sudo systemctl enable --now unbound

and update DHCP if this node was advertised to clients.
MSG
