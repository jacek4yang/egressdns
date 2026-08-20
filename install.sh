#!/usr/bin/env bash
#
# EgressDNS installer.
#
# Remote install (latest release):
#   curl -fsSL "https://raw.githubusercontent.com/jacek4yang/egressdns/main/install.sh" \
#     | sudo bash
#
# Remote install (pinned version):
#   curl -fsSL "https://raw.githubusercontent.com/jacek4yang/egressdns/main/install.sh" \
#     | sudo bash -s -- --version "v1.0.0"
#
# Local install from an extracted source archive:
#   sudo ./install.sh --local-build
#
# The installer never removes another DNS service. If something already owns port 53 it
# reports what and stops, leaving your system exactly as it was.

set -Eeuo pipefail

readonly PROGRAM="egressdns"
readonly DAEMON="egressdnsd"
readonly CONTROL="egressdnsctl"
readonly BIN_DIR="/usr/local/bin"
readonly CONF_DIR="/etc/egressdns"
readonly STATE_DIR="/var/lib/egressdns"
readonly RUN_DIR="/run/egressdns"
readonly UNIT_PATH="/etc/systemd/system/egressdns.service"
readonly SERVICE_USER="egressdns"

REPO="jacek4yang/egressdns"
VERSION="latest"
CONFIG_SOURCE=""
LOCAL_BUILD=0
NO_START=0
FORCE=0
BACKUP_DIR=""
ROOT_PREFIX="${EGRESSDNS_TEST_ROOT:-}"
WORK_DIR=""
ROLLBACK_NEEDED=0

log()  { printf '[%s] %s\n' "$PROGRAM" "$*" >&2; }
warn() { printf '[%s] warning: %s\n' "$PROGRAM" "$*" >&2; }
die()  { printf '[%s] error: %s\n' "$PROGRAM" "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
Usage: install.sh [options]

  --repo <owner/name>   GitHub repository to download release assets from
                        (default: jacek4yang/egressdns). Advanced override,
                        intended for development and testing forks.
  --version <tag>       Release tag to install (default: latest).
  --config <path>       Configuration file to install when none exists yet.
  --local-build         Build from the current source tree instead of downloading.
  --no-start            Install without enabling or starting the service.
  --force               Continue even when a pre-flight check would normally stop.
  --help                Show this help.

Environment:
  EGRESSDNS_TEST_ROOT   Install into this prefix instead of /. Used by the test suite;
                        systemd integration and health checks are skipped.
USAGE
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --repo)         REPO="${2:-}";          shift 2 ;;
            --version)      VERSION="${2:-}";       shift 2 ;;
            --config)       CONFIG_SOURCE="${2:-}"; shift 2 ;;
            --local-build)  LOCAL_BUILD=1;          shift ;;
            --no-start)     NO_START=1;             shift ;;
            --force)        FORCE=1;                shift ;;
            --help|-h)      usage; exit 0 ;;
            *)              die "unknown option '$1' (try --help)" ;;
        esac
    done
    if [ -n "$REPO" ] && ! printf '%s' "$REPO" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$'; then
        die "repository '$REPO' is not in <owner>/<name> form"
    fi
    if [ -n "$VERSION" ] && [ "$VERSION" != "latest" ] &&
       ! printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$'; then
        die "version '$VERSION' is not a valid release tag"
    fi
}

path() { printf '%s%s' "$ROOT_PREFIX" "$1"; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "must run as root (use sudo)"
    fi
}

detect_platform() {
    local os_id="unknown"
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        os_id="$(. /etc/os-release && printf '%s' "${ID:-unknown}")"
        local like
        # shellcheck source=/dev/null
        like="$(. /etc/os-release && printf '%s' "${ID_LIKE:-}")"
        case "$os_id $like" in
            *debian*|*ubuntu*) : ;;
            *)
                if [ "$FORCE" -eq 1 ]; then
                    warn "unsupported distribution '$os_id'; continuing because --force was given"
                else
                    die "this installer targets Debian and derivatives; found '$os_id' (use --force to override)"
                fi
                ;;
        esac
    else
        warn "cannot read /etc/os-release; assuming a Debian-like system"
    fi

    local machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64)  ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)             die "unsupported CPU architecture '$machine'; supported: x86_64, aarch64" ;;
    esac
    log "platform: ${os_id}/${ARCH}"
}

need_tool() {
    command -v "$1" >/dev/null 2>&1 || die "required tool '$1' is not installed"
}

check_port_53() {
    [ -n "$ROOT_PREFIX" ] && return 0
    local holder=""
    if command -v ss >/dev/null 2>&1; then
        holder="$(ss -lntup 2>/dev/null | awk '$5 ~ /:53$/ {print}' || true)"
    fi
    if [ -z "$holder" ]; then
        return 0
    fi
    if systemctl is-active --quiet egressdns.service 2>/dev/null; then
        log "port 53 is held by this service; treating as an upgrade"
        return 0
    fi
    printf '%s\n' "$holder" >&2
    if [ "$FORCE" -eq 1 ]; then
        warn "port 53 is already in use; continuing because --force was given"
        return 0
    fi
    cat >&2 <<'MSG'

Port 53 is already in use by the process shown above.

EgressDNS will not remove or disable another DNS service for you. Stop or reconfigure it
first, for example:

    sudo systemctl disable --now systemd-resolved
    sudo systemctl disable --now unbound

then re-run this installer.
MSG
    exit 3
}

create_user() {
    [ -n "$ROOT_PREFIX" ] && return 0
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        log "service account '$SERVICE_USER' already exists"
        return 0
    fi
    log "creating service account '$SERVICE_USER'"
    useradd --system --no-create-home --home-dir "$STATE_DIR" \
            --shell /usr/sbin/nologin "$SERVICE_USER"
}

make_dirs() {
    install -d -m 0755 "$(path "$BIN_DIR")"
    install -d -m 0750 "$(path "$CONF_DIR")"
    install -d -m 0750 "$(path "$STATE_DIR")"
    install -d -m 0750 "$(path "$RUN_DIR")"
    if [ -z "$ROOT_PREFIX" ]; then
        chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR" "$RUN_DIR"
        chown "root:$SERVICE_USER" "$CONF_DIR"
    fi
}

# Download with retries that cover the failures that actually happen.
#
# `curl --retry` alone does not retry a connection reset or an HTTP/2 PROTOCOL_ERROR —
# it covers transient *HTTP* statuses and timeouts. Those were exactly the failures seen
# against the GitHub CDN, and they aborted an install that a second attempt completed.
# `--retry-all-errors` covers them; the HTTP/1.1 fallback covers a middlebox that mangles
# HTTP/2, which no number of retries would fix.
fetch() {
    local url="$1" dest="$2"
    if curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors \
        --connect-timeout 20 --max-time 300 -o "$dest" "$url"; then
        return 0
    fi
    warn "download failed over HTTP/2; retrying with HTTP/1.1"
    curl -fsSL --http1.1 --retry 5 --retry-delay 2 --retry-all-errors \
        --connect-timeout 20 --max-time 300 -o "$dest" "$url"
}

backup_existing() {
    BACKUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/egressdns-backup.XXXXXX")"
    # Recorded before anything is replaced, so rollback can tell "restore the previous
    # version" from "there was no previous version".
    HAD_PREVIOUS=0
    if [ -f "$(path "$BIN_DIR")/$DAEMON" ]; then
        HAD_PREVIOUS=1
    fi
    for binary in "$DAEMON" "$CONTROL"; do
        if [ -f "$(path "$BIN_DIR")/$binary" ]; then
            cp -p "$(path "$BIN_DIR")/$binary" "$BACKUP_DIR/$binary"
        fi
    done
    if [ -f "$(path "$CONF_DIR")/config.toml" ]; then
        cp -p "$(path "$CONF_DIR")/config.toml" "$BACKUP_DIR/config.toml"
    fi
    if [ -f "$(path "$UNIT_PATH")" ]; then
        cp -p "$(path "$UNIT_PATH")" "$BACKUP_DIR/egressdns.service"
    fi
    log "previous installation backed up to $BACKUP_DIR"
}

rollback() {
    [ "$ROLLBACK_NEEDED" -eq 1 ] || return 0
    [ -n "$BACKUP_DIR" ] || return 0
    warn "rolling back to the previous installation"
    for binary in "$DAEMON" "$CONTROL"; do
        if [ -f "$BACKUP_DIR/$binary" ]; then
            install -m 0755 "$BACKUP_DIR/$binary" "$(path "$BIN_DIR")/$binary"
        else
            rm -f "$(path "$BIN_DIR")/$binary"
        fi
    done
    if [ -f "$BACKUP_DIR/config.toml" ]; then
        install -m 0640 "$BACKUP_DIR/config.toml" "$(path "$CONF_DIR")/config.toml"
        # `install` run as root leaves the file root:root. The service runs as
        # $SERVICE_USER and reads the config through its *group*, so without this the
        # restored configuration is unreadable to the daemon and the rollback leaves DNS
        # down while reporting success. Found by exercising a failed cutover.
        if [ -z "$ROOT_PREFIX" ] && id -u "$SERVICE_USER" >/dev/null 2>&1; then
            chown "root:$SERVICE_USER" "$(path "$CONF_DIR")/config.toml" || true
        fi
    fi
    if [ -f "$BACKUP_DIR/egressdns.service" ]; then
        install -m 0644 "$BACKUP_DIR/egressdns.service" "$(path "$UNIT_PATH")"
    fi
    if [ -z "$ROOT_PREFIX" ]; then
        systemctl daemon-reload || true
        # A unit that has just failed repeatedly is rate-limited: systemd refuses to
        # start it again until the failure is cleared. Without this the restart is
        # silently declined and the rollback ends with the service dead.
        systemctl reset-failed egressdns.service >/dev/null 2>&1 || true
        systemctl start egressdns.service >/dev/null 2>&1 || true

        # Rollback is the last line of defence, so it verifies itself rather than
        # assuming. If the previous version does not come back, say so plainly: an
        # operator who believes a rollback worked will not go looking.
        local recovered=0
        local had_previous="${HAD_PREVIOUS:-0}"
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if systemctl is-active --quiet egressdns.service; then
                recovered=1
                break
            fi
            sleep 1
        done
        if [ "$recovered" -eq 1 ]; then
            log "rolled back; the previous version is running again"
        elif [ "$had_previous" -eq 0 ]; then
            # Nothing was installed before this attempt, so there is nothing to restore
            # and nothing is running. Saying "the previous version did not start" here
            # would send an operator looking for a version that never existed.
            log "nothing was installed before this attempt; the host is as it was"
        else
            warn "ROLLBACK INCOMPLETE: the previous version did not start."
            warn "The previous binary, unit and configuration have been restored."
            warn "Inspect: systemctl status egressdns; journalctl -xeu egressdns"
        fi
    fi
}

cleanup() {
    local status=$?
    if [ "$status" -ne 0 ]; then
        rollback
    fi
    [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"
    exit "$status"
}

resolve_version() {
    # shellcheck disable=SC2031  # VERSION is only ever assigned in this function, which
    # runs in the main shell; the subshell shellcheck sees is the command substitution
    # below, whose output is assigned back here.
    if [ "$VERSION" != "latest" ]; then
        return 0
    fi
    log "resolving the latest release of $REPO"
    local api="https://api.github.com/repos/${REPO}/releases/latest"
    local body
    body="$(curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 20 \
        -H 'Accept: application/vnd.github+json' "$api")" ||
        die "cannot query the GitHub release API for $REPO"
    VERSION="$(printf '%s' "$body" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 |
               sed 's/.*"\([^"]*\)"$/\1/')"
    [ -n "$VERSION" ] || die "could not determine the latest release tag"
    log "latest release is $VERSION"
}

download_release() {
    need_tool curl
    need_tool sha256sum
    need_tool tar
    resolve_version

    local base="https://github.com/${REPO}/releases/download/${VERSION}"
    local asset="egressdns-${VERSION}-linux-${ARCH}.tar.gz"
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/egressdns-install.XXXXXX")"

    log "downloading $asset"
    fetch "$base/$asset" "$WORK_DIR/$asset" ||
        die "cannot download $base/$asset"
    log "downloading SHA256SUMS"
    fetch "$base/SHA256SUMS" "$WORK_DIR/SHA256SUMS" ||
        die "cannot download $base/SHA256SUMS"

    log "verifying SHA-256"
    local expected actual
    expected="$(awk -v want="$asset" '$2 == want || $2 == "*" want {print $1}' "$WORK_DIR/SHA256SUMS" | head -1)"
    [ -n "$expected" ] || die "SHA256SUMS does not list $asset"
    actual="$(sha256sum "$WORK_DIR/$asset" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
        die "checksum mismatch for $asset (expected $expected, got $actual)"
    fi
    log "checksum verified"

    tar -xzf "$WORK_DIR/$asset" -C "$WORK_DIR"
    STAGE_DIR="$WORK_DIR"
    if [ -d "$WORK_DIR/egressdns" ]; then
        STAGE_DIR="$WORK_DIR/egressdns"
    fi
    [ -f "$STAGE_DIR/$DAEMON" ] || die "release archive does not contain $DAEMON"
}

build_locally() {
    need_tool tar
    local user_home=""
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        user_home="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)"
        [ -n "$user_home" ] || user_home="/home/$SUDO_USER"
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        # cargo is usually installed per-user by rustup, and sudo drops it from PATH.
        # Fall back to the invoking user's rustup toolchain before giving up.
        if [ -n "$user_home" ] && [ -x "$user_home/.cargo/bin/cargo" ]; then
            PATH="$user_home/.cargo/bin:$PATH"
            log "cargo not on PATH as root; using $user_home/.cargo/bin"
        fi
    fi
    need_tool cargo
    log "building from source with cargo build --release --locked"
    if [ -n "$user_home" ]; then
        # Build as the invoking user so target/ does not end up root-owned.
        sudo -u "$SUDO_USER" env HOME="$user_home" PATH="$PATH" \
            cargo build --release --locked
    else
        cargo build --release --locked
    fi
    STAGE_DIR="target/release"
    [ -f "$STAGE_DIR/$DAEMON" ] || die "build did not produce $DAEMON"
}

install_files() {
    install -m 0755 "$STAGE_DIR/$DAEMON"  "$(path "$BIN_DIR")/$DAEMON"
    install -m 0755 "$STAGE_DIR/$CONTROL" "$(path "$BIN_DIR")/$CONTROL"
    log "installed $DAEMON and $CONTROL into $BIN_DIR"

    local unit_src=""
    for candidate in "$STAGE_DIR/egressdns.service" "packaging/systemd/egressdns.service"; do
        if [ -f "$candidate" ]; then unit_src="$candidate"; break; fi
    done
    if [ -n "$unit_src" ]; then
        # The unit directory always exists on a real systemd host; create it so the
        # EGRESSDNS_TEST_ROOT path exercises the same steps.
        install -d -m 0755 "$(path "$(dirname "$UNIT_PATH")")"
        install -m 0644 "$unit_src" "$(path "$UNIT_PATH")"
        log "installed the systemd unit"
    else
        warn "no systemd unit found in the archive or source tree"
    fi

    if [ ! -f "$(path "$CONF_DIR")/config.toml" ]; then
        local conf_src="$CONFIG_SOURCE"
        if [ -z "$conf_src" ]; then
            for candidate in \
                "$STAGE_DIR/egressdns.toml" \
                "config/egressdns.toml" \
                "$STAGE_DIR/config.toml"; do
                if [ -f "$candidate" ]; then conf_src="$candidate"; break; fi
            done
        fi
        [ -n "$conf_src" ] || die "no configuration file to install; pass --config <path>"
        install -m 0640 "$conf_src" "$(path "$CONF_DIR")/config.toml"
        if [ -z "$ROOT_PREFIX" ]; then
            chown "root:$SERVICE_USER" "$(path "$CONF_DIR")/config.toml"
        fi
        log "installed a starting configuration at $CONF_DIR/config.toml"
        warn "EDIT $CONF_DIR/config.toml before exposing this node: server.allow_from must list your LAN"
    else
        log "keeping the existing configuration at $CONF_DIR/config.toml"
    fi

    for extra in LICENSE-MIT LICENSE-APACHE; do
        if [ -f "$STAGE_DIR/$extra" ]; then
            install -m 0644 "$STAGE_DIR/$extra" "$(path "$CONF_DIR")/$extra"
        fi
    done
}

validate_config() {
    log "validating the configuration"
    if ! "$(path "$BIN_DIR")/$DAEMON" --config "$(path "$CONF_DIR")/config.toml" --check-config; then
        die "the installed configuration is not valid"
    fi
}

start_service() {
    [ -n "$ROOT_PREFIX" ] && { log "test root in use; skipping systemd integration"; return 0; }
    [ "$NO_START" -eq 1 ] && { log "--no-start given; not enabling the service"; return 0; }
    command -v systemctl >/dev/null 2>&1 || { warn "systemctl not found; skipping service start"; return 0; }

    systemctl daemon-reload
    systemctl enable egressdns.service >/dev/null
    log "starting egressdns.service"
    if ! systemctl restart egressdns.service; then
        systemctl status --no-pager --lines 30 egressdns.service >&2 || true
        die "the service failed to start"
    fi
    sleep 1
    if ! systemctl is-active --quiet egressdns.service; then
        journalctl -u egressdns.service --no-pager --lines 40 >&2 || true
        die "the service is not active after start"
    fi
}

# One canary query, judged on the answer rather than on the exchange.
#
# This runs `egressdnsctl query`, not `dig`. Two reasons, and both were defects:
#
#   * `dig` is optional. A host without bind9-dnsutils skipped the check entirely, so a
#     broken cutover was "verified" by a check that never ran.
#   * `dig` exits 0 for SERVFAIL, REFUSED and NXDOMAIN alike — it asked and something
#     replied. A resolver failing every query passed. See
#     docs/incidents/2026-08-deployment-failure.md.
#
# `egressdnsctl query` ships with the daemon, so it is always present, and exits non-zero
# unless the rcode is NOERROR with a record in the answer.
canary() {
    local host="$1" port="$2" proto="$3" name="${4:-example.com}"
    local args=(query "$name" --server "$host" --port "$port" --require-answer --wait 4)
    [ "$proto" = "tcp" ] && args+=(--tcp)
    if ! "$(path "$BIN_DIR")/$CONTROL" "${args[@]}" >/dev/null 2>&1; then
        warn "${proto} canary against ${host}:${port} did not return a usable answer"
        return 1
    fi
    return 0
}

# A name that must fail DNSSEC validation, proving the resolver fails closed rather than
# serving an answer it could not authenticate.
canary_dnssec_bogus() {
    local host="$1" port="$2"
    if "$(path "$BIN_DIR")/$CONTROL" query dnssec-failed.org --server "$host" \
        --port "$port" --dnssec --require-answer --wait 6 >/dev/null 2>&1; then
        warn "a deliberately DNSSEC-bogus name was answered; validation is not failing closed"
        return 1
    fi
    return 0
}

health_check() {
    [ -n "$ROOT_PREFIX" ] && return 0
    [ "$NO_START" -eq 1 ] && return 0

    local listen
    listen="$("$(path "$BIN_DIR")/$DAEMON" --config "$(path "$CONF_DIR")/config.toml" --dump-config 2>/dev/null |
              awk -F'"' '/^udp_listen/ {print $2; exit}')"
    listen="${listen:-127.0.0.1:53}"
    local host port
    host="${listen%:*}"
    port="${listen##*:}"
    host="${host#[}"
    host="${host%]}"
    if [ "$host" = "0.0.0.0" ] || [ "$host" = "::" ]; then host="127.0.0.1"; fi

    log "UDP canary against ${host}:${port}"
    if ! canary "$host" "$port" "udp"; then
        ROLLBACK_NEEDED=1
        die "post-install UDP canary failed"
    fi
    log "TCP canary against ${host}:${port}"
    if ! canary "$host" "$port" "tcp"; then
        ROLLBACK_NEEDED=1
        die "post-install TCP canary failed"
    fi
    # Only meaningful when validation is on, which it is by default.
    log "DNSSEC fail-closed canary against ${host}:${port}"
    if ! canary_dnssec_bogus "$host" "$port"; then
        ROLLBACK_NEEDED=1
        die "the resolver answered a DNSSEC-bogus name"
    fi
    log "canaries passed"
}

main() {
    parse_args "$@"
    require_root
    detect_platform
    check_port_53
    trap cleanup EXIT
    create_user
    make_dirs
    backup_existing
    ROLLBACK_NEEDED=1
    if [ "$LOCAL_BUILD" -eq 1 ]; then
        build_locally
    else
        download_release
    fi
    install_files
    validate_config
    start_service
    health_check
    ROLLBACK_NEEDED=0

    cat <<MSG

EgressDNS is installed.

  configuration   $CONF_DIR/config.toml
  state           $STATE_DIR
  service         systemctl status egressdns
  control         $CONTROL status

Next steps:
  1. Edit $CONF_DIR/config.toml and set server.allow_from to your LAN networks.
  2. sudo systemctl reload egressdns
  3. $CONTROL status

MSG
}

main "$@"
