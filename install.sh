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

# Deployment choices. Each is either answered on the command line, or asked on the
# terminal, or — with --non-interactive and no answer — defaulted to the safe option.
#
# "Safe" here means: serve only this machine, keep what is already on the host, and change
# nothing about the system resolver. Every default below is the one that cannot surprise
# somebody who piped a script into a shell.
MODE=""                     # local | lan
LAN_CIDRS=""                # space-separated, for MODE=lan
LISTEN_V4_ALL=0
LISTEN_V6_ALL=0
PROFILE="recommended"
REPLACE_EXISTING=""         # 1 replace, 0 keep configuration
PURGE_OLD_CONFIG=""         # 1 discard the old configuration file
PURGE_OLD_STATE=""          # 1 discard learned route quality and caches
SYSTEM_RESOLVER_ACTION=""   # replace | keep
NON_INTERACTIVE=0
ASSUME_YES=0
ALLOW_OPEN_RESOLVER=0
TTY_AVAILABLE=0
GENERATED_CONFIG=""         # set when the installer wrote the configuration itself

# Facts about the host, filled in by detection and reported in the summary.
EXISTING_INSTALL=0
EXISTING_VERSION=""
SYSTEM_RESOLVER_UNIT=""
RESOLV_CONF_BACKUP=""
DETECTED_LAN_CIDRS=""

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

Deployment. Omit these and the installer asks on the terminal; every one of them
defaults to the choice that changes the least about your host.

  --non-interactive     Never prompt. Unanswered choices take their safe default.
  --yes                 Accept the offered default for every prompt.
  --mode local|lan      Serve this machine only (default), or serve a LAN.
  --lan-cidr <cidr>     A client network for --mode lan. Repeatable.
  --listen-ipv4-all     Listen on 0.0.0.0 rather than only the detected LAN address.
  --listen-ipv6-all     Listen on [::] as well.
  --profile <name>      Built-in resolver set: recommended (default), global, china,
                        privacy, security-filtered, ad-blocking.
  --replace-existing    Replace an existing EgressDNS configuration with a fresh one.
  --keep-existing       Keep the existing configuration; upgrade binaries only.
  --purge-old-config    Delete the previous configuration instead of backing it up.
  --purge-old-state     Delete learned route quality and persisted caches.
  --replace-system-resolver
                        Take over from systemd-resolved (or similar) and point
                        /etc/resolv.conf at this resolver.
  --keep-system-resolver
                        Leave the system resolver exactly as it is (default).
  --i-know-this-is-an-open-resolver
                        Permit allow_from covering the whole Internet. Do not use this.

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
            --non-interactive) NON_INTERACTIVE=1;   shift ;;
            --yes|-y)       ASSUME_YES=1;           shift ;;
            --mode)         MODE="${2:-}";          shift 2 ;;
            --lan-cidr)     LAN_CIDRS="${LAN_CIDRS} ${2:-}"; shift 2 ;;
            --listen-ipv4-all) LISTEN_V4_ALL=1;     shift ;;
            --listen-ipv6-all) LISTEN_V6_ALL=1;     shift ;;
            --profile)      PROFILE="${2:-}";       shift 2 ;;
            --replace-existing) REPLACE_EXISTING=1; shift ;;
            --keep-existing)    REPLACE_EXISTING=0; shift ;;
            --purge-old-config) PURGE_OLD_CONFIG=1; shift ;;
            --purge-old-state)  PURGE_OLD_STATE=1;  shift ;;
            --replace-system-resolver) SYSTEM_RESOLVER_ACTION="replace"; shift ;;
            --keep-system-resolver)    SYSTEM_RESOLVER_ACTION="keep";    shift ;;
            --i-know-this-is-an-open-resolver) ALLOW_OPEN_RESOLVER=1; shift ;;
            --help|-h)      usage; exit 0 ;;
            *)              die "unknown option '$1' (try --help)" ;;
        esac
    done
    if [ -n "$MODE" ] && [ "$MODE" != "local" ] && [ "$MODE" != "lan" ]; then
        die "--mode must be 'local' or 'lan', not '$MODE'"
    fi
    case "$PROFILE" in
        recommended|global|china|privacy|security-filtered|ad-blocking) : ;;
        *) die "unknown --profile '$PROFILE'; try recommended, global, china, privacy, security-filtered or ad-blocking" ;;
    esac
    LAN_CIDRS="$(printf '%s' "$LAN_CIDRS" | tr -s ' ' | sed 's/^ //;s/ $//')"
    for cidr in $LAN_CIDRS; do
        valid_cidr "$cidr" || die "--lan-cidr '$cidr' is not an IPv4 or IPv6 network in CIDR form"
    done
    # A CIDR was named, so the intent is a LAN whether or not --mode was written out.
    if [ -n "$LAN_CIDRS" ] && [ -z "$MODE" ]; then
        MODE="lan"
    fi
    if [ -n "$REPO" ] && ! printf '%s' "$REPO" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$'; then
        die "repository '$REPO' is not in <owner>/<name> form"
    fi
    if [ -n "$VERSION" ] && [ "$VERSION" != "latest" ] &&
       ! printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$'; then
        die "version '$VERSION' is not a valid release tag"
    fi
}

path() { printf '%s%s' "$ROOT_PREFIX" "$1"; }

# ---------------------------------------------------------------------------
# Asking the operator
# ---------------------------------------------------------------------------

# This script is normally run as `curl ... | sudo bash`, which means stdin is the script
# itself. Reading a prompt from stdin would consume the script's own remaining lines — so
# every prompt reads /dev/tty, the controlling terminal, which is unaffected by the pipe.
# When there is no controlling terminal there is nobody to ask, and the defaults apply.
open_tty() {
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        TTY_AVAILABLE=0
        return 0
    fi
    if [ -r /dev/tty ] && [ -w /dev/tty ] && { : >/dev/tty; } 2>/dev/null; then
        TTY_AVAILABLE=1
    else
        TTY_AVAILABLE=0
        log "no terminal to ask on; taking the safe default for every choice"
    fi
}

# Ask a yes/no question. `$2` is the default, taken when the answer is empty, when --yes
# was given, and when there is no terminal.
ask_yes_no() {
    local prompt="$1" default="$2" reply=""
    if [ "$TTY_AVAILABLE" -eq 0 ] || [ "$ASSUME_YES" -eq 1 ]; then
        [ "$default" = "y" ] && return 0 || return 1
    fi
    local hint="[y/N]"
    [ "$default" = "y" ] && hint="[Y/n]"
    while :; do
        printf '\n%s %s ' "$prompt" "$hint" >/dev/tty
        IFS= read -r reply </dev/tty || reply=""
        reply="$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
        case "${reply:-$default}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *)     printf 'Please answer y or n.\n' >/dev/tty ;;
        esac
    done
}

# Ask for a line of free text, echoing the default in the prompt.
ask_line() {
    local prompt="$1" default="$2" reply=""
    if [ "$TTY_AVAILABLE" -eq 0 ] || [ "$ASSUME_YES" -eq 1 ]; then
        printf '%s' "$default"
        return 0
    fi
    printf '\n%s\n  [%s] ' "$prompt" "$default" >/dev/tty
    IFS= read -r reply </dev/tty || reply=""
    reply="$(printf '%s' "$reply" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    printf '%s' "${reply:-$default}"
}

# Show a numbered menu and return the chosen item.
ask_choice() {
    local prompt="$1" default="$2"; shift 2
    local options=("$@") reply="" i=1
    if [ "$TTY_AVAILABLE" -eq 0 ] || [ "$ASSUME_YES" -eq 1 ]; then
        printf '%s' "$default"
        return 0
    fi
    printf '\n%s\n' "$prompt" >/dev/tty
    for opt in "${options[@]}"; do
        local marker=" "
        [ "$opt" = "$default" ] && marker="*"
        printf '  %s %d) %s\n' "$marker" "$i" "$opt" >/dev/tty
        i=$((i + 1))
    done
    while :; do
        printf '  choose 1-%d [%s] ' "${#options[@]}" "$default" >/dev/tty
        IFS= read -r reply </dev/tty || reply=""
        reply="$(printf '%s' "$reply" | tr -d '[:space:]')"
        if [ -z "$reply" ]; then
            printf '%s' "$default"
            return 0
        fi
        if printf '%s' "$reply" | grep -Eq '^[0-9]+$' &&
           [ "$reply" -ge 1 ] && [ "$reply" -le "${#options[@]}" ]; then
            printf '%s' "${options[$((reply - 1))]}"
            return 0
        fi
        printf '  Not one of the choices.\n' >/dev/tty
    done
}

# ---------------------------------------------------------------------------
# Networks
# ---------------------------------------------------------------------------

# Is this an IPv4 or IPv6 network in CIDR form, with a prefix length in range?
valid_cidr() {
    local cidr="$1" addr="${1%%/*}" len="${1##*/}"
    case "$cidr" in */*) : ;; *) return 1 ;; esac
    printf '%s' "$len" | grep -Eq '^[0-9]+$' || return 1
    case "$addr" in
        *:*)
            [ "$len" -le 128 ] || return 1
            printf '%s' "$addr" | grep -Eq '^[0-9A-Fa-f:]+$'
            ;;
        *)
            [ "$len" -le 32 ] || return 1
            printf '%s' "$addr" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
            local IFS=.
            # shellcheck disable=SC2086  # deliberate word splitting on the octets
            set -- $addr
            for octet in "$@"; do [ "$octet" -le 255 ] || return 1; done
            ;;
    esac
}

# Does this CIDR cover the whole Internet?
#
# Checked separately from the parse, because writing it is almost always a mistake and
# the consequence — an open resolver anyone on the Internet can use for amplification —
# is severe enough that it must be refused rather than warned about.
is_open_prefix() {
    case "$1" in
        0.0.0.0/0|::/0) return 0 ;;
        *) return 1 ;;
    esac
}

# The networks this host is actually attached to, as CIDRs.
#
# Deliberately narrow. An interface is skipped when serving DNS on it would be wrong or
# meaningless: loopback (already covered), link-local (not routable between hosts),
# point-to-point and tunnel devices (a VPN's other end is not "the LAN"), and container
# bridges (docker0, br-*, veth*, cni*) whose clients are this host's own workloads.
#
# The result is a proposal shown to the operator, never something applied unasked.
detect_lan_cidrs() {
    command -v ip >/dev/null 2>&1 || return 0
    local out=""
    while read -r iface cidr; do
        [ -n "$cidr" ] || continue
        case "$iface" in
            lo|docker*|br-*|veth*|cni*|flannel*|kube*|virbr*|tun*|tap*|wg*|ppp*|zt*|tailscale*)
                continue ;;
        esac
        case "$cidr" in
            169.254.*|fe80:*|127.*|::1/*) continue ;;
            # A single-host prefix is not a client network. Offering one invites an
            # operator to admit exactly one machine — this one — and wonder why nothing
            # else can resolve.
            */128|*/32) continue ;;
        esac
        # Reduce the interface address to its network: 192.168.31.204/24 -> 192.168.31.0/24.
        local network
        network="$(network_of "$cidr")" || continue
        case " $out " in *" $network "*) continue ;; esac
        out="${out:+$out }$network"
    done < <(ip -o addr show scope global 2>/dev/null \
             | awk '$3 == "inet" || $3 == "inet6" {print $2, $4}')
    printf '%s' "$out"
}

# The network containing an interface address, e.g. 192.168.31.204/24 -> 192.168.31.0/24.
network_of() {
    local cidr="$1" addr="${1%%/*}" len="${1##*/}"
    case "$addr" in
        *:*)
            # Only whole-nibble IPv6 prefixes are reduced. Anything else is offered as
            # written rather than truncated wrongly; the operator can edit it.
            [ "$len" -eq 64 ] || { printf '%s' "$cidr"; return 0; }
            printf '%s' "$(printf '%s' "$addr" | cut -d: -f1-4)::/64"
            ;;
        *)
            local IFS=. o1 o2 o3 o4
            # shellcheck disable=SC2086
            set -- $addr
            o1="$1" o2="$2" o3="$3" o4="$4"
            case "$len" in
                8)  printf '%s.0.0.0/8'    "$o1" ;;
                16) printf '%s.%s.0.0/16'  "$o1" "$o2" ;;
                24) printf '%s.%s.%s.0/24' "$o1" "$o2" "$o3" ;;
                32) printf '%s.%s.%s.%s/32' "$o1" "$o2" "$o3" "$o4" ;;
                *)  printf '%s' "$cidr" ;;
            esac
            ;;
    esac
}

# The address of the interface carrying the default route, for a non-wildcard listener.
primary_address() {
    local family="$1"
    command -v ip >/dev/null 2>&1 || return 1
    ip -o "$family" addr show scope global 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | head -n 1
}

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

# Refuse to start only when something already holds an address we actually need.
#
# "Anything on port 53" is too blunt, and it was: systemd-resolved's stub listener is
# 127.0.0.53:53, which does not collide with 127.0.0.1:53 or with a LAN address, so a
# stock Debian or Ubuntu host was refused an install it could perfectly well have had.
# Only an exact address match, or a wildcard on either side, is a conflict.
check_port_53() {
    [ -n "$ROOT_PREFIX" ] && return 0
    command -v ss >/dev/null 2>&1 || return 0

    local wanted holders="" conflict=""
    wanted="$(listen_addresses_v4)"
    [ "$LISTEN_V6_ALL" -eq 1 ] && wanted="$wanted [::]:53"

    holders="$(ss -lntupH 2>/dev/null | awk '{print $5, $NF}' | grep ':53 ' || true)"
    [ -n "$holders" ] || return 0

    # An upgrade in place: we hold the socket, and restarting the unit releases it.
    if systemctl is-active --quiet egressdns.service 2>/dev/null; then
        log "port 53 is held by this service; treating as an upgrade"
        return 0
    fi

    while read -r held owner; do
        [ -n "$held" ] || continue
        local held_host="${held%:*}"
        held_host="${held_host#[}"; held_host="${held_host%]}"
        for want in $wanted; do
            local want_host="${want%:*}"
            want_host="${want_host#[}"; want_host="${want_host%]}"
            if [ "$held_host" = "$want_host" ] ||
               [ "$held_host" = "0.0.0.0" ] || [ "$held_host" = "*" ] ||
               [ "$want_host" = "0.0.0.0" ] ||
               { [ "$held_host" = "::" ] && [ "$want_host" = "::" ]; }; then
                conflict="${conflict}  ${held}  ${owner}\n"
                break
            fi
        done
    done <<< "$holders"

    [ -n "$conflict" ] || return 0

    printf '%b' "$conflict" >&2
    if [ "$FORCE" -eq 1 ]; then
        warn "an address EgressDNS needs is already in use; continuing because --force was given"
        return 0
    fi
    cat >&2 <<MSG

The address EgressDNS would listen on is already held by the process shown above.

This installer does not remove another DNS service for you. Either stop it:

    sudo systemctl disable --now <that service>

or install alongside it by choosing a different address, for example --mode lan
with --lan-cidr for your network only.

Nothing has been changed on this host.
MSG
    exit 3
}

# ---------------------------------------------------------------------------
# What is already on this host
# ---------------------------------------------------------------------------

detect_existing_install() {
    EXISTING_INSTALL=0
    EXISTING_VERSION=""
    if [ -f "$(path "$CONF_DIR")/config.toml" ] || [ -f "$(path "$BIN_DIR")/$DAEMON" ]; then
        EXISTING_INSTALL=1
    fi
    if [ -x "$(path "$BIN_DIR")/$DAEMON" ]; then
        EXISTING_VERSION="$("$(path "$BIN_DIR")/$DAEMON" --version 2>/dev/null \
                            | head -n 1 | awk '{print $NF}')"
    fi
}

# Which system resolver, if any, owns DNS on this host.
#
# Only the units that actually listen on port 53 count. A stub-resolver setup is the
# interesting case: systemd-resolved listens on 127.0.0.53:53 and writes an
# /etc/resolv.conf pointing at itself, so leaving it running and pointing resolv.conf
# elsewhere is a perfectly reasonable outcome — and is the default.
detect_system_resolver() {
    SYSTEM_RESOLVER_UNIT=""
    [ -n "$ROOT_PREFIX" ] && return 0
    command -v systemctl >/dev/null 2>&1 || return 0
    for unit in systemd-resolved dnsmasq unbound bind9 named pdns-recursor connman; do
        if systemctl is-active --quiet "${unit}.service" 2>/dev/null; then
            SYSTEM_RESOLVER_UNIT="$unit"
            return 0
        fi
    done
}

# ---------------------------------------------------------------------------
# The interview
# ---------------------------------------------------------------------------

# Settle every deployment choice that the command line did not already settle.
#
# Runs before anything on the host is touched, so answering it is free: the operator can
# hit Ctrl-C at any prompt and the machine is exactly as it was. Nothing here asks about
# transports, route weights, HTTP versions, address families or hedging — the daemon
# measures all of those, and a question whose right answer is "measure it" is a question
# that should not be asked.
interview() {
    open_tty

    if [ "$TTY_AVAILABLE" -eq 1 ]; then
        cat >/dev/tty <<'INTRO'

  EgressDNS install
  -----------------
  A few questions about this host. Every default is the choice that changes the
  least; pressing Enter throughout gives a resolver that serves only this machine
  and leaves the rest of your system alone.

INTRO
    fi

    # --- An existing EgressDNS -------------------------------------------------
    if [ "$EXISTING_INSTALL" -eq 1 ]; then
        local desc="EgressDNS is already installed here"
        [ -n "$EXISTING_VERSION" ] && desc="EgressDNS ${EXISTING_VERSION} is already installed here"
        if [ -z "$REPLACE_EXISTING" ]; then
            log "$desc"
            if ask_yes_no "Replace its configuration with a fresh one? (No = upgrade the binaries and keep your settings)" "n"; then
                REPLACE_EXISTING=1
            else
                REPLACE_EXISTING=0
            fi
        fi
        if [ "$REPLACE_EXISTING" -eq 1 ] && [ -z "$PURGE_OLD_CONFIG" ]; then
            # Separate from the replace decision on purpose: replacing a configuration
            # and destroying the only copy of it are different sizes of mistake.
            if ask_yes_no "Delete the previous configuration file? (No = keep a copy in the backup directory)" "n"; then
                PURGE_OLD_CONFIG=1
            else
                PURGE_OLD_CONFIG=0
            fi
        fi
        if [ -z "$PURGE_OLD_STATE" ]; then
            if ask_yes_no "Delete learned route quality and cached data in ${STATE_DIR}? (No = keep it; the resolver starts warm)" "n"; then
                PURGE_OLD_STATE=1
            else
                PURGE_OLD_STATE=0
            fi
        fi
    fi
    REPLACE_EXISTING="${REPLACE_EXISTING:-1}"
    PURGE_OLD_CONFIG="${PURGE_OLD_CONFIG:-0}"
    PURGE_OLD_STATE="${PURGE_OLD_STATE:-0}"

    # --- Who this resolver serves ----------------------------------------------
    DETECTED_LAN_CIDRS="$(detect_lan_cidrs)"
    if [ -z "$MODE" ]; then
        MODE="$(ask_choice "Who should this resolver serve?" "local" \
            "local" "lan")"
        if [ "$TTY_AVAILABLE" -eq 1 ] && [ "$MODE" = "lan" ]; then
            : # the CIDR prompt below explains itself
        fi
    fi

    if [ "$MODE" = "lan" ] && [ -z "$LAN_CIDRS" ]; then
        if [ -n "$DETECTED_LAN_CIDRS" ]; then
            local answer
            answer="$(ask_line "Which client networks may query it? Detected on this host:
  ${DETECTED_LAN_CIDRS}
Enter CIDRs separated by spaces, or press Enter to accept the detected ones." \
                "$DETECTED_LAN_CIDRS")"
            LAN_CIDRS="$answer"
        else
            LAN_CIDRS="$(ask_line "Which client networks may query it? No LAN was detected, so this must be answered.
Enter CIDRs separated by spaces, for example: 192.168.1.0/24" "")"
        fi
    fi

    if [ "$MODE" = "lan" ]; then
        LAN_CIDRS="$(printf '%s' "$LAN_CIDRS" | tr -s ' ' | sed 's/^ //;s/ $//')"
        [ -n "$LAN_CIDRS" ] ||
            die "--mode lan needs at least one client network; pass --lan-cidr <cidr>"
        for c in $LAN_CIDRS; do
            valid_cidr "$c" || die "'$c' is not an IPv4 or IPv6 network in CIDR form"
            if is_open_prefix "$c" && [ "$ALLOW_OPEN_RESOLVER" -eq 0 ]; then
                die "'$c' covers the entire Internet. A resolver reachable from everywhere is an
open resolver: it will be found within hours and used to amplify traffic at somebody
else. Name your actual client networks — the installer detected${DETECTED_LAN_CIDRS:+ }${DETECTED_LAN_CIDRS:-nothing to suggest}."
            fi
        done
        # A LAN listener is a change with consequences beyond this machine, so it is
        # confirmed once more with the exact effect spelled out.
        if [ "$TTY_AVAILABLE" -eq 1 ] && [ "$ASSUME_YES" -eq 0 ]; then
            printf '\n  This will listen on %s and answer queries from: %s\n' \
                "$(listen_addresses_v4)" "$LAN_CIDRS" >/dev/tty
            ask_yes_no "Correct?" "y" || die "cancelled at your request; nothing has been changed"
        fi
    fi

    # --- The system resolver ----------------------------------------------------
    if [ -n "$SYSTEM_RESOLVER_UNIT" ] && [ -z "$SYSTEM_RESOLVER_ACTION" ]; then
        log "this host runs ${SYSTEM_RESOLVER_UNIT}"
        if ask_yes_no "Point /etc/resolv.conf at EgressDNS, so this machine uses it for its own lookups?
  (No = install alongside ${SYSTEM_RESOLVER_UNIT} and change nothing about it)" "n"; then
            SYSTEM_RESOLVER_ACTION="replace"
        else
            SYSTEM_RESOLVER_ACTION="keep"
        fi
    fi
    SYSTEM_RESOLVER_ACTION="${SYSTEM_RESOLVER_ACTION:-keep}"

    if [ "$TTY_AVAILABLE" -eq 1 ]; then
        printf '\n  Proceeding: mode=%s, resolvers=builtin:%s, system resolver=%s\n\n' \
            "$MODE" "$PROFILE" "$SYSTEM_RESOLVER_ACTION" >/dev/tty
    fi
}

# ---------------------------------------------------------------------------
# The configuration the installer writes
# ---------------------------------------------------------------------------

listen_addresses_v4() {
    if [ "$MODE" != "lan" ]; then
        printf '127.0.0.1:53'
        return 0
    fi
    if [ "$LISTEN_V4_ALL" -eq 1 ]; then
        printf '0.0.0.0:53'
        return 0
    fi
    local addr
    addr="$(primary_address -4 || true)"
    if [ -n "$addr" ]; then
        printf '127.0.0.1:53 %s:53' "$addr"
    else
        printf '0.0.0.0:53'
    fi
}

# Write a complete configuration for the chosen mode.
#
# Everything here is a *deployment* decision: which machines may ask, and which resolver
# set to ask. Transport, address family, HTTP version, hedging, route weights and endpoint
# preference are all absent, because the daemon measures them — an operator asked to
# choose them in advance is being asked to guess.
render_config() {
    local dest="$1"
    {
        printf '# EgressDNS — written by the installer on %s.\n' "$(date -u '+%Y-%m-%d')"
        printf '#\n'
        printf '# You describe *where to ask* and *who may ask*. Everything else — UDP or TCP,\n'
        printf '# HTTP/2 or HTTP/3, IPv4 or IPv6, which endpoint to prefer, when to hedge, when to\n'
        printf '# give up on a path — the daemon decides from what it measures on your network.\n'
        printf '\n'
        printf '# The built-in "%s" resolver set: several independently operated public\n' "$PROFILE"
        printf '# resolvers, each with its plaintext seeds and its encrypted endpoints. Replace this\n'
        printf '# with your own list at any time; `egressdnsctl reload-contract` says what applies\n'
        printf '# on reload and what needs a restart.\n'
        printf 'upstreams = ["builtin:%s"]\n' "$PROFILE"
        printf '\n'
        printf '# Egress proxies, tried when the direct path is unhealthy. Empty means direct only.\n'
        printf '#\n'
        printf '#   proxies = ["socks5h://127.0.0.1:1080", "http://127.0.0.1:7890"]\n'
        printf 'proxies = []\n'
        if [ "$MODE" = "lan" ]; then
            printf '\n[server]\n'
            printf 'udp_listen = ['
            local first=1
            for a in $(listen_addresses_v4); do
                [ "$first" -eq 1 ] || printf ', '
                printf '"%s"' "$a"; first=0
            done
            [ "$LISTEN_V6_ALL" -eq 1 ] && printf ', "[::]:53"'
            printf ']\n'
            printf 'tcp_listen = ['
            first=1
            for a in $(listen_addresses_v4); do
                [ "$first" -eq 1 ] || printf ', '
                printf '"%s"' "$a"; first=0
            done
            [ "$LISTEN_V6_ALL" -eq 1 ] && printf ', "[::]:53"'
            printf ']\n'
            printf '\n'
            printf '# Only these networks may query the resolver. Loopback is listed explicitly\n'
            printf '# because naming any network at all replaces the loopback default.\n'
            printf 'allow_from = [\n'
            for c in $LAN_CIDRS; do
                printf '    "%s",\n' "$c"
            done
            printf '    "127.0.0.0/8",\n'
            printf '    "::1/128",\n'
            printf ']\n'
        fi
    } > "$dest"
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
    # A slow link is not a failure. Rather than a wall-clock limit — which punishes a
    # large artifact on a thin connection — abort only when throughput actually stalls:
    # under 1 KB/s sustained for a minute. The generous --max-time is a backstop against
    # a connection that trickles forever.
    local common=(-fsSL --retry 5 --retry-delay 3 --retry-all-errors
        --connect-timeout 20 --speed-limit 1024 --speed-time 60 --max-time 1800)
    if curl "${common[@]}" -o "$dest" "$url"; then
        return 0
    fi
    warn "download failed over HTTP/2; retrying with HTTP/1.1"
    curl --http1.1 "${common[@]}" -o "$dest" "$url"
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
    # First, because it is what the machine needs to resolve names at all. Everything
    # below this line is easier to debug on a host whose DNS works.
    restore_system_resolver
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

    local target
    target="$(path "$CONF_DIR")/config.toml"
    if [ -f "$target" ] && [ "$REPLACE_EXISTING" -eq 0 ]; then
        log "keeping the existing configuration at $CONF_DIR/config.toml"
    else
        local conf_src="$CONFIG_SOURCE"
        if [ -n "$conf_src" ]; then
            # An explicit --config is taken as written. Somebody who names a file has
            # already made the decisions this installer would otherwise ask about.
            [ -f "$conf_src" ] || die "--config file '$conf_src' does not exist"
            install -m 0640 "$conf_src" "$target"
            log "installed the configuration from $conf_src"
        else
            render_config "$target"
            chmod 0640 "$target"
            GENERATED_CONFIG=1
            log "wrote a ${MODE} configuration using the built-in '${PROFILE}' resolver set"
        fi
        if [ -z "$ROOT_PREFIX" ]; then
            chown "root:$SERVICE_USER" "$target"
        fi
    fi

    for extra in LICENSE-MIT LICENSE-APACHE; do
        if [ -f "$STAGE_DIR/$extra" ]; then
            install -m 0644 "$STAGE_DIR/$extra" "$(path "$CONF_DIR")/$extra"
        fi
    done
}

# Discard what the operator asked to discard — and nothing else.
#
# Runs after the backup, so "purge" still leaves a copy under $BACKUP_DIR until the
# install is verified. Purging is about what ends up on the running system, not about
# destroying the only route back.
apply_purges() {
    if [ "${PURGE_OLD_STATE:-0}" -eq 1 ]; then
        local dir
        dir="$(path "$STATE_DIR")"
        if [ -d "$dir" ]; then
            log "discarding learned route quality and cached data in $STATE_DIR"
            find "$dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
        fi
    fi
    # PURGE_OLD_CONFIG needs no action here: install_files overwrites the file, and the
    # backup copy is removed on success rather than now, so a failed install can still
    # put the operator's own configuration back.
}

# ---------------------------------------------------------------------------
# The system resolver
# ---------------------------------------------------------------------------

# Point this machine's own lookups at EgressDNS.
#
# Only ever called when the operator asked for it. Two properties matter:
#
#   * The previous /etc/resolv.conf is preserved exactly, symlink or file. On a
#     systemd-resolved host it is usually a symlink into /run, and replacing it with a
#     regular file without recording that would leave the host unable to go back.
#   * It happens *after* the daemon is verified answering. Pointing resolv.conf at a
#     resolver that does not work yet breaks name resolution for the whole machine,
#     including for whatever the operator would use to fix it.
replace_system_resolver() {
    [ "$SYSTEM_RESOLVER_ACTION" = "replace" ] || return 0
    [ -n "$ROOT_PREFIX" ] && return 0

    RESOLV_CONF_BACKUP="$BACKUP_DIR/resolv.conf.backup"
    if [ -L /etc/resolv.conf ]; then
        readlink /etc/resolv.conf > "$BACKUP_DIR/resolv.conf.symlink"
        log "recorded /etc/resolv.conf as a symlink to $(readlink /etc/resolv.conf)"
    elif [ -f /etc/resolv.conf ]; then
        cp -p /etc/resolv.conf "$RESOLV_CONF_BACKUP"
    fi

    # systemd-resolved's stub listener does not collide with 127.0.0.1:53, so it is left
    # running unless it actually holds a socket we need. Disabling a working component
    # of the operator's system for tidiness is not the installer's call.
    if [ "$SYSTEM_RESOLVER_UNIT" = "systemd-resolved" ]; then
        if systemctl is-enabled --quiet systemd-resolved.service 2>/dev/null; then
            log "leaving systemd-resolved running; only /etc/resolv.conf changes"
        fi
    fi

    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/resolv.conf.XXXXXX")"
    {
        printf '# Written by the EgressDNS installer.\n'
        printf '# The previous file is preserved under %s\n' "$BACKUP_DIR"
        printf 'nameserver 127.0.0.1\n'
        printf 'options edns0 trust-ad\n'
    } > "$tmp"
    chmod 0644 "$tmp"
    rm -f /etc/resolv.conf
    mv "$tmp" /etc/resolv.conf
    log "/etc/resolv.conf now points at EgressDNS"
}

restore_system_resolver() {
    [ -n "$BACKUP_DIR" ] || return 0
    [ -n "$ROOT_PREFIX" ] && return 0
    if [ -f "$BACKUP_DIR/resolv.conf.symlink" ]; then
        local target
        target="$(cat "$BACKUP_DIR/resolv.conf.symlink")"
        rm -f /etc/resolv.conf
        ln -s "$target" /etc/resolv.conf
        log "restored /etc/resolv.conf as a symlink to $target"
    elif [ -f "$RESOLV_CONF_BACKUP" ]; then
        install -m 0644 "$RESOLV_CONF_BACKUP" /etc/resolv.conf
        log "restored the previous /etc/resolv.conf"
    fi
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
# Where the last canary's structured result was written, so a failure can be explained
# rather than merely reported.
CANARY_LAST=""

# One canary query, judged on the answer rather than on the exchange.
#
# Run with proxy interception cleared. `proxychains` hooks connect(2) through LD_PRELOAD
# and, with no `localnet` bypass, redirects *every* TCP connection to the SOCKS proxy —
# including one to 127.0.0.1. That sent this health check to a proxy on another host and
# asked it to reach its own loopback, so the stream closed with no RFC 7766 length prefix
# and the install rolled back every time. UDP was untouched, which is why the symptom was
# UDP-passes-TCP-fails and looked like a daemon defect.
#
# The question a local canary asks is "is the resolver on *this machine* answering".
# Through an intermediary it answers a different question. Downloads keep the proxy; this
# does not. See docs/incidents/2026-08-installer-tcp-canary.md.
# Set for a check whose *failure* is the passing result, so the expected outcome is not
# reported as a warning. A DNSSEC-bogus name failing to resolve is the resolver working.
CANARY_EXPECT_FAILURE=0

canary() {
    local host="$1" port="$2" proto="$3" name="${4:-localhost}" want_dnssec="${5:-}"
    local args=(query "$name" --server "$host" --port "$port" --require-answer --wait 6 --json)
    [ "$proto" = "tcp" ] && args+=(--tcp)
    [ -n "$want_dnssec" ] && args+=(--dnssec)

    CANARY_LAST="$(env -u LD_PRELOAD -u LD_LIBRARY_PATH \
        -u ALL_PROXY -u all_proxy \
        -u HTTP_PROXY -u http_proxy \
        -u HTTPS_PROXY -u https_proxy \
        "$(path "$BIN_DIR")/$CONTROL" "${args[@]}" 2>&1)" && return 0

    if [ "$CANARY_EXPECT_FAILURE" -eq 0 ]; then
        warn "${proto} canary for ${name} against ${host}:${port} did not return a usable answer"
    fi
    return 1
}

# Print everything known about a canary failure, and keep it.
#
# The original discarded stdout and stderr, so an operator saw one sentence and had
# nothing to act on.
canary_failed() {
    local what="$1"
    warn "${what} failed:"
    if [ -n "$CANARY_LAST" ]; then
        printf '%s\n' "$CANARY_LAST" | sed 's/^/    /' >&2
    else
        printf '    (no output captured)\n' >&2
    fi

    DIAG_DIR="${DIAG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/egressdns-install-diagnostics.XXXXXX")}"
    {
        printf '=== %s ===\n' "$what"
        printf '%s\n\n' "$CANARY_LAST"
        printf '=== systemctl status ===\n'
        systemctl status egressdns --no-pager 2>&1 | head -40
        printf '\n=== recent journal ===\n'
        journalctl -u egressdns --no-pager --since "-5 minutes" 2>&1 | tail -60
        printf '\n=== listeners ===\n'
        ss -lntup 2>&1 | grep -E ':(53|1053)\b' || true
        printf '\n=== effective configuration ===\n'
        "$(path "$BIN_DIR")/$DAEMON" --config "$(path "$CONF_DIR")/config.toml" \
            --dump-config 2>&1 | head -80
    } > "$DIAG_DIR/report.txt" 2>&1
    # The effective configuration redacts secrets already; proxy credentials never reach
    # it. Strip anything that looks like userinfo from the transcript for good measure.
    sed -i -E 's#(socks5h?|https?)://[^/@[:space:]]+:[^/@[:space:]]+@#\1://<redacted>@#g' \
        "$DIAG_DIR/report.txt" 2>/dev/null || true

    warn ""
    warn "Recent daemon logs and the effective configuration were saved to:"
    warn "  $DIAG_DIR/report.txt"
    warn "It is kept after rollback so the failure can be diagnosed."
}

# Prove local ingress, without needing the Internet.
#
# `localhost` is answered by EgressDNS itself from the special-use registry, so this tests
# listener binding, ACL admission, parsing, DNS-over-TCP framing and serialisation — and
# nothing else. Resolving a public name here would let upstream trouble fail a listener
# test, which is how a network problem came to look like a TCP ingress bug.
local_canaries() {
    local host="$1" port="$2"
    log "local UDP canary against ${host}:${port}"
    if ! canary "$host" "$port" "udp" "localhost"; then
        canary_failed "local UDP canary"
        return 1
    fi
    log "local TCP canary against ${host}:${port}"
    if ! canary "$host" "$port" "tcp" "localhost"; then
        canary_failed "local TCP canary"
        return 1
    fi
    return 0
}

# Prove forwarding actually works, with a quorum rather than one fragile name.
#
# A single public name makes installation depend on that name resolving from this network
# at this moment. Two of three is enough to distinguish "forwarding is broken" from "one
# domain is having a bad day".
external_canaries() {
    local host="$1" port="$2"
    local ok=0 tried=0
    for name in example.com cloudflare.com wikipedia.org; do
        tried=$((tried + 1))
        if canary "$host" "$port" "udp" "$name"; then
            ok=$((ok + 1))
        fi
        [ "$ok" -ge 2 ] && break
    done
    if [ "$ok" -lt 2 ]; then
        canary_failed "forwarding canary (${ok}/${tried} public names resolved)"
        return 1
    fi
    log "forwarding canary passed (${ok}/${tried} public names resolved)"
    # One forwarded answer over TCP ingress too, so the stream path is exercised end to
    # end rather than only against the locally answered name.
    if ! canary "$host" "$port" "tcp" "example.com"; then
        canary_failed "forwarding canary over TCP"
        return 1
    fi
    return 0
}

# A name that must fail DNSSEC validation, proving the resolver fails closed rather than
# serving an answer it could not authenticate.
canary_dnssec_bogus() {
    local host="$1" port="$2" rc=0
    CANARY_EXPECT_FAILURE=1
    canary "$host" "$port" "udp" "dnssec-failed.org" "dnssec" && rc=1
    CANARY_EXPECT_FAILURE=0
    if [ "$rc" -eq 1 ]; then
        warn "a deliberately DNSSEC-bogus name was answered; validation is not failing closed"
        return 1
    fi
    log "a DNSSEC-bogus name was refused, as it must be"
    return 0
}

# A signed name should carry AD when validation is on. Advisory: a network that filters
# DNSSEC records can fail this without the installation being wrong.
canary_dnssec_secure() {
    local host="$1" port="$2" rc=0
    # Advisory, so a failure here is reported by the caller in its own words rather than
    # as a warning that reads like something broke.
    CANARY_EXPECT_FAILURE=1
    canary "$host" "$port" "udp" "cloudflare.com" "dnssec" || rc=1
    CANARY_EXPECT_FAILURE=0
    return "$rc"
}

# Poll for real readiness with bounded exponential backoff.
#
# "systemd says active" is not readiness: the unit is active the moment the process
# signals it, and a canary fired immediately afterwards can race listener binding or the
# first upstream bootstrap. Never retries indefinitely.
wait_ready() {
    local host="$1" port="$2"
    local delay=1 waited=0 limit=45
    while [ "$waited" -lt "$limit" ]; do
        if systemctl is-active --quiet egressdns.service &&
            canary "$host" "$port" "udp" "localhost"; then
            return 0
        fi
        sleep "$delay"
        waited=$((waited + delay))
        [ "$delay" -lt 8 ] && delay=$((delay * 2))
    done
    return 1
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

    # Wait for the daemon to be genuinely ready rather than sleeping a fixed second. A
    # canary that races startup produces a failure that looks like a defect and is not.
    wait_ready "$host" "$port" || {
        ROLLBACK_NEEDED=1
        canary_failed "the service did not become ready"
        die "the service did not become ready"
    }

    # Local ingress first, with a name the daemon answers itself. If this fails the
    # listener is broken; nothing beyond it is worth testing.
    if ! local_canaries "$host" "$port"; then
        ROLLBACK_NEEDED=1
        die "local ingress canary failed"
    fi

    # Then forwarding, which is a different subsystem and a different failure.
    if ! external_canaries "$host" "$port"; then
        ROLLBACK_NEEDED=1
        die "forwarding canary failed"
    fi

    # Fail-closed is a correctness property and is not optional.
    log "DNSSEC fail-closed canary against ${host}:${port}"
    if ! canary_dnssec_bogus "$host" "$port"; then
        ROLLBACK_NEEDED=1
        canary_failed "DNSSEC fail-closed canary"
        die "the resolver answered a DNSSEC-bogus name"
    fi

    # AD on a signed name is advisory: a network that strips DNSSEC records can fail this
    # without the installation being wrong.
    if canary_dnssec_secure "$host" "$port"; then
        DNSSEC_SECURE_RESULT="PASS"
    else
        DNSSEC_SECURE_RESULT="WARN"
        warn "a DNSSEC-signed name did not validate; this network may filter DNSSEC records"
    fi

    log "canaries passed"
}

summary() {
    # Report what is actually in the file. An operator who passed --config, or who kept
    # their existing configuration, did not get the built-in set and must not be told they
    # did — the summary is the only place most installs are ever read.
    local RESOLVER_SUMMARY="builtin:${PROFILE}"
    if [ "${GENERATED_CONFIG:-0}" -ne 1 ]; then
        RESOLVER_SUMMARY="as configured in $CONF_DIR/config.toml"
    fi

    local listeners="127.0.0.1:53"
    [ "$MODE" = "lan" ] && listeners="$(listen_addresses_v4)"
    [ "$LISTEN_V6_ALL" -eq 1 ] && listeners="$listeners [::]:53"

    cat <<MSG

EgressDNS is installed and answering.

  mode            ${MODE}
  listening on    ${listeners}
  clients         ${LAN_CIDRS:-this machine only (loopback)}
  resolvers       ${RESOLVER_SUMMARY}
  proxies         none configured
  DNSSEC          Bogus answers rejected${DNSSEC_SECURE_RESULT:+; validation ${DNSSEC_SECURE_RESULT}}
  system resolver ${SYSTEM_RESOLVER_ACTION}${SYSTEM_RESOLVER_UNIT:+ (${SYSTEM_RESOLVER_UNIT} was running)}

  configuration   $CONF_DIR/config.toml
  state           $STATE_DIR
  service         systemctl status egressdns
  control         $CONTROL status

Verified before this message was printed: the service is active, it answers over
UDP and over TCP, it resolves real names on the Internet, and it refuses a
DNSSEC-Bogus name with SERVFAIL.

MSG

    if [ "$MODE" = "local" ] && [ "$SYSTEM_RESOLVER_ACTION" = "keep" ]; then
        cat <<MSG
Nothing on this machine uses it yet — it listens on loopback and /etc/resolv.conf
was left alone. To try it:

    $CONTROL query example.com --server 127.0.0.1

To make this machine use it, re-run with --replace-system-resolver, or point
/etc/resolv.conf at 127.0.0.1 yourself.

MSG
    fi
}

main() {
    parse_args "$@"
    require_root
    detect_platform

    # Everything that reads the host happens before anything writes to it, so the
    # interview can be abandoned at any prompt with the machine untouched.
    detect_existing_install
    detect_system_resolver
    interview

    check_port_53
    trap cleanup EXIT
    create_user
    make_dirs
    backup_existing
    ROLLBACK_NEEDED=1
    apply_purges
    if [ "$LOCAL_BUILD" -eq 1 ]; then
        build_locally
    else
        download_release
    fi
    install_files
    validate_config
    start_service
    health_check

    # Only now, with the resolver proven to answer, is the machine's own name resolution
    # moved onto it. In the other order a failed install takes DNS down with it.
    replace_system_resolver
    ROLLBACK_NEEDED=0

    if [ "${PURGE_OLD_CONFIG:-0}" -eq 1 ] && [ -n "$BACKUP_DIR" ]; then
        rm -f "$BACKUP_DIR/config.toml"
        log "the previous configuration was deleted at your request"
    elif [ -n "$BACKUP_DIR" ] && [ -f "$BACKUP_DIR/config.toml" ]; then
        log "the previous configuration is kept at $BACKUP_DIR/config.toml"
    fi

    summary
}

main "$@"
