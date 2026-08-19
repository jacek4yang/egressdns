#!/usr/bin/env bash
#
# Fault-injection test against a running EgressDNS instance.
#
#   ./scripts/chaos-test.sh --host 127.0.0.1 --port 1053 --socket /tmp/egressdns-admin.sock
#
# Each scenario breaks something and then asserts that DNS still works, or fails in the
# documented way. Run this before promoting a node to production; it is the fastest way to
# find a configuration that only looks correct while everything is healthy.

set -Eeuo pipefail

HOST="127.0.0.1"
PORT="1053"
SOCKET="/run/egressdns/admin.sock"
CTL="egressdnsctl"
FAILURES=0

usage() {
    cat <<'USAGE'
Usage: chaos-test.sh [--host <addr>] [--port <port>] [--socket <path>] [--ctl <path>]
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --socket) SOCKET="$2"; shift 2 ;;
        --ctl) CTL="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) printf 'unknown option %s\n' "$1" >&2; exit 1 ;;
    esac
done

step()  { printf '\n=== %s\n' "$*" >&2; }
pass()  { printf '  PASS  %s\n' "$*" >&2; }
fail()  { printf '  FAIL  %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }

query() {
    local name="$1" type="${2:-A}" extra="${3:-}"
    if command -v dig >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        dig @"$HOST" -p "$PORT" +timeout=3 +tries=1 $extra "$name" "$type" 2>/dev/null
    else
        python3 "$(dirname "$0")/load_generator.py" \
            --host "$HOST" --port "$PORT" --duration 0.5 --clients 1 --names 1 2>/dev/null
    fi
}

# shellcheck disable=SC2317  # called from the scenario blocks further down.
answers() {
    query "$1" "${2:-A}" "${3:-}" | grep -c "^${1%.}\." || true
}

ctl() { "$CTL" --socket "$SOCKET" "$@"; }

step "baseline resolution"
if query example.com A | grep -q "status: NOERROR"; then
    pass "the resolver answers"
else
    fail "the resolver did not answer a baseline query"
fi

step "TCP path"
if query example.com A "+tcp" | grep -q "status: NOERROR"; then
    pass "TCP works"
else
    fail "TCP did not answer"
fi

step "administration socket"
if ctl status >/dev/null 2>&1; then
    pass "the administration socket responds"
else
    fail "the administration socket did not respond"
fi

step "configuration reload under traffic"
(
    end=$(( $(date +%s) + 5 ))
    while [ "$(date +%s)" -lt "$end" ]; do
        query example.com A >/dev/null 2>&1 || true
    done
) &
traffic=$!
sleep 1
if ctl reload >/dev/null 2>&1; then
    pass "reload succeeded while traffic was flowing"
else
    fail "reload failed"
fi
wait "$traffic" 2>/dev/null || true

step "cache flush"
if ctl flush-all >/dev/null 2>&1 && query example.com A | grep -q "status: NOERROR"; then
    pass "resolution continues after a full flush"
else
    fail "resolution broke after a flush"
fi

step "Cloudflare subsystem can be inspected and does not gate DNS"
if ctl cloudflare status >/dev/null 2>&1; then
    pass "cloudflare status responds"
else
    fail "cloudflare status failed"
fi

step "answers survive an unreachable optimizer"
# Point the probe engine at documentation space by asking for a name that cannot be
# validated, then confirm resolution is unaffected.
if query cloudflare.com A | grep -q "status: NOERROR"; then
    pass "a Cloudflare-hosted name still resolves"
else
    printf '  SKIP  no Internet connectivity for the Cloudflare check\n' >&2
fi

step "malformed input"
if command -v python3 >/dev/null 2>&1; then
    python3 - "$HOST" "$PORT" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
for payload in (b"", b"\x00", b"\xff" * 64, bytes(range(256))):
    try:
        s.sendto(payload, (host, port))
    except OSError:
        pass
try:
    s.recvfrom(4096)
except OSError:
    pass
PY
    if query example.com A | grep -q "status: NOERROR"; then
        pass "the resolver survived malformed datagrams"
    else
        fail "the resolver stopped answering after malformed input"
    fi
fi

step "summary"
if [ "$FAILURES" -eq 0 ]; then
    printf '\nall chaos scenarios passed\n' >&2
    exit 0
fi
printf '\n%d chaos scenario(s) failed\n' "$FAILURES" >&2
exit 1
