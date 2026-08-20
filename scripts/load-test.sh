#!/usr/bin/env bash
#
# Realistic load-test suite for EgressDNS.
#
# Starts a scriptable mock upstream (scripts/mock_upstream.py), starts a release build of
# the daemon against it, and runs a matrix of scenarios through scripts/loadtest.py:
#
#   cache-hit      small working set, perfect upstream
#   mixed          moderate working set, perfect upstream
#   miss-heavy     large working set, every query reaches the upstream
#   elevated-rtt   40ms +/- 15ms upstream
#   packet-loss    2% of upstream queries never answered
#   timeouts       10% of upstream queries never answered, so retries dominate
#   servfail       20% SERVFAIL, which is where a circuit breaker either helps or hurts
#   truncation     15% of UDP answers set TC, forcing TCP retries
#   ipv6-mixed     half the queries ask AAAA
#   dnssec-closed  validation enabled against an upstream that supplies no chain of
#                  trust. 100% SERVFAIL is the *correct* result and is the point of the
#                  scenario: it proves validation fails closed under load rather than
#                  degrading to unvalidated answers, and measures the cost of that path.
#   sustained      a long run, to separate a steady state from a leak
#
# Results are written as JSON under the output directory so that docs/BENCHMARKS.md can
# quote measured numbers rather than estimates.
#
# Usage:
#   ./scripts/load-test.sh                       # full suite
#   ./scripts/load-test.sh --duration 10         # quick pass
#   ./scripts/load-test.sh --only cache-hit,servfail
#   ./scripts/load-test.sh --sustained 900       # 15 minute soak
#   ./scripts/load-test.sh --inflight 32         # deeper client concurrency
#
# The generator is closed-loop: throughput is bounded by clients x inflight / latency by
# construction, so RTT-impaired scenarios report latency and stability honestly but must
# not be read as peak-throughput numbers. Each result records `harness_ceiling_qps` for
# exactly this comparison.
#
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/target/loadtest"
DURATION=30
SUSTAINED=180
CLIENTS=8
INFLIGHT=8
ONLY=""
DNS_PORT=15053
UPSTREAM_PORT=15353
KEEP=0

usage() {
    sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --sustained) SUSTAINED="$2"; shift 2 ;;
        --clients) CLIENTS="$2"; shift 2 ;;
        --inflight) INFLIGHT="$2"; shift 2 ;;
        --only) ONLY="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --port) DNS_PORT="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

mkdir -p "$OUT"
WORK="$(mktemp -d)"
DAEMON_PID=""
UPSTREAM_PID=""

cleanup() {
    if [ -n "$DAEMON_PID" ]; then kill "$DAEMON_PID" 2>/dev/null || true; fi
    if [ -n "$UPSTREAM_PID" ]; then kill "$UPSTREAM_PID" 2>/dev/null || true; fi
    wait 2>/dev/null || true
    if [ "$KEEP" -eq 0 ]; then rm -rf "$WORK"; else echo "workdir kept: $WORK"; fi
}
trap cleanup EXIT

echo "==> building release binary"
cargo build --release --bin egressdnsd >/dev/null

write_config() {
    # $1 = dnssec mode
    cat > "${WORK}/egressdns.toml" <<EOF
upstreams = ["127.0.0.1:${UPSTREAM_PORT}"]
proxies = []

[server]
udp_listen = ["127.0.0.1:${DNS_PORT}"]
tcp_listen = ["127.0.0.1:${DNS_PORT}"]
allow_from = ["127.0.0.0/8"]

# The daemon's own inbound rate limiter would otherwise be the thing being measured: at
# default settings a single load-generating host trips the per-client limit long before
# the resolver itself is loaded, and the run reports the limiter's throughput rather than
# the resolver's. These are deliberately far above any real per-client rate.
[server.rate_limit]
enabled = true
per_client_qps = 5000000
per_client_burst = 5000000
global_qps = 5000000
global_burst = 5000000

[metrics]
enabled = false

[admin]
enabled = false

[storage]
enabled = false
path = "${WORK}/state.sqlite3"

[cache]
max_memory_bytes = 268435456

[dnssec]
mode = "$1"

[probe]
enabled = false

[prefetch]
enabled = false

[cloudflare]
enabled = false
EOF
}

start_upstream() {
    python3 "${ROOT}/scripts/mock_upstream.py" --port "$UPSTREAM_PORT" "$@" \
        >"${WORK}/upstream.log" 2>&1 &
    UPSTREAM_PID=$!
    sleep 0.5
}

start_daemon() {
    "${ROOT}/target/release/egressdnsd" --config "${WORK}/egressdns.toml" \
        >"${WORK}/daemon.log" 2>&1 &
    DAEMON_PID=$!
    # Wait for the listener rather than sleeping a fixed amount. A daemon that failed to
    # start must abort the run: reporting 0 qps as a result would be a silent lie.
    local ready=0
    for _ in $(seq 1 50); do
        if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            echo "daemon exited during startup:" >&2
            cat "${WORK}/daemon.log" >&2
            exit 1
        fi
        if python3 - "$DNS_PORT" <<'PY' 2>/dev/null; then ready=1; break; fi
import socket, sys, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.2)
q = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x05ready\x04test\x00" + struct.pack("!HH", 1, 1)
s.sendto(q, ("127.0.0.1", int(sys.argv[1])))
s.recvfrom(4096)
PY
        sleep 0.2
    done
    if [ "$ready" -ne 1 ]; then
        echo "daemon never answered on port ${DNS_PORT}:" >&2
        cat "${WORK}/daemon.log" >&2
        exit 1
    fi
}

stop_all() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    if [ -n "$UPSTREAM_PID" ]; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    DAEMON_PID=""
    UPSTREAM_PID=""
}

summarise() {
    python3 - "$1" <<'PYSUM'
import json, sys

with open(sys.argv[1], encoding="utf-8") as fh:
    r = json.load(fh)
lat = r["latency_ms"]
proc = r.get("process", {})
print(
    f"    qps={r['qps']:>9}  useful={r['useful_qps']:>9}  "
    f"success={r['success_rate']:.3f}  "
    f"p50={lat['p50']:.2f}ms p99={lat['p99']:.2f}ms p99.9={lat['p999']:.2f}ms"
)
print(
    f"    rss={proc.get('rss_mb_end', 0)}MB (peak {proc.get('rss_mb_peak', 0)}MB)  "
    f"fds={proc.get('fds_end', 0)}  threads={proc.get('threads_end', 0)}  "
    f"cpu={proc.get('cpu_percent', 0)}%  rcodes={r['rcodes']}"
)
PYSUM
}

wants() {
    [ -z "$ONLY" ] && return 0
    case ",${ONLY}," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

# scenario <name> <duration> <names> <ipv6-fraction> <dnssec-mode> [upstream flags...]
scenario() {
    local name="$1" dur="$2" names="$3" v6="$4" dnssec="$5"
    shift 5
    wants "$name" || return 0

    echo "==> ${name}"
    write_config "$dnssec"
    start_upstream "$@"
    start_daemon
    python3 "${ROOT}/scripts/loadtest.py" \
        --port "$DNS_PORT" --duration "$dur" --clients "$CLIENTS" \
        --inflight "$INFLIGHT" \
        --names "$names" --ipv6-fraction "$v6" --label "$name" \
        --daemon-pid "$DAEMON_PID" --json "${OUT}/${name}.json" >/dev/null
    summarise "${OUT}/${name}.json"
    stop_all
}

scenario cache-hit    "$DURATION"  64      0.0 off
scenario mixed        "$DURATION"  5000    0.0 off
scenario miss-heavy   "$DURATION"  200000  0.0 off
scenario elevated-rtt "$DURATION"  200000  0.0 off --delay-ms 40 --jitter-ms 15
scenario packet-loss  "$DURATION"  200000  0.0 off --loss 0.02
scenario timeouts     "$DURATION"  200000  0.0 off --loss 0.10
scenario servfail     "$DURATION"  200000  0.0 off --servfail 0.20
scenario truncation   "$DURATION"  200000  0.0 off --truncate 0.15
scenario ipv6-mixed   "$DURATION"  5000    0.5 off
scenario dnssec-closed "$DURATION" 5000    0.0 validate
scenario sustained    "$SUSTAINED" 20000   0.2 off --delay-ms 5 --jitter-ms 3

echo
echo "results written to ${OUT}"
