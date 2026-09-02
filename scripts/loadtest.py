#!/usr/bin/env python3
"""Load generator for EgressDNS with honest accounting.

Two properties matter more than raw throughput here:

1. **A reply is not a success.** An earlier version of this harness counted any DNS
   response as a completed query, and consequently reported ~17,000 qps against an
   upstream that was returning SERVFAIL to half of them. Every run now reports the full
   rcode distribution, and the headline success rate counts only NOERROR *with an answer
   record* — the thing a client actually wanted.

2. **Percentiles must be measured, not estimated.** Every latency sample is retained and
   percentiles are computed from the sorted vector, out to p99.9, so a tail that only
   shows up once in a thousand queries is visible.

The process's own resource use is sampled from `/proc/<pid>` while the run is in
progress — RSS, open file descriptors and thread count — so a leak shows up as a trend
across a sustained run rather than as a single end-of-run number.

The generator is closed-loop: each client keeps `--inflight` queries outstanding and
sends a replacement only when one completes. That makes latency meaningful, but it also
means peak throughput is bounded by `clients x inflight / mean-latency` *by construction*.
With a 40 ms upstream and 8 clients at `--inflight 1`, ~200 qps is the harness's ceiling,
not the resolver's. Raise `--inflight` when the goal is to find the resolver's limit, and
read RTT-impaired scenarios as latency and stability measurements rather than throughput
ones.

    ./loadtest.py --port 1053 --duration 60 --clients 8 --names 10000 \
        --daemon-pid $(pidof egressdnsd) --json results.json

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import statistics
import struct
import sys
import threading
import time

RCODE_NAMES = {
    0: "noerror",
    1: "formerr",
    2: "servfail",
    3: "nxdomain",
    4: "notimp",
    5: "refused",
}

TYPE_A = 1
TYPE_AAAA = 28


def encode_query(txid: int, name: str, qtype: int) -> bytes:
    """Encode a standard recursive query. No EDNS, so the wire format stays trivial."""
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in name.rstrip(".").split(".")
    ) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def decode_response(data: bytes) -> tuple[int, int, int] | None:
    """Return (txid, rcode, ancount)."""
    if len(data) < 12:
        return None
    txid, flags, _qd, ancount, _ns, _ar = struct.unpack_from("!HHHHHH", data, 0)
    return txid, flags & 0x000F, ancount


class Results:
    """Thread-safe accumulation of latencies and outcomes."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.latencies: list[float] = []
        self.rcodes: dict[str, int] = {}
        self.sent = 0
        self.timeouts = 0
        self.answered_with_data = 0
        self.errors = 0
        self.abandoned = 0

    def record(self, latency: float, rcode: int, ancount: int) -> None:
        name = RCODE_NAMES.get(rcode, f"rcode{rcode}")
        with self.lock:
            self.latencies.append(latency)
            self.rcodes[name] = self.rcodes.get(name, 0) + 1
            if rcode == 0 and ancount > 0:
                self.answered_with_data += 1

    def timeout(self) -> None:
        with self.lock:
            self.timeouts += 1

    def error(self) -> None:
        with self.lock:
            self.errors += 1

    def count_sent(self, n: int) -> None:
        with self.lock:
            self.sent += n

    def count_abandoned(self, n: int) -> None:
        with self.lock:
            self.abandoned += n


class ProcSampler(threading.Thread):
    """Sample RSS, file descriptors and thread count while the test runs.

    Linux reads `/proc/<pid>`. Windows uses the process API through `ctypes`: RSS from
    `GetProcessMemoryInfo`, the open-handle count from `GetProcessHandleCount` (a handle
    count is not a descriptor count, but it answers the same leak question), and CPU time
    from `GetProcessTimes`. Windows cannot report a thread count without extra
    privileges, so it is recorded as 0 there and the report notes the platform.
    """

    IS_WINDOWS = os.name == "nt"

    def __init__(self, pid: int, interval: float = 1.0) -> None:
        super().__init__(daemon=True)
        self.pid = pid
        self.interval = interval
        self.samples: list[dict[str, float]] = []
        self.stop_event = threading.Event()
        self._process = None  # Windows: HANDLE kept open for the duration.

    def run(self) -> None:
        if self.IS_WINDOWS:
            self._process = self._open_windows_process()
            if self._process is None:
                return
        while not self.stop_event.is_set():
            sample = self.sample()
            if sample is None:
                return
            self.samples.append(sample)
            self.stop_event.wait(self.interval)

    # --- Windows ------------------------------------------------------------------

    def _open_windows_process(self) -> "ctypes.WinDLL | None":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, self.pid)
        return handle if handle else None

    def _sample_windows(self) -> dict[str, float] | None:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        api_ms = ctypes.WinDLL("api_ms_win_psapi_l1_1_0")
        handle = self._process

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        pmc = PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(pmc)
        if not api_ms.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
            return None
        handle_count = wintypes.DWORD(0)
        if not kernel32.GetProcessHandleCount(handle, ctypes.byref(handle_count)):
            return None
        creation = wintypes.FILETIME()
        exit_t = wintypes.FILETIME()
        kernel_t = wintypes.FILETIME()
        user_t = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_t),
            ctypes.byref(kernel_t),
            ctypes.byref(user_t),
        ):
            return None
        # Kernel and user time arrive as 100-nanosecond FILETIME units.
        cpu_ticks = kernel_t.dwHighDateTime << 32 | kernel_t.dwLowDateTime
        cpu_ticks += user_t.dwHighDateTime << 32 | user_t.dwLowDateTime
        return {
            "t": time.monotonic(),
            "rss_mb": pmc.WorkingSetSize / (1024.0 * 1024.0),
            "fds": float(handle_count.value),
            "threads": 0.0,  # Not available unprivileged on Windows.
            "cpu_ticks": float(cpu_ticks),
        }

    # --- Linux --------------------------------------------------------------------

    def sample(self) -> dict[str, float] | None:
        if self.IS_WINDOWS:
            return self._sample_windows()
        base = f"/proc/{self.pid}"
        try:
            with open(f"{base}/status", encoding="ascii") as fh:
                status = fh.read()
            rss_kb = 0
            threads = 0
            for line in status.splitlines():
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
            fds = len(os.listdir(f"{base}/fd"))
            with open(f"{base}/stat", encoding="ascii") as fh:
                fields = fh.read().rsplit(") ", 1)[1].split()
            # utime + stime, in clock ticks.
            cpu_ticks = int(fields[11]) + int(fields[12])
        except (OSError, IndexError, ValueError):
            return None
        return {
            "t": time.monotonic(),
            "rss_mb": rss_kb / 1024.0,
            "fds": float(fds),
            "threads": float(threads),
            "cpu_ticks": float(cpu_ticks),
        }


def worker(
    args: argparse.Namespace,
    results: Results,
    stop: threading.Event,
    worker_id: int,
) -> None:
    """One client: keeps `--inflight` queries outstanding at all times."""
    rng = random.Random(args.seed + worker_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.05)
    target = (args.host, args.port)
    sent = 0
    next_txid = rng.randrange(1, 65535)
    # txid -> send time. A DNS transaction ID is 16 bits, so `--inflight` must stay well
    # under 65536 for collisions to be impossible.
    pending: dict[int, float] = {}

    def emit() -> None:
        nonlocal sent, next_txid
        # The working-set size is what makes a scenario cache-hit or miss-heavy: a small
        # `--names` keeps everything resident, a large one guarantees misses.
        index = rng.randrange(args.names)
        name = f"n{index}.{args.zone}"
        qtype = (
            TYPE_AAAA
            if (args.ipv6_fraction and rng.random() < args.ipv6_fraction)
            else TYPE_A
        )
        for _ in range(65536):
            next_txid = (next_txid + 1) & 0xFFFF
            if next_txid not in pending:
                break
        pending[next_txid] = time.perf_counter()
        try:
            sock.sendto(encode_query(next_txid, name, qtype), target)
            sent += 1
        except OSError:
            pending.pop(next_txid, None)
            results.error()

    while not stop.is_set():
        while len(pending) < args.inflight:
            emit()
        try:
            data, _peer = sock.recvfrom(4096)
        except TimeoutError:
            # Expire anything past the deadline so a lost reply frees its slot rather
            # than stalling this client for the rest of the run.
            now = time.perf_counter()
            for txid in [t for t, s in pending.items() if now - s > args.timeout]:
                pending.pop(txid, None)
                results.timeout()
            continue
        except OSError:
            results.error()
            continue
        decoded = decode_response(data)
        if decoded is None:
            results.error()
            continue
        got_txid, rcode, ancount = decoded
        start = pending.pop(got_txid, None)
        if start is None:
            # A reply to a query already written off as a timeout.
            continue
        results.record(time.perf_counter() - start, rcode, ancount)

    # Anything still outstanding when the clock ran out is neither a success nor a
    # timeout; counting it either way would distort the result.
    results.count_sent(sent)
    results.count_abandoned(len(pending))
    sock.close()


def percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, int(q * len(sorted_values)))
    return sorted_values[index]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1053)
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--clients", type=int, default=8)
    parser.add_argument(
        "--names",
        type=int,
        default=64,
        help="working-set size; small = cache-hit, large = miss-heavy",
    )
    parser.add_argument("--zone", default="load.test")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument(
        "--ipv6-fraction",
        type=float,
        default=0.0,
        help="fraction of queries asking AAAA instead of A",
    )
    parser.add_argument(
        "--inflight",
        type=int,
        default=1,
        help="queries each client keeps outstanding; raise this to find the resolver's "
        "limit rather than the harness's",
    )
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--label", default="")
    parser.add_argument(
        "--daemon-pid",
        type=int,
        default=0,
        help="sample RSS/fds/threads from this pid during the run",
    )
    parser.add_argument("--json", default="", help="write the full result object here")
    args = parser.parse_args()

    results = Results()
    stop = threading.Event()
    sampler = None
    if args.daemon_pid:
        sampler = ProcSampler(args.daemon_pid)
        sampler.start()

    threads = [
        threading.Thread(target=worker, args=(args, results, stop, i), daemon=True)
        for i in range(args.clients)
    ]
    started = time.monotonic()
    for t in threads:
        t.start()
    time.sleep(args.duration)
    stop.set()
    for t in threads:
        t.join(timeout=args.timeout + 5)
    elapsed = time.monotonic() - started
    if sampler:
        sampler.stop_event.set()
        sampler.join(timeout=3)

    latencies = sorted(results.latencies)
    completed = len(latencies)
    total = completed + results.timeouts + results.errors
    report = {
        "label": args.label,
        "elapsed_s": round(elapsed, 3),
        "clients": args.clients,
        # The harness's own throughput ceiling, for comparison with `qps`. A measured qps
        # close to this number means the harness saturated before the resolver did.
        "harness_ceiling_qps": (
            round(args.clients * args.inflight / (statistics.fmean(latencies) or 1e-9), 1)
            if latencies
            else 0.0
        ),
        "working_set": args.names,
        "sent": results.sent,
        "completed": completed,
        "timeouts": results.timeouts,
        "errors": results.errors,
        "abandoned_at_end": results.abandoned,
        "inflight_per_client": args.inflight,
        "qps": round(completed / elapsed, 1) if elapsed else 0.0,
        # The honest number: NOERROR *with* an answer record, per second.
        "useful_qps": round(results.answered_with_data / elapsed, 1) if elapsed else 0.0,
        "answered_with_data": results.answered_with_data,
        "success_rate": round(results.answered_with_data / total, 4) if total else 0.0,
        "rcodes": results.rcodes,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50) * 1000, 3),
            "p95": round(percentile(latencies, 0.95) * 1000, 3),
            "p99": round(percentile(latencies, 0.99) * 1000, 3),
            "p999": round(percentile(latencies, 0.999) * 1000, 3),
            "max": round(latencies[-1] * 1000, 3) if latencies else 0.0,
            "mean": round(statistics.fmean(latencies) * 1000, 3) if latencies else 0.0,
        },
    }

    if sampler and sampler.samples:
        first, last = sampler.samples[0], sampler.samples[-1]
        span = max(1e-9, last["t"] - first["t"])
        # Linux CPU time is measured in clock ticks; Windows FILETIME units are 100 ns.
        ticks_per_sec = 10_000_000 if os.name == "nt" else os.sysconf("SC_CLK_TCK")
        report["process"] = {
            "platform": "windows" if os.name == "nt" else "linux",
            "samples": len(sampler.samples),
            "rss_mb_start": round(first["rss_mb"], 1),
            "rss_mb_end": round(last["rss_mb"], 1),
            "rss_mb_peak": round(max(s["rss_mb"] for s in sampler.samples), 1),
            "fds_start": int(first["fds"]),
            "fds_end": int(last["fds"]),
            "fds_peak": int(max(s["fds"] for s in sampler.samples)),
            "threads_end": int(last["threads"]),
            "threads_peak": int(max(s["threads"] for s in sampler.samples)),
            "cpu_percent": round(
                100.0 * (last["cpu_ticks"] - first["cpu_ticks"]) / ticks_per_sec / span,
                1,
            ),
            # A start-and-end RSS pair cannot distinguish a cache filling to its budget
            # from a leak. The series can: a cache plateaus, a leak keeps climbing. Kept
            # to ~40 points so a long soak stays readable.
            "rss_mb_series": [
                round(s["rss_mb"], 1)
                for s in sampler.samples[:: max(1, len(sampler.samples) // 40)]
            ],
            # Growth over the final third of the run. A filled cache is flat here; a leak
            # is not.
            "rss_mb_growth_last_third": round(
                max(s["rss_mb"] for s in sampler.samples[2 * len(sampler.samples) // 3 :])
                - min(
                    s["rss_mb"] for s in sampler.samples[2 * len(sampler.samples) // 3 :]
                ),
                1,
            ),
        }

    text = json.dumps(report, indent=2, sort_keys=True)
    print(text)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
