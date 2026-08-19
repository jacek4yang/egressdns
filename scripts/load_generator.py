#!/usr/bin/env python3
"""Minimal UDP DNS load generator with latency percentiles.

Deliberately dependency-free so it runs anywhere the daemon does. It measures the
cache-hit path: a small working set is warmed first, then queried at maximum rate.
"""

from __future__ import annotations

import argparse
import multiprocessing
import os
import random
import socket
import struct
import sys
import time


def encode_query(qid: int, name: str, qtype: int = 1) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in name.rstrip(".").split(".")
    ) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    # EDNS(0) OPT with a 1232-byte payload, matching DNS Flag Day 2020.
    opt = b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)
    return header + question + opt


def worker(args, index: int, results):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    target = (args.host, args.port)
    names = [f"load{i:03d}.example.com" for i in range(args.names)]
    rng = random.Random(1000 + index)

    latencies: list[float] = []
    sent = 0
    ok = 0
    failed = 0
    deadline = time.monotonic() + args.duration
    qid = (os.getpid() * 7919 + index) & 0xFFFF

    while time.monotonic() < deadline:
        name = rng.choice(names)
        qid = (qid + 1) & 0xFFFF
        payload = encode_query(qid, name)
        started = time.perf_counter()
        try:
            sock.sendto(payload, target)
            sent += 1
            data, _ = sock.recvfrom(4096)
            elapsed = time.perf_counter() - started
            if len(data) >= 4 and struct.unpack(">H", data[:2])[0] == qid:
                latencies.append(elapsed)
                ok += 1
            else:
                failed += 1
        except TimeoutError:
            failed += 1
        except OSError:
            failed += 1

    results[index] = (sent, ok, failed, latencies)


def percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, max(0, round(q * len(sorted_values)) - 1))
    return sorted_values[index]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1053)
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--names", type=int, default=64)
    args = parser.parse_args()

    # Warm the cache so the measurement is of the cache-hit path.
    warm = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    warm.settimeout(3.0)
    for i in range(args.names):
        try:
            warm.sendto(encode_query(i + 1, f"load{i:03d}.example.com"), (args.host, args.port))
            warm.recvfrom(4096)
        except OSError:
            pass
    warm.close()

    manager = multiprocessing.Manager()
    results = manager.dict()
    procs = [
        multiprocessing.Process(target=worker, args=(args, i, results))
        for i in range(args.clients)
    ]
    started = time.monotonic()
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    elapsed = time.monotonic() - started

    sent = ok = failed = 0
    latencies: list[float] = []
    for i in range(args.clients):
        if i not in results:
            continue
        s, o, f, lat = results[i]
        sent += s
        ok += o
        failed += f
        latencies.extend(lat)
    latencies.sort()

    print(f"duration        {elapsed:.2f} s")
    print(f"clients         {args.clients}")
    print(f"working set     {args.names} names")
    print(f"queries sent    {sent}")
    print(f"answered        {ok}")
    print(f"failed          {failed}")
    print(f"throughput      {ok / elapsed:,.0f} queries/s")
    if latencies:
        print(f"latency p50     {percentile(latencies, 0.50) * 1000:.3f} ms")
        print(f"latency p95     {percentile(latencies, 0.95) * 1000:.3f} ms")
        print(f"latency p99     {percentile(latencies, 0.99) * 1000:.3f} ms")
        print(f"latency max     {latencies[-1] * 1000:.3f} ms")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
