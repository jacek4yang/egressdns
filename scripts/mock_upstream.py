#!/usr/bin/env python3
"""A scriptable DNS upstream for load testing EgressDNS.

This is deliberately *not* a resolver. It answers any A/AAAA query with a synthetic
address, and its whole purpose is to be able to misbehave on demand so that the daemon
under test can be measured against elevated RTT, packet loss, SERVFAIL storms, truncation
and timeouts rather than only against a perfect upstream.

Every impairment is a probability or a fixed delay, so a scenario is reproducible from its
command line:

    ./mock_upstream.py --port 15353 --delay-ms 40 --jitter-ms 15 --loss 0.02

Only the standard library is used, so it runs anywhere the daemon does.
"""

from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Minimal DNS wire handling
# ---------------------------------------------------------------------------
#
# Building a response by editing the request in place avoids reimplementing name
# compression: the question section is copied verbatim and the answer uses a 0xC00C
# pointer back to it, which is the only compression pointer this file ever needs.

TYPE_A = 1
TYPE_AAAA = 28
RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3


def parse_question(data: bytes) -> tuple[int, int, int, int] | None:
    """Return (txid, qname_end_offset, qtype, qclass) or None if unparseable."""
    if len(data) < 12:
        return None
    txid, _flags, qdcount = struct.unpack_from("!HHH", data, 0)
    if qdcount < 1:
        return None
    offset = 12
    while True:
        if offset >= len(data):
            return None
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # A compression pointer in a question is malformed for our purposes.
        if length & 0xC0:
            return None
        offset += 1 + length
        if offset > len(data):
            return None
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack_from("!HH", data, offset)
    return txid, offset + 4, qtype, qclass


def build_response(
    request: bytes,
    question_end: int,
    qtype: int,
    *,
    rcode: int,
    truncated: bool,
    ttl: int,
    address: bytes | None,
) -> bytes:
    """Assemble a response by reusing the request's header and question section."""
    txid = struct.unpack_from("!H", request, 0)[0]
    # QR=1, RD copied from the request, RA=1.
    request_flags = struct.unpack_from("!H", request, 2)[0]
    rd = request_flags & 0x0100
    flags = 0x8000 | rd | 0x0080 | (0x0200 if truncated else 0) | (rcode & 0x000F)

    answers = b""
    ancount = 0
    if address is not None and rcode == RCODE_NOERROR and not truncated:
        # NAME as a pointer to offset 12, the start of the question's QNAME.
        answers = struct.pack("!HHHIH", 0xC00C, qtype, 1, ttl, len(address)) + address
        ancount = 1

    header = struct.pack("!HHHHHH", txid, flags, 1, ancount, 0, 0)
    return header + request[12:question_end] + answers


# ---------------------------------------------------------------------------
# Impairment model
# ---------------------------------------------------------------------------


class Impairments:
    """How this upstream should misbehave, as reproducible probabilities."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.delay = args.delay_ms / 1000.0
        self.jitter = args.jitter_ms / 1000.0
        self.loss = args.loss
        self.servfail = args.servfail
        self.nxdomain = args.nxdomain
        self.truncate = args.truncate
        self.ttl = args.ttl
        # A dedicated Random keeps the impairment stream independent of anything else and
        # reproducible from --seed.
        self.rng = random.Random(args.seed)
        self.lock = threading.Lock()

    def draw(self) -> tuple[float, str]:
        """Return (delay_seconds, outcome) for one query."""
        with self.lock:
            roll_loss = self.rng.random()
            roll_kind = self.rng.random()
            jitter = self.rng.uniform(-self.jitter, self.jitter) if self.jitter else 0.0
        delay = max(0.0, self.delay + jitter)
        if roll_loss < self.loss:
            return delay, "drop"
        if roll_kind < self.servfail:
            return delay, "servfail"
        if roll_kind < self.servfail + self.nxdomain:
            return delay, "nxdomain"
        if roll_kind < self.servfail + self.nxdomain + self.truncate:
            return delay, "truncate"
        return delay, "answer"


class Counters:
    """Per-outcome totals, reported on exit so a run can be audited."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.data: dict[str, int] = {}

    def bump(self, key: str) -> None:
        with self.lock:
            self.data[key] = self.data.get(key, 0) + 1

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(self.data)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


def serve_udp(sock: socket.socket, imp: Impairments, counters: Counters) -> None:
    while True:
        try:
            data, peer = sock.recvfrom(4096)
        except OSError:
            return
        parsed = parse_question(data)
        if parsed is None:
            counters.bump("malformed")
            continue
        _txid, question_end, qtype, _qclass = parsed
        delay, outcome = imp.draw()
        threading.Thread(
            target=respond,
            args=(sock, peer, data, question_end, qtype, delay, outcome, imp, counters),
            daemon=True,
        ).start()


def respond(
    sock: socket.socket,
    peer: tuple[str, int],
    request: bytes,
    question_end: int,
    qtype: int,
    delay: float,
    outcome: str,
    imp: Impairments,
    counters: Counters,
) -> None:
    if delay:
        time.sleep(delay)
    counters.bump(outcome)
    if outcome == "drop":
        return

    address: bytes | None = None
    rcode = RCODE_NOERROR
    truncated = False
    if outcome == "servfail":
        rcode = RCODE_SERVFAIL
    elif outcome == "nxdomain":
        rcode = RCODE_NXDOMAIN
    elif outcome == "truncate":
        truncated = True
    elif qtype == TYPE_A:
        address = socket.inet_aton("203.0.113.7")
    elif qtype == TYPE_AAAA:
        address = socket.inet_pton(socket.AF_INET6, "2001:db8::7")
    else:
        # Any other type gets an empty NOERROR, which is a legitimate answer.
        address = None

    reply = build_response(
        request,
        question_end,
        qtype,
        rcode=rcode,
        truncated=truncated,
        ttl=imp.ttl,
        address=address,
    )
    try:
        sock.sendto(reply, peer)
    except OSError:
        pass


def serve_tcp(listener: socket.socket, imp: Impairments, counters: Counters) -> None:
    while True:
        try:
            conn, _peer = listener.accept()
        except OSError:
            return
        threading.Thread(
            target=handle_tcp, args=(conn, imp, counters), daemon=True
        ).start()


def handle_tcp(conn: socket.socket, imp: Impairments, counters: Counters) -> None:
    # A stream retry after truncation must succeed, otherwise the daemon has no way to
    # complete the exchange and the scenario measures nothing useful. TCP therefore
    # ignores --truncate, but still honours delay, loss and rcode impairments.
    with conn:
        conn.settimeout(30)
        while True:
            try:
                header = recv_exact(conn, 2)
                if header is None:
                    return
                length = struct.unpack("!H", header)[0]
                request = recv_exact(conn, length)
                if request is None:
                    return
            except OSError:
                return
            parsed = parse_question(request)
            if parsed is None:
                counters.bump("malformed")
                return
            _txid, question_end, qtype, _qclass = parsed
            delay, outcome = imp.draw()
            if delay:
                time.sleep(delay)
            if outcome == "drop":
                counters.bump("tcp_drop")
                return
            if outcome == "truncate":
                outcome = "answer"
            counters.bump(f"tcp_{outcome}")
            address = None
            rcode = RCODE_NOERROR
            if outcome == "servfail":
                rcode = RCODE_SERVFAIL
            elif outcome == "nxdomain":
                rcode = RCODE_NXDOMAIN
            elif qtype == TYPE_A:
                address = socket.inet_aton("203.0.113.7")
            elif qtype == TYPE_AAAA:
                address = socket.inet_pton(socket.AF_INET6, "2001:db8::7")
            reply = build_response(
                request,
                question_end,
                qtype,
                rcode=rcode,
                truncated=False,
                ttl=imp.ttl,
                address=address,
            )
            try:
                conn.sendall(struct.pack("!H", len(reply)) + reply)
            except OSError:
                return


def recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=15353)
    parser.add_argument(
        "--delay-ms", type=float, default=0.0, help="fixed added round-trip delay"
    )
    parser.add_argument(
        "--jitter-ms", type=float, default=0.0, help="uniform jitter around --delay-ms"
    )
    parser.add_argument(
        "--loss", type=float, default=0.0, help="probability a query is never answered"
    )
    parser.add_argument("--servfail", type=float, default=0.0)
    parser.add_argument("--nxdomain", type=float, default=0.0)
    parser.add_argument(
        "--truncate",
        type=float,
        default=0.0,
        help="probability a UDP answer sets TC, forcing a TCP retry",
    )
    parser.add_argument("--ttl", type=int, default=60)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--no-tcp", action="store_true")
    args = parser.parse_args()

    total = args.loss + args.servfail + args.nxdomain + args.truncate
    if total > 1.0:
        print(
            f"impairment probabilities sum to {total:.2f}, which is over 1.0",
            file=sys.stderr,
        )
        return 2

    imp = Impairments(args)
    counters = Counters()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((args.host, args.port))
    threads = [threading.Thread(target=serve_udp, args=(udp, imp, counters), daemon=True)]

    tcp = None
    if not args.no_tcp:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((args.host, args.port))
        tcp.listen(128)
        threads.append(
            threading.Thread(target=serve_tcp, args=(tcp, imp, counters), daemon=True)
        )

    for t in threads:
        t.start()
    print(
        f"mock upstream on {args.host}:{args.port} "
        f"delay={args.delay_ms}ms jitter={args.jitter_ms}ms loss={args.loss} "
        f"servfail={args.servfail} nxdomain={args.nxdomain} truncate={args.truncate}",
        flush=True,
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        udp.close()
        if tcp:
            tcp.close()
        print(f"counters: {counters.snapshot()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
