#!/usr/bin/env python3
"""Compare EgressDNS answers against Unbound, forwarding to the same upstream.

Both resolvers are pointed at the same upstream and asked the same questions, so a
difference is a difference in *our* semantics rather than in what the Internet said.
That is the only comparison worth making: a recursive-versus-forwarding comparison, or
one against a different upstream, would report the network as a defect.

What is compared, and what is deliberately not:

* **rcode** — must match. A different rcode for the same question is a real disagreement.
* **answer RRset, as a set** — must match. Order is *not* compared: EgressDNS reorders
  A and AAAA records by measured quality, which is the point of the program, and RFC 1035
  does not promise an order.
* **AD bit** — must match. Disagreeing about whether an answer is authenticated is a
  security-relevant difference.
* **TTL** — not compared for equality. EgressDNS caps client-facing TTLs downward by
  policy; a lower TTL is expected. It is checked for being *no higher* than Unbound's,
  because TTL policy may only ever reduce.

Usage:
    scripts/differential-test.py --egressdns 127.0.0.1:15390 --unbound 127.0.0.1:15391
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time

# (qname, qtype, why this case is here)
CASES: list[tuple[str, str, str]] = [
    ("example.com", "A", "ordinary positive answer"),
    ("example.com", "AAAA", "positive AAAA"),
    ("www.cloudflare.com", "A", "CNAME chain to a terminal RRset"),
    ("cloudflare.com", "MX", "non-address record type"),
    ("cloudflare.com", "TXT", "text record, multiple strings"),
    ("cloudflare.com", "DNSKEY", "DNSSEC record type"),
    ("cloudflare.com", "HTTPS", "SVCB-family record"),
    ("cloudflare.com", "DS", "delegation signer"),
    ("internetsociety.org", "A", "DNSSEC-signed zone, AD expected"),
    ("dnssec-failed.org", "A", "deliberately bogus, must fail closed"),
    ("nothing-here-zzz.invalid-tld-zzz", "A", "NXDOMAIN for a bogus TLD"),
    ("example.com", "SOA", "SOA at the apex"),
    ("example.com", "NS", "NS at the apex"),
    ("_dmarc.cloudflare.com", "TXT", "underscore label"),
    ("example.com", "CAA", "NODATA where the name exists"),
]


def dig(server: str, name: str, qtype: str, extra: list[str] | None = None) -> dict:
    """Query one resolver, retrying once if no answer arrives.

    This network intermittently drops egress, and a single lost packet would otherwise be
    reported as a semantic disagreement between the two resolvers — which is exactly the
    kind of false finding this harness exists to avoid. One retry, then the no-answer is
    reported honestly as `NO_ANSWER`.
    """
    for attempt in range(2):
        result = _dig_once(server, name, qtype, extra)
        if result["rcode"] not in ("NO_ANSWER", "TIMEOUT"):
            return result
        if attempt == 0:
            time.sleep(0.5)
    return result


def _dig_once(server: str, name: str, qtype: str, extra: list[str] | None = None) -> dict:
    """Query one resolver and return a normalised view of the answer."""
    host, _, port = server.partition(":")
    cmd = [
        "dig",
        f"@{host}",
        "-p",
        port or "53",
        name,
        qtype,
        "+dnssec",
        "+timeout=6",
        "+tries=1",
        "+noidnout",
    ]
    if extra:
        cmd.extend(extra)
    try:
        # check=False: a non-zero dig exit is a normal outcome here (SERVFAIL, no
        # answer), and it is the parsed output that decides, not the exit status.
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=25, check=False
        ).stdout
    except subprocess.TimeoutExpired:
        return {"rcode": "TIMEOUT", "answers": set(), "ad": False, "min_ttl": None}

    rcode = "NO_ANSWER"
    ad = False
    answers: set[tuple[str, str, str]] = set()
    ttls: list[int] = []
    in_answer = False
    for line in out.splitlines():
        if line.startswith(";; ->>HEADER<<-") and "status:" in line:
            rcode = line.split("status:")[1].split(",")[0].strip()
            continue
        if line.startswith(";; flags:"):
            ad = " ad" in line.split(";; flags:")[1].split(";")[0]
            continue
        if line.startswith(";; ANSWER SECTION:"):
            in_answer = True
            continue
        if in_answer:
            if not line.strip() or line.startswith(";"):
                in_answer = False
                continue
            parts = line.split(maxsplit=4)
            if len(parts) < 5:
                continue
            owner, ttl, _cls, rtype, rdata = parts
            # RRSIG rdata embeds an expiry and a signer-specific signature; comparing it
            # byte for byte would report key rollovers as defects.
            if rtype == "RRSIG":
                answers.add((owner.lower(), rtype, rdata.split()[0]))
            else:
                answers.add((owner.lower(), rtype, rdata.strip().lower()))
            try:
                ttls.append(int(ttl))
            except ValueError:
                pass
    return {
        "rcode": rcode,
        "answers": answers,
        "ad": ad,
        "min_ttl": min(ttls) if ttls else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--egressdns", required=True, help="host:port")
    ap.add_argument("--unbound", required=True, help="host:port")
    args = ap.parse_args()

    if not shutil.which("dig"):
        print("dig is required", file=sys.stderr)
        return 2

    agree = 0
    differ: list[str] = []
    skipped = 0

    print(f"{'case':44} {'egressdns':16} {'unbound':16} verdict")
    print("-" * 92)
    for name, qtype, why in CASES:
        ours = dig(args.egressdns, name, qtype)
        theirs = dig(args.unbound, name, qtype)
        label = f"{name} {qtype}"

        # A case neither resolver could answer says nothing about either of them; this
        # network intermittently filters egress, and reporting that as agreement would be
        # as dishonest as reporting it as a difference.
        unanswered = ("TIMEOUT", "NO_ANSWER")
        if ours["rcode"] in unanswered and theirs["rcode"] in unanswered:
            print(f"{label:44} {ours['rcode']:16} {theirs['rcode']:16} SKIP (neither answered)")
            skipped += 1
            continue

        problems = []
        if ours["rcode"] != theirs["rcode"]:
            problems.append(f"rcode {ours['rcode']} vs {theirs['rcode']}")
        if ours["answers"] != theirs["answers"]:
            only_ours = ours["answers"] - theirs["answers"]
            only_theirs = theirs["answers"] - ours["answers"]
            problems.append(f"rrset differs (+{len(only_ours)} -{len(only_theirs)})")
        if ours["ad"] != theirs["ad"]:
            problems.append(f"AD {ours['ad']} vs {theirs['ad']}")
        if (
            ours["min_ttl"] is not None
            and theirs["min_ttl"] is not None
            and ours["min_ttl"] > theirs["min_ttl"]
        ):
            problems.append(f"TTL {ours['min_ttl']} > {theirs['min_ttl']} (policy may only reduce)")

        ours_s = f"{ours['rcode']}{'/ad' if ours['ad'] else ''}"
        theirs_s = f"{theirs['rcode']}{'/ad' if theirs['ad'] else ''}"
        if problems:
            print(f"{label:44} {ours_s:16} {theirs_s:16} DIFFER: {'; '.join(problems)}")
            differ.append(f"{label} ({why}): {'; '.join(problems)}")
        else:
            print(f"{label:44} {ours_s:16} {theirs_s:16} agree")
            agree += 1

    print("-" * 92)
    print(f"{agree} agree, {len(differ)} differ, {skipped} skipped")
    for d in differ:
        print(f"  ! {d}")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
