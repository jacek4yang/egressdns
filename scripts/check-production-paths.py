#!/usr/bin/env python3
"""Fail if a fallible-panic construct appears outside a `#[cfg(test)]` module.

`unwrap`, `expect`, `todo!` and `unimplemented!` all abort the process on an unexpected
input. In a DNS resolver that means an attacker-shaped packet, a malformed upstream
response or an unusual configuration can take the whole service down — so they are barred
from production paths entirely. `unsafe` is barred by `#![forbid(unsafe_code)]`; this
script catches it anyway, since a `#[allow]` could in principle be added.

Tests and benches may use all of them freely: a panicking test is a failing test, which is
exactly what should happen.

    ./scripts/check-production-paths.py
"""
import pathlib
import re
import sys


def in_test_region(lines):
    """Return a boolean per line: True if inside a #[cfg(test)] mod block."""
    out = [False]*len(lines)
    i = 0
    while i < len(lines):
        if re.match(r'\s*#\[cfg\(test\)\]', lines[i]):
            # find the opening brace of the following mod/fn
            j = i
            while j < len(lines) and '{' not in lines[j]:
                j += 1
            depth = 0
            started = False
            k = j
            while k < len(lines):
                depth += lines[k].count('{') - lines[k].count('}')
                out[k] = True
                if lines[k].count('{'):
                    started = True
                if started and depth <= 0:
                    break
                k += 1
            i = k + 1
            continue
        i += 1
    return out

pat = re.compile(r'\.unwrap\(\)|\.expect\(|\btodo!|\bunimplemented!|\bunsafe\b')
findings = []
for p in sorted(pathlib.Path('src').rglob('*.rs')):
    lines = p.read_text().splitlines()
    mask = in_test_region(lines)
    for n, line in enumerate(lines):
        if mask[n]:
            continue
        if line.lstrip().startswith('//') or line.lstrip().startswith('///'):
            continue
        if pat.search(line):
            findings.append((str(p), n+1, line.strip()))

for f in findings:
    print(f"{f[0]}:{f[1]}: {f[2][:110]}", file=sys.stderr)
if findings:
    print(
        f"\n{len(findings)} fallible-panic construct(s) on a production path. "
        "Return a Result, or move the code into a #[cfg(test)] module.",
        file=sys.stderr,
    )
    sys.exit(1)
print("no unwrap/expect/todo!/unimplemented!/unsafe outside test modules")
