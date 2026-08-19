#!/usr/bin/env python3
"""Fail if docs/CONFIGURATION.md and the configuration parser have drifted apart.

Two failure modes matter, and both are silent without a check like this:

* **A field exists and is undocumented.** An operator cannot use a setting they cannot
  find, and an undocumented field is usually one that was added without anyone deciding
  what it should mean.
* **A field is documented and does not exist.** Because every table is
  `deny_unknown_fields`, following the documentation then produces a hard parse error at
  startup — the documentation actively breaks the deployment it was meant to enable.

The comparison is done on **full dotted paths**, not bare key names. Bare names are not
identifiers here: `queue_size` alone matches `probe.queue_size` and
`storage.queue_size`, and a set of bare names cannot tell them apart — deleting one
documented row would be masked by the other. So the Rust side is parsed per `pub struct`
and walked from the root `Config` struct (`server.udp.max_payload`,
`upstream.groups.scheduler.hedge_max_fraction`), and each documentation row is attributed
to the nearest preceding `### \\`[section.path]\\`` heading. Array tables (`[[...]]`)
contribute the same dotted path as their element (`[[upstream.groups]]` documents
`upstream.groups.*`).

This is deliberately a textual check rather than a generated document: the prose in the
reference is written by hand and is worth keeping that way, but the *set of keys* is not
something a human should be responsible for keeping in sync.

    ./scripts/check-config-docs.py
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Paths that appear in a reference table but are not fields of a config struct, because
# they are documented at a level of detail the structs do not express.
KNOWN_NON_FIELDS: set[str] = set()

# A `pub struct Name { ... }` block. Field lists are indented four spaces and the closing
# brace sits at column zero, so the non-greedy body match cannot escape the struct.
STRUCT_RE = re.compile(r"\npub struct (\w+)\s*\{(.*?)\n\}", re.DOTALL)
# One field line: `pub name: Type,`. Types in src/config/mod.rs never contain a comma,
# so capturing up to the trailing comma is exact.
FIELD_RE = re.compile(r"\n    pub (\w+):\s*(.+),")
# `### \`[server.udp]\`` or `### \`[[upstream.groups]]\`` — brackets are stripped, so an
# array-of-tables heading denotes the element path.
HEADING_RE = re.compile(r"^### `\[{1,2}([^\]]+?)\]{1,2}`")
# A reference row starts with a single back-ticked key in the first column.
ROW_RE = re.compile(r"^\| `([a-z0-9_]+)` \|")


def inner_type(type_text: str) -> str:
    """Unwrap `Vec<T>`, `Option<T>` and `[T; N]` down to the element type."""
    text = type_text.strip()
    while True:
        generic = re.fullmatch(r"(?:Vec|Option)<(.+)>", text)
        if generic:
            text = generic.group(1).strip()
            continue
        array = re.fullmatch(r"\[(.+);\s*\d+\]", text)
        if array:
            text = array.group(1).strip()
            continue
        return text


def config_paths(src: str) -> set[str]:
    """Every dotted field path reachable from the root `Config` struct.

    A field whose (unwrapped) type is another struct in the file is an intermediate node
    and is recursed into; anything else — scalars, enums, strings, addresses — is a leaf.
    Both nodes and leaves are emitted, because the reference documents tables as well as
    their keys.
    """
    structs: dict[str, list[tuple[str, str]]] = {}
    for match in STRUCT_RE.finditer(src):
        structs[match.group(1)] = [
            (name, inner_type(type_text))
            for name, type_text in FIELD_RE.findall(match.group(2))
        ]
    if "Config" not in structs:
        sys.exit("src/config/mod.rs: could not find the root `pub struct Config` block")

    paths: set[str] = set()

    def walk(struct_name: str, prefix: str, stack: tuple[str, ...]) -> None:
        if struct_name in stack:
            sys.exit(
                "src/config/mod.rs: recursive struct cycle "
                + " -> ".join((*stack, struct_name))
            )
        for field, type_name in structs[struct_name]:
            path = prefix + field
            paths.add(path)
            if type_name in structs:
                walk(type_name, path + ".", (*stack, struct_name))

    walk("Config", "", ())
    return paths


def documented_paths(text: str) -> set[str]:
    """Every dotted path named in the section-reference tables.

    A row is attributed to the nearest preceding section heading, so the key `queue_size`
    under `### \\`[probe]\\`` is the path `probe.queue_size` and is not interchangeable
    with `storage.queue_size`. Headings also document their own path (a table's existence
    is part of the reference), which is how top-level sections such as `server` are
    covered.
    """
    try:
        start = text.index("## Section reference")
        end = text.index("## Validation rules")
    except ValueError:
        sys.exit("docs/CONFIGURATION.md is missing its section reference or validation rules")
    paths: set[str] = set()
    section: str | None = None
    for line in text[start:end].splitlines():
        heading = HEADING_RE.match(line)
        if heading:
            section = heading.group(1)
            paths.add(section)
            continue
        row = ROW_RE.match(line)
        if row is not None and section is not None:
            paths.add(f"{section}.{row.group(1)}")
    return paths


def leaf_paths(paths: set[str]) -> set[str]:
    """Paths that no other path extends; everything else is a table."""
    return {p for p in paths if not any(o.startswith(p + ".") for o in paths)}


def main() -> int:
    docs = (ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    src = (ROOT / "src" / "config" / "mod.rs").read_text(encoding="utf-8")

    documented = documented_paths(docs)
    declared = config_paths(src)

    undocumented = sorted(declared - documented)
    stale = sorted(documented - declared - KNOWN_NON_FIELDS)

    status = 0
    if undocumented:
        status = 1
        print("These configuration paths exist but are not documented:", file=sys.stderr)
        for name in undocumented:
            print(f"  {name}", file=sys.stderr)
    if stale:
        status = 1
        print(
            "\nThese documented paths are not fields of any config struct.",
            file=sys.stderr,
        )
        print(
            "Because every table is deny_unknown_fields, following this documentation",
            file=sys.stderr,
        )
        print("would produce a hard parse error at startup:", file=sys.stderr)
        for name in stale:
            print(f"  {name}", file=sys.stderr)

    if status == 0:
        fields = len(leaf_paths(declared))
        tables = len(declared) - fields
        print(
            f"configuration documentation is in sync: "
            f"{fields} fields across {tables} tables, all documented"
        )
    return status


if __name__ == "__main__":
    sys.exit(main())
