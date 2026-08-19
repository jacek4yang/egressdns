#!/usr/bin/env python3
"""Fail if docs/CONFIGURATION.md and the configuration parser have drifted apart.

Two failure modes matter, and both are silent without a check like this:

* **A field exists and is undocumented.** An operator cannot use a setting they cannot
  find, and an undocumented field is usually one that was added without anyone deciding
  what it should mean.
* **A field is documented and does not exist.** Because every table is
  `deny_unknown_fields`, following the documentation then produces a hard parse error at
  startup — the documentation actively breaks the deployment it was meant to enable.

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

# Keys that appear in a reference table but are not `pub` fields of a config struct,
# because they are documented at a level of detail the struct does not express.
KNOWN_NON_FIELDS: set[str] = set()


def documented_keys(text: str) -> set[str]:
    """Every key named in the section-reference tables."""
    try:
        start = text.index("## Section reference")
        end = text.index("## Validation rules")
    except ValueError:
        sys.exit("docs/CONFIGURATION.md is missing its section reference or validation rules")
    body = text[start:end]
    # A reference row starts with a single back-ticked key in the first column.
    keys = set(re.findall(r"^\| `([a-z0-9_]+)` \|", body, re.MULTILINE))
    # Top-level sections are documented as `### \`[section]\`` headings rather than as
    # rows, so collect the leading path component of every heading too.
    for heading in re.findall(r"^### `\[([^\]]+)\]`", body, re.MULTILINE):
        keys.add(heading.lstrip("[").split(".")[0].split("]")[0])
    return keys


def declared_fields(src: str) -> set[str]:
    """Every `pub` field of every struct in src/config/mod.rs.

    Over-approximating is safe here: a helper struct's field appearing in the "declared"
    set can only cause a *missing documentation* complaint, never a false pass.
    """
    fields: set[str] = set()
    for match in re.finditer(r"\npub struct (\w+)\s*\{(.*?)\n\}", src, re.DOTALL):
        for field in re.findall(r"\n    pub (\w+):", match.group(2)):
            fields.add(field)
    return fields


def main() -> int:
    docs = (ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    src = (ROOT / "src" / "config" / "mod.rs").read_text(encoding="utf-8")

    documented = documented_keys(docs)
    declared = declared_fields(src)

    undocumented = sorted(declared - documented)
    stale = sorted(documented - declared - KNOWN_NON_FIELDS)

    status = 0
    if undocumented:
        status = 1
        print("These configuration fields exist but are not documented:", file=sys.stderr)
        for name in undocumented:
            print(f"  {name}", file=sys.stderr)
    if stale:
        status = 1
        print(
            "\nThese keys are documented but are not fields of any config struct.",
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
        print(
            f"configuration documentation is in sync: "
            f"{len(declared)} fields, all documented"
        )
    return status


if __name__ == "__main__":
    sys.exit(main())
