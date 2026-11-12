#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Keep only the named fuzz targets in a cargo-fuzz manifest.

cargo-fuzz builds either one fuzz target or every target in the crate. To build
a chosen set in one cargo invocation, this script rewrites the manifest in place
so that its only `[[bin]]` tables are the named targets. Every other line stays
as it was, so naming every target leaves the file unchanged.

Usage:
  keep_fuzz_targets.py MANIFEST TARGET...

Every named target must have a `[[bin]]` table, so a stale or misspelled name
fails instead of quietly building nothing.
"""

import re
import sys

HEADER = re.compile(r"^\s*\[")
NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"')


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: keep_fuzz_targets.py MANIFEST TARGET...")
    path, keep = sys.argv[1], set(sys.argv[2:])
    with open(path) as f:
        lines = f.readlines()

    # Split the manifest into blocks that each start at a table header.
    blocks, current = [], []
    for line in lines:
        if HEADER.match(line) and current:
            blocks.append(current)
            current = []
        current.append(line)
    if current:
        blocks.append(current)

    kept, found = [], set()
    for block in blocks:
        if block[0].strip() == "[[bin]]":
            names = [m.group(1) for m in map(NAME.match, block) if m]
            if len(names) != 1:
                sys.exit(f"keep_fuzz_targets.py: [[bin]] without exactly one name in {path}")
            if names[0] not in keep:
                continue
            found.add(names[0])
        kept.extend(block)

    missing = keep - found
    if missing:
        sys.exit(f"keep_fuzz_targets.py: no [[bin]] for {', '.join(sorted(missing))} in {path}")
    with open(path, "w") as f:
        f.writelines(kept)


if __name__ == "__main__":
    main()
