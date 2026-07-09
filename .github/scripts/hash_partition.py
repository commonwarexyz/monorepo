#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Hash-partition stdin lines deterministically.

Reads lines from stdin and prints only those whose SHA-256 hash falls into the
requested partition.

Usage:
  - <command> | hash_partition.py N/M

where N is the 1-indexed partition (1..M) and M is the total partition count.
M=1 is a pass-through. Blank input lines are skipped.

The hash bucket is `sha256(line) mod M`, which gives a stable assignment that
doesn't shift when unrelated entries are added or removed.
"""

import hashlib
import sys


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} N/M")

    spec = sys.argv[1]
    try:
        part_s, total_s = spec.split("/")
        part, total = int(part_s), int(total_s)
    except ValueError:
        sys.exit(f"invalid partition spec {spec!r}: expected N/M")
    if total < 1 or not (1 <= part <= total):
        sys.exit(f"partition out of range: {part}/{total}")

    for raw in sys.stdin:
        line = raw.rstrip("\n")
        if not line:
            continue
        if total == 1:
            print(line)
            continue
        bucket = int(hashlib.sha256(line.encode()).hexdigest(), 16) % total
        if bucket == part - 1:
            print(line)


if __name__ == "__main__":
    main()
