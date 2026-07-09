#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Partition stdin lines deterministically, with no partition exceeding its
fair share.

Reads lines from stdin and prints only those assigned to the requested
partition. Assignment uses rendezvous hashing with bounded loads: every entry
ranks the partitions by `sha256(entry || partition)` and takes the
highest-ranked partition that still has capacity `ceil(n / M)`. The capacity
bound caps the largest partition (and thus the job tail) at `ceil(n / M)`
entries while preserving most of the stability of plain hashing: adding or
removing an entry moves that entry plus at most a short chain of capacity
overflows, rather than reshuffling the whole set. Only the maximum is
bounded, so a partition can fall more than one entry below the others.

Usage:
  - <command> | hash_partition.py N/M

where N is the 1-indexed partition (1..M) and M is the total partition count.
M=1 is a pass-through. Blank input lines are skipped and duplicates are
assigned once.

Entries are processed in an order derived from their own hashes, so the
outcome is independent of input order. Assignment does depend on the full
input set, however. Parallel invocations selecting different partitions of
the same set must be fed identical input, or an entry can be assigned to
multiple partitions or to none.
"""

import hashlib
import math
import sys


def digest(data: str) -> int:
    return int(hashlib.sha256(data.encode()).hexdigest(), 16)


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

    lines = []
    seen = set()
    for raw in sys.stdin:
        line = raw.rstrip("\n")
        if not line or line in seen:
            continue
        seen.add(line)
        lines.append(line)

    if total == 1:
        for line in lines:
            print(line)
        return

    capacity = math.ceil(len(lines) / total)
    loads = [0] * total
    assignment = {}
    for line in sorted(lines, key=digest):
        prefs = sorted(
            range(total), key=lambda p: digest(f"{line}\x00{p}"), reverse=True
        )
        for p in prefs:
            if loads[p] < capacity:
                loads[p] += 1
                assignment[line] = p
                break

    for line in lines:
        if assignment[line] == part - 1:
            print(line)


if __name__ == "__main__":
    main()
