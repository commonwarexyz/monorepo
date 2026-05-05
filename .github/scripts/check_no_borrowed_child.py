#!/usr/bin/env python3
"""
Reject borrowed temporary child contexts like `&context.child("worker")`.

Child contexts should either be bound to a local before borrowing or avoided
entirely when the callee only needs the parent capability.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


BORROWED_CHILD = re.compile(
    r"&\s*\(?\s*[A-Za-z_][A-Za-z0-9_]*\s*\.\s*child\s*\("
)
SKIP_DIRS = {".git", "target"}


def iter_rust_files(root: Path):
    for path in root.rglob("*.rs"):
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        yield path


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]
    failures = []

    for path in iter_rust_files(root):
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            code = line.split("//", 1)[0]
            match = BORROWED_CHILD.search(code)
            if match is None:
                continue
            failures.append((path.relative_to(root), line_no, match.start() + 1, line.strip()))

    if not failures:
        return 0

    print("borrowed temporary child contexts are not allowed")
    print("bind the child first when the scoped child is intentional, or pass the parent context")
    for path, line_no, column, line in failures:
        print(f"{path}:{line_no}:{column}: {line}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
