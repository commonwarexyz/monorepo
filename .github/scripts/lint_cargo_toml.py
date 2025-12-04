#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = ["tomlkit==0.13.3"]
# ///
"""
Usage:
  ./sort_deps.py                # edits ./Cargo.toml in place
  ./sort_deps.py path/to/Cargo.toml
"""

import re
import sys
from pathlib import Path

from tomlkit import parse, dumps, key, item
from tomlkit.items import Table, InlineTable

def reorder_table_inplace(tbl: Table):
    """Sort keys in alphabetical order while preserving comments/formatting."""
    items = [(k, tbl[k]) for k in list(tbl.keys())]
    for k, _ in items:
        del tbl[k]

    for k, v in sorted(items, key=lambda kv: kv[0]):
        if len(v) == 1 and isinstance(v, dict) and next(iter(v)) == 'workspace':
            tbl.append(key([k, "workspace"]), item(True))
        else:
            tbl.append(k, v)

def walk(node):
    if hasattr(node, "items"):
        for k, v in list(node.items()):
            if k.endswith("dependencies"):
                reorder_table_inplace(v)
            walk(v)

def normalize_blank_lines(s: str) -> str:
    # Collapse accidental double+ newlines before table headers to exactly two
    # https://github.com/python-poetry/tomlkit/issues/48
    s = re.sub(r"\n{2,}(\[)", r"\n\n\1", s)
    return s

def main(path: Path):
    text = path.read_text(encoding="utf-8")
    doc = parse(text)
    walk(doc)
    out = dumps(doc)
    out = normalize_blank_lines(out)
    path.write_text(out, encoding="utf-8")

if __name__ == "__main__":
    cargo_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("Cargo.toml")
    main(cargo_path)
