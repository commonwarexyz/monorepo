#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = ["tomlkit==0.13.3"]
# ///
"""
Usage:
  ./lint_cargo_toml.py                         # edits ./Cargo.toml in place
  ./lint_cargo_toml.py path/to/Cargo.toml
  ./lint_cargo_toml.py --check path/to/Cargo.toml
"""

import argparse
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

def format_toml(text: str) -> str:
    doc = parse(text)
    walk(doc)
    out = dumps(doc)
    return normalize_blank_lines(out)

def main(path: Path, check: bool) -> int:
    text = path.read_text(encoding="utf-8")
    out = format_toml(text)
    if check:
        if text != out:
            print(f"Cargo.toml formatting needed: {path}")
            return 1
        return 0

    path.write_text(out, encoding="utf-8")
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cargo_path", nargs="?", default="Cargo.toml")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check formatting only; do not modify files.",
    )
    args = parser.parse_args()
    sys.exit(main(Path(args.cargo_path), args.check))
