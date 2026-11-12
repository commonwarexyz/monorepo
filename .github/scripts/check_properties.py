#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Validate that every test cited in the Multimmit properties document exists.

consensus/src/multimmit/docs/PROPERTIES.md cites evidence as Rust paths in code
spans: `multimmit::...` paths are relative to commonware-consensus, and
`commonware_consensus_fuzz::...` paths name the fuzz crate. Each path is resolved
statically, without compiling: its module segments select a source file (a
`name.rs` or `name/mod.rs` module file, with any remaining segments naming inline
`mod` blocks in that file), and the file must define `fn <name>`.

Usage
-----
  ./check_properties.py
  ./check_properties.py /path/to/repo
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


PROPERTIES = Path("consensus/src/multimmit/docs/PROPERTIES.md")
CRATES = {
    "multimmit": (Path("consensus/src/multimmit"), "mod.rs"),
    "commonware_consensus_fuzz": (Path("consensus/fuzz/src"), "lib.rs"),
}
CITATION = re.compile(r"`((?:%s)(?:::\w+)+)`" % "|".join(CRATES))


def find_repo_root(start: Path) -> Path:
    root = start.resolve()
    while root != root.parent:
        if (root / "Cargo.toml").exists() and (root / ".github").exists():
            return root
        root = root.parent
    raise SystemExit("ERROR: could not find repository root")


def resolve(root: Path, citation: str) -> str | None:
    """Returns why `citation` does not name a function, or None when it does."""
    crate, *modules, name = citation.split("::")
    directory, entry = CRATES[crate]
    directory = root / directory
    source = directory / entry
    inline = []
    for module in modules:
        if not inline and (directory / module / "mod.rs").exists():
            source, directory = directory / module / "mod.rs", directory / module
        elif not inline and (directory / f"{module}.rs").exists():
            source, directory = directory / f"{module}.rs", directory / module
        else:
            inline.append(module)
    text = source.read_text()
    for module in inline:
        if not re.search(rf"\bmod {module}\b", text):
            return f"no module `{module}` in {source.relative_to(root)}"
    if not re.search(rf"\bfn {name}\b", text):
        return f"no `fn {name}` in {source.relative_to(root)}"
    return None


def main() -> int:
    root = find_repo_root(Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd())
    citations = sorted(set(CITATION.findall((root / PROPERTIES).read_text())))
    failures = [
        (citation, reason)
        for citation in citations
        if (reason := resolve(root, citation)) is not None
    ]
    for citation, reason in failures:
        print(f"ERROR: {PROPERTIES}: `{citation}`: {reason}")
    if failures:
        return 1
    print(f"OK: {len(citations)} cited tests exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
