#!/usr/bin/env python3
"""
Check that code files contain only ASCII characters.

Usage
-----
  python3 .github/scripts/check_ascii.py
  python3 .github/scripts/check_ascii.py path/to/file.rs path/to/crate
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


SKIP_DIRS = {".git", "target"}
SOURCE_SUFFIXES = {
    ".js",
    ".jsx",
    ".py",
    ".qnt",
    ".rs",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}


def iter_source_files(paths: list[Path]) -> list[Path]:
    files = []
    for path in paths:
        if path.is_file():
            if path.suffix in SOURCE_SUFFIXES:
                files.append(path)
            continue

        for root, dirs, names in os.walk(path):
            dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
            files.extend(
                Path(root) / name
                for name in names
                if Path(name).suffix in SOURCE_SUFFIXES
            )

    return sorted(files)


def check_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as err:
        return [f"{path}: invalid UTF-8 ({err})"]

    violations = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for col_no, char in enumerate(line, start=1):
            if ord(char) > 0x7F:
                violations.append(
                    f"{path}:{line_no}:{col_no}: non-ASCII character "
                    f"U+{ord(char):04X} ({ascii(char)})"
                )

    return violations


def main() -> int:
    paths = [Path(arg) for arg in sys.argv[1:]] or [Path.cwd()]
    files = iter_source_files(paths)

    violations = []
    for path in files:
        violations.extend(check_file(path))

    if violations:
        print(f"Found non-ASCII characters in code files ({len(violations)} total):")
        print("\n".join(violations))
        return 1

    print(f"Checked {len(files)} code files, all ASCII-only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
