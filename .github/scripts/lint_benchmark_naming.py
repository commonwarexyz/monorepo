#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Lint benchmark names for naming convention violations.

Background
----------
Benchmark names are parsed by docs/benchmarks.html for display. The parsing
expects the format: `module::function/params`

    const parts = bench.name.split("::");
    const moduleName = parts[0];
    const functionPart = parts.slice(1).join("::");
    let [funcName, params] = functionPart.split("/", 2);

The `params` string becomes the chart title and is displayed as-is without
further parsing. These rules ensure consistent, readable chart titles.

Rules
-----
1. Use `key=value` format in benchmark params (e.g., `group=g1`, not just `g1`)
   - Chart titles should be self-documenting
   - `n=5 t=4` is clearer than `5 4` when viewed in isolation

2. Separate parameters with spaces, not commas
   - Params are displayed as-is; commas add visual noise
   - `n=5 t=4` reads better than `n=5, t=4`

3. Use `/` instead of `:` as value separators for ratios
   - Colons could be confused with the `::` module separator
   - `value=1/2` is unambiguous; `value=1:2` could look like `value=1::2`

How it works
------------
This script runs `cargo bench --workspace -- --list` to extract actual
registered benchmark names from the compiled binaries, then validates them.
This is more reliable than parsing source code.

Usage
-----
  ./lint_benchmark_naming.py           # lint from repo root
  ./lint_benchmark_naming.py /path/to/repo
"""

import re
import subprocess
import sys
from pathlib import Path


def get_benchmark_names(root: Path) -> list[str]:
    """Run cargo bench --list to get all benchmark names."""
    result = subprocess.run(
        ["cargo", "bench", "--workspace", "--", "--list"],
        cwd=root,
        capture_output=True,
        text=True,
    )

    # Parse output - benchmark names end with ": benchmark"
    names = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.endswith(": benchmark"):
            name = line[:-12]  # Remove ": benchmark" suffix
            names.append(name)

    return names


def validate_benchmark_name(name: str) -> list[str]:
    """Validate a single benchmark name and return any violations."""
    violations = []

    # Parse the name: module::function/params
    if "::" not in name:
        violations.append(f"`{name}`: Missing module separator `::`")
        return violations

    parts = name.split("::")
    module = parts[0]
    rest = "::".join(parts[1:])

    if "/" in rest:
        func, params = rest.split("/", 1)
    else:
        # No params is fine
        return violations

    # Check for comma-separated parameters
    if re.search(r"=\w+,\s*\w+=", params):
        violations.append(
            f"`{name}`: Parameters should be space-separated, not comma-separated"
        )

    # Check for colon in value position (like value=1:2)
    if re.search(r"=\d+:\d+", params):
        violations.append(
            f"`{name}`: Use `/` instead of `:` as value separator (e.g., `1/2` not `1:2`)"
        )

    # Check for bare values (word without = followed by word with =)
    # Pattern: "word word=" where first word has no =
    param_parts = params.split()
    for i, part in enumerate(param_parts):
        if i + 1 < len(param_parts):
            next_part = param_parts[i + 1]
            if (
                "=" not in part
                and "=" in next_part
                and re.match(r"^[\w-]+$", part)
            ):
                violations.append(
                    f"`{name}`: Bare value `{part}` should use key=value format "
                    f"(e.g., `type={part}`)"
                )

    return violations


def main() -> int:
    if len(sys.argv) > 1:
        root = Path(sys.argv[1])
    else:
        root = Path.cwd()
        while root != root.parent:
            if (root / "Cargo.toml").exists() and (root / ".github").exists():
                break
            root = root.parent

    print("Compiling benchmarks and extracting names...", file=sys.stderr)
    benchmark_names = get_benchmark_names(root)

    if not benchmark_names:
        print("ERROR: No benchmark names found. Is this the right directory?")
        return 1

    all_violations = []
    for name in benchmark_names:
        all_violations.extend(validate_benchmark_name(name))

    if all_violations:
        print(f"Benchmark naming violations found ({len(all_violations)} total):\n")
        print("\n".join(all_violations))
        print("\n\nRules:")
        print("1. Use `key=value` format in benchmark params (e.g., `group=g1`)")
        print("2. Separate parameters with spaces, not commas")
        print("3. Use `/` instead of `:` as value separators for ratios")
        return 1

    print(f"Checked {len(benchmark_names)} benchmarks, all naming conventions followed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
