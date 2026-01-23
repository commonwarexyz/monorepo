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
1. Include module separator `::` (use `module_path!()` macro)
   - Required for the benchmarks site to parse and group benchmarks correctly
   - Example: `crate_name::bench_foo/n=10` not `bench_foo/n=10`

2. Use `key=value` format in benchmark params (e.g., `group=g1`, not just `g1`)
   - Chart titles should be self-documenting
   - `n=5 t=4` is clearer than `5 4` when viewed in isolation

3. Separate parameters with spaces, not commas
   - Params are displayed as-is; commas add visual noise
   - `n=5 t=4` reads better than `n=5, t=4`

4. Use only one `/` separator (between function name and params)
   - The params string is extracted via `split("/", 2)` so only the first `/` matters
   - Multiple `/` in params may indicate unclear parameter formatting

How it works
------------
This script runs `cargo bench --workspace -- --list` to extract actual
registered benchmark names from the compiled binaries, then validates them.

Usage
-----
  ./lint_benchmark_names.py           # lint from repo root
  ./lint_benchmark_names.py /path/to/repo
"""

import re
import subprocess
import sys
from pathlib import Path


def get_benchmark_names(root: Path) -> list[str]:
    """
    Run cargo bench --list to get all benchmark names.

    Returns list of benchmark names.
    """
    # Exclude fuzz crates which aren't criterion benchmarks
    result = subprocess.run(
        [
            "cargo", "bench", "--workspace",
            "--exclude", "commonware-runtime-fuzz",
            "--exclude", "commonware-consensus-fuzz",
            "--", "--list"
        ],
        cwd=root,
        capture_output=True,
        text=True,
    )

    # Parse benchmark names from stdout
    benchmarks = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.endswith(": benchmark"):
            name = line[:-11]  # Remove ": benchmark" suffix
            benchmarks.append(name)

    return benchmarks


def validate_benchmark_name(name: str) -> list[str]:
    """Validate a single benchmark name and return any violations."""
    violations = []

    # Parse the name: module::function/params
    if "::" not in name:
        violations.append(f"`{name}`: Missing module separator `::`")
        return violations

    parts = name.split("::")
    rest = "::".join(parts[1:])

    if "/" not in rest:
        # No params is fine
        return violations

    # Check for multiple / separators (should only have one)
    if rest.count("/") > 1:
        violations.append(
            f"`{name}`: Multiple `/` separators found; use `key=value` pairs instead"
        )

    _, params = rest.split("/", 1)

    # Check for comma-separated parameters
    if re.search(r"=\w+,\s*\w+=", params):
        violations.append(
            f"`{name}`: Parameters should be space-separated, not comma-separated"
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
    benchmarks = get_benchmark_names(root)

    if not benchmarks:
        print("ERROR: No benchmark names found. Is this the right directory?")
        return 1

    all_violations = []
    for name in benchmarks:
        all_violations.extend(validate_benchmark_name(name))

    if all_violations:
        print(f"Benchmark naming violations found ({len(all_violations)} total):\n")
        print("\n".join(all_violations))
        print("\n\nRules:")
        print("1. Include module separator `::` (use `module_path!()` macro)")
        print("2. Use `key=value` format in benchmark params (e.g., `group=g1`)")
        print("3. Separate parameters with spaces, not commas")
        print("4. Use only one `/` separator (between function name and params)")
        return 1

    print(f"Checked {len(benchmarks)} benchmarks, all naming conventions followed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
