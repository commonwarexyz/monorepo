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
This script parses benchmark names from benchmark command output and validates
them. Supported input formats:
1. Bencher output from `cargo bench ... -- --output-format bencher`:
   `test module::function/k=v ... bench: ...`
2. List output from `cargo bench ... -- --list`:
   `module::function/k=v: benchmark`

Usage
-----
  ./lint_benchmark_names.py benchmark-output.txt
  ./lint_benchmark_names.py output1.txt output2.txt
  cargo bench -- --output-format bencher | ./lint_benchmark_names.py -
"""

import re
import sys

BENCHER_RE = re.compile(r"^test (.+?) \.\.\. bench:")
LIST_RE = re.compile(r"^(.+): benchmark$")


def parse_benchmark_names(text: str) -> list[str]:
    """Extract benchmark names from command output."""
    names = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = BENCHER_RE.match(line)
        if match:
            names.append(match.group(1))
            continue
        match = LIST_RE.match(line)
        if match:
            names.append(match.group(1))
    return names


def read_inputs(paths: list[str]) -> list[str]:
    """Read benchmark names from files or stdin ('-')."""
    all_names = []
    for path in paths:
        if path == "-":
            text = sys.stdin.read()
        else:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        all_names.extend(parse_benchmark_names(text))
    # Preserve order while de-duplicating.
    return list(dict.fromkeys(all_names))


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
    if len(sys.argv) <= 1:
        print(
            "Usage: lint_benchmark_names.py <benchmark-output> [<benchmark-output> ...]\n"
            "Pass '-' to read from stdin.",
            file=sys.stderr,
        )
        return 1

    benchmarks = read_inputs(sys.argv[1:])

    if not benchmarks:
        print("ERROR: No benchmark names found in provided input.", file=sys.stderr)
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
