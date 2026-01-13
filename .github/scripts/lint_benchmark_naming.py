#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Lint benchmark files for naming convention violations.

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
1. Use `bench_` prefix for benchmark functions (not `benchmark_`)
   - Shorter and consistent with Rust's `#[bench]` attribute convention
   - The majority of existing benchmarks already use this prefix

2. Use `key=value` format in benchmark names (e.g., `group=g1`, not just `g1`)
   - Chart titles should be self-documenting
   - `n=5 t=4` is clearer than `5 4` when viewed in isolation

3. Separate parameters with spaces, not commas
   - Params are displayed as-is; commas add visual noise
   - `n=5 t=4` reads better than `n=5, t=4`

4. Use `/` instead of `:` as value separators for ratios
   - Colons could be confused with the `::` module separator
   - `value=1/2` is unambiguous; `value=1:2` could look like `value=1::2`

Usage
-----
  ./lint_benchmark_naming.py           # lint from repo root
  ./lint_benchmark_naming.py /path/to/repo
"""

import re
import sys
from pathlib import Path


def find_benchmark_files(root: Path) -> list[Path]:
    """Find all benchmark files in the repository."""
    results = []
    for benches_dir in root.rglob("benches"):
        if benches_dir.is_dir():
            # Skip target directory
            if "target" in benches_dir.parts:
                continue
            for rs_file in benches_dir.glob("*.rs"):
                results.append(rs_file)
    return sorted(results)


def check_function_names(path: Path, content: str) -> list[str]:
    """Check for `fn benchmark_` patterns that should be `fn bench_`."""
    violations = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        trimmed = line.strip()
        if trimmed.startswith("fn benchmark_") or trimmed.startswith(
            "pub fn benchmark_"
        ):
            violations.append(
                f"{path}:{line_num}: Function should use `bench_` prefix, "
                f"not `benchmark_`\n    {trimmed}"
            )
    return violations


def check_format_strings(path: Path, content: str) -> list[str]:
    """Check for format string issues in benchmark names."""
    violations = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        trimmed = line.strip()
        if trimmed.startswith("//"):
            continue

        # Check for format strings with module_path!()
        if "module_path!()" in line and "format!" in line:
            # Check for comma between parameters
            if "={}," in line or "={} ," in line:
                violations.append(
                    f"{path}:{line_num}: Parameters should be space-separated, "
                    f"not comma-separated\n    {trimmed}"
                )

            # Check for colon in value position
            if "={}:{}" in line:
                violations.append(
                    f"{path}:{line_num}: Consider using `/` instead of `:` "
                    f"as value separator for readability\n    {trimmed}"
                )

            # Check for space before parameter name without key= prefix
            # Pattern: "/word space word=" where first word has no =
            match = re.search(r'"/([^"]*)"', line)
            if match:
                inner = match.group(1)
                for segment in inner.split("/")[1:]:
                    parts = segment.split()
                    if len(parts) >= 2:
                        first, second = parts[0], parts[1]
                        if (
                            "=" not in first
                            and "{" not in first
                            and "=" in second
                            and re.match(r"^[\w-]+$", first)
                        ):
                            violations.append(
                                f"{path}:{line_num}: Bare value `{first}` should "
                                f"use key=value format (e.g., `type={first}`)\n"
                                f"    {trimmed}"
                            )

    return violations


def main() -> int:
    if len(sys.argv) > 1:
        root = Path(sys.argv[1])
    else:
        # Find repo root by looking for Cargo.toml
        root = Path.cwd()
        while root != root.parent:
            if (root / "Cargo.toml").exists() and (root / ".github").exists():
                break
            root = root.parent

    benchmark_files = find_benchmark_files(root)
    all_violations = []

    for path in benchmark_files:
        try:
            content = path.read_text()
        except OSError as e:
            all_violations.append(f"{path}: Failed to read file: {e}")
            continue

        all_violations.extend(check_function_names(path, content))
        all_violations.extend(check_format_strings(path, content))

    if all_violations:
        print(f"Benchmark naming violations found ({len(all_violations)} total):\n")
        print("\n\n".join(all_violations))
        print("\n\nRules:")
        print("1. Use `bench_` prefix for benchmark functions (not `benchmark_`)")
        print("2. Use `key=value` format in benchmark names (e.g., `group=g1`)")
        print("3. Separate parameters with spaces, not commas")
        print("4. Use `/` instead of `:` as value separators for ratios")
        return 1

    print(f"Checked {len(benchmark_files)} benchmark files, all naming conventions followed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
