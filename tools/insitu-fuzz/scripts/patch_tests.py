#!/usr/bin/env python3
"""Add #[fuzzable_test] attribute to test functions in the monorepo.

This script reads test names from message_counts.json and patches each test
function to have the #[fuzzable_test] attribute, enabling the fuzzing hooks.

Usage:
    python3 scripts/patch_tests.py           # Patch all tests
    python3 scripts/patch_tests.py -n 20     # Patch top 20 tests
    python3 scripts/patch_tests.py --output patched.txt  # Write patched list
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


def add_fuzzable_to_test(file_path: Path, test_fn: str) -> tuple[bool, bool, bool]:
    """Add #[fuzzable_test] attribute and import to a specific test function.

    Returns:
        (found, modified): found=True if test exists, modified=True if file was changed
    """
    content = file_path.read_text()
    original = content

    # Check if test function exists
    fn_pattern = rf'\bfn\s+{re.escape(test_fn)}\b'
    if not re.search(fn_pattern, content):
        return False, False, False  # Test function not found

    # Check if test has #[should_panic] - can't be fuzzed
    should_panic_pattern = (
        r'#\[should_panic[^\]]*\]\s*\n'
        r'(?:[ \t]*#\[[^\]]+\]\s*\n)*'  # Other attributes
        rf'[ \t]*(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(test_fn)}\b'
    )
    if re.search(should_panic_pattern, content, flags=re.MULTILINE):
        return False, False, False  # Test has should_panic, can't fuzz

    # Check if test has #[tokio::test] - can't fuzz (requires tokio runtime, not deterministic)
    tokio_test_pattern = (
        r'#\[tokio::test[^\]]*\]\s*\n'
        r'(?:[ \t]*#\[[^\]]+\]\s*\n)*'  # Other attributes
        rf'[ \t]*(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(test_fn)}\b'
    )
    if re.search(tokio_test_pattern, content, flags=re.MULTILINE):
        return False, False, False  # Test uses tokio::test, can't fuzz

    # Add import if needed
    if 'fuzzable_test' not in content:
        # Match either "pub mod tests/test/mocks" or just "mod tests/test/mocks"
        # (the pub might be added by the bash script later)
        # Note: "test" (singular) is used by reshare's #[test_group] macro
        content = re.sub(
            r'((?:pub\s+)?mod\s+(?:tests?|mocks)\s*\{)\s*\n',
            r'\1\n    use commonware_macros::fuzzable_test;\n',
            content, count=1
        )
    # Add #[fuzzable_test] attribute before the test function
    pattern = (
        r'((?:[ \t]*#\[[\w:]+(?:\([^)]*\))?\]\s*\n)*)'  # Optional preceding attributes
        r'([ \t]*(?:#\[(?:test|test_traced|test_collect_traces|tokio::test)(?:\([^)]*\))?\]\s*\n)+)'  # Test attributes
        rf'([ \t]*(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(test_fn)}\b)'  # Function declaration
    )

    def add_attr(match):
        attrs_before, test_attrs, fn_decl = match.groups()

        # Skip if already present
        if 'fuzzable_test' in attrs_before or 'fuzzable_test' in test_attrs:
            return match.group(0)

        # Extract indentation and insert attribute
        indent = re.match(r'(\s*)', test_attrs).group(1)
        return f"{attrs_before}{indent}#[fuzzable_test]\n{test_attrs}{fn_decl}"

    # Skip tests that collect traces (require TraceStorage arg; not compatible with registry yet).
    if re.search(r'#\[(test_collect_traces(?:\([^)]*\))?)\]', content):
        return True, False, True  # Found, but intentionally skipped

    content = re.sub(pattern, add_attr, content, flags=re.MULTILINE)

    if content != original:
        file_path.write_text(content)
        return True, True, False  # Found and modified
    return True, False, False  # Found but already patched


def find_test_file(monorepo: Path, test_name: str) -> Path:
    """Find source file for a test name like 'commonware-broadcast::buffered::tests::test_broadcast'."""
    parts = test_name.split("::")
    crate = parts[0].replace("commonware-", "")

    # Handle binary crate test paths like "commonware-reshare::bin/commonware-reshare::validator::test::..."
    # nextest adds "bin/crate-name::" for binary crates
    if len(parts) > 1 and parts[1].startswith("bin/"):
        # Skip the "bin/crate-name" part
        parts = [parts[0]] + parts[2:]

    # Module path is everything between crate and "tests/test::test_fn"
    # Handle both "tests" and "test" module names
    test_mod_name = parts[-2]
    if test_mod_name in ("tests", "test"):
        module_parts = parts[1:-2]
    else:
        module_parts = parts[1:-1]

    module_path = "/".join(module_parts)

    # Determine crate path - check if it's a top-level crate or in examples/
    if (monorepo / crate).exists():
        crate_path = monorepo / crate
    elif (monorepo / "examples" / crate).exists():
        crate_path = monorepo / "examples" / crate
    else:
        raise FileNotFoundError(f"Can't find crate directory for {test_name}")

    # Try both module.rs and module/mod.rs
    candidates = [
        crate_path / "src" / f"{module_path}.rs",
        crate_path / "src" / module_path / "mod.rs",
    ]

    for path in candidates:
        if path.exists():
            return path

    raise FileNotFoundError(f"Can't find source file for {test_name}")


def main():
    parser = argparse.ArgumentParser(description="Add #[fuzzable_test] to monorepo tests")
    parser.add_argument("-n", type=int, help="Limit to top N tests (by duration)")
    parser.add_argument("--output", type=Path, help="Write list of successfully patched tests")
    parser.add_argument("--skipped", type=Path, help="Write list of skipped tests")
    args = parser.parse_args()

    repo_root = Path(__file__).parent.parent
    monorepo = Path(os.environ.get("MONOREPO", repo_root / "../..")).resolve()
    msg_counts = repo_root / "tools" / "message_counts.json"

    if not msg_counts.exists():
        print(f"Error: {msg_counts} not found")
        sys.exit(1)

    # Load tests from message_counts.json
    with open(msg_counts) as f:
        all_tests = []
        for line in f:
            data = json.loads(line)
            if "test" in data:
                all_tests.append((data["test"], data["messages"], data["duration_secs"]))

    # Sort by duration (fast tests first)
    all_tests.sort(key=lambda x: x[2])

    # Limit if requested
    if args.n:
        all_tests = all_tests[:args.n]

    print(f"Processing {len(all_tests)} tests\n")

    # Track results
    skipped_tests = []
    successfully_patched = []

    # Add #[fuzzable_test] to each specific test function
    for test_name, msg_count, duration in all_tests:
        test_fn = test_name.split("::")[-1]
        # Strip _slow_ suffix - #[test_group("slow")] macro renames tests at compile time
        # Source has fn test_foo() but runtime name is test_foo_slow_
        if test_fn.endswith("_slow_"):
            test_fn = test_fn[:-6]  # Remove "_slow_"

        # Some tests are reported as test_* but the source fn omits the prefix.
        # Try the original name first, then a stripped variant.
        fn_candidates = [test_fn]
        if test_fn.startswith("test_"):
            fn_candidates.append(test_fn[len("test_"):])
        try:
            file_path = find_test_file(monorepo, test_name)
            found_any = False
            for candidate in fn_candidates:
                found, modified, skipped_trace = add_fuzzable_to_test(file_path, candidate)
                if found:
                    found_any = True
                    # Use the actual function name in the registry output.
                    if candidate != test_fn:
                        test_name_out = test_name.rsplit("::", 1)[0] + "::" + candidate
                    else:
                        test_name_out = test_name
                    if skipped_trace:
                        skipped_tests.append((test_name_out, "uses #[test_collect_traces] (TraceStorage arg)"))
                    else:
                        successfully_patched.append((test_name_out, msg_count, duration))
                    break
            if not found_any:
                reason = "test not found or has #[should_panic] or #[tokio::test]"
                skipped_tests.append((test_name, reason))
        except FileNotFoundError as e:
            reason = str(e)
            skipped_tests.append((test_name, reason))

    print(f"Patched {len(successfully_patched)}/{len(all_tests)} tests")
    if skipped_tests:
        print(f"Skipped {len(skipped_tests)} tests")

    # Write output files if requested
    if args.output:
        with open(args.output, "w") as f:
            for test_name, msg_count, duration in successfully_patched:
                f.write(f"{test_name},{msg_count},{duration}\n")
        print(f"Wrote patched tests to {args.output}")

    if args.skipped:
        with open(args.skipped, "w") as f:
            for test_name, reason in skipped_tests:
                f.write(f"{test_name},{reason}\n")
        print(f"Wrote skipped tests to {args.skipped}")


if __name__ == "__main__":
    main()
