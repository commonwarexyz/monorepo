#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
List the fuzz targets of a cargo-fuzz package that build under a feature set.

Reads the package manifest through `cargo metadata` and prints one target name
per line. Targets whose `required-features` are not all enabled are omitted,
mirroring what `cargo build --bins` compiles, so a package can group its
targets into build partitions selected with
`--no-default-features --features <partition>`.

Usage:
  - <command> [+TOOLCHAIN] FUZZ_DIR [FEATURES]

where +TOOLCHAIN selects the cargo toolchain exactly as it does for cargo
itself, FUZZ_DIR holds the package's `Cargo.toml`, and FEATURES is a
comma-separated list that replaces the package's default features, as in
`cargo build --no-default-features --features FEATURES`. When FEATURES is empty
or omitted, the default features apply.
"""

import json
import os
import subprocess
import sys


def main() -> None:
    args = sys.argv[1:]
    toolchain = [args.pop(0)] if args and args[0].startswith("+") else []
    if len(args) not in (1, 2):
        sys.exit("usage: fuzz_targets.py [+TOOLCHAIN] FUZZ_DIR [FEATURES]")
    manifest = os.path.realpath(os.path.join(args[0], "Cargo.toml"))
    if not os.path.isfile(manifest):
        sys.exit(f"fuzz_targets.py: {args[0]} is not a cargo-fuzz package: no Cargo.toml in it")
    requested = [f for f in (args[1] if len(args) == 2 else "").split(",") if f]

    proc = subprocess.run(
        [
            "cargo",
            *toolchain,
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            manifest,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.exit(f"fuzz_targets.py: cargo metadata failed for {manifest}:\n{proc.stderr.strip()}")
    metadata = json.loads(proc.stdout)
    package = next(
        (p for p in metadata["packages"] if os.path.realpath(p["manifest_path"]) == manifest),
        None,
    )
    if package is None:
        sys.exit(f"fuzz_targets.py: {manifest} is not a package of its workspace")
    if (package.get("metadata") or {}).get("cargo-fuzz") is not True:
        sys.exit(
            f"fuzz_targets.py: {package['name']} is not a cargo-fuzz package: "
            "its manifest lacks `cargo-fuzz = true` under [package.metadata]"
        )

    # Requested features must exist, as `cargo build --features` requires;
    # a typo must fail loudly rather than select no targets.
    features = package["features"]
    unknown = [f for f in requested if f not in features]
    if unknown:
        sys.exit(
            f"fuzz_targets.py: {package['name']} has no feature {', '.join(unknown)}; "
            f"available: {', '.join(sorted(features))}"
        )

    # Resolve the closure of enabled package features. Entries that name
    # dependencies or dependency features never gate a target, so they are
    # skipped when they do not match a feature of this package.
    enabled = set()
    pending = list(requested) if requested else ["default"]
    while pending:
        feature = pending.pop()
        if feature in enabled or feature not in features:
            continue
        enabled.add(feature)
        pending.extend(features[feature])

    selected = [
        target["name"]
        for target in package["targets"]
        if "bin" in target["kind"] and set(target.get("required-features", [])) <= enabled
    ]
    # Selecting nothing is a misconfiguration, not an empty job: either the
    # requested features gate every target or the package defines none.
    if not selected:
        if requested:
            sys.exit(
                f"fuzz_targets.py: features {','.join(requested)} select no target of {package['name']}"
            )
        sys.exit(f"fuzz_targets.py: {package['name']} defines no fuzz target")
    for name in selected:
        print(name)


if __name__ == "__main__":
    main()
