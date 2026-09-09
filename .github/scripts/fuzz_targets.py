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
    requested = [f for f in (args[1] if len(args) == 2 else "").split(",") if f]

    metadata = json.loads(
        subprocess.run(
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
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    package = next(
        p for p in metadata["packages"] if os.path.realpath(p["manifest_path"]) == manifest
    )

    # Resolve the closure of enabled package features. Entries that name
    # dependencies or dependency features never gate a target, so they are
    # skipped when they do not match a feature of this package.
    features = package["features"]
    enabled = set()
    pending = requested if requested else ["default"]
    while pending:
        feature = pending.pop()
        if feature in enabled or feature not in features:
            continue
        enabled.add(feature)
        pending.extend(features[feature])

    for target in package["targets"]:
        if "bin" not in target["kind"]:
            continue
        if set(target.get("required-features", [])) <= enabled:
            print(target["name"])


if __name__ == "__main__":
    main()
