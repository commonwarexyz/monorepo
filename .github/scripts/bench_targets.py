#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Print the bench targets of a package that `cargo test --benches` builds.

Reads `cargo metadata --no-deps --format-version 1` from stdin and prints, one
per line, the bench targets of the package whose required features are all
enabled. Enabled features are the ones the given flags select, the package's
default features unless `--no-default-features` is passed, and every feature
those enable in turn. Listing targets this way needs no build.

Usage:
  cargo metadata --no-deps --format-version 1 | bench_targets.py PACKAGE [FLAGS...]

FLAGS are the feature flags passed to `cargo test`: `--features LIST`,
`--features=LIST`, `-F LIST`, `--all-features`, and `--no-default-features`.
Any other flag is an error, so a flag this script would misread cannot go
unnoticed.
"""

import json
import sys


def split_features(value):
    """Split a cargo feature list, which may use commas, spaces, or both."""
    return [feature for feature in value.replace(",", " ").split() if feature]


def enabled_features(package, flags):
    """Return the features of `package` that `flags` enable."""
    table = package["features"]
    requested = set()
    defaults = True
    args = iter(flags)
    for arg in args:
        if arg == "--all-features":
            return set(table)
        if arg == "--no-default-features":
            defaults = False
        elif arg in ("--features", "-F"):
            requested.update(split_features(next(args, "")))
        elif arg.startswith("--features="):
            requested.update(split_features(arg.split("=", 1)[1]))
        else:
            sys.exit(f"bench_targets.py: unsupported flag: {arg}")
    if defaults:
        requested.add("default")

    # A feature spelled `package/feature` names one of this package's features.
    prefix = package["name"] + "/"
    pending = [f[len(prefix):] if f.startswith(prefix) else f for f in requested]
    enabled = set()
    while pending:
        feature = pending.pop()
        if feature in enabled or feature not in table:
            continue
        enabled.add(feature)
        pending.extend(table[feature])
    return enabled


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: bench_targets.py PACKAGE [FLAGS...]")
    name, flags = sys.argv[1], sys.argv[2:]
    metadata = json.load(sys.stdin)
    packages = [p for p in metadata["packages"] if p["name"] == name]
    if len(packages) != 1:
        sys.exit(f"bench_targets.py: expected one package named {name}, found {len(packages)}")
    package = packages[0]
    enabled = enabled_features(package, flags)
    for target in package["targets"]:
        if "bench" not in target["kind"]:
            continue
        if all(f in enabled for f in target.get("required-features") or []):
            print(target["name"])


if __name__ == "__main__":
    main()
