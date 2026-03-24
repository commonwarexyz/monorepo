#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Validate that the publish workflow orders crates after all publishable internal
dependencies.

This catches `cargo publish` failures caused by publishing a crate before one of
its workspace dependencies is available on crates.io. The check includes normal,
build, and dev dependencies because `cargo publish` verifies all of them.

Usage
-----
  ./check_publish_order.py
  ./check_publish_order.py /path/to/repo
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


PUBLISH_WORKFLOW = Path(".github/workflows/publish.yml")
PUBLISH_PATTERN = re.compile(r"cargo publish --manifest-path (?P<path>\S+)")


def find_repo_root(start: Path) -> Path:
    root = start.resolve()
    while root != root.parent:
        if (root / "Cargo.toml").exists() and (root / ".github").exists():
            return root
        root = root.parent
    raise SystemExit("ERROR: could not find repository root")


def load_publish_order(root: Path) -> list[Path]:
    workflow = root / PUBLISH_WORKFLOW
    text = workflow.read_text(encoding="utf-8")
    manifests = [
        (root / match.group("path").strip("'\"")).resolve()
        for match in PUBLISH_PATTERN.finditer(text)
    ]
    if not manifests:
        raise SystemExit(f"ERROR: no cargo publish steps found in {workflow}")
    return manifests


def load_workspace_metadata(root: Path) -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            "ERROR: failed to load cargo metadata\n"
            f"{result.stderr.strip()}"
        )
    return json.loads(result.stdout)


def rel(root: Path, path: Path) -> str:
    return str(path.resolve().relative_to(root))


def dependency_kind(dep: dict) -> str:
    return dep["kind"] or "normal"


def workspace_packages(metadata: dict, *, publishable_only: bool = False) -> dict[Path, dict]:
    workspace_members = set(metadata["workspace_members"])
    packages = {}
    for package in metadata["packages"]:
        if package["id"] not in workspace_members:
            continue
        if publishable_only and package.get("publish") == []:
            continue
        manifest = Path(package["manifest_path"]).resolve()
        packages[manifest] = package
    return packages


def main() -> int:
    root = find_repo_root(Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd())
    publish_order = load_publish_order(root)
    metadata = load_workspace_metadata(root)
    workspace = workspace_packages(metadata)
    packages = workspace_packages(metadata, publishable_only=True)

    duplicates = []
    seen = set()
    for manifest in publish_order:
        if manifest in seen:
            duplicates.append(manifest)
        seen.add(manifest)

    problems = []
    if duplicates:
        problems.extend(
            f"publish.yml contains duplicate publish steps for {rel(root, manifest)}"
            for manifest in duplicates
        )

    workflow_manifests = set(publish_order)
    package_manifests = set(packages)

    missing = sorted(package_manifests - workflow_manifests)
    extra = sorted(workflow_manifests - package_manifests)

    problems.extend(
        f"publish.yml is missing publishable workspace crate {packages[manifest]['name']} "
        f"({rel(root, manifest)})"
        for manifest in missing
    )
    problems.extend(
        f"publish.yml includes non-publishable or unknown manifest {rel(root, manifest)}"
        for manifest in extra
    )

    order_index = {manifest: idx for idx, manifest in enumerate(publish_order)}
    workspace_by_root = {manifest.parent.resolve(): manifest for manifest in workspace}

    for manifest in publish_order:
        package = packages.get(manifest)
        if package is None:
            continue

        blocked_by: dict[Path, set[str]] = {}
        for dep in package["dependencies"]:
            dep_path = dep.get("path")
            if dep_path is None:
                continue

            dep_manifest = workspace_by_root.get(Path(dep_path).resolve())
            if dep_manifest is None:
                problems.append(
                    f"{package['name']} ({rel(root, manifest)}) depends on unknown workspace "
                    f"path {dep_path}"
                )
                continue

            dep_package = packages.get(dep_manifest)
            if dep_package is None:
                problems.append(
                    f"{package['name']} ({rel(root, manifest)}) depends on unpublished workspace "
                    f"crate {dep['name']} ({rel(root, dep_manifest)})"
                )
                continue

            if dep_manifest == manifest:
                continue

            if order_index.get(dep_manifest, -1) >= order_index[manifest]:
                blocked_by.setdefault(dep_manifest, set()).add(dependency_kind(dep))

        for dep_manifest, kinds in sorted(blocked_by.items(), key=lambda item: str(item[0])):
            dep_package = packages[dep_manifest]
            kind_list = ", ".join(sorted(kinds))
            problems.append(
                f"{package['name']} ({rel(root, manifest)}) is published at step "
                f"{order_index[manifest] + 1}, but depends on {dep_package['name']} "
                f"({rel(root, dep_manifest)}) at step {order_index[dep_manifest] + 1} "
                f"via {kind_list} dependencies"
            )

    if problems:
        print("Publish order validation failed:\n")
        print("\n".join(f"- {problem}" for problem in problems))
        return 1

    print(
        f"Validated publish order for {len(publish_order)} publishable workspace crates."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
