#!/usr/bin/env python3
"""
Verify all public items in a crate have #[ready(N)] annotations.

Usage:
    RUSTDOCFLAGS="-Z unstable-options --output-format json" cargo +nightly doc -p <crate>
    ./scripts/check_readiness.py target/doc/<crate>.json
"""

import json
import sys

# Item kinds that require readiness annotations (keys in the 'inner' field)
# Note: traits are excluded - they define interfaces, not implementation maturity
REQUIRED_KINDS = {"struct", "enum", "type_alias", "constant"}


def get_kind(item):
    """Extract kind from item's inner field."""
    inner = item.get("inner", {})
    if isinstance(inner, dict):
        keys = list(inner.keys())
        return keys[0] if keys else None
    return None


def get_public_module_paths(index, root_id):
    """
    Build a set of public module paths by traversing from the root.
    Returns a set of tuples representing the path segments.
    """
    public_paths = set()

    def traverse(mod_id, path_segments):
        item = index.get(str(mod_id))
        if not item:
            return

        inner = item.get("inner", {})
        if "module" not in inner:
            return

        # This module path is public
        public_paths.add(tuple(path_segments))

        # Check children
        mod_items = inner.get("module", {}).get("items", [])
        for child_id in mod_items:
            child = index.get(str(child_id))
            if not child:
                continue
            child_inner = child.get("inner", {})
            # Only traverse into public child modules
            if "module" in child_inner and child.get("visibility") == "public":
                child_name = child.get("name", "")
                traverse(child_id, path_segments + [child_name])

    root_item = index.get(str(root_id))
    if root_item:
        root_name = root_item.get("name", "")
        traverse(root_id, [root_name])

    return public_paths


def is_publicly_accessible(item_path, public_module_paths):
    """
    Check if an item is publicly accessible by verifying that
    all modules in its path are public.
    """
    if not item_path:
        return False

    # The item path includes the item itself at the end
    # We need to check that all parent modules are public
    # e.g., for ['crate', 'mod1', 'mod2', 'Item'], check that
    # ('crate',), ('crate', 'mod1'), and ('crate', 'mod1', 'mod2') are all public

    for i in range(1, len(item_path)):
        module_path = tuple(item_path[:i])
        if module_path not in public_module_paths:
            return False

    return True


def check_readiness(path):
    with open(path) as f:
        data = json.load(f)

    index = data.get("index", {})
    paths = data.get("paths", {})
    root_id = data.get("root")

    # Build set of public module paths
    public_module_paths = get_public_module_paths(index, root_id)

    missing = []
    for item_id, item in index.items():
        # Skip non-public items
        if item.get("visibility") != "public":
            continue

        # Get kind from inner field
        kind = get_kind(item)
        if kind not in REQUIRED_KINDS:
            continue

        # Get the item's path from the paths section
        path_info = paths.get(item_id, {})
        item_path = path_info.get("path", [])

        # Skip items that aren't accessible through public modules
        if not is_publicly_accessible(item_path, public_module_paths):
            continue

        # Check for readiness annotation in docs
        docs = item.get("docs") or ""
        if "**Readiness:" not in docs:
            name = item.get("name", item_id)
            # Include path for debugging
            path_str = "::".join(item_path) if item_path else name
            missing.append((kind, name, path_str))

    if missing:
        print(f"Missing #[ready(N)] annotation ({len(missing)} items):")
        for kind, name, path_str in sorted(missing):
            print(f"  {kind}: {name} ({path_str})")
        sys.exit(1)

    print("All public items have readiness annotations")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <rustdoc-json-path>")
        sys.exit(1)
    check_readiness(sys.argv[1])
