#!/usr/bin/env python3
"""
Verify all public items in a crate have #[ready(N)] annotations,
and that private items do NOT have unnecessary annotations.

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


def get_reexported_item_ids(index, root_id):
    """
    Find all item IDs that are re-exported via public 'use' statements.
    Returns a set of item IDs that are publicly accessible via re-export.
    """
    reexported = set()

    def traverse(mod_id, is_public_path):
        item = index.get(str(mod_id))
        if not item:
            return

        inner = item.get("inner", {})
        if "module" not in inner:
            return

        mod_items = inner.get("module", {}).get("items", [])
        for child_id in mod_items:
            child = index.get(str(child_id))
            if not child:
                continue

            child_inner = child.get("inner", {})
            is_public = child.get("visibility") == "public"

            # Check for re-exports (use/import statements)
            if "use" in child_inner and is_public_path and is_public:
                use_data = child_inner.get("use", {})
                target_id = use_data.get("id")
                if target_id:
                    reexported.add(str(target_id))

            # Recurse into child modules
            if "module" in child_inner:
                child_is_public_path = is_public_path and is_public
                traverse(child_id, child_is_public_path)

    traverse(root_id, True)
    return reexported


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


def get_type_path(type_info, paths):
    """Extract the path for a type from rustdoc JSON type representation."""
    if not type_info:
        return None

    # Handle resolved_path (most common for concrete types)
    if "resolved_path" in type_info:
        resolved = type_info["resolved_path"]
        type_id = str(resolved.get("id", ""))
        path_info = paths.get(type_id, {})
        return path_info.get("path", [])

    # Handle generic types (we skip these as they're not concrete)
    if "generic" in type_info:
        return None

    return None


def check_trait_impls(index, paths, public_module_paths):
    """
    Check that all public trait implementations have readiness annotations.

    A trait impl is considered public if:
    - The trait is defined in this crate (crate_id 0) and publicly accessible
    - The implementing type is defined in this crate and publicly accessible
    """
    missing = []

    for item_id, item in index.items():
        inner = item.get("inner", {})
        if "impl" not in inner:
            continue

        impl_data = inner.get("impl", {})
        trait_info = impl_data.get("trait")

        # Skip inherent impls (no trait)
        if not trait_info:
            continue

        # Skip blanket impls
        if impl_data.get("blanket_impl"):
            continue

        # Get trait path
        trait_id = str(trait_info.get("id", ""))
        trait_path_info = paths.get(trait_id, {})

        # Skip if trait is not from this crate
        if trait_path_info.get("crate_id") != 0:
            continue

        trait_path = trait_path_info.get("path", [])

        # Skip if trait is not publicly accessible
        if not is_publicly_accessible(trait_path, public_module_paths):
            continue

        # Get the implementing type's path
        for_type = impl_data.get("for")
        type_path = get_type_path(for_type, paths)

        # Skip if we can't determine the type path (e.g., generic types)
        if not type_path:
            continue

        # Check if the type is from this crate
        if for_type and "resolved_path" in for_type:
            type_id = str(for_type["resolved_path"].get("id", ""))
            type_path_info = paths.get(type_id, {})
            if type_path_info.get("crate_id") != 0:
                continue

        # Skip if type is not publicly accessible
        if not is_publicly_accessible(type_path, public_module_paths):
            continue

        # Check for readiness annotation in docs
        docs = item.get("docs") or ""
        if "**Readiness:" not in docs:
            trait_name = trait_path[-1] if trait_path else "?"
            type_name = type_path[-1] if type_path else "?"
            impl_str = f"impl {trait_name} for {type_name}"
            missing.append(("impl", impl_str, f"{' :: '.join(type_path)}"))

    return missing


def check_unnecessary_annotations(index, paths, public_module_paths, reexported_ids):
    """
    Check that private items do NOT have #[ready(N)] annotations.
    Items are considered public if they're in a public module path OR re-exported.
    """
    unnecessary = []

    for item_id, item in index.items():
        # Only check items that have readiness annotations
        docs = item.get("docs") or ""
        if "**Readiness:" not in docs:
            continue

        # Skip items that aren't the kinds we care about
        kind = get_kind(item)
        if kind not in REQUIRED_KINDS:
            continue

        # Skip non-public items (visibility at item level)
        if item.get("visibility") != "public":
            continue

        # Get the item's path
        path_info = paths.get(item_id, {})
        item_path = path_info.get("path", [])

        # Check if item is publicly accessible (direct path or re-export)
        is_direct_public = is_publicly_accessible(item_path, public_module_paths)
        is_reexported = item_id in reexported_ids

        if not is_direct_public and not is_reexported:
            name = item.get("name", item_id)
            path_str = "::".join(item_path) if item_path else name
            unnecessary.append((kind, name, path_str))

    return unnecessary


def check_readiness(path):
    with open(path) as f:
        data = json.load(f)

    index = data.get("index", {})
    paths = data.get("paths", {})
    root_id = data.get("root")

    # Build set of public module paths
    public_module_paths = get_public_module_paths(index, root_id)

    # Build set of re-exported item IDs
    reexported_ids = get_reexported_item_ids(index, root_id)

    missing = []
    errors = False

    # Check structs, enums, type aliases, constants
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

        # Item is public if directly accessible OR re-exported
        is_direct_public = is_publicly_accessible(item_path, public_module_paths)
        is_reexported = item_id in reexported_ids

        if not is_direct_public and not is_reexported:
            continue

        # Check for readiness annotation in docs
        docs = item.get("docs") or ""
        if "**Readiness:" not in docs:
            name = item.get("name", item_id)
            # Include path for debugging
            path_str = "::".join(item_path) if item_path else name
            missing.append((kind, name, path_str))

    # Check trait implementations
    missing.extend(check_trait_impls(index, paths, public_module_paths))

    # Check for unnecessary annotations on private items
    unnecessary = check_unnecessary_annotations(
        index, paths, public_module_paths, reexported_ids
    )

    if missing:
        print(f"Missing #[ready(N)] annotation ({len(missing)} items):")
        for kind, name, path_str in sorted(missing):
            print(f"  {kind}: {name} ({path_str})")
        errors = True

    if unnecessary:
        print(f"\nUnnecessary #[ready(N)] on private items ({len(unnecessary)} items):")
        for kind, name, path_str in sorted(unnecessary):
            print(f"  {kind}: {name} ({path_str})")
        errors = True

    if errors:
        sys.exit(1)

    print("All public items have readiness annotations (no unnecessary annotations)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <rustdoc-json-path>")
        sys.exit(1)
    check_readiness(sys.argv[1])
