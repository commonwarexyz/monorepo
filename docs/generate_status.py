#!/usr/bin/env python3

"""Generate status.json showing module maturity levels across the workspace."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DOCS_ROOT = Path(__file__).resolve().parent
REPO_ROOT = DOCS_ROOT.parent

# Marker pattern: //! @beta("0.1.0") or //! @gamma("0.2.0") or //! @lts("0.3.0")
MARKER_PATTERN = re.compile(r"//!\s*@(beta|gamma|lts)\(\"([^\"]+)\"\)")

# Use statement pattern to find commonware dependencies with module paths
# Captures: crate name, optional module path
USE_PATTERN = re.compile(r"use\s+commonware_(\w+)(?:::(\w+(?:::\w+)*))?")

# Crates excluded from LTS dependency checking (test-only dependencies)
LTS_EXCLUDED_CRATES = {"conformance"}

# Core crates to scan (exclude examples and fuzz)
CORE_CRATES = [
    "broadcast",
    "codec",
    "coding",
    "collector",
    "conformance",
    "consensus",
    "cryptography",
    "deployer",
    "macros",
    "math",
    "p2p",
    "parallel",
    "resolver",
    "runtime",
    "storage",
    "stream",
    "utils",
]


@dataclass
class ModuleStatus:
    """Status markers for a single module."""

    beta: str | None = None
    gamma: str | None = None
    lts: str | None = None
    inherited_from: str | None = None
    _dependencies: list["Dependency"] = field(default_factory=list)

    def current_stage(self) -> str:
        """Return the highest stage this module has reached."""
        if self.gamma:
            return "gamma"
        if self.beta:
            return "beta"
        return "alpha"

    def is_lts(self) -> bool:
        return self.lts is not None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.beta:
            result["beta"] = self.beta
        if self.gamma:
            result["gamma"] = self.gamma
        if self.lts:
            result["lts"] = self.lts
        if self.inherited_from:
            result["inherited_from"] = self.inherited_from
        return result


@dataclass
class Conflict:
    """A detected conflict in status markers."""

    path: str
    message: str
    severity: str  # "error" or "warning"

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message, "severity": self.severity}


def parse_markers(content: str) -> ModuleStatus:
    """Parse status markers from file content."""
    status = ModuleStatus()
    for match in MARKER_PATTERN.finditer(content):
        marker_type, version = match.groups()
        if marker_type == "beta":
            status.beta = version
        elif marker_type == "gamma":
            status.gamma = version
        elif marker_type == "lts":
            status.lts = version
    return status


@dataclass
class Dependency:
    """A dependency on another commonware module."""

    crate: str  # e.g., "codec"
    module_path: str | None  # e.g., "codec" or "types::vec" or None for crate root


def parse_dependencies(content: str) -> list[Dependency]:
    """Parse commonware crate dependencies from use statements.

    Skips doc comments (lines starting with ///, //!, or inside /** */).
    """
    deps: list[Dependency] = []
    seen: set[tuple[str, str | None]] = set()

    # Process line by line to skip comments
    in_block_comment = False
    for line in content.split("\n"):
        stripped = line.strip()

        # Track block comments
        if "/*" in stripped and "*/" not in stripped:
            in_block_comment = True
            continue
        if "*/" in stripped:
            in_block_comment = False
            continue
        if in_block_comment:
            continue

        # Skip doc comments and regular comments
        if stripped.startswith("//"):
            continue
        if stripped.startswith("*"):  # Inside block comment
            continue

        # Now look for actual use statements
        for match in USE_PATTERN.finditer(line):
            crate_name = match.group(1)
            module_path = match.group(2)  # May be None
            key = (crate_name, module_path)
            if key not in seen:
                seen.add(key)
                deps.append(Dependency(crate=crate_name, module_path=module_path))
    return deps


def scan_crate(crate_path: Path) -> dict[str, ModuleStatus]:
    """Scan a crate for status markers and build inheritance tree."""
    modules: dict[str, ModuleStatus] = {}
    src_path = crate_path / "src"

    if not src_path.exists():
        return modules

    # First pass: collect all explicit markers
    explicit_markers: dict[str, ModuleStatus] = {}
    for rs_file in src_path.rglob("*.rs"):
        rel_path = rs_file.relative_to(crate_path)
        content = rs_file.read_text(encoding="utf-8", errors="ignore")
        status = parse_markers(content)
        deps = parse_dependencies(content)
        status._dependencies = deps

        # Only store if there are explicit markers
        if status.beta or status.gamma or status.lts:
            explicit_markers[str(rel_path)] = status

        # Store all modules (will apply inheritance later)
        modules[str(rel_path)] = ModuleStatus(_dependencies=deps)

    # Second pass: apply inheritance from mod.rs files only
    # (lib.rs markers do NOT cascade to submodules - only mod.rs does)
    # Sort paths so parents are processed before children
    sorted_paths = sorted(modules.keys())

    for path in sorted_paths:
        # Check for explicit markers first
        if path in explicit_markers:
            explicit = explicit_markers[path]
            modules[path].beta = explicit.beta
            modules[path].gamma = explicit.gamma
            modules[path].lts = explicit.lts
            continue

        # Look for parent mod.rs that might provide inheritance
        path_obj = Path(path)
        parts = path_obj.parts

        # Check ancestors for mod.rs with markers
        for i in range(len(parts) - 1, 0, -1):
            parent_dir = Path(*parts[:i])
            parent_mod = str(parent_dir / "mod.rs")

            if parent_mod in explicit_markers:
                parent_status = explicit_markers[parent_mod]
                modules[path].beta = parent_status.beta
                modules[path].gamma = parent_status.gamma
                modules[path].lts = parent_status.lts
                modules[path].inherited_from = parent_mod
                break

    return modules


def check_conflicts(
    crate_name: str, modules: dict[str, ModuleStatus]
) -> list[Conflict]:
    """Check for conflicts in status markers."""
    conflicts: list[Conflict] = []

    # Build a map of explicit markers for parent checking
    explicit_markers: dict[str, ModuleStatus] = {
        path: status
        for path, status in modules.items()
        if (status.beta or status.gamma or status.lts) and not status.inherited_from
    }

    for path, status in modules.items():
        if status.inherited_from:
            continue  # Skip inherited modules for parent/child conflict check

        # Skip if this module has no markers
        if not (status.beta or status.gamma or status.lts):
            continue

        path_obj = Path(path)
        parts = path_obj.parts

        # Check if any ancestor mod.rs has markers (redundant marker check)
        # Note: lib.rs does NOT cascade, so we don't check it here
        for i in range(len(parts) - 1, 0, -1):
            parent_dir = Path(*parts[:i])
            parent_mod = str(parent_dir / "mod.rs")

            if parent_mod in explicit_markers and parent_mod != path:
                parent_status = explicit_markers[parent_mod]

                # Check for redundant markers
                if status.beta and parent_status.beta:
                    conflicts.append(
                        Conflict(
                            path=f"{crate_name}/{path}",
                            message=f"Redundant @beta marker (already inherited from {parent_mod})",
                            severity="error",
                        )
                    )
                if status.gamma and parent_status.gamma:
                    conflicts.append(
                        Conflict(
                            path=f"{crate_name}/{path}",
                            message=f"Redundant @gamma marker (already inherited from {parent_mod})",
                            severity="error",
                        )
                    )
                if status.lts and parent_status.lts:
                    conflicts.append(
                        Conflict(
                            path=f"{crate_name}/{path}",
                            message=f"Redundant @lts marker (already inherited from {parent_mod})",
                            severity="error",
                        )
                    )
                break

    return conflicts


def find_module_paths(crate: str, module_path: str | None) -> list[str]:
    """Find possible source file paths for a module import."""
    if module_path is None:
        # Import from crate root
        return ["src/lib.rs"]

    # Convert module path like "codec" or "types::vec" to file paths
    parts = module_path.split("::")
    paths = []

    # Could be src/module.rs or src/module/mod.rs
    file_path = "src/" + "/".join(parts) + ".rs"
    mod_path = "src/" + "/".join(parts) + "/mod.rs"
    paths.append(file_path)
    paths.append(mod_path)

    # Also check parent modules (for re-exports)
    for i in range(len(parts) - 1, 0, -1):
        parent_file = "src/" + "/".join(parts[:i]) + ".rs"
        parent_mod = "src/" + "/".join(parts[:i]) + "/mod.rs"
        paths.append(parent_file)
        paths.append(parent_mod)

    # Always include lib.rs as items can be re-exported
    paths.append("src/lib.rs")

    return paths


def check_lts_violations(
    all_modules: dict[str, dict[str, ModuleStatus]]
) -> list[Conflict]:
    """Check for LTS modules that depend on non-LTS code."""
    violations: list[Conflict] = []

    # Check each LTS module for non-LTS dependencies
    for crate_name, modules in all_modules.items():
        for path, status in modules.items():
            if not status.is_lts():
                continue

            for dep in status._dependencies:
                # Skip excluded crates (test-only dependencies)
                if dep.crate in LTS_EXCLUDED_CRATES:
                    continue

                # Skip if dependency crate is not in our tracked crates
                if dep.crate not in all_modules:
                    continue

                dep_modules = all_modules[dep.crate]
                possible_paths = find_module_paths(dep.crate, dep.module_path)

                # Check if any of the possible source paths are LTS
                is_dep_lts = False
                for possible_path in possible_paths:
                    if possible_path in dep_modules and dep_modules[possible_path].is_lts():
                        is_dep_lts = True
                        break

                if not is_dep_lts:
                    dep_str = f"commonware_{dep.crate}"
                    if dep.module_path:
                        dep_str += f"::{dep.module_path}"
                    violations.append(
                        Conflict(
                            path=f"{crate_name}/{path}",
                            message=f"LTS module imports from non-LTS: {dep_str}",
                            severity="error",
                        )
                    )

    return violations


def compute_summary(all_modules: dict[str, dict[str, ModuleStatus]]) -> dict[str, Any]:
    """Compute summary statistics."""
    total = 0
    by_stage = {"alpha": 0, "beta": 0, "gamma": 0}
    lts_count = 0

    for modules in all_modules.values():
        for status in modules.values():
            total += 1
            stage = status.current_stage()
            by_stage[stage] += 1
            if status.is_lts():
                lts_count += 1

    return {
        "total_modules": total,
        "by_stage": by_stage,
        "lts_count": lts_count,
    }


def main() -> int:
    all_modules: dict[str, dict[str, ModuleStatus]] = {}
    all_conflicts: list[Conflict] = []

    # Scan each core crate
    for crate_name in CORE_CRATES:
        crate_path = REPO_ROOT / crate_name
        if not crate_path.exists():
            continue

        modules = scan_crate(crate_path)
        all_modules[crate_name] = modules

        # Check for conflicts within the crate
        conflicts = check_conflicts(crate_name, modules)
        all_conflicts.extend(conflicts)

    # Check for LTS violations across crates
    lts_violations = check_lts_violations(all_modules)
    all_conflicts.extend(lts_violations)

    errors = [c for c in all_conflicts if c.severity == "error"]
    warnings = [c for c in all_conflicts if c.severity == "warning"]

    # Build output (no errors/warnings in JSON - CI handles validation)
    output: dict[str, Any] = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "crates": {},
        "summary": compute_summary(all_modules),
    }

    for crate_name, modules in all_modules.items():
        output["crates"][crate_name] = {
            "modules": {
                path: status.to_dict() for path, status in sorted(modules.items())
            }
        }

    # Write output
    output_path = DOCS_ROOT / "status.json"
    output_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {output_path}")

    # Print summary
    summary = output["summary"]
    print(f"\nSummary:")
    print(f"  Total modules: {summary['total_modules']}")
    print(f"  By stage: {summary['by_stage']}")
    print(f"  LTS modules: {summary['lts_count']}")

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for c in warnings:
            print(f"  - {c.path}: {c.message}")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for c in errors:
            print(f"  - {c.path}: {c.message}")
        return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
