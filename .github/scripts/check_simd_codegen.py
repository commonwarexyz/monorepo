#!/usr/bin/env python3
"""Check optimized SIMD consumers compiled separately from the library, without LTO."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[2]
    arguments = sys.argv[1:]
    feature_scopes = "--feature-scopes" in arguments
    if feature_scopes:
        arguments.remove("--feature-scopes")
    environment = os.environ.copy()
    if feature_scopes:
        # Compile only: disabling baseline NEON violates the AArch64 target ABI.
        # This diagnostic configuration exposes otherwise hidden feature boundaries.
        environment["RUSTFLAGS"] = environment.get("RUSTFLAGS", "") + " -C target-feature=-neon"
    command = [
        "cargo", "rustc", "-p", "commonware-simd", "--release", "--test", "codegen",
        "--message-format=json", *arguments, "--", "--emit=llvm-ir,asm",
        "-C", "lto=off", "-C", "codegen-units=1",
    ]
    result = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True)
    artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    if result.returncode:
        print(result.stderr, file=sys.stderr)
        for item in artifacts:
            if item.get("reason") == "compiler-message":
                print(item["message"]["rendered"], file=sys.stderr)
        return result.returncode
    binary = next(
        Path(item["executable"]) for item in artifacts
        if item.get("reason") == "compiler-artifact" and item["target"]["name"] == "codegen"
    )
    ir = binary.with_suffix(".ll")
    text = ir.read_text()
    symbol = r'("[^"\n]+"|[-\w.$]+)'
    bodies = dict(re.findall(r"^define[^\n]*@" + symbol + r"\([^\n]*\).*?\n(.*?)^}", text, re.M | re.S))
    aliases = dict(re.findall(r"^@" + symbol + r" =[^\n]* alias[^\n]*@" + symbol, text, re.M))
    probes = sorted(name for name in bodies | aliases if name.startswith("probe_"))
    expected = {
        "probe_scalar", "probe_emulated_neon", "probe_emulated_arm_v9",
        "probe_emulated_ice_lake", "probe_nested_scalar", "probe_nested_emulated_neon",
        "probe_nested_emulated_arm_v9", "probe_nested_emulated_ice_lake", "probe_dispatch",
        "probe_slice_scalar", "probe_slice_emulated_neon", "probe_slice_emulated_arm_v9",
        "probe_slice_emulated_ice_lake", "probe_slice_dispatch",
    }
    if re.search(r'target triple = "(?:aarch64|arm64)', text):
        expected.update({
            "probe_native_neon", "probe_nested_native_neon", "probe_outlined_neon",
            "probe_slice_native_neon",
        })
    elif feature_scopes:
        raise RuntimeError("--feature-scopes requires an AArch64 target")
    if missing := expected - set(probes):
        raise RuntimeError(f"missing consumer probes in {ir}: {sorted(missing)}")
    failures = []
    hot_functions = []
    if feature_scopes:
        hot_functions = [name for name in bodies if "execute_neon" in name]
        if not hot_functions:
            raise RuntimeError("missing native feature-scope functions")
    for probe in probes + hot_functions:
        name = probe
        while name in aliases:
            name = aliases[name]
        body = bodies[name]
        code = "\n".join(line.split(";", 1)[0] for line in body.splitlines())
        calls = re.findall(r"\b(?:call|invoke)\b[^\n]+", code)
        # These fixed-size consumers should reduce entirely to loads, adds, and stores.
        # LLVM intrinsics describe optimized instructions rather than function boundaries.
        remaining = [call for call in calls if not re.search(r'@"?llvm\.', call)]
        if feature_scopes and ("native_neon" in probe or probe in {
            "probe_outlined_neon", "probe_dispatch", "probe_slice_dispatch",
        }):
            # A root may detect CPU features and enter one native feature scope.
            # Bodies inside that scope must contain no further adapter or primitive calls.
            remaining = [call for call in remaining if not (
                "execute_neon" in call or ("NativeNeon" in call and "3new" in call)
            )]
        if remaining:
            failures.append(f"{probe}: {', '.join(remaining)}")
    if failures:
        print("SIMD consumer calls remain:\n" + "\n".join(failures), file=sys.stderr)
        return 1
    if feature_scopes:
        print(f"Checked {len(probes)} consumers and {len(hot_functions)} native feature scopes: no inner calls.")
        print("Compile-only NEON-disabled diagnostic; do not execute this binary.")
    else:
        print(f"Checked {len(probes)} separate-crate consumers without LTO: no residual calls.")
    print(f"LLVM IR: {ir}\nAssembly: {ir.with_suffix('.s')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
