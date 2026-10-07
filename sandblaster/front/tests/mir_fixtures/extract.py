#!/usr/bin/env python3
"""Extracts rustc's MIR of the toolchain's test fixtures (the `*.sbmir` files
next to them) with `sandblaster/mirx/extract.sh --manifest`.

    sandblaster/front/tests/mir_fixtures/extract.py [fixture ..]

Each fixture is a small crate of this workspace whose module a test of
`sandblaster/front/tests` lifts; the test reads the crate's source and the
MIR with `include_str!`. Re-run an entry when its sources change (the front
end refuses a stale extraction). Without arguments every entry is extracted. The workspace's
members are written from the table below.
"""
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../../../.."))

# (name, crate dir, modules, output (relative to the crate dir), extra args);
# `--inject` paths are relative to the crate dir
FIXTURES = [
    # tests/lift.rs
    ("lift_w", "lift_w", "w", "w.sbmir", []),
    # tests/lift_conformance.rs
    ("conf_w", "conf_w", "w", "w.sbmir", []),
    ("conf_w64", "conf_w64", "w", "w.sbmir", []),
    ("conf_m", "conf_m", "m", "m.sbmir", []),
    ("conf_inplace", "conf_inplace", "a", "a.sbmir", []),
    # tests/lift_open.rs
    ("lo_open_small", "lo_open_small", "a", "a.sbmir", ["--instance", "Fam=a::Small"]),
    ("lo_open_big9", "lo_open_big9", "a", "a.sbmir", ["--instance", "Fam=a::Big"]),
    ("lo_ops", "lo_ops", "a", "a.sbmir", []),
    ("lo_iter", "lo_iter", "a", "a.sbmir", []),
    ("lo_walk", "lo_walk", "a", "a.sbmir", []),
    ("lo_halve", "lo_halve", "a", "a.sbmir", []),
    ("lo_asserts", "lo_asserts", "a", "a.sbmir", []),
    ("lo_hosty", "lo_hosty", "a", "a.sbmir", []),
    ("lo_partly", "lo_partly", "a", "a.sbmir", []),
    ("lo_partly_call", "lo_partly_call", "a", "a.sbmir", []),
    ("lo_two", "lo_two", "a", "a.sbmir", []),
    ("lo_expect", "lo_expect", "a", "a.sbmir", []),
    ("lo_safe", "lo_safe", "a", "a.sbmir", []),
    # tests/lift_verifier.rs
    ("lv_items", "lv_items", "a", "a.sbmir", []),
    ("lv_tr", "lv_tr", "a", "a.sbmir", ["--instance", "Mix=a::Std"]),
    ("lv_er", "lv_er", "a", "a.sbmir", ["--instance", "Fam=host::Mark,Word=host::W,HashFn=host::Hw"]),
    ("lv_st", "lv_st", "a", "a.sbmir", ["--instance", "Iterator=Elements"]),
    ("lv_wb", "lv_wb", "a", "a.sbmir", []),
    ("lv_bump", "lv_bump", "a", "a.sbmir", []),
    ("lv_rec", "lv_rec", "a", "a.sbmir", []),
    ("lv_inv", "lv_inv", "a", "a.sbmir", []),
    # tests/mmr_toolchain.rs
    ("mt_derived", "mt_derived", "a", "a.sbmir", []),
    ("mt_qualified", "mt_qualified", "a", "a.sbmir", []),
    ("mt_half", "mt_half", "a", "a.sbmir", []),
    ("mt_pair", "mt_pair", "a", "a.sbmir", []),
    ("mt_cmp", "mt_cmp", "a", "a.sbmir", []),
    ("mt_ord", "mt_ord", "a", "a.sbmir", ["--skip-traits", "Debug,Display,Hash"]),
    # tests/lock_surface.rs
    ("lk_prim", "lk_prim", "a", "a.sbmir", []),
    ("lk_paths", "lk_paths", "a,b", "ab.sbmir", []),
    ("lk_host", "lk_host", "a,b", "ab.sbmir", ["--skip-fns", "Tick::left_out", "--items", "a::child="]),
    ("lk_rec", "lk_rec", "a", "a.sbmir", ["--skip-fns", "Pos::left_out"]),
    # tests/aug_int_toolchain.rs
    ("ai_err", "ai_err", "w", "w.sbmir", []),
    ("ai_signed", "ai_signed", "s", "s.sbmir", []),
    ("ai_panics", "ai_panics", "s", "s.sbmir", []),
    ("ai_lit", "ai_lit", "s", "s.sbmir", []),
    ("ai_ref_add", "ai_ref_add", "s", "s.sbmir", []),
    ("ai_ref_lt", "ai_ref_lt", "s", "s.sbmir", []),
    ("ai_ref_widen", "ai_ref_widen", "s", "s.sbmir", []),
    ("ai_ref_abs", "ai_ref_abs", "s", "s.sbmir", []),
    # tests/build_loop.rs (`opt_mbits`: the name is kept so its MIR stays as extracted)
    ("opt_mbits", "opt_mbits", "bits", "bits.sbmir", []),
    # tests/build_loop.rs
    ("bl_mbits_edited", "bl_mbits_edited", "bits", "bits.sbmir", []),
    # tests/in_place_cache.rs
    ("ic_two", "ic_two", "a", "a.sbmir", []),
    # tests/reader_widen.rs
    ("rw_mix", "rw_mix", "a", "a.sbmir", []),
    # tests/refined_model.rs: the original, its optimization, a wrong optimization
    ("rm_orig", "rm_orig", "a", "a.sbmir", []),
    ("rm_fast", "rm_fast", "a", "a.sbmir", []),
    ("rm_wrong", "rm_wrong", "a", "a.sbmir", []),
    # tests/panic_contracts.rs: documented panics as panic contracts
    ("pc_guard", "pc_guard", "a", "a.sbmir", []),
    # tests/simd.rs: `core::arch` code read from MIR (C8, docs/mir-lift.md §20.9)
    ("sd_neon", "sd_neon", "a", "a.sbmir", []),
    ("sd_neon_shift", "sd_neon_shift", "a", "a.sbmir", []),
    ("sd_neon_lane", "sd_neon_lane", "a", "a.sbmir", []),
    ("sd_neon_ptr", "sd_neon_ptr", "a", "a.sbmir", []),
    ("sd_neon_nomodel", "sd_neon_nomodel", "a", "a.sbmir", []),
    ("sd_neon_detect", "sd_neon_detect", "a", "a.sbmir", []),
    ("sd_x86", "sd_x86", "a", "a.sbmir", ["--target", "x86_64-apple-darwin"]),
    # tests/unsafe_simd.rs: existing `unsafe` read through the narrow reading of
    # raw pointers (docs/DESIGN-UNSAFE-SIMD.md); each with its window
    # extraction (`--mir-opt-level 0`, the window rule's input)
    ("sd_ptr", "sd_ptr", "a", "a.sbmir", []),
    ("sd_ptr_window", "sd_ptr", "a", "a.window.sbmir", ["--mir-opt-level", "0"]),
    ("sd_ptr_twins", "sd_ptr_twins", "a", "a.sbmir", []),
    ("sd_ptr_twins_window", "sd_ptr_twins", "a", "a.window.sbmir", ["--mir-opt-level", "0"]),
    # tests/simd.rs: Reed–Solomon's NEON `mul_128` shape (table rows loaded
    # through shared pointers, TBL lookups proven lane by lane), and its twins
    ("sd_neon_mul128", "sd_neon_mul128", "a", "a.sbmir", []),
    ("sd_neon_mul128_window", "sd_neon_mul128", "a", "a.window.sbmir", ["--mir-opt-level", "0"]),
    ("sd_neon_mul128_shift", "sd_neon_mul128_shift", "a", "a.sbmir", []),
    ("sd_neon_mul128_shift_window", "sd_neon_mul128_shift", "a", "a.window.sbmir", ["--mir-opt-level", "0"]),
    ("sd_neon_mul128_row", "sd_neon_mul128_row", "a", "a.sbmir", []),
    ("sd_neon_mul128_row_window", "sd_neon_mul128_row", "a", "a.window.sbmir", ["--mir-opt-level", "0"]),
]

# crates of the workspace that are dependencies only (no MIR of their own)
DEPENDENCIES = ["fx_codec", "fx_cfg_if", "fx_hosts"]


def package(crate):
    for line in open(os.path.join(HERE, crate, "Cargo.toml")):
        if line.startswith("name = "):
            return line.split('"')[1]
    raise SystemExit(f"{crate}: no package name")


def write_workspace():
    crates = sorted({c for _, c, _, _, _ in FIXTURES} | set(DEPENDENCIES))
    members = "".join(f'    "{c}",\n' for c in crates)
    text = (
        "# The toolchain's own MIR fixtures (sandblaster/front/tests): small crates\n"
        "# whose modules the front end's tests lift, with rustc's MIR checked in\n"
        "# next to them (`*.sbmir`; regenerate with `extract.py`, which writes this\n"
        "# member list). Not part of the monorepo's workspace: nothing here is\n"
        "# built by the workspace build.\n"
        f'[workspace]\nresolver = "2"\nmembers = [\n{members}]\n'
    )
    open(os.path.join(HERE, "Cargo.toml"), "w").write(text)


def main():
    write_workspace()
    want = set(sys.argv[1:])
    table = FIXTURES
    unknown = {w for w in want if w not in {f[0] for f in table} and w not in {f[1] for f in table}}
    if unknown:
        raise SystemExit(f"unknown fixture(s): {sorted(unknown)}")
    manifest = os.path.join(HERE, "Cargo.toml")
    failed = []
    for name, crate, modules, out, extra in table:
        # a crate's name selects its fixture
        if want and name not in want and crate not in want:
            continue
        args = list(extra)
        for i, a in enumerate(args):
            if i > 0 and args[i - 1] == "--inject":
                mname, file = a.split("=", 1)
                args[i] = f"{mname}={os.path.join(HERE, crate, file)}"
        cmd = [os.path.join(ROOT, "sandblaster/mirx/extract.sh"), package(crate), modules, os.path.join(HERE, crate, out), "--manifest", manifest] + args
        print(f"== {name}", flush=True)
        if subprocess.run(cmd).returncode != 0:
            failed.append(name)
    if failed:
        raise SystemExit(f"not extracted: {failed}")


if __name__ == "__main__":
    main()
