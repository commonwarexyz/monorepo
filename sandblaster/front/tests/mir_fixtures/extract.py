#!/usr/bin/env python3
"""Extracts rustc's MIR of the toolchain's test fixtures (the `*.sbmir` files
next to them) with `sandblaster/mirx/extract.sh --manifest`.

    sandblaster/front/tests/mir_fixtures/extract.py [fixture ..]

Each fixture is a small crate of this workspace whose module a test of
`sandblaster/front/tests` lifts; the test reads the crate's source and the
MIR with `include_str!`. A round-trip entry is the MIR of the lifted round
trip's copy of a lowered module (DESIGN.md §2.1, docs/mir-lift.md §20.1): the
copy is a checked-in file the test's lowering writes (`LoweredModule::
roundtrip_copy`), compiled in place of the module's source (`--replace`).
Re-run an entry when its sources change (the front end refuses a stale
extraction). Without arguments every entry is extracted. The workspace's
members are written from the table below.
"""
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../../../.."))

# (name, crate dir, modules, output (relative to the crate dir), extra args);
# `--replace` paths are relative to the crate dir
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
    # tests/aug_int_toolchain.rs
    ("ai_err", "ai_err", "w", "w.sbmir", []),
    ("ai_signed", "ai_signed", "s", "s.sbmir", []),
    ("ai_panics", "ai_panics", "s", "s.sbmir", []),
    ("ai_lit", "ai_lit", "s", "s.sbmir", []),
    ("ai_ref_add", "ai_ref_add", "s", "s.sbmir", []),
    ("ai_ref_lt", "ai_ref_lt", "s", "s.sbmir", []),
    ("ai_ref_widen", "ai_ref_widen", "s", "s.sbmir", []),
    ("ai_ref_abs", "ai_ref_abs", "s", "s.sbmir", []),
    # tests/lift_opt.rs (and tests/build_loop.rs: `opt_mbits`)
    ("opt_bits", "opt_bits", "bits", "bits.sbmir", []),
    ("opt_driven", "opt_driven", "bits", "bits.sbmir", []),
    ("opt_driven_more", "opt_driven_more", "bits", "bits.sbmir", []),
    ("opt_driven_taken", "opt_driven_taken", "bits", "bits.sbmir", []),
    ("opt_mbits", "opt_mbits", "bits", "bits.sbmir", []),
    ("opt_mbits_cheap", "opt_mbits_cheap", "bits", "bits.sbmir", []),
    ("opt_buf", "opt_buf", "bits", "bits.sbmir", []),
    ("opt_gen2", "opt_gen2", "bits", "bits.sbmir", []),
    ("opt_gen2_more", "opt_gen2_more", "bits", "bits.sbmir", []),
    ("opt_rd", "opt_rd", "bits", "bits.sbmir", []),
    ("opt_panics", "opt_panics", "bits", "bits.sbmir", []),
    ("opt_shipped", "opt_shipped", "bits", "bits.sbmir", []),
    ("opt_ip_mod", "opt_ip_mod", "bits,opt", "bits.sbmir", ["--inject", "opt=opt.rs"]),
    ("opt_ip_inplace", "opt_ip_inplace", "bits,opt", "bits.sbmir", ["--inject", "opt=opt.rs"]),
    # tests/build_loop.rs
    ("bl_mbits_edited", "bl_mbits_edited", "bits", "bits.sbmir", []),
    # tests/in_place_cache.rs
    ("ic_two", "ic_two", "a", "a.sbmir", []),
    # tests/reader_widen.rs
    ("rw_mix", "rw_mix", "a", "a.sbmir", []),
    # tests/lowered_use.rs
    ("lu_nested", "lu_nested", "outer,opt", "bits.sbmir", ["--inject", "opt=opt.rs"]),
    ("lu_nested_line", "lu_nested_line", "outer,opt", "bits.sbmir", ["--inject", "opt=opt.rs"]),
    ("lu_nested_mod", "lu_nested_mod", "outer,opt", "bits.sbmir", ["--inject", "opt=opt.rs"]),
    ("lu_top", "lu_top", "bits,opt", "bits.sbmir", ["--inject", "opt=opt.rs"]),
    ("lu_hostmod", "lu_hostmod", "outer", "bits.sbmir", ["--items", "outer::bits="]),
]

# The module source each lowering fixture's round-trip copies replace: every
# `rt*.rs` of the crate (a copy a test's lowering wrote) gets the entry
# `<crate>/<rt>` writing `<rt>.sbmir` (`--replace <source>=<rt>.rs`).
RT_SOURCE = {
    "opt_bits": "bits.rs",
    "opt_driven": "bits.rs",
    "opt_driven_more": "bits.rs",
    "opt_driven_taken": "bits.rs",
    "opt_mbits": "bits.rs",
    "opt_buf": "bits.rs",
    "opt_gen2": "bits.rs",
    "opt_gen2_more": "bits.rs",
    "opt_rd": "bits.rs",
    "opt_panics": "bits.rs",
    "opt_shipped": "bits.rs",
    "opt_ip_mod": "bits.rs",
    "opt_ip_inplace": "src/bits.rs",
    "bl_mbits_edited": "bits.rs",
    "lu_nested": "src/outer/bits.rs",
    "lu_nested_line": "src/outer/bits.rs",
    "lu_top": "src/bits.rs",
}

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


def entries():
    """The fixtures and the round-trip copies found next to them."""
    out = []
    for name, crate, modules, out_file, extra in FIXTURES:
        out.append((name, crate, modules, out_file, extra))
        src = RT_SOURCE.get(crate)
        if src is None:
            continue
        for f in sorted(os.listdir(os.path.join(HERE, crate))):
            if f.startswith("rt") and f.endswith(".rs"):
                rt = f[:-3]
                out.append((f"{crate}/{rt}", crate, modules, f"{rt}.sbmir", extra + ["--replace", f"{src}={f}"]))
    return out


def main():
    write_workspace()
    want = set(sys.argv[1:])
    table = entries()
    unknown = {w for w in want if w not in {f[0] for f in table} and w not in {f[1] for f in table}}
    if unknown:
        raise SystemExit(f"unknown fixture(s): {sorted(unknown)}")
    manifest = os.path.join(HERE, "Cargo.toml")
    failed = []
    for name, crate, modules, out, extra in table:
        # a crate's name selects its fixture and its round-trip copies
        if want and name not in want and crate not in want:
            continue
        args = list(extra)
        for i, a in enumerate(args):
            if i > 0 and args[i - 1] == "--replace":
                src, text = a.split("=", 1)
                args[i] = f"{os.path.join(HERE, crate, src)}={os.path.join(HERE, crate, text)}"
            if i > 0 and args[i - 1] == "--inject":
                mname, file = a.split("=", 1)
                args[i] = f"{mname}={os.path.join(HERE, crate, file)}"
        cmd = [os.path.join(ROOT, "sandblaster/mirx/extract.sh"), package(crate), modules, os.path.join(HERE, crate, out), "--manifest", manifest] + args
        print(f"== {name}", flush=True)
        if subprocess.run(cmd).returncode != 0:
            failed.append(name)
    # (a round-trip copy of a faulty printer may not compile: rustc refuses
    # it, so it has no MIR and the round trip cannot read it back)
    if failed:
        raise SystemExit(f"not extracted: {failed}")


if __name__ == "__main__":
    main()
