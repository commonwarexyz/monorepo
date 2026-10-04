#!/usr/bin/env python3
"""report.py --results DIR --rounds N: sandblaster/bench/shipped-harness/REPORT.md
from a run.sh run (every number comes from the run's result files)."""
import argparse
import json
import math
import os
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../.."))
TAGS = ["default-release", "align-release", "default-release-nooc"]
TAG_TEXT = {
    "default-release": "default layout, overflow checks on (Commonware's release profile)",
    "align-release": "every function and block aligned to 64 bytes, overflow checks on",
    "default-release-nooc": "default layout, overflow checks off",
}
SETS = {
    "varint": "codec's varint (`codec/sandblaster/varint`, module mode: the emitted `varint.rs`)",
    "mmr": "storage's MMR position and peak arithmetic (`storage/sandblaster/mmr`, in place: `iterator.rs` through its lowered copy)",
    "verifier": "storage's Merkle proof verifier, first set (`storage/sandblaster/verifier`, in place: hasher and proof files compiled as written)",
}


def geomean(xs):
    xs = [x for x in xs if x > 0]
    return math.exp(sum(math.log(x) for x in xs) / len(xs)) if xs else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--rounds", type=int, required=True)
    a = ap.parse_args()
    tags = [t for t in TAGS if os.path.exists(os.path.join(a.results, f"bench-{t}.json"))]
    bench = {t: {r["function"]: r for r in json.load(open(os.path.join(a.results, f"bench-{t}.json")))["rows"]} for t in tags}
    same = {t: json.load(open(os.path.join(a.results, f"samecode-{t}.json"))) for t in tags}
    # the looser check (samecode.py --data-blind): every data address dropped
    blind_path = lambda t: os.path.join(a.results, f"samecode-blind-{t}.json")
    blind = {t: json.load(open(blind_path(t))) for t in tags if os.path.exists(blind_path(t))}
    loads = {t: json.load(open(os.path.join(a.results, f"load-{t}.json"))) for t in tags}
    sources = open(os.path.join(a.results, "sources.txt")).read()
    fns = list(bench[tags[0]])
    sets = {f: bench[tags[0]][f]["set"] for f in fns}
    ident = {t: {f: bool(same[t].get(f, {}).get("subj_shipped")) for f in fns} for t in tags}
    ident_aa = {t: {f: bool(same[t].get(f, {}).get("subj_aa")) for f in fns} for t in tags}
    bident = {t: {f: bool(blind.get(t, {}).get(f, {}).get("subj_shipped")) for f in fns} for t in tags}
    bident_aa = {t: {f: bool(blind.get(t, {}).get(f, {}).get("subj_aa")) for f in fns} for t in tags}
    all_ident = all(all(ident[t].values()) for t in tags)
    all_blind = bool(blind) and all(all(bident[t].values()) for t in tags if t in blind) and len(blind) == len(tags)
    data_only = sorted({f for t in tags for f in fns if not ident[t][f] and bident[t][f]})
    base = re.search(r"^base (\S+)", sources, re.M).group(1)
    P = print
    P("# The shipped verified code against the original Commonware functions")
    P()
    P("Written by `sandblaster/bench/shipped-harness/run.sh` (report.py); every number below comes from")
    P("that run's result files (`sandblaster/bench/shipped-harness/results/`). Finish-A, task 4: the code")
    P("commonware-codec and commonware-storage actually compile from sandblaster's emitted and lowered")
    P("copies, timed against the original Commonware functions, in one binary, with an A/A control and the")
    P("machine-code identity check.")
    P()
    P("## Headline")
    P()
    n_id = {t: sum(ident[t].values()) for t in tags}
    if all_ident or all_blind:
        P(f"**The shipped code is the original code.** In every binary all {len(fns)} measured functions")
        P("compiled to the same instructions in the shipped subject as in the original one (the identity")
        P("check, following calls into each subject's own copies of the two crates)" + ("." if all_ident else
          f": {sum(ident[tags[0]].values())} of {len(fns)} identical outright, and the other {len(data_only)} ({', '.join('`' + f + '`' for f in data_only)}) identical except for the"))
        if not all_ident:
            P("addresses of the constant data each copy carries (a jump table, SHA-256's initial state: `samecode.py")
            P("--data-blind`); the A/A pair, the same source compiled twice, differs in exactly the same way.")
        P("Neither check compares the panic messages' constants: each copy has its own, and a panic in")
        P("storage's MMR iterator names the file rustc compiled, the lowered copy, two lines further down")
        P("than the source (its header replaces the three `//!` lines). That is what the sandblaster build")
        P("ships today: codec's varint module is emitted `VERIFIED + LIFTED AS-IS` (a header of comments, then")
        P("the original file byte for byte, then rustc-checked host facts that compile to no code), and")
        P("storage's MMR iterator is compiled through a lowered copy that is the source byte for byte after")
        P("its header (the optimizer found nothing cheaper in either module; the verifier's files, a")
        P("development build, are compiled as written). So every timing difference below is code placement")
        P("and machine noise, and the A/A row shows its size.")
    else:
        P(f"The shipped code is not identical in every function: identical machine code in "
          + ", ".join(f"{n_id[t]} of {len(fns)} ({t})" for t in tags) + ". The rows that differ are marked.")
    P()
    P("| binary | geomean shipped / original, all functions | geomean A/A / original | A/A spread (per function) | identical code, shipped = original (A/A) | identical except data addresses (A/A) | load before → after |")
    P("| --- | ---: | ---: | --- | ---: | ---: | --- |")
    for t in tags:
        rs = [bench[t][f]["shipped_over_orig"] for f in fns]
        aa = [bench[t][f]["aa_over_orig"] for f in fns]
        bl = f"{sum(bident[t].values())} of {len(fns)} ({sum(bident_aa[t].values())})" if t in blind else "not run"
        P(f"| {t} | {geomean(rs):.3f} | {geomean(aa):.3f} | {min(aa):.3f}–{max(aa):.3f} | {n_id[t]} of {len(fns)} ({sum(ident_aa[t].values())}) | {bl} | {loads[t]['before']} → {loads[t]['after']} |")
    P()
    P("Per set (default layout, overflow checks on):")
    P()
    P("| set | functions | geomean shipped / original | geomean A/A / original | identical code | identical except data addresses |")
    P("| --- | ---: | ---: | ---: | ---: | ---: |")
    for s in SETS:
        fs = [f for f in fns if sets[f] == s]
        if not fs:
            continue
        t = tags[0]
        P(f"| {SETS[s]} | {len(fs)} | {geomean([bench[t][f]['shipped_over_orig'] for f in fs]):.3f} | {geomean([bench[t][f]['aa_over_orig'] for f in fs]):.3f} | {sum(ident[t][f] for f in fs)} of {len(fs)} | " + (f"{sum(bident[t][f] for f in fs)} of {len(fs)}" if t in blind else "not run") + " |")
    P()
    P("## Every function")
    P()
    P("Ratios are shipped / original time (< 1: the shipped code is faster); `=` marks a function whose")
    P("shipped and original subjects compiled to the same machine code in that binary, `≈` one whose code")
    P("is the same except for the addresses of each copy's own constant data (`--data-blind`). A/A /")
    P("original is the control: the original code compiled a second time from its own copies.")
    P()
    hdr = "| set | function | " + " | ".join(f"shipped / original [{t}]" for t in tags) + " | " + " | ".join(f"A/A / original [{t}]" for t in tags) + " | rounds p10–p90 [default-release] |"
    P(hdr)
    P("| --- | --- | " + " | ".join("---:" for _ in tags) + " | " + " | ".join("---:" for _ in tags) + " | --- |")
    for f in fns:
        cells = []
        for t in tags:
            r = bench[t][f]["shipped_over_orig"]
            cells.append(("= " if ident[t][f] else "≈ " if bident[t][f] else "") + f"{r:.3f}")
        aa = [f"{bench[t][f]['aa_over_orig']:.3f}" for t in tags]
        rr = sorted(bench[tags[0]][f]["round_ratios_shipped"])
        p10, p90 = rr[round((len(rr) - 1) * 0.1)], rr[round((len(rr) - 1) * 0.9)]
        P(f"| {sets[f]} | `{f}` | " + " | ".join(cells) + " | " + " | ".join(aa) + f" | {p10:.3f}–{p90:.3f} |")
    P()
    aa_same = {t: sum(ident_aa[t].values()) for t in tags}
    P("A/A pairs identical by the check: " + ", ".join(f"{aa_same[t]} of {len(fns)} [{t}]" for t in tags) + ".")
    P()
    P("## What was run")
    P()
    P("- **Subjects** (one crate source, `subject/lib.rs` with `probe.rs`, over each subject's own copies of")
    P("  the two crates, written by `prepare.py` into `gen/`):")
    P(f"  - `original`: commonware-codec and commonware-storage at `{base[:12]}`, the merge base of the sandblaster")
    P("    branch with Commonware's `main` (`git archive`, read-only): the code before sandblaster;")
    P("  - `A/A`: the same again, from its own copies: the noise floor;")
    P("  - `shipped`: the two crates as this worktree builds them, with the files a verified build writes to")
    P("    `OUT_DIR` included where the crates include them (codec's `src/varint.rs` includes the emitted")
    P("    `varint.rs`; storage's `src/merkle/mmr/mod.rs` declares `iterator` by its lowered declaration and")
    P("    includes `mmr-lowered__merkle__mmr__iterator.rs`); only the include paths differ, so rustc compiles")
    P("    the text the host build compiles. The OUT_DIR files and their SHA-256:")
    P()
    P("```text")
    P(sources.strip())
    P("```")
    P()
    P("  Every storage copy links the monorepo's own commonware-codec, as every other crate in its graph does")
    P("  (cryptography's types implement that codec's traits): the varint rows time the codec copies, the MMR")
    P("  and verifier rows the storage copies.")
    P("- **Functions**: the verified functions of the three modules, through their public API (`probe.rs`):")
    P("  varint's `UInt`/`SInt` write, read and encoded size at the verified instances (`u16`, `u32`, `u64`,")
    P("  `i16`, `i32`, `i64`; the `u128`/`i128` instances are declared unverified; a byte slice is read")
    P("  through codec's `Copying` adapter, as codec requires) and `Decoder::feed`; the")
    P("  MMR's `Family` methods (`is_valid_size`, `to_nearest_size`, `location_to_position`,")
    P("  `position_to_location`, `peaks`, `children`, `parent_heights`), `PeakIterator` and the")
    P("  `Position`/`Location` conversions; the verifier's `Standard<Sha256>` leaf and node digests and")
    P("  `Proof::verify_element_inclusion` (whose core is the verified `Subtree::reconstruct_digest`) on a")
    P("  1024-leaf MMR each subject builds with its own code before timing.")
    P("- **Protocol** (the held-out harness's, J11): one workspace profile for all three subjects: rustc -O")
    P("  (opt-level 3), 16 codegen units, no LTO, no target-cpu flag, no PGO; overflow checks on (Commonware's")
    P("  release profile) and, as a second binary, off; a third binary with every function and block aligned")
    P("  to 64 bytes; build scripts optimized, the monorepo's own `build-override` (the one build script is")
    P("  the monorepo's commonware-codec's, which every subject's storage copy shares: it compiles no subject")
    P("  code). `fair-baseline.sh --heldout` is written for the held-out harness's subjects (`subj_rustc`, ..)")
    P("  and refuses any `build-override`, so it does not apply here as it stands; the rest of its rule, one")
    P("  crate source, an A/A subject, the identity check, >= 21 rounds after the differential check, holds")
    P("  by construction of `run.sh` and `src/main.rs`. Inputs: a fixed-seed generator within each function's documented preconditions (valid")
    P("  MMR sizes for the peak functions, leaf counts below 2^62, LEB128 encodings with one in eight corrupted")
    P("  for the readers), plus edge cases; 512 per function. The differential check runs first and must pass;")
    P(f"  then {a.rounds} interleaved rounds (the subject order rotates), 5 samples of about 200 µs per subject per")
    P("  round, the median of the per-round medians. `samecode.py --family` compares the subjects' machine code,")
    P("  following calls into each subject's own copies of the two crates (the addresses of each crate's own")
    P("  panic `Location` and message constants are not compared), and again with `--data-blind` (no data")
    P("  address compared). Stage finish-A widened the first check's panic rule (all of core's panic entry")
    P("  points, the whole argument setup) and taught it the back-references of v0 symbols whose crate names")
    P("  differ in length; the identity results were computed with that version on the timed binaries.")
    try:
        m = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip()
        rv = subprocess.run(["rustc", "-V"], capture_output=True, text=True).stdout.strip()
        P(f"- Machine: {m}; {rv}.")
    except Exception:
        pass
    P()
    P("## Reproducing")
    P()
    P("```sh")
    P("cargo test -p commonware-codec; cargo test -p commonware-storage --lib   # verified builds: their OUT_DIRs")
    P("HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/shipped-harness/run.sh \\")
    P("    --codec-out <codec OUT_DIR> --storage-out <storage OUT_DIR>   # --rounds N (>= 21)")
    P("```")


if __name__ == "__main__":
    main()
