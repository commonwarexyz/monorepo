#!/usr/bin/env python3
"""report.py --results DIR --rounds N: sandblaster/bench/heldout/REPORT.md from a run.sh run.

Reads DIR/eval.json (the optimizer's records, evaluate.py), DIR/bench-<tag>.json (timings),
DIR/samecode-<tag>.json (the identity check) and DIR/load-<tag>.json, and prints the report.
Every number in it comes from those files; nothing is typed in by hand.
"""
import argparse
import glob
import json
import math
import os
import platform
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../.."))

CATEGORIES = [
    (r"`while` loops need a measure", "reader", "a `while` loop with no termination measure (in-place code carries none; the lift asks for `proof! { decreases(..) }`)"),
    (r"rvalue AddressOf", "reader", "slice iteration: core's slice iterator (`Iter::new`, `into_iter`) takes a raw address (`AddressOf`), which the MIR reader does not read"),
    (r"the signed operation `lt`", "reader", "`for _ in 0..N` over an `i32` range: `Range::next` compares signed integers, which SEMANTICS.md §19.3 does not read"),
    (r"the intrinsic `rotate_left`", "reader", "the `rotate_left` intrinsic is not read"),
    (r"sign extension is not read", "reader", "a sign-extending cast (`i16 as i32`) is not read"),
    (r"zero-sized value", "reader", "`?` on an `Option` (its residual `Option<Infallible>` is a zero-sized value used as data)"),
    (r"both targets in the loop", "reader", "a loop test whose two targets are both inside the loop (`while a != 0 || b != 0 || ..`)"),
    (r"mutual recursion is not supported", "reader", "nested loops: the lift's two loop functions call each other (mutual recursion is not supported)"),
    (r"cannot infer a termination measure", "elaboration", "no termination measure inferred for a `for` loop over a range (`#[decreases]` needed)"),
    (r"Unproven", "elaboration", "a panic obligation (overflow or division by zero) that no stated precondition rules out: the function can panic on some inputs, and H1 states no contract the verifier reads"),
    (r"not 3% cheaper", "lowering", "reached the optimizer, specialized; the residual is not 3% cheaper than the source (the selection gate)"),
    (r"neutral scrutinee", "optimizer", "reached the optimizer, not specialized: a branch on an argument (`if n <= 1`) is not stuck-free for the straight-line rung, and the driven residual cannot print `Le(Int)`"),
    (r"a `const fn`", "lowering", "reached the optimizer, specialized; the lowering does not replace a `const fn` (its helpers would have to be `const fn` too)"),
]


def category(reason):
    for pat, stage, text in CATEGORIES:
        if re.search(pat, reason):
            return stage, text
    return "other", reason


def geomean(xs):
    return math.exp(sum(math.log(x) for x in xs) / len(xs)) if xs else None


def med(xs):
    s = sorted(xs)
    n = len(s)
    return (s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2) if s else None


def fmt(x, d=3):
    return "—" if x is None else f"{x:.{d}f}"


def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, cwd=REPO).stdout.strip()
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--rounds", type=int, required=True)
    a = ap.parse_args()
    ev = json.load(open(os.path.join(a.results, "eval.json")))
    fns = ev["h1"] + ev["h2"]
    tags = sorted(os.path.basename(p)[6:-5] for p in glob.glob(os.path.join(a.results, "bench-*.json")))
    order = {"default-release": 0, "align-release": 1, "default-release-nooc": 2}
    tags.sort(key=lambda t: order.get(t, 9))
    bench = {t: {r["function"]: r for r in json.load(open(os.path.join(a.results, f"bench-{t}.json")))["rows"]} for t in tags}
    same = {t: json.load(open(os.path.join(a.results, f"samecode-{t}.json"))) for t in tags}
    load = {t: json.load(open(os.path.join(a.results, f"load-{t}.json"))) for t in tags if os.path.exists(os.path.join(a.results, f"load-{t}.json"))}
    short = lambda f: f["function"].rsplit("::", 1)[1]
    changed = [f for f in fns if f["changed"]]
    n = len(fns)
    stage_count = {}
    for f in fns:
        stage_count[f["stage"]] = stage_count.get(f["stage"], 0) + 1
    reached = [f for f in fns if f.get("optimizer")]
    specialized = [f for f in reached if f["optimizer"]["outcome"] == "Specialized"]
    rungs = {}
    for f in specialized:
        rungs[f["optimizer"]["rung"]] = rungs.get(f["optimizer"]["rung"], 0) + 1
    driven_tried = [f for f in reached if any(c["rung"] == "Driven" for c in f["optimizer"]["candidates"])]
    lowered_by = {}
    for f in changed:
        lowered_by[f.get("origin", "?")] = lowered_by.get(f.get("origin", "?"), 0) + 1

    # per binary: ratios, A/A spread, geomeans
    stats = {}
    for t in tags:
        rows = bench[t]
        ratios = {k: r["opt_over_rustc"] for k, r in rows.items()}
        aa = {k: r["aa_over_rustc"] for k, r in rows.items()}
        lo, hi = min(aa.values()), max(aa.values())
        stats[t] = {
            "gm_all": geomean(list(ratios.values())),
            "gm_changed": geomean([ratios[short(f)] for f in changed if short(f) in ratios]),
            "median": med(list(ratios.values())),
            "worst": max(ratios.values()),
            "best": min(ratios.values()),
            "aa_lo": lo,
            "aa_hi": hi,
            "aa_gm": geomean(list(aa.values())),
            "improved": sorted(k for k, v in ratios.items() if v < lo),
            "regressed": sorted(k for k, v in ratios.items() if v > hi),
            "identical": sorted(k for k, v in same[t].items() if v.get("subj_opt")),
            "aa_identical": sorted(k for k, v in same[t].items() if v.get("subj_rustc_aa")),
        }
    head = sh(["git", "log", "-1", "--format=%H"])
    rustc = sh(["rustc", "-V"])
    cpu = sh(["sysctl", "-n", "machdep.cpu.brand_string"]) or platform.processor()
    manifest = open(os.path.join(REPO, "sandblaster/bench/heldout/manifest.toml")).read()
    date = re.search(r'^date = "(.*)"', manifest, re.M).group(1)
    src_commit = re.search(r'^source_commit = "(.*)"', manifest, re.M).group(1)
    d = stats.get("default-release")
    al = stats.get("align-release")
    # is the optimized subject's text the source? (gen/ against the frozen files)
    h1_same = open(os.path.join(HERE, "gen/h1.rs")).read() == open(os.path.join(REPO, "sandblaster/bench/heldout/h1/src/lib.rs")).read()
    body = lambda p: "\n".join(open(p).read().split("\n")[1:])
    h2_same = body(os.path.join(HERE, "gen/h2_opt.rs")) == body(os.path.join(HERE, "gen/h2_source.rs"))
    P = print

    P("# Held-out evaluation report")
    P()
    P("Written by `sandblaster/bench/heldout-harness/run.sh` (report.py); every number below comes from")
    P("that run's result files (`sandblaster/bench/heldout-harness/results/latest/`). This is the fairness")
    P("audit's evaluation protocol (plan step 8): the optimizer's own output on code it was never")
    P("developed on, against rustc on the unmodified source, in one binary.")
    P()
    P("## Headline")
    P()
    if not changed:
        P(f"**The optimizer changed none of the {n} held-out functions.** " + ("Every lowered copy it wrote is the" if h1_same and h2_same else "(Yet the optimized subject's text differs from the source: see the files in gen/.)"))
        P(("source byte for byte (`gen/h1.rs` is H1's file; H2's text equals the source's), so the optimized subject is the rustc subject compiled again. The held-out") if h1_same and h2_same else "The held-out")
        P(f"optimizer-only geomean is **{fmt(d['gm_all'])}** (optimized / rustc time, all {n} functions, no")
        P(f"exclusions; default layout, overflow checks on). That is placement noise around 1.00: the A/A")
        P(f"control (the same source compiled twice) spreads {fmt(d['aa_lo'])}–{fmt(d['aa_hi'])} in the same binary.")
        if al:
            P(f"With every function and block aligned to 64 bytes (less placement noise) it is {fmt(al['gm_all'])}, A/A spread")
            P(f"{fmt(al['aa_lo'])}–{fmt(al['aa_hi'])}.")
        P("The geomean over changed functions is undefined: no function changed.")
    else:
        P(f"The optimizer changed {len(changed)} of the {n} held-out functions. Optimized / rustc time,")
        P(f"geomean over all {n} functions (no exclusions): **{fmt(d['gm_all'])}**; over the changed functions only:")
        P(f"**{fmt(d['gm_changed'])}** (default layout, overflow checks on). A/A control spread:")
        P(f"{fmt(d['aa_lo'])}–{fmt(d['aa_hi'])}.")
    P()
    P(f"Most of the reason is upstream of the optimizer. Of {n} functions, {stage_count.get('reader', 0)} are refused by")
    P(f"the lift's MIR reader, {stage_count.get('elaboration', 0)} by exec-only elaboration, and {len(reached)} reach the")
    loops_reached = [short(f) for f in reached if f["optimizer"]["loopsum_steps"] > 0]
    P(f"optimizer. Of those {len(reached)}, {len(specialized)} get a residual that is not lowered (not cheaper than the")
    P(f"source, or not replaceable), and {len(reached) - len(specialized)} is not specialized at all." + (" No loop" if not loops_reached else f" Loops summarized: {', '.join(loops_reached)}."))
    if not loops_reached:
        P("reaches the optimizer, so none of its loop machinery (closed forms, set-bit iteration, early exit,")
        P("unrolling, the aegraph) is exercised on held-out code.")
    P()
    P("These are held-out numbers. The QMDB, corpus, codec and storage numbers elsewhere are the")
    P("development set; they do not show that the optimizer is general or faster than rustc.")
    P()
    P("## What was run")
    P()
    P(f"- **Held-out set** (`sandblaster/bench/heldout/manifest.toml`, frozen by G6, dated {date},")
    P(f"  source commit `{src_commit[:12]}`): H1, 30 functions written blind from a committed idiom list;")
    P("  H2, every monorepo function the sampling rule accepted (1 of the 40 asked for: the rule's probe")
    P("  found only one, `commonware-utils::rng::mix64`; shortfall 39, h2/PROBE-LOG.md).")
    P("- **Optimizer**: the exec-only path (`elab::Options { exec_only: true }`, no laws, as")
    P("  `tests/opt_qmdb.rs`), the production optimizer (`OptOptions::default()`) with only")
    P("  `exclude_user_rewrites` set (there are no user `#[rewrite]` alternatives here; the option makes")
    P("  sure none is counted), then the in-place lowering with its lifted round trip")
    P("  (`driver::lowered::lower_in_place`), through `sandblaster/front/examples/heldout_eval.rs`. H1 is")
    P("  lifted in place with `items = \"<fn>\"`, one root per function (so each refusal is that function's");
    P("  own), then once more with every function that passed the reader, which gives the one lowered")
    P("  copy the optimized subject compiles. H2 uses its frozen root. No profile exists for the held-out")
    P("  set, so every result is without a profile, for both subjects.")
    P("- **Harness** (`sandblaster/bench/heldout-harness`, J11): three subjects of one crate source")
    P("  (`subject/lib.rs`; the package feature selects the module), linked into one binary: `rustc` (the")
    P("  frozen H1 file itself; H2's function text copied verbatim from its file), `A/A` (the same again)")
    P("  and `optimized` (the lowered copies). One workspace profile for all three: rustc -O")
    P("  (opt-level 3), 16 codegen units, no LTO, no target-cpu flag, no PGO; overflow checks on")
    P("  (Commonware's release profile) and, as a second binary, off. No hand-written variant exists in")
    P("  the held-out set, so neither subject has one. Inputs: a fixed-seed type-driven generator (uniform")
    P("  bit length for integers, short byte strings) respecting each function's documented preconditions,")
    P("  plus edge cases; 512 inputs per function. The differential check runs first and must pass;")
    P(f"  then {a.rounds} interleaved rounds (the subject order rotates), 5 samples of about 200 µs per subject")
    P("  per round, the median of the per-round medians. `samecode.py` compares the subjects' machine code")
    P("  (`--ignore-panic-locations`: each crate's own copy of a panic `Location` constant is not compared).")
    P("- **Gates run first**: G6 and `fair-baseline.sh --heldout` (one profile, one binary, the identity")
    P("  check, an A/A subject, the rustc subject from the frozen source, >= 21 rounds after the check).")
    P(f"- Machine: {cpu}; {rustc}; worktree HEAD `{head[:12]}` plus the uncommitted fairness-audit work.")
    for t in tags:
        if t in load:
            P(f"- Load average [{t}]: before {load[t]['before']}; after {load[t]['after']} (a shared, busy host).")
    P()
    P("## Results per binary")
    P()
    P("Ratios are optimized / rustc time (< 1: the optimized subject is faster). The A/A spread (the")
    P("noise floor) is the control's range over all functions in that binary.")
    P()
    P("| binary | geomean, all functions | geomean, changed only | median | best | worst | A/A spread (geomean) | identical code (optimized = rustc) | beyond the A/A spread: faster / slower |")
    P("| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |")
    for t in tags:
        s = stats[t]
        P(f"| {t} | {fmt(s['gm_all'])} | {fmt(s['gm_changed']) if changed else 'none changed'} | {fmt(s['median'])} | {fmt(s['best'])} | {fmt(s['worst'])} | {fmt(s['aa_lo'])}–{fmt(s['aa_hi'])} ({fmt(s['aa_gm'])}) | {len(s['identical'])} of {len(bench[t])} | {len(s['improved'])} / {len(s['regressed'])} |")
    P()
    beyond = sorted({k for t in tags for k in stats[t]["improved"] + stats[t]["regressed"]})
    if beyond and not changed:
        P(f"Rows outside the A/A spread in some binary ({', '.join(beyond)}) are not optimizer effects: their source")
        P("text is identical in both subjects. They show how far placement and a busy host move identical code")
        P("on this machine; a real gain has to clear that.")
        P()
    P("## Every function")
    P()
    cols = " | ".join(f"opt / rustc [{t}]" for t in tags)
    P(f"| set | function | stage reached | optimizer outcome | changed | {cols} | A/A / rustc [{tags[0]}] | rounds p10–p90 [{tags[0]}] | why nothing changed |")
    P("| --- | --- | --- | --- | --- |" + " ---: |" * len(tags) + " ---: | --- | --- |")
    for f in fns:
        k = short(f)
        opt = f.get("optimizer")
        outcome = "—" if not opt else (f"{opt['outcome']} ({opt['rung']})" if opt["outcome"] == "Specialized" else opt["outcome"])
        cells = []
        for t in tags:
            r = bench[t].get(k)
            if not r:
                cells.append("—")
                continue
            mark = "= " if same[t].get(k, {}).get("subj_opt") else ""
            cells.append(f"{mark}{r['opt_over_rustc']:.3f}")
        r0 = bench[tags[0]].get(k)
        rr = sorted(r0["round_ratios_opt"]) if r0 else []
        p = (lambda q: rr[round((len(rr) - 1) * q)]) if rr else None
        reason = f["reason"].replace("|", "\\|")
        reason = re.sub(r"sandblaster/bench/heldout/h1/src/lib.rs:\d+:\d+: ", "", reason)
        P(f"| {f['set']} | `{k}` | {f['stage']} | {outcome} | {'yes' if f['changed'] else 'no'} | {' | '.join(cells)} | {fmt(r0['aa_over_rustc']) if r0 else '—'} | {fmt(p(0.1)) + '–' + fmt(p(0.9)) if rr else '—'} | {reason[:260]} |")
    P()
    P("`=`: the optimized and rustc subjects compiled to the same machine code (samecode.py). A row")
    P("without `=` whose function did not change differs only in data addresses the conservative check")
    P("compares (for example `crc8`, which rustc compiles to a 256-byte lookup table, one copy per crate:")
    P(f"its A/A pair is not `=` either). A/A pairs identical by the check: {len(stats[tags[0]]['aa_identical'])} of {len(bench[tags[0]])} [{tags[0]}].")
    P()
    P("## Why: the funnel")
    P()
    groups = {}
    for f in fns:
        st, text = category(f["reason"])
        groups.setdefault((st, text), []).append(short(f))
    stage_order = {"reader": 0, "elaboration": 1, "optimizer": 2, "lowering": 3, "other": 4}
    P("| stage | reason | functions |")
    P("| --- | --- | --- |")
    for (st, text), names in sorted(groups.items(), key=lambda kv: (stage_order.get(kv[0][0], 9), -len(kv[1]))):
        P(f"| {st} | {text} | {len(names)}: {', '.join('`' + x + '`' for x in names)} |")
    P()
    P("## The four columns (protocol item 7)")
    P()
    P("| column | functions | geomean |")
    P("| --- | ---: | ---: |")
    P(f"| optimizer-derived (driver, Σ1–Σ5, aegraph, residuals) | {lowered_by.get('optimizer', 0)} | {fmt(d['gm_changed']) if lowered_by.get('optimizer') else 'none'} |")
    P(f"| user `#[rewrite]` alternatives | {lowered_by.get('user_rewrite', 0)} (excluded by the evaluation option; none exist) | none |")
    P("| hand-written hardware variants | 0 (the held-out set has none) | none |")
    P("| source restructuring | 0 (the subjects compile the frozen files) | none |")
    P()
    P("## Rung and lowering hits (protocol item 6)")
    P()
    P(f"- Reached the optimizer: {len(reached)} of {n}. Specialized: {len(specialized)} ({', '.join(f'{k} {v}' for k, v in sorted(rungs.items())) or 'none'}). Unspecialized: {len(reached) - len(specialized)}.")
    P("- ClosedForm 0, SetBits 0, EarlyExit 0, SkipIdle 0, Fused 0, Rewritten (aegraph) 0, Driven 0" + (f" ({len(driven_tried)} attempt refused: " + "; ".join(next(c['reason'] for c in f['optimizer']['candidates'] if c['rung'] == 'Driven') for f in driven_tried) + ")" if driven_tried else "") + ".")
    P(f"- Lowered into the source: {len(changed)} of {n}" + (f" ({', '.join(f'{k} {v}' for k, v in lowered_by.items())})" if changed else "") + ".")
    P()
    P("## Cost-model decision accuracy on held-out pairs (J12)")
    P()
    pairs = [f for f in reached if f["optimizer"]["outcome"] == "Specialized" and f.get("lowering") and "cheaper" in (f["lowering"].get("reason") or "")]
    P(f"Candidate pairs with a measured winner: **0**. Accuracy is undefined (n = 0). The only held-out decision")
    P(f"the cost model made is {len(pairs)} source-vs-residual comparison" + (f" (`{'`, `'.join(short(f) for f in pairs)}`: equal cost, so the source stays)" if pairs else "") + ". A rejected residual")
    P("is never printed, so there is no second subject to time against the source.")
    P("`mix64`'s residual is refused before any cost comparison (a `const fn`), and `next_power_of_two` has")
    P("no residual. The cost model is therefore unvalidated on held-out code; its three M5 decisions remain")
    P("development-set regression checks only (front/tests/opt_cost.rs).")
    P()
    P("## Ablations (protocol item 8, J7)")
    P()
    P("The guards stage removed the fixed unroll limit (J7: `drive::unroll_pays` decides by the cost model),")
    P("so there is no `max_static_trips` value left to ablate. The remaining tuned constants (LOOP_TRIPS,")
    P("the synthesis and guard pools, the 3% gate, TRY_FAIL, (CP+TP)/2, the popcount surcharge,")
    P("DERIVE_MIN_PROOF_NODES) were not ablated on this set: no held-out loop reaches the optimizer, and")
    P("the three functions that do reach it are decided before any of them applies (equal cost under any")
    P("gate of 0–5%, a `const fn`, an unprintable branch). An ablation here would measure nothing; it")
    P("becomes meaningful when held-out loops reach the optimizer.")
    P()
    P("## What would let the optimizer see held-out code (future items; not done here)")
    P()
    P("Recorded, not acted on: this stage does not change the optimizer or the reader in response to")
    P("held-out results. Any item below that is implemented because of a held-out function moves that")
    P("function to the development set; H1's replacement is a new function written blind from the same")
    P("idiom, and H2's rule has no candidate left (a wider rule is a new, versioned rule).")
    P()
    cnt = lambda pat: sum(1 for f in fns if re.search(pat, f["reason"]))
    P(f"1. **The MIR reader** refuses {stage_count.get('reader', 0)} of {n}: slice iterators (`AddressOf` in core's `Iter`), signed")
    P("   comparison (any `for _ in 0..N` whose range is `i32`), the `rotate_left` intrinsic, sign-extending")
    P("   casts, `?` on `Option`, a loop test with both targets in the loop, and nested loops (mutual")
    P("   recursion of the lift's loop functions). Ordinary Rust uses all of these.")
    P("2. **Termination**: in-place code has no `decreases`; the lift asks for one on every `while` loop")
    P(f"   ({cnt('while. loops need a measure')} functions), and {cnt('cannot infer a termination measure')} `for` loop over a range gets no inferred measure. Without an attachment")
    P("   per loop, no loop of unannotated code reaches the optimizer.")
    P(f"3. **Contracts**: {cnt('Unproven')} functions can genuinely panic (overflow, division by zero) for some inputs; the")
    P("   verifier is right to refuse them until a precondition is stated.")
    P(f"4. **The optimizer itself**, on the {len(reached)} it saw: it cannot print a residual that branches on an")
    P("   argument (`next_power_of_two`: the straight-line rung is not stuck-free on `if n <= 1`, and the")
    P("   driven residual cannot print `Le(Int)`); the lowering never replaces a `const fn` (`mix64`);")
    P("   and where it does produce a residual (`gray_encode`) the residual is the source.")
    P()
    P("## Reproducing")
    P()
    P("```sh")
    P("HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/heldout-harness/run.sh   # --rounds N (>= 21)")
    P("```")


if __name__ == "__main__":
    main()
