#!/usr/bin/env python3
"""report.py --set v1|v2 --results DIR --rounds N [--previous FILE]: the set's REPORT.md
(v2: sandblaster/bench/heldout-v2/REPORT.md, the held-out evaluation; v1:
sandblaster/bench/heldout/REPORT.md, development data) from a run.sh run.

Reads DIR/eval.json (the optimizer's records, evaluate.py), DIR/bench-<tag>.json (timings),
DIR/samecode-<tag>.json (the identity check) and DIR/load-<tag>.json, and prints the report.
With --previous, the eval.json of the run before (run.sh keeps it), each function's stage then
and now. Every number in it comes from those files; nothing is typed in by hand.

Held-out v1 is development data since 2026-10-02 (sandblaster/bench/heldout/README.md): its
refusal reasons were read and have motivated reader and optimizer changes, so the report is
labelled a development-set report, and its numbers are regression checks, never evidence that
the optimizer is general or faster than rustc (DESIGN.md §8.2 item 11; the held-out evaluation
is held-out v2, sandblaster/bench/heldout-v2/).
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

# (pattern of a function's reason, stage, what it means); the first match wins.
# A function kept unspecialized has its driven candidate's reason appended
# (`; driven: ..`, see `reason_of`), which the optimizer rows below match.
CATEGORIES = [
    (r"`while` loops need a measure", "reader", "a `while` loop with no termination measure (in-place code carries none; the lift asks for `proof! { decreases(..) }`)"),
    (r"rvalue AddressOf", "reader", "slice iteration: core's slice iterator (`Iter::new`, `into_iter`) takes a raw address (`AddressOf`), which the MIR reader does not read"),
    (r"the signed operation `lt`", "reader", "`for _ in 0..N` over an `i32` range: `Range::next` compares signed integers, which SEMANTICS.md §19.3 does not read"),
    (r"the intrinsic `rotate_left`", "reader", "the `rotate_left` intrinsic is not read"),
    (r"sign extension is not read", "reader", "a sign-extending cast (`i16 as i32`) is not read"),
    (r"zero-sized value", "reader", "`?` on an `Option` (its residual `Option<Infallible>` is a zero-sized value used as data)"),
    (r"both targets in the loop", "reader", "a loop test whose two targets are both inside the loop (`while a != 0 || b != 0 || ..`)"),
    (r"mutual recursion is not supported", "reader", "nested loops: the lift's two loop functions call each other (mutual recursion is not supported)"),
    (r"the cast `transmute` of Unsupported\(\"type RawPtr", "reader", "slice iteration: core's slice iterator's `size_hint` transmutes a raw pointer, which the MIR reader does not read"),
    (r"has a loop \(library loops are not inlined\)", "reader", "a library function with a loop (`Iterator::position`): library loops are not inlined"),
    (r"a constructor of `std::iter::Enumerate`", "reader", "`.iter().enumerate()`: core's `Enumerate` is not modeled"),
    (r"checked `mul` of a signed", "reader", "a signed checked multiplication (an overflow-checked `*` of a signed type, `saturating_mul`, `for _ in 0..N` over `i32`) is not read"),
    (r"cannot find type `State`", "reader", "the lift does not resolve a type the file declares (`State`)"),
    (r"a constructor of `std::mem::Alignment`", "reader", "an allocation (`Vec::with_capacity`, `String::with_capacity`, `Vec::new` grown by `push`): alloc's layout code (`Alignment`) is not read"),
    (r"a constructor of `std::iter::Rev`", "reader", "`.iter().rev()`: core's `Rev` is not modeled"),
    (r"split_first`\): projection \(cindex", "reader", "`split_first` (a slice pattern with a constant index) is not read"),
    (r"is `&mut` but the lift does not pass it as a state", "reader", "a `&mut [T]` parameter (a slice updated in place) is not passed as a state"),
    (r"error\[resolve\]: cannot find", "reader", "the lift does not resolve a name the function uses"),
    (r"has no MIR body", "reader", "a callee in another crate whose MIR rustc does not export (neither generic nor `#[inline]`)"),
    (r"rustc's MIR has no instance for the lifted function", "reader", "generic code read at a library-type instance: the lift names a function's instance only at an instance it declares (a type of the lifted crate or a host model)"),
    (r"impl of the trait `[^`]*`, which the lift does not know", "reader", "an impl of a trait the lift does not know (the candidate's own impl, or one its closure calls)"),
    (r"#\[derive\(Default\)\]`: the lift does not know this field type's default", "reader", "`#[derive(Default)]` over a field type whose default the lift does not know"),
    (r"constant constant of type \(ref shared str\)", "reader", "a string constant (`&str`) is not read"),
    (r"has no host spelling", "lowering", "specialized; the residual uses a lift-prelude type with no Rust spelling (`crate::__lift::I32`), so it cannot be printed"),
    (r"cannot infer a termination measure", "elaboration", "no termination measure inferred for a `for` loop over a range (`#[decreases]` needed)"),
    (r"no panic-explicit reading: no operation it can panic at", "elaboration", "unproven (a loop of it did not verify, or a panic no precondition rules out), and no panic-explicit reading: what can fail is where the reading does not read (inside a loop, an `unreachable!()`, a callee's `requires`, an indexed place; DESIGN.md §8.2 item 12)"),
    (r"no panic-explicit reading: it calls", "elaboration", "blocked by a loop helper that did not elaborate, and no panic-explicit reading: it calls that helper"),
    (r"Unreachable obligation.*no panic-explicit reading", "elaboration", "can panic on some inputs, no contract, and no panic-explicit reading: an `unreachable!()` the prover does not refute (an `assert!`; in MIR a `debug_assert!` is one) is not read (DESIGN.md §8.2 item 12)"),
    (r"no panic-explicit reading", "elaboration", "can panic on some inputs, no contract, and no panic-explicit reading (the function's own reason is in the table above)"),
    (r"Unproven", "elaboration", "a panic obligation (overflow or division by zero) that no stated precondition rules out: the function can panic on some inputs, and H1 states no contract the verifier reads"),
    (r"driven: driven residual not printable: a stuck application of `[^`]*::loop#", "optimizer", "reached the optimizer with a loop: not specialized, the driven residual cannot print the call of the loop the elaborator made (`<f>::loop#k`)"),
    (r"driven: the equality lemma was not proven: a leaf of the process tree is not closed", "optimizer", "reached the optimizer, not specialized: the driven candidate's equality proof has a leaf not closed within its budget"),
    (r"driven: the equality lemma was not proven: the residual and the source split on different scrutinees", "optimizer", "reached the optimizer, not specialized: the driven candidate's equality proof finds the residual and the source splitting on different scrutinees"),
    (r"driven residual not printable", "optimizer", "reached the optimizer; the driven residual is not printable as exec code"),
    (r"neutral scrutinee", "optimizer", "reached the optimizer, not specialized: a branch on an argument is not stuck-free for the straight-line rung"),
    (r"does not match its replacement: relevant structure differs", "lowering", "specialized and cheaper; the lifted round trip's comparison of the printed helper, read back from rustc's MIR, with the residual finds a different structure (the same operations, written otherwise: rustc's temporaries bound by `let` where the residual has them inline, `?` read as a test of `option::is_none`; the comparison is syntactic up to `let x = v; x`), so the source stays"),
    (r"the residual is the source itself", "lowering", "specialized; the residual is the source itself: the optimizer found nothing cheaper, and the source stays"),
    (r"a tie keeps the source", "lowering", "specialized; the residual costs what the source costs: a tie keeps the source (DESIGN.md §8.2 item 6)"),
    (r"not 3% cheaper", "lowering", "specialized; the residual is not 3% cheaper than the source (the selection gate)"),
    (r"a `const fn` whose residual is", "lowering", "specialized; a `const fn` whose residual cannot be a `const fn` (its helpers would have to be)"),
    (r"a reading's helpers are not lowered", "lowering", "specialized through its panic-explicit reading; the residual calls helpers, which a reading's lowering does not print yet"),
    (r"panic-explicit reading's residual has no Rust form", "lowering", "specialized through its panic-explicit reading; the residual has no Rust form"),
    (r"the shipped code's theorem", "lowering", "specialized; the shipped code's theorem was not proven or not accepted, so the source stays"),
    (r"^lowered: ", "lowered", "lowered: the optimizer's residual replaces the source, accepted by the lifted round trip"),
]

STAGE_ORDER = {"reader": 0, "elaboration": 1, "optimizer": 2, "kept": 3, "lowering": 3, "lowered": 4, "other": 5}
RUNGS = ["ClosedForm", "SetBits", "EarlyExit", "SkipIdle", "Fused", "Rewritten", "Driven", "StraightLine"]


def reason_of(f):
    """A function's reason on one line, with its driven candidate's reason
    appended when the optimizer kept it unspecialized."""
    r = " ".join(f["reason"].split())
    opt = f.get("optimizer") or {}
    if opt.get("outcome") == "Unspecialized":
        d = next((c["reason"] for c in opt.get("candidates", []) if c["rung"] == "Driven"), None)
        if d and d not in r:
            r += "; driven: " + " ".join(d.split())
    return r


def category(reason):
    for pat, stage, text in CATEGORIES:
        if re.search(pat, reason):
            return stage, text
    # an uncategorized reason, verbatim but without its source position
    return "other", re.sub(r"^\S+\.rs:\d+:\d+: ", "", reason)


def geomean(xs):
    return math.exp(sum(math.log(x) for x in xs) / len(xs)) if xs else None


def med(xs):
    s = sorted(xs)
    n = len(s)
    return (s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2) if s else None


def fmt(x, d=3):
    return "—" if x is None else f"{x:.{d}f}"


def plural(n, one, many=None):
    return f"{n} {one if n == 1 else (many or one + 's')}"


def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, cwd=REPO).stdout.strip()
    except Exception:
        return ""


H2V2 = os.path.join(REPO, "sandblaster/bench/heldout-v2/h2")


def sample_manifest():
    """H2-v2's sample manifest (h2/sample-manifest.toml), {} before sampling."""
    p = os.path.join(H2V2, "sample-manifest.toml")
    if not os.path.exists(p):
        return {}
    import tomllib
    return tomllib.load(open(p, "rb"))


def tsv(path):
    with open(path) as f:
        cols = f.readline().rstrip("\n").split("\t")
        return [dict(zip(cols, l.rstrip("\n").split("\t"))) for l in f if l.strip()]


def sample_section(P, fns):
    """H2-v2's funnel from enumeration to the sample (the frozen h2/ files)."""
    sm = sample_manifest()
    rej = tsv(os.path.join(H2V2, "rejections.tsv")) if os.path.exists(os.path.join(H2V2, "rejections.tsv")) else []
    probe = tsv(os.path.join(H2V2, "probe.tsv")) if os.path.exists(os.path.join(H2V2, "probe.tsv")) else []
    P("## H2-v2: the sample")
    P()
    P("The rule `h2-v2` (`sandblaster/bench/heldout-v2/h2/RULE.md`, seed `" + str(sm.get("seed", "")) + "`) applied unchanged at")
    P("the source commit; the decisions its implementation made are in `h2/PROBE-LOG.md`, every rejection")
    P("with its reason in `h2/rejections.tsv`, every probed candidate in `h2/probe.tsv`.")
    P()
    def group(why):
        if why.startswith("not pure: names"):
            return "not pure: names an I/O or shared-state token (RULE.md 3)"
        if why.startswith("excluded: names a target area"):
            return "excluded: names a target area (RULE.md 2.1)"
        if why.startswith("not enumerated: inline module"):
            return "not enumerated: inside an inline module (RULE.md 3)"
        if why.startswith("not enumerated: inside"):
            return "not enumerated: inside a macro invocation or `macro_rules!` (RULE.md 3)"
        if why.startswith("no instance"):
            return "no instance (RULE.md 3.1)"
        return re.sub(r"\s+", " ", why)
    static = [r for r in rej if r["stage"] in ("static", "instance")]
    fn_rows = [r for r in static if r["id"] != "-"]
    blocks = [r for r in static if r["id"] == "-"]
    counts = {}
    for r in fn_rows:
        k = group(r["reason"])
        counts[k] = counts.get(k, 0) + 1
    P(f"Enumeration and the static criteria (RULE.md §1–§3.1): {sum(counts.values())} functions of the scope files are not candidates,")
    P(f"{sm.get('candidates', 0)} are; {len(blocks)} blocks (inline modules, macro bodies) are not entered.")
    P()
    P("| reason | functions |")
    P("| --- | ---: |")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        P(f"| {k} | {v} |")
    P()
    steps = {}
    for r in probe:
        why = r["reason"]
        m = re.match(r"(probe \d \([^)]*\))", why.replace(", with the closure's items", ""))
        k = "accepted" if r["accepted"] == "yes" else (m.group(1) if m else why[:60])
        steps[k] = steps.get(k, 0) + 1
    P(f"The probe (RULE.md §5), in the seeded order: {len(probe)} candidates probed, {sm.get('accepted', 0)} accepted, {sm.get('sampled', 0)} sampled" + (f" (shortfall {sm['shortfall']}: RULE.md §4 says H2-v2 is then every candidate that passed, and the rule is not widened)." if sm.get("shortfall") else "."))
    P()
    P("| first failing step | candidates |")
    P("| --- | ---: |")
    order = ["probe 1 (extraction)", "probe 2 (callee closure)", "probe 3 (size)", "probe 4 (reader)", "probe 5 (exec-only)", "accepted"]
    for k in sorted(steps, key=lambda x: (order.index(x) if x in order else 9, x)):
        P(f"| {k} | {steps[k]} |")
    P()
    if sm.get("function"):
        P("| slug | function | instance | seeded rank |")
        P("| --- | --- | --- | ---: |")
        for f in sm["function"]:
            inst = json.loads(f["instance"]) if f.get("instance") else None
            it = ", ".join(f"{p['name']} = `{p['arg']}`" for p in inst["params"]) if inst else "—"
            P(f"| {f['slug']} | `{f['id']}` | {it} | {f['seeded_rank']} |")
        P()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--rounds", type=int, required=True)
    ap.add_argument("--previous", default="")
    ap.add_argument("--set", choices=["v1", "v2"], default="v1")
    a = ap.parse_args()
    v2 = a.set == "v2"
    heldout_rel = "sandblaster/bench/heldout-v2" if v2 else "sandblaster/bench/heldout"
    gen_rel = "gen/v2" if v2 else "gen"
    results_rel = "results/v2" if v2 else "results/latest"
    # the binary names held-out v2's rows `v2_<fn>` (H1) and `v2h2_<fn>` (H2), apart from v1's
    unprefix = (lambda k: re.sub(r"^v2(h2)?_", "", k)) if v2 else (lambda k: k)
    ev = json.load(open(os.path.join(a.results, "eval.json")))
    prev = None
    if a.previous and os.path.exists(a.previous):
        p = json.load(open(a.previous))
        prev = {f["function"]: f for f in p["h1"] + p["h2"]}
    fns = ev["h1"] + ev["h2"]
    tags = sorted(os.path.basename(p)[6:-5] for p in glob.glob(os.path.join(a.results, "bench-*.json")))
    order = {"default-release": 0, "align-release": 1, "default-release-nooc": 2}
    tags.sort(key=lambda t: order.get(t, 9))
    bench = {t: {unprefix(r["function"]): r for r in json.load(open(os.path.join(a.results, f"bench-{t}.json")))["rows"]} for t in tags}
    # the identity check covers every probe of the binary: keep this set's
    want = set(bench[tags[0]]) if tags else set()
    same, blind = {}, {}
    for t in tags:
        for kind, d in (("samecode", same), ("samecode-blind", blind)):
            path = os.path.join(a.results, f"{kind}-{t}.json")
            if not os.path.exists(path):
                continue
            sc = json.load(open(path))
            rows = {(k if not v2 else unprefix(k)): x for k, x in sc.items() if (k.startswith("v2") if v2 else not k.startswith("v2_") and not k.startswith("v2h2_"))}
            d[t] = {k: x for k, x in rows.items() if k in want}
    load = {t: json.load(open(os.path.join(a.results, f"load-{t}.json"))) for t in tags if os.path.exists(os.path.join(a.results, f"load-{t}.json"))}
    short = lambda f: f["function"].rsplit("::", 1)[1]
    # the union run decides what the optimized subject compiles for H1 (one
    # lowered copy with every rewrite); a function counts as changed when
    # its own run lowered it and the union did too (H2: its own run)
    union_info = ev.get("union") or {}
    union = {r["function"]: r for r in (union_info.get("records") or [])}
    union_ran = bool(union_info.get("items"))
    def changed_in_subject(f):
        if not f["changed"]:
            return False
        # (a union run that did not get through the front end left gen/h1.rs the source)
        if f["set"] == "H1" and union_ran:
            return bool(union.get(f["function"], {}).get("changed"))
        return True
    changed = [f for f in fns if changed_in_subject(f)]
    lowered_alone = [f for f in fns if f["changed"]]
    n = len(fns)
    stage_count = {}
    for f in fns:
        stage_count[f["stage"]] = stage_count.get(f["stage"], 0) + 1
    reached = [f for f in fns if f.get("optimizer")]
    via_reading = [f for f in reached if f.get("panic_reading")]
    specialized = [f for f in reached if f["optimizer"]["outcome"] == "Specialized"]
    rungs = {}
    for f in specialized:
        rungs[f["optimizer"]["rung"]] = rungs.get(f["optimizer"]["rung"], 0) + 1
    tried = {r: [f for f in reached if any(c["rung"] == r for c in f["optimizer"]["candidates"])] for r in RUNGS}
    lowered_by = {}
    for f in changed:
        lowered_by[f.get("origin", "?")] = lowered_by.get(f.get("origin", "?"), 0) + 1
    # the functions the exec-only elaboration left unproven or blocked: the
    # ones a panic-explicit reading is built for (or why not)
    can_panic = [f for f in fns if f.get("panic_reading") or re.search(r"exec-only elaboration: (Unproven|Blocked)", f["reason"])]

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
    manifest = open(os.path.join(REPO, heldout_rel, "manifest.toml")).read()
    date = re.search(r'^date = "(.*)"', manifest, re.M).group(1)
    src_commit = re.search(r'^source_commit = "(.*)"', manifest, re.M).group(1)
    d = stats.get("default-release")
    al = stats.get("align-release")
    # is the optimized subject's text the source? (gen/ against the frozen files)
    h1_same = open(os.path.join(HERE, gen_rel, "h1.rs")).read() == open(os.path.join(REPO, heldout_rel, "h1/src/lib.rs")).read()
    body = lambda p: "\n".join(open(p).read().split("\n")[1:])
    h2_same = body(os.path.join(HERE, gen_rel, "h2_opt.rs")) == body(os.path.join(HERE, gen_rel, "h2_source.rs"))
    P = print

    if v2:
        P("# Held-out v2 report")
        P()
        P("**This is the held-out evaluation** (DESIGN.md §8.2 item 11). Held-out v2 was frozen on 2026-10-02")
        P("before the reader and optimizer work it judges (`sandblaster/bench/heldout-v2/manifest.toml`, G6): a")
        P("second blind H1 set, and H2-v2, monorepo functions sampled afterwards by the versioned rule `h2-v2`")
        P("with its committed seed, unchanged, from scope crates development did not look at. Any \"faster than")
        P("rustc\" statement cites this report. Its refusal reasons are now read, so by the held-out-versions")
        P("rule a change they motivate moves the function to the development set (H2-v2: its replacement is the")
        P("next accepted candidate in the seeded order).")
        P()
        P("Written by `sandblaster/bench/heldout-harness/run.sh --set v2` (report.py); every number below comes")
        P("from that run's result files (`sandblaster/bench/heldout-harness/results/v2/`) and the frozen sample")
        P("(`sandblaster/bench/heldout-v2/h2/`). The protocol is the fairness audit's held-out protocol (plan")
        P("step 8), unchanged: the optimizer's own output against rustc on the unmodified source, in one binary.")
        P()
    else:
        P("# Held-out v1 report (development set)")
        P()
        P("**This is a development-set report.** Held-out v1 was retired to the development set on")
        P("2026-10-02 (`sandblaster/bench/heldout/README.md`): its refusal reasons were read, and they have")
        P("motivated reader and optimizer changes since. Its numbers are regression checks. They do not show")
        P("that the optimizer is general, and a \"faster than rustc\" statement never cites them (DESIGN.md")
        P("§8.2 item 11): the held-out evaluation is held-out v2 (`sandblaster/bench/heldout-v2/`).")
        P()
        P("Written by `sandblaster/bench/heldout-harness/run.sh` (report.py); every number below comes from")
        P("that run's result files (`sandblaster/bench/heldout-harness/results/latest/`). The protocol is the")
        P("fairness audit's held-out protocol (plan step 8), unchanged: the optimizer's own output against")
        P("rustc on the unmodified source, in one binary.")
        P()
    P("## Headline")
    P()
    # the functions the binary times (held-out v2 times an H2 function only when
    # it changed and is a free function at no instance: evaluate.py h2_untimed)
    timed = [f for f in fns if short(f) in bench[tags[0]]] if tags else []
    untimed = [f for f in fns if f not in timed]
    nt = len(timed)
    over = f"all {n} functions, no exclusions" if not untimed else f"the {nt} timed functions, every H1 function and every timed H2 function; no exclusions"
    if not changed:
        P(f"**The optimizer changed none of the {n} functions.** " + ("Every lowered copy it wrote is the" if h1_same and h2_same else "(Yet the optimized subject's text differs from the source: see the files in gen/.)"))
        h2_note = "H2's text equals the source's" if ev["h2"] else ("H2-v2 is empty: no candidate passed its probe" if v2 else "H2 has no function")
        P((f"source byte for byte (`{gen_rel}/h1.rs` is H1's file; {h2_note}), so the optimized subject is the rustc subject compiled again. The") if h1_same and h2_same else "The")
        P(f"optimizer-only geomean is **{fmt(d['gm_all'])}** (optimized / rustc time, {over};")
        P(f"default layout, overflow checks on). That is placement noise around 1.00: the A/A")
        P(f"control (the same source compiled twice) spreads {fmt(d['aa_lo'])}–{fmt(d['aa_hi'])} in the same binary.")
        if al:
            P(f"With every function and block aligned to 64 bytes (less placement noise) it is {fmt(al['gm_all'])}, A/A spread")
            P(f"{fmt(al['aa_lo'])}–{fmt(al['aa_hi'])}.")
        P("The geomean over changed functions is undefined: no function changed.")
    else:
        P(f"**The optimizer changed {len(changed)} of the {n} functions** ({', '.join('`' + short(f) + '`' for f in changed)}).")
        P(f"Optimized / rustc time, geomean over {over}: **{fmt(d['gm_all'])}**; over the")
        P(f"changed functions timed: **{fmt(d['gm_changed'])}** (default layout, overflow checks on). A/A control spread:")
        P(f"{fmt(d['aa_lo'])}–{fmt(d['aa_hi'])}.")
        if al:
            P(f"Aligned layout: {fmt(al['gm_all'])} over all timed, {fmt(al['gm_changed'])} over the changed ones (A/A {fmt(al['aa_lo'])}–{fmt(al['aa_hi'])}).")
    if untimed:
        P()
        why = {}
        for f in untimed:
            why.setdefault(f.get("untimed") or "not in the binary", []).append(short(f))
        P(f"Not timed: {plural(len(untimed), 'H2 function')}. " + " ".join(f"{len(v)} {k} ({', '.join('`' + x + '`' for x in v)})." for k, v in why.items()))
        P("Counting each unchanged one at 1.000, the same code in both subjects, would move the geomean")
        P("toward 1.00 and add no measurement; they are left out of it.")
    if v2 and not ev["h2"]:
        sm0 = sample_manifest()
        P()
        P(f"**H2-v2 is empty**: the frozen rule's probe accepted none of its {sm0.get('candidates', 0)} candidates (shortfall")
        P(f"{sm0.get('shortfall', 40)}; the sample section below and `h2/PROBE-LOG.md`), so this run measures H1-v2 alone.")
    if len(lowered_alone) != len(changed):
        P()
        P(f"{plural(len(lowered_alone), 'function')} lowered in its own run; the union run (one lowered copy of H1 with every")
        P(f"rewrite, what the optimized subject compiles) lowered {len(changed)} of them.")
    P()
    kept = [f for f in specialized if not f["changed"]]
    P(f"Of {n} functions, {stage_count.get('reader', 0)} are refused by the lift's MIR reader, {stage_count.get('elaboration', 0)} by exec-only")
    P(f"elaboration, and {len(reached)} reach the optimizer" + (f" ({len(via_reading)} of them through their panic-explicit reading, DESIGN.md §8.2 item 12)" if via_reading else "") + ".")
    P(f"Of those {len(reached)}, {len(specialized)} are specialized ({len(lowered_alone)} lowered, {len(kept)} kept as written) and")
    P(f"{len(reached) - len(specialized)} not specialized.")
    loops_reached = [short(f) for f in reached if f["optimizer"]["loopsum_steps"] > 0]
    loop_text = lambda f: (f["optimizer"].get("reason") or "") + " ".join(c["reason"] for c in f["optimizer"]["candidates"])
    loops_seen = [short(f) for f in reached if short(f) not in loops_reached and re.search(r"loop#|__loop", loop_text(f))]
    if loops_reached:
        P(f"Loops summarized: {', '.join(loops_reached)}.")
    elif loops_seen:
        P(f"No loop is summarized: the {plural(len(loops_seen), 'function')} whose loop reaches the optimizer ({', '.join('`' + x + '`' for x in loops_seen)})")
        P("keep it (each reason is in the table below), so none of the loop machinery (closed forms, set-bit")
        P("iteration, early exit, unrolling, the aegraph) applies on this set.")
    else:
        P("No loop reaches the optimizer, so none of its loop machinery (closed forms, set-bit iteration,")
        P("early exit, unrolling, the aegraph) is exercised on this set.")
    P()
    if v2:
        sample_section(P, fns)
    P("## What was run")
    P()
    if v2:
        sm = sample_manifest()
        P(f"- **Set**: held-out v2 (`sandblaster/bench/heldout-v2/manifest.toml`, frozen by G6, dated {date},")
        P(f"  source commit `{src_commit[:12]}`): H1, 30 functions written blind from a committed idiom list")
        P(f"  (`h1/idioms.md`); H2, every monorepo function the rule `h2-v2` accepted: {sm.get('sampled', 0)} of the 40 asked for")
        P(f"  ({sm.get('candidates', 0)} candidates, {sm.get('probed', 0)} probed, {sm.get('accepted', 0)} accepted" + (f"; shortfall {sm['shortfall']}" if sm.get("shortfall") else "") + "; the sample, below).")
    else:
        P(f"- **Set**: held-out v1 (`sandblaster/bench/heldout/manifest.toml`, frozen by G6, dated {date},")
        P(f"  source commit `{src_commit[:12]}`), development data since 2026-10-02: H1, 30 functions written")
        P("  blind from a committed idiom list; H2, every monorepo function the sampling rule accepted (1 of")
        P("  the 40 asked for: the rule's probe found only one, `commonware-utils::rng::mix64`; shortfall 39,")
        P("  h2/PROBE-LOG.md).")
    P("- **Optimizer**: the exec-only path (`elab::Options { exec_only: true }`, no laws, as")
    P("  `tests/opt_qmdb.rs`), the production optimizer (`OptOptions::default()`) with only")
    P("  `exclude_user_rewrites` set (there are no user `#[rewrite]` alternatives here; the option makes")
    P("  sure none is counted), then the in-place lowering with its lifted round trip")
    P("  (`driver::lowered::lower_in_place`), through `sandblaster/front/examples/heldout_eval.rs`. A")
    P("  function that can panic on some inputs and states no contract is optimized through its")
    P("  panic-explicit reading (`f__panics`, `None` the panic; DESIGN.md §8.2 item 12), and is replaced")
    P("  only with the kernel's panic theorems of its own MIR and of the replacement's MIR. The round trip")
    P("  reads rustc's MIR of each lowered copy (evaluate.py extracts it and runs the root again). H1 is")
    P("  lifted in place with `items = \"<fn>\"` plus the file's types its signature names, one root per")
    P("  function (so each refusal is that function's own), then once more with every function that passed")
    P("  the reader, which gives the one lowered copy the optimized subject compiles. H2 uses a copy of its")
    P("  frozen root" + (" (and replays its frozen extraction arguments, instance included, for the round trip)" if v2 else "") + ". No profile exists for")
    P("  this set, so every result is without a profile, for both subjects.")
    P("- **Harness** (`sandblaster/bench/heldout-harness`, J11): three subjects of one crate source")
    P("  (`subject/lib.rs`; the package feature selects the module), linked into one binary: `rustc` (the")
    P("  frozen H1 file itself; H2's function text copied verbatim from its file), `A/A` (the same again)")
    P("  and `optimized` (the lowered copies). One workspace profile for all three: rustc -O")
    P("  (opt-level 3), 16 codegen units, no LTO, no target-cpu flag, no PGO; overflow checks on")
    P("  (Commonware's release profile) and, as a second binary, off. No hand-written variant exists in")
    P("  the set, so neither subject has one. Inputs: a fixed-seed type-driven generator (uniform")
    P("  bit length for integers, short byte strings) respecting each function's documented preconditions,")
    P("  plus edge cases; 512 inputs per function. The differential check runs first and must pass;")
    P(f"  then {a.rounds} interleaved rounds (the subject order rotates), 5 samples of about 200 µs per subject")
    P("  per round, the median of the per-round medians. `samecode.py` compares the subjects' machine code")
    P("  (`--ignore-panic-locations`: the addresses of each crate's own panic `Location` and message constants")
    P("  are not compared), and again with `--data-blind` (no data address compared). Stage finish-A widened")
    P("  the first check's panic rule to all of core's panic entry points and their whole argument setup, and")
    P("  taught it the v0 back-references that the subject crates' different name lengths shift.")
    P("- **Gates run first**: G6 and `fair-baseline.sh --heldout` (one profile, one binary, the identity")
    P("  check, an A/A subject, the rustc subject from the frozen source, >= 21 rounds after the check).")
    P(f"- Machine: {cpu}; {rustc}; worktree HEAD `{head[:12]}` plus the branch's uncommitted work.")
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
    unchanged_beyond = [k for k in beyond if k not in {short(f) for f in changed}]
    if unchanged_beyond:
        P(f"Rows of unchanged functions outside the A/A spread in some binary ({', '.join(unchanged_beyond)}) are not")
        P("optimizer effects: their source text is identical in both subjects. They show how far placement and")
        P("a busy host move identical code on this machine; a real gain has to clear that.")
        P()
    P("## Every function")
    P()
    P("Optimizer time: the front end, exec-only elaboration, the optimizer, the lowering and its round")
    P("trip for that function's root (wall clock, seconds, on the shared host; `+N rt`: the root ran again")
    P("after N extractions of the round trip's MIR), and the optimizer's own milliseconds for that root.")
    P()
    cols = " | ".join(f"opt / rustc [{t}]" for t in tags)
    P(f"| set | function | stage reached | optimizer outcome | changed | {cols} | A/A / rustc [{tags[0]}] | rounds p10–p90 [{tags[0]}] | optimizer time | reason |")
    P("| --- | --- | --- | --- | --- |" + " ---: |" * len(tags) + " ---: | --- | ---: | --- |")
    for f in fns:
        k = short(f)
        opt = f.get("optimizer")
        outcome = "—" if not opt else (f"{opt['outcome']} ({opt['rung']})" if opt["outcome"] == "Specialized" else opt["outcome"])
        if opt and f.get("panic_reading"):
            outcome += ", through its panic-explicit reading"
        cells = []
        for t in tags:
            r = bench[t].get(k)
            if not r:
                cells.append("—")
                continue
            mark = "= " if same[t].get(k, {}).get("subj_opt") else "≈ " if blind.get(t, {}).get(k, {}).get("subj_opt") else ""
            cells.append(f"{mark}{r['opt_over_rustc']:.3f}")
        r0 = bench[tags[0]].get(k)
        rr = sorted(r0["round_ratios_opt"]) if r0 else []
        p = (lambda q: rr[round((len(rr) - 1) * q)]) if rr else None
        reason = reason_of(f).replace("|", "\\|")
        reason = re.sub(r"sandblaster/bench/heldout(-v2)?/h1/src/lib.rs:\d+:\d+: ", "", reason)
        secs = "—" if f.get("secs") is None else f"{f['secs']:.1f} s" + (f" (+{f['roundtrip_extractions']} rt)" if f.get("roundtrip_extractions") else "") + (f"; opt {f['opt_ms']} ms" if f.get("opt_ms") is not None else "")
        ch = "yes" if changed_in_subject(f) else ("own run only" if f["changed"] else "no")
        P(f"| {f['set']} | `{k}` | {f['stage']} | {outcome} | {ch} | {' | '.join(cells)} | {fmt(r0['aa_over_rustc']) if r0 else '—'} | {fmt(p(0.1)) + '–' + fmt(p(0.9)) if rr else '—'} | {secs} | {reason[:300]} |")
    P()
    if untimed:
        P("`—` in the timing columns: not timed (the headline says why: an unchanged H2 function compiles")
        P("its source text in both subjects).")
    P("`=`: the optimized and rustc subjects compiled to the same machine code (samecode.py). A row")
    P("without `=` whose function did not change differs only in data addresses the conservative check")
    P("compares (for example `crc8`, which rustc compiles to a 256-byte lookup table, one copy per crate:")
    P(f"its A/A pair is not `=` either). A/A pairs identical by the check: {len(stats[tags[0]]['aa_identical'])} of {len(bench[tags[0]])} [{tags[0]}].")
    if tags and tags[0] in blind:
        nb = sum(1 for v in blind[tags[0]].values() if v.get("subj_opt"))
        nba = sum(1 for v in blind[tags[0]].values() if v.get("subj_rustc_aa"))
        P(f"`≈`: the same code except for the addresses of each crate's own constant data (`samecode.py --data-blind`;")
        P(f"the constants' contents are not compared): {nb} of {len(bench[tags[0]])} optimized = rustc, {nba} A/A [{tags[0]}], `=` rows included.")
    P()
    if prev is not None:
        P("## Change since the previous run")
        P()
        moved = [(f, prev.get(f["function"])) for f in fns]
        diff = [(f, q) for f, q in moved if q is None or q["stage"] != f["stage"] or bool(q["changed"]) != bool(f["changed"]) or (q.get("optimizer") or {}).get("outcome") != (f.get("optimizer") or {}).get("outcome")]
        ps = {}
        for q in prev.values():
            ps[q["stage"]] = ps.get(q["stage"], 0) + 1
        P(f"The previous run (its `eval.json`, `--previous`; run.sh passes the one its run replaces): {ps.get('reader', 0)} refused by the reader, {ps.get('elaboration', 0)} by exec-only")
        P(f"elaboration, {sum(1 for q in prev.values() if q.get('optimizer'))} reached the optimizer, {sum(1 for q in prev.values() if q['changed'])} lowered. This run: {stage_count.get('reader', 0)}, {stage_count.get('elaboration', 0)}, {len(reached)}, {len(lowered_alone)}.")
        P()
        if diff:
            P("| function | stage then → now | optimizer outcome then → now | lowered then → now |")
            P("| --- | --- | --- | --- |")
            for f, q in diff:
                oq = ((q or {}).get("optimizer") or {}).get("outcome", "—")
                of = (f.get("optimizer") or {}).get("outcome", "—")
                P(f"| `{short(f)}` | {(q or {}).get('stage', '—')} → {f['stage']} | {oq} → {of} | {'yes' if (q or {}).get('changed') else 'no'} → {'yes' if f['changed'] else 'no'} |")
        else:
            P("No function's stage, outcome or lowering changed.")
        P()
    P("## Why: the funnel")
    P()
    groups = {}
    for f in fns:
        st, text = category(reason_of(f))
        groups.setdefault((st, text), []).append(short(f))
    P("| stage | reason | functions |")
    P("| --- | --- | --- |")
    for (st, text), names in sorted(groups.items(), key=lambda kv: (STAGE_ORDER.get(kv[0][0], 9), -len(kv[1]))):
        P(f"| {st} | {text.replace('|', chr(92) + '|')} | {len(names)}: {', '.join('`' + x + '`' for x in names)} |")
    P()
    if can_panic:
        P("## Functions the exec-only path leaves unproven (DESIGN.md §8.2 item 12)")
        P()
        P("A function whose arithmetic, division or indexing no precondition makes safe is `Unproven` in the")
        P("exec-only path (and its callers are blocked by it); so is one with a loop that does not verify.")
        P("The optimizer works on the panic-explicit reading `f__panics : Option<R>` of each (`None` the")
        P("panic), whose residual is linked to it by a kernel-checked equality over `Option<R>`, so no rewrite")
        P("adds, removes or moves a panic; a replacement ships only with the panic theorems of the source's MIR")
        P("and of the copy's MIR.")
        P()
        P("| function | reading | optimizer outcome | lowered | reason |")
        P("| --- | --- | --- | --- | --- |")
        for f in can_panic:
            opt = f.get("optimizer")
            oc = "—" if not opt else (f"{opt['outcome']} ({opt['rung']})" if opt["outcome"] == "Specialized" else opt["outcome"])
            reading = f"`{f['panic_reading'].rsplit('::', 1)[1]}`" if f.get("panic_reading") else "none"
            reason = re.sub(r"sandblaster/bench/heldout(-v2)?/h1/src/lib.rs:\d+:\d+: ", "", reason_of(f)).replace("|", "\\|")
            P(f"| `{short(f)}` | {reading} | {oc} | {'yes' if f['changed'] else 'no'} | {reason[:300]} |")
        P()
    P("## The four columns (protocol item 7)")
    P()
    P("| column | functions | geomean |")
    P("| --- | ---: | ---: |")
    P(f"| optimizer-derived (driver, Σ1–Σ5, aegraph, residuals) | {lowered_by.get('optimizer', 0)} | {fmt(d['gm_changed']) if lowered_by.get('optimizer') else 'none'} |")
    P(f"| user `#[rewrite]` alternatives | {lowered_by.get('user_rewrite', 0)} (excluded by the evaluation option; none exist) | none |")
    P("| hand-written hardware variants | 0 (the set has none) | none |")
    P("| source restructuring | 0 (the subjects compile the frozen files) | none |")
    P()
    P("## Rung and lowering hits (protocol item 6)")
    P()
    P(f"- Reached the optimizer: {len(reached)} of {n}" + (f" ({len(via_reading)} through a panic-explicit reading)" if via_reading else "") + f". Specialized: {len(specialized)} ({', '.join(f'{k} {v}' for k, v in sorted(rungs.items())) or 'none'}). Unspecialized: {len(reached) - len(specialized)}.")
    P("- Candidates per rung (functions with a candidate of that rung; specialized by it): " + ", ".join(f"{r} {len(tried[r])}/{rungs.get(r, 0)}" for r in RUNGS) + ".")
    P(f"- Lowered into the source: {len(changed)} of {n} in the optimized subject" + (f" ({', '.join(f'{k} {v}' for k, v in lowered_by.items())})" if changed else "") + (f"; {len(lowered_alone)} in their own runs" if len(lowered_alone) != len(changed) else "") + ".")
    P()
    P("## Cost-model decisions (J12)")
    P()
    lowered_rows = [f for f in changed if short(f) in bench[tags[0]]]
    if lowered_rows:
        s0 = stats[tags[0]]
        faster = [short(f) for f in lowered_rows if short(f) in s0["improved"]]
        slower = [short(f) for f in lowered_rows if short(f) in s0["regressed"]]
        P(f"The model predicted a gain (at least 3%) for the {plural(len(lowered_rows), 'lowered function')}. Measured [{tags[0]}]:")
        P(f"{len(faster)} faster beyond the A/A spread ({', '.join(faster) or 'none'}), {len(slower)} slower beyond it ({', '.join(slower) or 'none'}),")
        P(f"{len(lowered_rows) - len(faster) - len(slower)} within it.")
        pairs = []
        for f in lowered_rows:
            m = re.search(r"portable cost (\d+) -> (\d+) milli-cycles", f["reason"])
            if m and int(m.group(1)) > 0:
                pairs.append((f, int(m.group(1)), int(m.group(2))))
        if pairs:
            P()
            P("Cost-model accuracy, per lowered function: the portable model's predicted ratio (residual / source")
            P("cost) against the measured optimized / rustc time in each binary.")
            P()
            P("| function | portable cost, source → residual (milli-cycles) | predicted | " + " | ".join(f"measured [{t}]" for t in tags) + " |")
            P("| --- | --- | ---: | " + " | ".join("---:" for _ in tags) + " |")
            for f, c0, c1 in pairs:
                P(f"| `{short(f)}` | {c0} → {c1} | {c1 / c0:.3f} | " + " | ".join(fmt(bench[t][short(f)]["opt_over_rustc"]) if short(f) in bench[t] else "—" for t in tags) + " |")
            pr = [c1 / c0 for _, c0, c1 in pairs]
            me = [bench[tags[0]][short(f)]["opt_over_rustc"] for f, _, _ in pairs]
            P()
            P(f"Geomean predicted {fmt(geomean(pr))}, measured {fmt(geomean(me))} [{tags[0]}]; the model's direction (a gain) "
              + f"held for {sum(1 for x in me if x < 1)} of {len(me)} (any gain, inside the noise or not).")
    else:
        P("No function was lowered, so no prediction of a gain can be checked against a measurement.")
    def costs(f):
        m = re.search(r"portable model: (\d+) vs (\d+) milli-cycles", f["reason"])
        return (int(m.group(1)), int(m.group(2))) if m else None
    compared = [f for f in kept if costs(f)]
    ties = [short(f) for f in compared if costs(f)[0] == costs(f)[1]]
    dearer = [short(f) for f in compared if costs(f)[0] > costs(f)[1]]
    notch = [short(f) for f in compared if costs(f)[0] < costs(f)[1]]
    q = lambda xs: (" (" + ", ".join("`" + x + "`" for x in xs) + ")") if xs else ""
    P(f"Kept as written after the cost comparison (residual vs source, portable model): {len(ties)} equal in cost{q(ties)},")
    P(f"{len(dearer)} dearer{q(dearer)}, {len(notch)} cheaper but not by 3%{q(notch)}.")
    P("A rejected residual is never printed, so there is no second subject to time against the source:")
    P("these decisions are not measured here.")
    P()
    P("## Ablations (protocol item 8, J7)")
    P()
    if v2:
        P("Not run in this evaluation. The tuned constants (LOOP_TRIPS, the synthesis and guard pools, the 3%")
        P("gate, TRY_FAIL, (CP+TP)/2, the popcount surcharge, DERIVE_MIN_PROOF_NODES) can only be ablated where")
        P("they act: " + ("no function of this set is lowered" if not changed else f"{plural(len(changed), 'function')} lowered") + ("" if loops_reached else ", and no loop of it is summarized") + ".")
        P()
        P("## What keeps code unchanged")
        P()
        P("Counts from this run's reasons. Reading them retires held-out v2 for any change they motivate")
        P("(DESIGN.md §8.2 item 11): such a change states its structural justification, and the function it")
        P("was read from moves to the development set.")
        P()
    else:
        P("Not run on this set. The tuned constants (LOOP_TRIPS, the synthesis and guard pools, the 3% gate,")
        P("TRY_FAIL, (CP+TP)/2, the popcount surcharge, DERIVE_MIN_PROOF_NODES) are ablated on held-out")
        P("code; this set is development data now." + ("" if loops_reached else " No loop of this set is summarized either."))
        P()
        P("## What keeps code unchanged (development notes)")
        P()
        P("Counts from this run's reasons; this set may motivate changes (it is development data), and each")
        P("change states its structural justification (DESIGN.md §8.2 item 11).")
        P()
    cnt = lambda pat: sum(1 for f in fns if re.search(pat, reason_of(f)))
    P(f"1. **The MIR reader** refuses {stage_count.get('reader', 0)} of {n}.")
    by_reader = sorted(((text, names) for (st, text), names in groups.items() if st == "reader"), key=lambda x: -len(x[1]))
    for text, names in by_reader:
        P(f"   - {len(names)}: {text}.")
    nw, nf = cnt('while. loops need a measure'), cnt('cannot infer a termination measure')
    P(f"2. **Termination**: " + (f"{plural(nw, 'function')} with a `while` loop, for which the lift asks a measure that in-place code does not carry; " if nw else "") + f"{plural(nf, 'function')} with a loop over a range that gets no inferred measure.")
    no_reading = [f for f in can_panic if not f.get("panic_reading")]
    P(f"3. **Unproven in the exec-only path**: {plural(len(can_panic), 'function')} (a panic no contract rules out, or a loop that does not")
    P(f"   verify, or a callee of either); {len(via_reading)} reach the optimizer through their panic-explicit reading, {len(no_reading)} have none")
    P(f"   ({', '.join('`' + short(f) + '`' for f in no_reading) or 'none'}; each reason is in the tables above).")
    unspec = [f for f in reached if f["optimizer"]["outcome"] != "Specialized"]
    P(f"4. **The optimizer**, on the {len(reached)} it saw: {len(unspec)} not specialized" + (f" ({', '.join('`' + short(f) + '`' for f in unspec)})" if unspec else "") + f"; of the {len(specialized)} specialized,")
    rt_rejected = [short(f) for f in kept if "lifted round trip" in f["reason"]]
    P(f"   {len(lowered_alone)} lowered and {len(kept)} kept (equal in cost: {len(ties)}" + (f"; cheaper, but the lifted round trip rejected the printed code: {len(rt_rejected)}, " + ", ".join("`" + x + "`" for x in rt_rejected) if rt_rejected else "") + ").")
    P()
    P("## Reproducing")
    P()
    P("```sh")
    P(f"HEAVY=<admission wrapper> CARGO_TARGET_DIR=<dir> sandblaster/bench/heldout-harness/run.sh --set {a.set}   # --rounds N (>= 21)")
    P("```")


if __name__ == "__main__":
    main()
