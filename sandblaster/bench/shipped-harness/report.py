#!/usr/bin/env python3
"""report.py --results DIR --rounds N: REPORT.md of a run.sh run (on stdout).

Every number comes from the run's result files: per binary the geometric
mean of worktree / original and of the A/A control, and per function the
ratios with the machine-code identity marks (`=` identical code, `≈`
identical but for data addresses: `samecode.py --data-blind`)."""
import argparse
import json
import math
import os

TAG_TEXT = {
    "default-release": "default layout, overflow checks on (Commonware's release profile)",
    "align-release": "every function and block aligned to 64 bytes, overflow checks on",
    "default-release-nooc": "default layout, overflow checks off",
    "align-release-nooc": "aligned layout, overflow checks off",
}


def geomean(xs):
    xs = [x for x in xs if x > 0]
    return math.exp(sum(math.log(x) for x in xs) / len(xs)) if xs else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--rounds", type=int, required=True)
    a = ap.parse_args()
    R = lambda f: os.path.join(a.results, f)
    tags = sorted(f[len("bench-"):-len(".json")] for f in os.listdir(a.results) if f.startswith("bench-") and f.endswith(".json"))
    bench = {t: {r["function"]: r for r in json.load(open(R(f"bench-{t}.json")))["rows"]} for t in tags}
    same = {t: json.load(open(R(f"samecode-exact-{t}.json"))) for t in tags}
    blind = {t: json.load(open(R(f"samecode-blind-{t}.json"))) for t in tags}
    loads = {t: json.load(open(R(f"load-{t}.json"))) for t in tags}
    sources = open(R("sources.txt")).read()
    fns = list(bench[tags[0]])
    ident = lambda d, t, f, s: bool(d[t].get(f, {}).get(s))
    P = print
    P("# Measurement: the worktree's crates against the original code")
    P()
    P("Written by `sandblaster/bench/shipped-harness/run.sh` (report.py) from the run's result files.")
    P(f"{a.rounds} interleaved rounds per function, medians; the differential check passed before any timing.")
    P()
    P("```")
    P(sources.strip())
    P("```")
    P()
    P("| binary | geomean worktree / original | geomean A/A / original | A/A spread | identical code, worktree = original (A/A) | identical but data addresses (A/A) | load before → after |")
    P("| --- | ---: | ---: | --- | ---: | ---: | --- |")
    for t in tags:
        rs = [bench[t][f]["wt_over_orig"] for f in fns]
        aa = [bench[t][f]["aa_over_orig"] for f in fns]
        n = len(fns)
        P(f"| {t} ({TAG_TEXT.get(t, t)}) | {geomean(rs):.3f} | {geomean(aa):.3f} | {min(aa):.3f}–{max(aa):.3f} | "
          f"{sum(ident(same, t, f, 'subj_wt') for f in fns)} of {n} ({sum(ident(same, t, f, 'subj_aa') for f in fns)}) | "
          f"{sum(ident(blind, t, f, 'subj_wt') for f in fns)} of {n} ({sum(ident(blind, t, f, 'subj_aa') for f in fns)}) | {loads[t]['before']} → {loads[t]['after']} |")
    P()
    P("Per function: worktree / original (< 1: the worktree is faster), `=` identical machine code, `≈` identical but")
    P("for data addresses; A/A / original is the noise floor (the original code compiled from a second copy).")
    P()
    P("| set | function | " + " | ".join(f"worktree / original [{t}]" for t in tags) + " | " + " | ".join(f"A/A / original [{t}]" for t in tags) + " |")
    P("| --- | --- | " + " | ".join("---:" for _ in tags) + " | " + " | ".join("---:" for _ in tags) + " |")
    for f in fns:
        cells = []
        for t in tags:
            mark = " =" if ident(same, t, f, "subj_wt") else (" ≈" if ident(blind, t, f, "subj_wt") else "")
            cells.append(f"{bench[t][f]['wt_over_orig']:.3f}{mark}")
        aa = [f"{bench[t][f]['aa_over_orig']:.3f}" for t in tags]
        P(f"| {bench[tags[0]][f]['set']} | `{f}` | " + " | ".join(cells) + " | " + " | ".join(aa) + " |")


if __name__ == "__main__":
    main()
