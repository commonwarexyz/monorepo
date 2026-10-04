#!/usr/bin/env python3
"""evaluate.py: the exec-only optimizer on the frozen held-out set (run.sh step 2).

  evaluate.py --work DIR --eval BIN [--heavy HEAVY]

For every H1 function (sandblaster/bench/heldout/h1/src/lib.rs, all 30)
it writes a DSL root lifting H1's file in place with `items = "<fn>"`
(the reading of h1/h1.sbmir, extracted by run.sh) and runs `heldout_eval`
on it (sandblaster/front/examples/heldout_eval.rs: driver::check, exec-only
elaboration, the always-on optimizer with user alternatives excluded, the
in-place lowering and its lifted round trip). For H2 it runs the frozen
root of each sampled function (h2/roots/<slug>/mod.rs) the same way.

Then one more root lifts H1 with `items` = every H1 function whose own run
passed the front end, so that one lowered copy holds every rewrite; it is
written to gen/h1.rs (the `optimized` subject). H2's lowered copies give
gen/h2_opt.rs (items.py); held-out v2 copies only the functions the harness
times, each changed free function at no instance, and writes the rustc
subject's text of them too (gen/v2/h2_source.rs; `h2_untimed` says why any
other is not timed). Each function's record, and the union run, go to
DIR/eval.json; nothing here reads a timing.

A rewrite is accepted only by the lifted round trip, which reads rustc's MIR
of the lowered copy (`<stem>.roundtrip__<module>.sbmir` next to the root's
MIR; DESIGN.md §2.1). So each root holds its own copy of the MIR (H1's
`h1.sbmir`; an H2 root and its MIR are copied out of the frozen directory),
and when the round trip asks for the MIR of its copy, the copy (written by
heldout_eval) is extracted with `sandblaster/mirx/extract.sh --replace` and
the root run again (at most three times: a function the round trip rejects
changes the copy). Held-out v1 is development data since 2026-10-02
(sandblaster/bench/heldout/README.md): these runs are development-set
regression checks.

No optimizer setting is passed: the run is the production optimizer
(OptOptions::default, strict off so a failure is recorded, not fatal) with
only `exclude_user_rewrites` set (there are no user alternatives in the
held-out set; the option makes sure of it).
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../.."))
# the held-out set evaluated (`--set`): v1 (development data since
# 2026-10-02) or v2 (the held-out set); configure() sets these
SETS = {
    "v1": {"heldout": "sandblaster/bench/heldout", "mir": "h1/h1.sbmir", "extract": "extract/Cargo.toml", "package": "heldout_h1_mir", "gen": "gen"},
    "v2": {"heldout": "sandblaster/bench/heldout-v2", "mir": "h1v2/h1.sbmir", "extract": "extract-v2/Cargo.toml", "package": "heldout_h1v2_mir", "gen": "gen/v2"},
}
SET = "v1"
HELDOUT = os.path.join(REPO, SETS[SET]["heldout"])
H1_SRC = os.path.join(HELDOUT, "h1/src/lib.rs")
H1_MIR = os.path.join(HERE, SETS[SET]["mir"])


def configure(name):
    global SET, HELDOUT, H1_SRC, H1_MIR
    SET = name
    HELDOUT = os.path.join(REPO, SETS[name]["heldout"])
    H1_SRC = os.path.join(HELDOUT, "h1/src/lib.rs")
    H1_MIR = os.path.join(HERE, SETS[name]["mir"])

sys.path.insert(0, HERE)
import items as items_mod  # noqa: E402


def h1_functions():
    """The public functions of H1, in file order."""
    s = items_mod.strip(open(H1_SRC).read())
    # module level only: stop at the test module
    s = s[: s.find("#[cfg(test)]")] if "#[cfg(test)]" in s else s
    return re.findall(r"(?m)^pub fn (\w+)", s)


def lift_items(names):
    """What a root lifting H1's functions `names` lifts (`items`): the
    functions, the file's module-level functions they call (transitively,
    lexically: an identifier followed by `(`), and the file's module-level
    types (struct, enum, type alias) the signatures of all of these name.
    A function's lift needs the functions it calls (a call of a module
    function is a call by its lifted name) and the types of its parameters
    and result; the rule is the same for every function."""
    s = items_mod.strip(open(H1_SRC).read())
    s = s[: s.find("#[cfg(test)]")] if "#[cfg(test)]" in s else s
    types = re.findall(r"(?m)^pub (?:struct|enum|type) (\w+)", s)
    fns = {}
    for m in re.finditer(r"(?m)^(?:pub(?:\([^)]*\))? )?(?:const )?fn (\w+)", s):
        i = s.index("{", m.end())
        depth, j = 0, i
        while True:
            if s[j] == "{":
                depth += 1
            elif s[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        fns[m.group(1)] = (s[m.end():i], s[i:j + 1])
    out = []
    todo = list(names)
    while todo:
        n = todo.pop(0)
        if n in out or n not in fns:
            continue
        out.append(n)
        for c in re.findall(r"\b(\w+)\s*\(", fns[n][1]):
            if c in fns and c not in out:
                todo.append(c)
    for n in list(out):
        out += [t for t in types if re.search(r"\b" + t + r"\b", fns[n][0]) and t not in out]
    return out


def h2_functions():
    """[(slug, kernel name, root, file, item, extraction)] from the held-out
    manifest (v1) or the sample manifest (v2: h2/sample-manifest.toml, whose
    `extract` holds the probe's extraction arguments, replayed for the round
    trip)."""
    try:
        import tomllib
    except ImportError:  # pragma: no cover
        raise SystemExit("python >= 3.11 needed (tomllib)")
    if SET == "v1":
        m = tomllib.load(open(os.path.join(HELDOUT, "manifest.toml"), "rb"))
        fs = m["h2"]["function"]
    else:
        p = os.path.join(HELDOUT, "h2/sample-manifest.toml")
        fs = tomllib.load(open(p, "rb")).get("function", []) if os.path.exists(p) else []
    out = []
    for f in fs:
        out.append((f["slug"], f["kernel_name"], os.path.join(HELDOUT, "h2", f["root"]), f["file"], f.get("item") or f["id"].rsplit("::", 1)[1], f.get("extract"), f))
    return out


def h2_untimed(rec, f):
    """Why the harness does not time an H2 function (None: it times it).
    v1: every sampled function is timed (its one function, `mix64`). v2: a
    function is timed when it changed and is a free function at no instance
    (manifest `kind = "fn"`, no `instance`): its own text, copied verbatim,
    is what each subject compiles. An unchanged function is not timed: the
    optimized subject would compile its source text as written, the same
    code as the rustc subject's. A changed method or generic instance would
    need its crate in each subject (not built: the report says so)."""
    if SET == "v1":
        return None
    if not rec["changed"]:
        return "unchanged: the optimized subject's text is the source as written (the same code), not timed"
    if f.get("kind", "fn") != "fn" or f.get("instance"):
        return "changed, but a %s: timing it needs its crate in each subject (not built)" % ("method" if f.get("kind", "fn") != "fn" else "generic instance")
    return None


def env():
    e = dict(os.environ)
    e.update(HEAVY_SLOTS="2", CARGO_BUILD_JOBS="4", SANDBLASTER_MEM_LIMIT_GB="6", SANDBLASTER_GATE_WORKERS="2")
    e.pop("SANDBLASTER_STRICT_OPT", None)
    if "SBMIR_TARGET_DIR" not in e and "CARGO_TARGET_DIR" in e:
        e["SBMIR_TARGET_DIR"] = os.path.join(e["CARGO_TARGET_DIR"], "mirx")
    return e


def fresh_mir(d, mir_src, name):
    """`d/name`: a copy of the MIR `mir_src` for one root (the round trip's
    MIR of a lowered copy lands next to it), with no stale round-trip MIR."""
    for f in os.listdir(d):
        if ".roundtrip__" in f:
            os.remove(os.path.join(d, f))
    shutil.copyfile(mir_src, os.path.join(d, name))
    return name


def write_root(d, item_list):
    os.makedirs(d, exist_ok=True)
    mir = fresh_mir(d, H1_MIR, "h1.sbmir")
    src = os.path.relpath(H1_SRC, d)
    uses = "".join(f"pub use h1::{i};\n" for i in item_list)
    lifted = lift_items(item_list)
    text = (
        "//! Held-out evaluation root (generated by sandblaster/bench/heldout-harness/evaluate.py).\n"
        "#![forbid(unsafe_code)]\n\n"
        f'#[lift(mir = "{mir}", in_place, items = "{", ".join(lifted)}")]\n'
        f'#[path = "{src}"]\n'
        "pub mod h1;\n\n" + uses
    )
    p = os.path.join(d, "mod.rs")
    open(p, "w").write(text)
    return p


def run1(args, root, out_dir, prefixes):
    # heldout_eval is neither cargo nor an extraction: it runs directly, its
    # memory capped by memguard (SANDBLASTER_MEM_LIMIT_GB, env()), so its
    # wall clock (the report's optimizer time) holds no wait for an admission
    # slot; the round-trip extractions go through `heavy` (extract_cmd)
    cmd = [args.eval, root, out_dir] + prefixes
    t = time.time()
    p = subprocess.run(cmd, cwd=REPO, env=env(), capture_output=True, text=True)
    secs = round(time.time() - t, 1)
    line = next((l for l in p.stdout.splitlines() if l.startswith("{")), None)
    if line is None:
        return {"front_end": False, "errors": "heldout_eval did not finish (exit %s): %s" % (p.returncode, p.stderr[-800:]), "secs": secs}
    r = json.loads(line)
    r["secs"] = secs
    return r


NEEDS_RT = ("no MIR of the round trip's copy", "changed since the MIR was extracted")


def rt_pending(m):
    """Whether a lowered module's round trip stopped for the MIR of its copy."""
    texts = [m.get("note") or ""] + [x.get("reason") or "" for x in m.get("records", [])]
    return m.get("roundtrip_copy") and m.get("roundtrip_mir") and any(n in t for t in texts for n in NEEDS_RT)


def run(args, root, out_dir, prefixes, rt_extract=None):
    """heldout_eval on `root`; while the round trip asks for the MIR of its
    copy, the copy is extracted (`rt_extract(copy, out)`) and the root run
    again (at most three extractions)."""
    r = run1(args, root, out_dir, prefixes)
    secs = r.get("secs", 0)
    extracted = []
    for _ in range(3):
        todo = [m for m in r.get("modules", []) if rt_pending(m)] if rt_extract else []
        if not todo:
            break
        for m in todo:
            t = time.time()
            p = rt_extract(m["roundtrip_copy"], m["roundtrip_mir"])
            secs += time.time() - t
            if p.returncode != 0:
                r["roundtrip_extraction_failed"] = (p.stderr or p.stdout)[-800:]
                r["secs"] = round(secs, 1)
                return r
            extracted.append(os.path.basename(m["roundtrip_mir"]))
        r = run1(args, root, out_dir, prefixes)
        secs += r.get("secs", 0)
    r["secs"] = round(secs, 1)
    r["roundtrip_extractions"] = extracted
    return r


def extract_cmd(args, package, module, out, replace, manifest=None, items=None, stubs=None):
    cmd = ([args.heavy] if args.heavy else []) + [os.path.join(REPO, "sandblaster/mirx/extract.sh"), package, module, out]
    if manifest:
        cmd += ["--manifest", manifest]
    if items:
        cmd += ["--items", items]
    if stubs:
        cmd += ["--stubs", stubs]
    cmd += ["--replace", replace]
    return subprocess.run(cmd, cwd=REPO, env=env(), capture_output=True, text=True)


def h1_rt_extract(args):
    """The round-trip extraction of a lowered copy of H1 (module `h1` of the
    extraction crate, its source replaced by the copy)."""
    manifest = os.path.join(HERE, SETS[SET]["extract"])
    return lambda copy, out: extract_cmd(args, SETS[SET]["package"], "h1", out, f"{H1_SRC}={copy}", manifest=manifest)


# the build scripts of workspace crates H2's files depend on that verify with
# sandblaster, stubbed as h2/probe.py stubs them
H2_STUBS = "commonware_codec:varint.rs=codec/sandblaster/varint/varint.rs;commonware_storage:mmr-lowered__merkle__mmr__iterator.rs=storage/src/merkle/mmr/iterator.rs"


def h2_rt_extract(args, package, file, item, extract=None):
    """The round-trip extraction of a lowered copy of an H2 file. v1: its
    module, only its item and the copy's check copies and helpers (as the
    probe extracted the item alone, RULE.md 5.1). v2: the probe's own
    extraction arguments (h2/sample-manifest.toml `extract`: its modules,
    items, skipped functions and instance), the copy's check copies and
    helpers added to the file's module's items."""
    module = os.path.splitext(os.path.relpath(os.path.join(REPO, file), os.path.join(REPO, file.split("/src/")[0], "src")))[0].replace("/", "::")
    if module.endswith("::mod"):
        module = module[: -len("::mod")]

    def go(copy, out):
        text = open(copy).read()
        names = sorted(set(re.findall(r"\bfn (__sandblaster_(?:opt|check)_\w+)", text)))
        if extract is None:
            items = f"{module}=" + ",".join([item] + names)
            return extract_cmd(args, package, module, out, f"{os.path.join(REPO, file)}={copy}", items=items, stubs=H2_STUBS)
        ex = json.loads(extract) if isinstance(extract, str) else extract
        its = []
        for e in ex["items"].split(";"):
            m, _, v = e.partition("=")
            if m == module:
                v = ",".join([x for x in v.split(",") if x] + names)
            its.append(f"{m}={v}")
        cmd = ([args.heavy] if args.heavy else []) + [os.path.join(REPO, "sandblaster/mirx/extract.sh"), package, ex["modules"], out, "--items", ";".join(its), "--stubs", H2_STUBS]
        cmd += ex.get("extra", [])
        cmd += ["--replace", f"{os.path.join(REPO, file)}={copy}"]
        return subprocess.run(cmd, cwd=REPO, env=env(), capture_output=True, text=True)

    return go


def h2_root(work, slug, frozen_root):
    """A copy of an H2 root (every file of its tree) and its MIR outside the
    frozen directory, with each `#[path]` and `mir` made to point at the
    same files (`mir` at the copy's MIR)."""
    d = os.path.join(work, "roots", slug)
    if os.path.isdir(d):
        shutil.rmtree(d)
    os.makedirs(d, exist_ok=True)
    base = os.path.dirname(frozen_root)
    mir_src = None
    files = []
    for root, dirs, fs in os.walk(base):
        for f in fs:
            if f.endswith(".rs"):
                files.append(os.path.relpath(os.path.join(root, f), base))
    for rel in files:
        src_dir = os.path.dirname(os.path.join(base, rel))
        m = re.search(r'mir = "([^"]+)"', open(os.path.join(base, rel)).read())
        if m:
            mir_src = os.path.normpath(os.path.join(decl_dir(base, rel), m.group(1)))
    mir = fresh_mir(d, mir_src, f"{slug}.sbmir")
    for rel in files:
        text = open(os.path.join(base, rel)).read()
        od, nd = decl_dir(base, rel), decl_dir(d, rel)
        text = re.sub(r'mir = "([^"]+)"', lambda x: 'mir = "%s"' % os.path.relpath(os.path.join(d, mir), nd), text)
        text = re.sub(r'#\[path = "([^"]+)"\]', lambda x: '#[path = "%s"]' % os.path.relpath(os.path.normpath(os.path.join(od, x.group(1))), nd), text)
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(text)
    return os.path.join(d, "mod.rs")


def decl_dir(base, rel):
    """The directory a root file's `#[path]` and `mir` are relative to: its
    own (`mod.rs`), or for `a/b.rs` the directory `a/` holding it."""
    return os.path.dirname(os.path.join(base, rel))


def summarize(r, name):
    """One function's record: stage reached, outcome, rung, lowering, reason."""
    rec = {"function": name, "secs": r.get("secs"), "opt_ms": r.get("opt_ms"), "lowering_ms": r.get("lowering_ms"), "roundtrip_extractions": len(r.get("roundtrip_extractions", []))}
    if not r.get("front_end"):
        errs = [l for l in r.get("errors", "").splitlines() if "error[" in l] or [r.get("errors", "")]
        rec.update(stage="reader", changed=False, reason=re.sub(r"\S*/mono-wt/", "", errs[0]).strip())
        return rec
    defs = [d for d in r["defs"] if d["name"] == name]
    if not defs:
        rec.update(stage="elaboration", changed=False, reason="no definition named %s%s" % (name, (": " + r["elab_errors"][:300]) if r.get("elab_errors") else ""))
        return rec
    subject = name
    if defs[0]["status"] != "Checked":
        obs = [o for o in r.get("unproven", []) if o["def"] == name]
        why = "; ".join("%s obligation %s: %s" % (o["kind"], o["status"].split("(")[0], " ".join(o["goal"].split())[:160]) for o in obs[:3])
        # a function that can panic: optimized through its panic-explicit
        # reading (DESIGN.md §8.2 item 12) when it has one
        pr = next((p for p in r.get("panics", []) if p["source"] == name), None)
        if pr is None or not pr.get("reading"):
            note = ("; no panic-explicit reading: " + pr["note"][:300]) if pr else ""
            rec.update(stage="elaboration", changed=False, reason="exec-only elaboration: %s%s%s" % (defs[0]["status"][:400], (" (" + why + ")") if why else "", note), unproven=obs)
            return rec
        subject = pr["reading"]
        rec["panic_reading"] = subject
        rec["unproven"] = obs
    fn = next((f for f in r["fns"] if f["name"] == subject and f["set"] is None), None)
    low = next((x for m in r["modules"] for x in m["records"] if x["function"] == name), None)
    rec["optimizer"] = fn
    rec["lowering"] = low
    if fn is None:
        rec.update(stage="optimizer", changed=False, reason="the optimizer has no report for it")
        return rec
    rec["outcome"] = fn["outcome"]
    rec["rung"] = fn["rung"]
    if low and low.get("lowered"):
        rec.update(stage="lowered", changed=True, origin=low["origin"], reason="lowered: rung %s, portable cost %s -> %s milli-cycles" % (low["rung"], low["cost_source"], low["cost_residual"]))
    else:
        why = low["reason"] if low else "no lowering record"
        if fn["outcome"] != "Specialized":
            why = "optimizer: %s%s" % ("FAILURE " if fn["failure"] else "", fn["reason"])
        rec.update(stage="kept", changed=False, reason=why)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--eval", required=True)
    ap.add_argument("--heavy", default="")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--set", choices=sorted(SETS), default="v1")
    args = ap.parse_args()
    configure(args.set)
    os.makedirs(os.path.join(args.work, "out"), exist_ok=True)
    fns = h1_functions()
    assert len(fns) == 30, f"H1 has {len(fns)} public functions, the manifest says 30"
    result = {"h1": [], "h2": [], "union": None}
    for f in fns:
        if args.only and f not in args.only:
            continue
        root = write_root(os.path.join(args.work, "roots", f), [f])
        r = run(args, root, os.path.join(args.work, "out", f), [f"crate::h1::{f}"], h1_rt_extract(args))
        json.dump(r, open(os.path.join(args.work, "out", f + ".json"), "w"), indent=1)
        rec = summarize(r, f"crate::h1::{f}")
        rec["set"] = "H1"
        result["h1"].append(rec)
        print(f"[H1] {f}: {rec['stage']}: {rec['reason'][:160]}", flush=True)
    for slug, kname, root, file, item, extract, mf in h2_functions():
        root = h2_root(args.work, slug, root)
        package = next((l.split('"')[1] for l in open(os.path.join(REPO, file.split("/src/")[0], "Cargo.toml")) if l.startswith("name = ")), None)
        r = run(args, root, os.path.join(args.work, "out", slug), [kname], h2_rt_extract(args, package, file, item, extract))
        json.dump(r, open(os.path.join(args.work, "out", slug + ".json"), "w"), indent=1)
        rec = summarize(r, kname)
        rec.update(set="H2", slug=slug, file=file, item=item, kind=mf.get("kind", "fn"), instance=mf.get("instance", ""), id=mf.get("id", kname))
        rec["untimed"] = h2_untimed(rec, mf)
        result["h2"].append(rec)
        print(f"[H2] {slug} {kname}: {rec['stage']}: {rec['reason'][:160]}", flush=True)
    # the union root: one lowered copy with every H1 rewrite
    passed = [r["function"].rsplit("::", 1)[1] for r in result["h1"] if r["stage"] != "reader"]
    gen = os.path.join(HERE, SETS[SET]["gen"])
    os.makedirs(gen, exist_ok=True)
    h1_gen = os.path.join(gen, "h1.rs")
    if passed and not args.only:
        root = write_root(os.path.join(args.work, "roots", "_union"), passed)
        r = run(args, root, os.path.join(args.work, "out", "_union"), [f"crate::h1::{f}" for f in passed], h1_rt_extract(args))
        json.dump(r, open(os.path.join(args.work, "out", "_union.json"), "w"), indent=1)
        result["union"] = {"items": passed, "front_end": r.get("front_end"), "errors": r.get("errors"), "records": [summarize(r, f"crate::h1::{f}") for f in passed] if r.get("front_end") else []}
        lowered = [m["written"] for m in r.get("modules", []) if m["file"].endswith("h1/src/lib.rs")]
        if lowered:
            open(h1_gen, "w").write(open(lowered[0]).read())
        else:
            open(h1_gen, "w").write(open(H1_SRC).read())
            result["union"]["note"] = "no lowered copy: gen/h1.rs is the source as-is"
    elif not args.only:
        open(h1_gen, "w").write(open(H1_SRC).read())
        result["union"] = {"items": [], "note": "no H1 function passed the reader: gen/h1.rs is the source as-is"}
    # H2: each timed function's text (h2_untimed): the optimized subject's from
    # its lowered copy (the source when nothing was lowered); v2 also writes
    # the rustc subject's, the source text (v1's is written by run.sh)
    parts, src_parts = [], []
    for rec in result["h2"]:
        if rec.get("untimed"):
            continue
        out = os.path.join(args.work, "out", rec["slug"])
        stem = os.path.splitext(os.path.basename(rec["file"]))[0]
        lowered = os.path.join(out, f"{stem}.lowered.rs")
        src = lowered if os.path.exists(lowered) else os.path.join(REPO, rec["file"])
        rec["opt_text_from"] = "lowered copy" if src == lowered else "source (no lowered copy)"
        p = subprocess.run([sys.executable, os.path.join(HERE, "items.py"), src, rec["item"], "--helpers", "--label", f"the lowered copy of {rec['file']}" if src == lowered else rec["file"]], capture_output=True, text=True, check=True)
        parts.append(p.stdout)
        if SET == "v2":
            p = subprocess.run([sys.executable, os.path.join(HERE, "items.py"), os.path.join(REPO, rec["file"]), rec["item"], "--label", rec["file"]], capture_output=True, text=True, check=True)
            src_parts.append(p.stdout)
    if not args.only:
        none = "// held-out v2 H2: no timed function (evaluate.py: a changed free function at no instance)\n"
        open(os.path.join(gen, "h2_opt.rs"), "w").write("\n".join(parts) if parts else none)
        if SET == "v2":
            open(os.path.join(gen, "h2_source.rs"), "w").write("\n".join(src_parts) if src_parts else none)
    json.dump(result, open(os.path.join(args.work, "eval.json"), "w"), indent=1)
    print(json.dumps({k: len(v) if isinstance(v, list) else bool(v) for k, v in result.items()}))


if __name__ == "__main__":
    main()
