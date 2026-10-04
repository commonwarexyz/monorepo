#!/usr/bin/env python3
"""H2-v2's rule-chosen instance (RULE.md section 3.1) of every generic candidate.

    PYTHONDONTWRITEBYTECODE=1 instance.py --dir DIR --heavy HEAVY --target TARGET

Reads DIR/candidates.tsv (sample.py) and rewrites it with an `instance`
column; a generic candidate with no instance moves to DIR/rejections.tsv
with `no instance (RULE.md 3.1)`, and the seeded order of the rest is
unchanged (ranks are renumbered). Per package with generic candidates:

1. the instance driver (instance/, a rustc driver on the pinned nightly of
   sandblaster/mirx) builds each parameter's list (the fixed primitive list,
   then at most 16 workspace types satisfying the parameter's bounds, as
   rustc's trait solver says, in the seeded order of
   `sha256("<seed>:instance:<full type path>")`) and walks the combinations
   in lexicographic order, at most 256, keeping those at which every
   predicate of the function holds and the function resolves;
2. a monomorphic wrapper for the first kept combination of each candidate
   is appended to a copy of its file, and rustc type-checks the package
   with the copies (the driver's SBI_REPLACE: no source file is edited);
   a candidate whose wrapper rustc refuses tries its next kept combination.

The instance is the first combination whose wrapper type-checks. Nothing
here is per function: every generic candidate goes through the same steps.
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
import sample  # noqa: E402

REPO = sample.REPO
TOOLCHAIN = re.search(r'channel = "(.*)"', open(os.path.join(REPO, "sandblaster/mirx/rust-toolchain.toml")).read()).group(1)
STUBS = f"commonware_codec:varint.rs={REPO}/codec/sandblaster/varint/varint.rs;commonware_storage:mmr-lowered__merkle__mmr__iterator.rs={REPO}/storage/src/merkle/mmr/iterator.rs"
csv.field_size_limit(1 << 30)


def read_tsv(path):
    with open(path) as f:
        return list(csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE))


def env(args):
    e = dict(os.environ)
    e.update(HEAVY_SLOTS="2", CARGO_BUILD_JOBS="4", SANDBLASTER_MEM_LIMIT_GB="6", SANDBLASTER_GATE_WORKERS="2")
    e["CARGO_TARGET_DIR"] = os.path.join(args.target, "sbinst-check")
    e["RUSTC_WRAPPER"] = ""
    e["RUSTC_WORKSPACE_WRAPPER"] = args.driver
    e["SBI_STUBS"] = STUBS
    e["SBI_SEED"] = sample.SEED
    e["SBI_REPO"] = REPO
    return e


def lib_rs(package):
    return os.path.join(REPO, package_dir(package), "src/lib.rs")


def package_dir(package):
    return next(d for p, d, _ in sample.SCOPE if p == package)


def cargo_check(args, package, extra):
    e = env(args)
    e.update(extra)
    e["SBI_CRATE"] = package.replace("-", "_")
    # the crate's library is re-checked each time, as extract.sh does (mtime only)
    os.utime(lib_rs(package))
    cmd = [args.heavy, "cargo", f"+{TOOLCHAIN}", "check", "-q", "-p", package]
    t = time.time()
    p = subprocess.run(cmd, cwd=REPO, env=e, capture_output=True, text=True)
    return p, time.time() - t


# ---------------------------------------------------------------------------
# wrappers (RULE.md 3.1 step 3)
# ---------------------------------------------------------------------------

def subst(text, names, self_qual=None):
    """`text` (a type or path as written) with each parameter name replaced by
    its chosen argument, `Self` by the self type (`Self::X` by
    `<Type as Trait>::X` in a trait impl), and lifetimes by `'_`."""
    toks = sample.lex(text)
    out = []
    for k, t in enumerate(toks):
        prev = toks[k - 1] if k else None
        nxt = toks[k + 1] if k + 1 < len(toks) else None
        if t.kind == "ident" and t.text == "Self" and self_qual and nxt is not None and nxt.kind == "punct" and nxt.text == "::":
            out.append(sample.Tok("raw", self_qual, t.line))
        elif t.kind == "ident" and t.text in names and not (prev is not None and prev.kind == "punct" and prev.text in ("::", ".")):
            out.append(sample.Tok("raw", names[t.text], t.line))
        elif t.kind == "life" and t.text != "'static":
            out.append(sample.Tok("raw", "'_", t.line))
        else:
            out.append(t)
    res, prev_word = [], False
    for t in out:
        s = t.text if t.kind != "str" else json.dumps(t.text)
        word = t.kind in ("ident", "life", "num", "raw")
        if res and word and prev_word:
            res.append(" ")
        res.append(s)
        prev_word = word
    return "".join(res)


def split_top(text):
    return [sample.text_of(p) for p in sample.split_top(sample.lex(text))]


def wrapper(cand, gen, params, combo, wname):
    """One monomorphic wrapper calling the candidate at `combo` (one
    argument per driver parameter, lifetimes included as `'_`)."""
    named, synth = {}, []
    for p, a in zip(params, combo):
        if p.get("synthetic"):
            synth.append(a)
        elif p["kind"] in ("type", "const"):
            named[p["name"]] = a
    n_impl = gen["n_impl_params"]
    src_params = [p for p in gen["params"] if p["kind"] != "lifetime" and not p.get("impl_trait")]
    impl_names = [p["name"] for p in gen["params"][:n_impl] if p["kind"] != "lifetime"]
    fn_names = [p["name"] for p in src_params if p["name"] not in impl_names]
    self_ty = subst(gen["self_ty"], named) if gen["self_ty"] else None
    names_self = dict(named)
    if self_ty:
        names_self["Self"] = self_ty
    trait = subst(gen["trait"], names_self) if gen["trait"] else None
    self_qual = f"<{self_ty} as {trait}>" if trait else (f"<{self_ty}>" if self_ty else None)
    if cand["kind"] == "fn":
        base = cand["name"]
    elif trait:
        base = f"<{self_ty} as {trait}>::{cand['name']}"
    else:
        base = f"<{self_ty}>::{cand['name']}"
    if not synth:
        targs = [named[n] for n in fn_names if n in named]
        path = base + (f"::<{', '.join(targs)}>" if targs else "")
        return f"#[allow(dead_code, unused, clippy::all)] fn {wname}() {{ let _ = {path}; }}"
    # an `impl Trait` argument: the call form (explicit arguments are not allowed)
    args, decls, k = [], [], 0
    for i, p in enumerate(split_top(gen["fn_params"])):
        toks = sample.lex(p)
        texts = [t.text for t in toks]
        if "self" in texts and (":" not in texts or texts.index("self") < texts.index(":")):
            if ":" in texts:
                ty = subst(p.split(":", 1)[1], names_self, self_qual)
            else:
                pre = "".join(t for t in texts[: texts.index("self")] if t in ("&", "mut") or t.startswith("'"))
                ty = ("&mut " if "&" in pre and "mut" in pre else "&" if "&" in pre else "") + self_ty
        else:
            # the type after the pattern's top-level `:`
            depth, colon = 0, None
            for j, t in enumerate(toks):
                if t.kind == "punct" and t.text in ("(", "[", "<"):
                    depth += 1
                elif t.kind == "punct" and t.text in (")", "]", ">"):
                    depth -= 1
                elif t.kind == "punct" and t.text == ":" and depth == 0:
                    colon = j
                    break
            ty_toks = toks[colon + 1:]
            # each `impl Bounds` in it: the chosen type of the next anonymous parameter
            ty_text = sample.text_of(ty_toks)
            while "impl" in [t.text for t in sample.lex(ty_text) if t.kind == "ident"]:
                lt = sample.lex(ty_text)
                at = next(j for j, t in enumerate(lt) if t.kind == "ident" and t.text == "impl")
                b = sample.impl_trait_params(lt[at:])[0]["_btoks"]
                ty_text = sample.text_of(lt[:at]) + " __SBI_SYNTH__ " + sample.text_of(lt[at + 1 + len(b):])
                ty_text = ty_text.replace("__SBI_SYNTH__", synth[k] if k < len(synth) else "()", 1)
                k += 1
            ty = subst(ty_text, names_self, self_qual)
        decls.append(f"a{i}: {ty}")
        args.append(f"a{i}")
    return f"#[allow(dead_code, unused, clippy::all)] fn {wname}({', '.join(decls)}) {{ let _ = {base}({', '.join(args)}); }}"


ERR = re.compile(r"^(error)(\[E\d+\])?: ")
LOC = re.compile(r"^\s*--> (.+?):(\d+):(\d+)")


def confirm(args, package, items):
    """items: [(rank, file, text)]: type-checks every wrapper at once (one
    copy per file); returns {rank: first error} for the refused ones."""
    by_file = {}
    for rank, file, text in items:
        by_file.setdefault(file, []).append((rank, text))
    work = os.path.join(args.work, package)
    os.makedirs(work, exist_ok=True)
    reps, line_of = [], {}
    for file, ws in by_file.items():
        src = open(os.path.join(REPO, file)).read()
        if not src.endswith("\n"):
            src += "\n"
        base = src.count("\n")
        lines = []
        for k, (rank, text) in enumerate(ws):
            lines.append(text)
            line_of[(file, base + k + 1)] = rank
        copy = os.path.join(work, file.replace("/", "__"))
        open(copy, "w").write(src + "\n".join(lines) + "\n")
        reps.append(f"{os.path.join(REPO, file)}={copy}")
    p, secs = cargo_check(args, package, {"SBI_REPLACE": ",".join(reps)})
    refused, other = {}, []
    lines = (p.stderr + p.stdout).splitlines()
    for k, l in enumerate(lines):
        m = ERR.match(l)
        if not m:
            continue
        loc = next((LOC.match(x) for x in lines[k + 1:k + 6] if LOC.match(x)), None)
        if loc is None:
            other.append(l)
            continue
        f = loc.group(1)
        rel = os.path.relpath(f, REPO) if os.path.isabs(f) else f
        rank = line_of.get((rel, int(loc.group(2))))
        if rank is None:
            other.append(l + " at " + loc.group(1) + ":" + loc.group(2))
            continue
        refused.setdefault(rank, l.strip())
    if p.returncode != 0 and not refused:
        raise SystemExit(f"{package}: the wrapper check failed outside the wrappers:\n" + "\n".join(lines[-40:]))
    return refused, other, secs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=HERE)
    ap.add_argument("--heavy", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--driver", required=True, help="the built sb-h2v2-instance binary")
    ap.add_argument("--work", help="scratch directory for the driver's files and the wrapper copies (default DIR/instance-work)")
    ap.add_argument("--only-package")
    args = ap.parse_args()
    args.work = args.work or os.path.join(args.dir, "instance-work")
    cands = read_tsv(os.path.join(args.dir, "candidates.tsv"))
    os.makedirs(args.work, exist_ok=True)
    log = open(os.path.join(args.work, "instance-log.txt"), "a")
    results = {}
    packages = sorted({c["package"] for c in cands if c["generic"] == "yes"})
    for package in packages:
        if args.only_package and package != args.only_package:
            continue
        gen_c = [c for c in cands if c["package"] == package and c["generic"] == "yes"]
        inp = os.path.join(args.work, f"{package}.in.tsv")
        out = os.path.join(args.work, f"{package}.out.jsonl")
        os.makedirs(os.path.dirname(inp), exist_ok=True)
        with open(inp, "w") as w:
            for c in gen_c:
                w.write(f"{c['rank']}\t{c['file']}\t{c['line']}\t{c['name']}\n")
        p, secs = cargo_check(args, package, {"SBI_IN": inp, "SBI_OUT": out})
        if p.returncode != 0 or not os.path.exists(out):
            raise SystemExit(f"{package}: the instance driver failed:\n{p.stderr[-3000:]}")
        recs = [json.loads(l) for l in open(out) if l.strip()]
        print(f"{package}: {len(gen_c)} generic candidates, {recs[0]['workspace_types']} workspace types, driver {secs:.0f} s", flush=True)
        log.write(f"{package}: driver {secs:.0f} s, {recs[0]['workspace_types']} workspace types\n")
        by_rank = {str(r["rank"]): r for r in recs[1:]}
        # literal wrapper check, kept combination after kept combination
        pending = {}
        for c in gen_c:
            r = by_rank.get(c["rank"])
            if r is None or not r.get("found"):
                results[c["rank"]] = {"none": "the instance driver did not find the function (RULE.md 3.1)"}
                continue
            if r.get("skip"):
                results[c["rank"]] = {"none": r["skip"]}
                continue
            if not r["kept"]:
                results[c["rank"]] = {"none": f"no instance (RULE.md 3.1): none of the {r['checked']} combinations checked type-checks", "driver": r}
                continue
            pending[c["rank"]] = (c, r, 0)
        rnd = 0
        while pending:
            rnd += 1
            items = []
            for rank, (c, r, i) in pending.items():
                items.append((rank, c["file"], wrapper(c, json.loads(c["generics"]), r["params"], r["kept"][i], f"__sb_h2v2_w{rank}")))
            refused, other, secs = confirm(args, package, items)
            log.write(f"{package}: wrapper round {rnd}: {len(items)} wrappers, {len(refused)} refused, {secs:.0f} s\n")
            for o in other[:20]:
                log.write(f"  error outside a wrapper line: {o}\n")
            nxt = {}
            for rank, (c, r, i) in pending.items():
                params = r["params"]
                if rank not in refused:
                    combo = r["kept"][i]
                    results[rank] = {"params": [{"name": p["name"], "kind": p["kind"], "synthetic": p.get("synthetic", False), "traits": p.get("traits", []), "arg": a,
                                                 "list": p["list"]} for p, a in zip(params, combo) if p["kind"] in ("type", "const")],
                                     "checked": r["checked"], "kept_index": i, "wrapper": next(t for rk, _, t in items if rk == rank)}
                    continue
                log.write(f"  #{rank} {c['id']}: wrapper {i} refused: {refused[rank]}\n")
                if i + 1 < len(r["kept"]):
                    nxt[rank] = (c, r, i + 1)
                else:
                    results[rank] = {"none": f"no instance (RULE.md 3.1): rustc refuses the wrapper of each of the {len(r['kept'])} combinations the trait solver kept ({r['checked']} checked)" + ("; the driver keeps at most 8: re-run with a larger KEEP" if len(r["kept"]) == 8 else ""), "driver": r, "last_error": refused[rank]}
            pending = nxt
        log.flush()
    if args.only_package:
        json.dump(results, open(os.path.join(args.work, f"{args.only_package}.results.json"), "w"), indent=1)
        return
    # rewrite candidates.tsv (instance column) and rejections.tsv (no instance)
    keep, rej = [], []
    for c in cands:
        if c["generic"] != "yes":
            c["instance"] = "-"
            keep.append(c)
            continue
        r = results[c["rank"]]
        if "none" in r:
            rej.append((c, r["none"]))
            continue
        c["instance"] = json.dumps({"params": r["params"], "checked": r["checked"], "wrapper": r["wrapper"]}, separators=(",", ":"))
        keep.append(c)
    cols = ["rank", "id", "package", "file", "line", "module", "kind", "item", "name", "others", "trait_methods", "traits", "children", "generic", "key", "instance", "generics"]
    with open(os.path.join(args.dir, "candidates.tsv"), "w") as w:
        w.write("\t".join(cols) + "\n")
        for k, c in enumerate(keep, 1):
            c["rank"] = str(k)
            w.write("\t".join(str(c[x]) for x in cols) + "\n")
    with open(os.path.join(args.dir, "rejections.tsv"), "a") as w:
        for c, why in rej:
            w.write(f"instance\t{c['id']}\t{c['file']}\t{c['line']}\t{why}\n")
    print(f"{len(keep)} candidates ({sum(c['generic'] == 'yes' for c in keep)} generic with an instance), {len(rej)} without an instance")


if __name__ == "__main__":
    main()
