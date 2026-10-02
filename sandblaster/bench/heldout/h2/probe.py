#!/usr/bin/env python3
"""H2 probe (RULE.md section 5): candidates in the seeded order of
candidates.tsv, until 40 pass.

    probe.py --work DIR --probe BIN [--heavy HEAVY] [--want 40]

For each candidate, in order (the first failing step is the reason):

1. extraction: sandblaster/mirx/extract.sh of the candidate's module with
   --items (its item; every other module under the module path empty),
   --skip-fns (the type's other methods) and the verifying build scripts of
   codec and storage stubbed by their sources; the .sbmir must have a root
   for the candidate;
2. size: the root's body has a loop (a back edge of a depth-first walk from
   bb0, or a direct call of itself) or at least 10 statements;
3. reader: a generated DSL root lifting the candidate's file in place
   (`#[lift(mir = .., in_place, items = ..)]`) passes `driver::check`;
4. exec-only elaboration: every definition elaborated from the candidate
   is `Checked`.

Steps 3 and 4 run `heldout_probe` (sandblaster/front/examples), which never
calls the optimizer. Results go to DIR/probe.tsv (one row per probed
candidate; a rerun resumes after the last row), the extractions to DIR/mir
and the generated roots to DIR/roots. No source file is edited (extract.sh
only touches the package's lib.rs mtime, as it always does).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sample  # noqa: E402

REPO = sample.REPO
STUBS = "commonware_codec:varint.rs=codec/sandblaster/varint/varint.rs;commonware_storage:mmr-lowered__merkle__mmr__iterator.rs=storage/src/merkle/mmr/iterator.rs"
STORAGE_OWN_STUB = "mmr-lowered__merkle__mmr__iterator.rs=storage/src/merkle/mmr/iterator.rs"
TERMINATORS = {"goto", "switch", "call", "return", "unreachable", "assert", "drop", "resume"}


def read_tsv(path):
    with open(path) as f:
        cols = f.readline().rstrip("\n").split("\t")
        return [dict(zip(cols, line.rstrip("\n").split("\t"))) for line in f if line.strip()]


def file_info(cand):
    """Re-reads the candidate's file: the type's other methods (inherent and
    of trait impls), the traits implemented for it, and the inline modules."""
    src = open(os.path.join(REPO, cand["file"]), encoding="utf-8").read()
    toks = sample.lex(src)
    out, mods = [], []
    ctx = {"testish": False, "kind": "free"}
    sample.SKIPPED.clear()
    sample.parse_items(toks, 0, len(toks), ctx, out, mods)
    ty = cand["item"] if cand["kind"] == "method" else None
    inherent_others, trait_methods, traits = set(), set(), set()
    if ty:
        for g in out:
            if g.ctx.get("self_ty") != ty:
                continue
            if g.ctx.get("kind") == "inherent" and g.name != cand["name"]:
                inherent_others.add(g.name)
            elif g.ctx.get("kind") == "trait_impl":
                trait_methods.add(g.name)
        for im in ctx.get("_impls", []):
            if im.get("kind") == "trait_impl" and im.get("self_ty") == ty and im.get("trait"):
                traits.add(im["trait"])
    # inline modules (any depth), as paths below the file's module
    inline, stack = [], []
    for k, t in enumerate(toks):
        while stack and k > stack[-1][1]:
            stack.pop()
        if t.kind == "ident" and t.text == "mod" and k + 2 < len(toks) and toks[k + 1].kind == "ident" and toks[k + 2].kind == "punct" and toks[k + 2].text == "{":
            close = sample.close_of(toks, k + 2)
            stack.append((toks[k + 1].text, close))
            inline.append("::".join(n for n, _ in stack))
    # whether the item is declared plain `pub` (the generated root re-exports it only then)
    if ty:
        item_pub = any(toks[k].kind == "ident" and toks[k].text == "pub" and toks[k + 1].kind == "ident" and toks[k + 1].text in ("struct", "enum", "union", "type")
                       and toks[k + 2].kind == "ident" and toks[k + 2].text == ty for k in range(len(toks) - 2))
    else:
        item_pub = any(g.name == cand["name"] and g.ctx.get("kind") == "free" and g.sig and g.sig[0].text == "pub" and not (len(g.sig) > 1 and g.sig[1].text == "(") for g in out)
    return sorted(inherent_others), sorted(trait_methods), sorted(traits), inline, item_pub


def descendant_modules(cand):
    """Module paths of the crate's files below the candidate's module."""
    crate_dir = cand["file"].split("/")[0]
    mp = cand["module"]
    res = set()
    for root, dirs, files in os.walk(os.path.join(REPO, crate_dir, "src")):
        for fn in files:
            if fn.endswith(".rs"):
                rel = os.path.relpath(os.path.join(root, fn), os.path.join(REPO, crate_dir))
                m = sample.module_path(rel)
                if m.startswith(mp + "::"):
                    res.add(m)
    return sorted(res)


def sbmir_fns(text):
    """{name: lines of its (fn ..) block} and the root list."""
    roots = re.findall(r'^\(root "([^"]*)"\)', text, re.M)
    fns, cur, buf = {}, None, []
    for line in text.split("\n"):
        m = re.match(r'^\(fn "([^"]*)"', line)
        if m:
            if cur:
                fns[cur] = buf
            cur, buf = m.group(1), [line]
        elif cur is not None:
            if line.startswith("(") and not line.startswith("(fn "):
                fns[cur] = buf
                cur, buf = None, []
            else:
                buf.append(line)
    if cur:
        fns[cur] = buf
    return roots, fns


def body_shape(lines, name):
    """(statements, has a loop) of one (fn ..) block."""
    blocks, cur = {}, None
    stmts = 0
    self_call = False
    for line in lines:
        m = re.match(r"^  \(bb (\d+)", line)
        if m:
            cur = int(m.group(1))
            blocks[cur] = []
            continue
        if cur is None:
            continue
        m = re.match(r"^    \((\w[\w-]*)", line)
        if not m:
            continue
        op = m.group(1)
        if op in TERMINATORS:
            # successors: the bare block numbers of goto/switch arms/call/assert/drop
            if op == "goto":
                blocks[cur] += [int(x) for x in re.findall(r"^    \(goto (\d+)", line)]
            elif op == "switch":
                blocks[cur] += [int(x) for x in re.findall(r"\((?:\d+|otherwise) (\d+)\)", line)]
            elif op in ("call", "assert", "drop"):
                # the target is the last bare integer before the optional `(at ..)`
                # (`none` for a diverging call)
                tail = re.sub(r'\s*\(at "[^"]*" \d+ \d+\)', "", line).rstrip().rstrip(")").rstrip()
                m2 = re.search(r"\s(\d+)$", tail)
                if m2:
                    blocks[cur].append(int(m2.group(1)))
                if op == "call" and f'(fn "{name}")' in line:
                    self_call = True
        else:
            stmts += 1
    # a back edge of a depth-first walk from bb0
    color, has_loop = {}, False
    stack = [(0, iter(blocks.get(0, [])))]
    color[0] = 1
    while stack:
        b, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            color[b] = 2
            stack.pop()
            continue
        if color.get(nxt) == 1:
            has_loop = True
        elif nxt not in color and nxt in blocks:
            color[nxt] = 1
            stack.append((nxt, iter(blocks[nxt])))
    return stmts, has_loop or self_call


def crate_name(pkg):
    return pkg.replace("-", "_")


def find_root(cand, roots):
    c = crate_name(cand["package"])
    mp = cand["module"]
    if cand["kind"] == "fn":
        want = f"{c}::{mp}::{cand['name']}"
        return want if want in roots else None
    pre = f"{c}::{mp}::{cand['item']}"
    for r in roots:
        if (r.startswith(pre + "::") or r.startswith(pre + "<")) and r.endswith("::" + cand["name"]):
            return r
    return None


def env():
    e = dict(os.environ)
    e.update(HEAVY_SLOTS="2", CARGO_BUILD_JOBS="4", SANDBLASTER_MEM_LIMIT_GB="6", SANDBLASTER_GATE_WORKERS="2")
    return e


def extract(cand, out, args, info):
    others, trait_methods, traits, inline, _ = info
    mp = cand["module"]
    item = cand["item"]
    items = [f"{mp}={item}"] + [f"{m}=" for m in descendant_modules(cand)] + [f"{mp}::{m}=" for m in inline]
    cmd = [args.heavy, os.path.join(REPO, "sandblaster/mirx/extract.sh"), cand["package"], mp, out, "--items", ";".join(items), "--stubs", STUBS]
    if cand["package"] == "commonware-storage":
        cmd += ["--stub", STORAGE_OWN_STUB]
    skip = sorted({f"{item}::{m}" for m in others + trait_methods if m != cand["name"]}) if cand["kind"] == "method" else []
    if skip:
        cmd += ["--skip-fns", ",".join(skip)]
    e = env()
    e["SBMIR_TARGET_DIR"] = os.path.join(args.target, "mirx")
    e["CARGO_TARGET_DIR"] = args.target
    t = time.time()
    p = subprocess.run(cmd, cwd=REPO, env=e, capture_output=True, text=True)
    return p, time.time() - t, cmd


def gen_root(cand, rank, mir_path, args, info, base, name=None):
    """The DSL root lifting the candidate's file in place (RULE.md 5.3), in
    base/<name> (default `r<rank>`)."""
    others, trait_methods, traits, inline, item_pub = info
    d = os.path.join(base, name or f"r{rank:03d}")
    os.makedirs(d, exist_ok=True)
    parts = cand["module"].split("::")
    host = os.path.join(REPO, cand["file"])
    item = cand["item"]
    # the declaring file: mod.rs for a one-segment path, else `<parts[:-1]>.rs`;
    # `mir` and `#[path]` are relative to its directory
    decl_dir = os.path.join(d, *parts[:-2]) if len(parts) >= 2 else d
    opts = [f'mir = "{os.path.relpath(mir_path, decl_dir)}"', "in_place", f'items = "{item}"']
    if cand["kind"] == "method":
        if others:
            opts.append('unverified_fns = "' + ", ".join(f"{item}::{m}" for m in others) + '"')
        if traits:
            opts.append('unverified_impls = "' + ", ".join(traits) + '"')
    lift = f"#[lift({', '.join(opts)})]\n#[path = \"{os.path.relpath(host, decl_dir)}\"]\npub mod {parts[-1]};\n"
    top = "//! H2 probe root (generated by sandblaster/bench/heldout/h2/probe.py).\n#![forbid(unsafe_code)]\n"
    if len(parts) == 1:
        top += "\n" + lift
    else:
        top += f"\nmod {parts[0]};\n"
    if item_pub:
        top += f"\npub use {'::'.join(parts)}::{item};\n"
    with open(os.path.join(d, "mod.rs"), "w") as w:
        w.write(top)
    for k in range(1, len(parts)):
        p = os.path.join(d, *parts[:k]) + ".rs"
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as w:
            w.write(lift if k == len(parts) - 1 else f"pub mod {parts[k]};\n")
    return os.path.join(d, "mod.rs")


def run_probe(root, cand, args):
    mp = cand["module"]
    pre = f"crate::{mp}::{cand['name']}" if cand["kind"] == "fn" else f"crate::{mp}::{cand['item']}::{cand['name']}"
    cmd = [args.heavy, args.probe, root, pre]
    t = time.time()
    p = subprocess.run(cmd, cwd=REPO, env=env(), capture_output=True, text=True)
    line = next((l for l in p.stdout.splitlines() if l.startswith("{")), None)
    if line is None:
        return None, p, time.time() - t, pre
    return json.loads(line), p, time.time() - t, pre


def one_line(s, n=400):
    # repo-relative paths: `<probe root>/../../mono-wt/utils/src/x.rs` -> `utils/src/x.rs`
    s = re.sub(r"\S*?/roots/r\d+/(?:[\w.-]+/)*?mono-wt/", "", s)
    s = re.sub(r"\S*?/roots/r\d+/", "<root>/", s)
    s = s.replace(REPO + "/", "")
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n]


def probe(cand, rank, args):
    """(accepted, reason, details) for one candidate."""
    if cand["module"] == "":
        return False, "probe 1 (extraction): in the crate root file; mirx extracts a module of the crate (SBMIR_MODULE) and the in-place lift declares one", {}
    info = file_info(cand)
    mir = os.path.join(args.work, "mir", f"r{rank:03d}.sbmir")
    os.makedirs(os.path.dirname(mir), exist_ok=True)
    p, secs, cmd = extract(cand, mir, args, info)
    det = {"extract_secs": round(secs, 1)}
    with open(mir + ".log", "w") as w:
        w.write(" ".join(cmd) + "\n\n" + p.stdout + "\n" + p.stderr)
    if p.returncode != 0 or not os.path.exists(mir):
        err = [l for l in (p.stderr + p.stdout).splitlines() if l.strip() and ("error" in l.lower() or "panicked" in l)]
        return False, "probe 1 (extraction): failed: " + one_line(err[0] if err else (p.stderr or p.stdout)[-300:]), det
    text = open(mir).read()
    roots, fns = sbmir_fns(text)
    root = find_root(cand, roots)
    if root is None:
        notes = [l for l in text.splitlines() if l.startswith("(note") and cand["name"] in l]
        return False, "probe 1 (extraction): no MIR root for the candidate" + (": " + one_line(notes[0], 200) if notes else ""), det
    stmts, loop = body_shape(fns.get(root, []), root)
    det.update(statements=stmts, loop=loop, mir_root=root)
    if not loop and stmts < 10:
        return False, f"probe 2 (size): no loop and {stmts} MIR statements (< 10)", det
    droot = gen_root(cand, rank, mir, args, info, os.path.join(args.work, "roots"))
    res, pp, secs, pre = run_probe(droot, cand, args)
    det["probe_secs"] = round(secs, 1)
    with open(os.path.join(os.path.dirname(droot), "probe.log"), "w") as w:
        w.write(pp.stdout + "\n" + pp.stderr)
    if res is None:
        return False, "probe 3 (reader): the probe did not finish: " + one_line(pp.stderr[-400:]), det
    if not res["front_end"]:
        errs = [l for l in res["errors"].splitlines() if "error[" in l]
        return False, "probe 3 (reader): driver::check refused: " + one_line(errs[0] if errs else res["errors"]), det
    defs = res["defs"]
    det["defs"] = [(d["name"], d["status"]) for d in defs]
    if not defs:
        return False, f"probe 4 (exec-only): no definition named {pre}" + (": elaboration errors: " + one_line(res["errors"], 300) if res["errors"] else ""), det
    bad = [d for d in defs if d["status"] != "Checked"]
    if bad:
        return False, "probe 4 (exec-only): " + one_line("; ".join(f"{d['name']}: {d['status']}" for d in bad[:3]), 400), det
    return True, f"accepted: {len(defs)} definition(s) Checked; {stmts} MIR statements, loop={loop}", det


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--probe", required=True)
    ap.add_argument("--heavy", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--want", type=int, default=40)
    ap.add_argument("--only", type=int, nargs="*")
    args = ap.parse_args()
    cands = read_tsv(os.path.join(HERE, "candidates.tsv"))
    os.makedirs(args.work, exist_ok=True)
    out = os.path.join(args.work, "probe.tsv")
    done = {}
    if os.path.exists(out):
        for r in read_tsv(out):
            done[int(r["rank"])] = r
    else:
        with open(out, "w") as w:
            w.write("rank\tid\taccepted\treason\tdetails\n")
    accepted = sum(1 for r in done.values() if r["accepted"] == "yes")
    for c in cands:
        rank = int(c["rank"])
        if args.only and rank not in args.only:
            continue
        if rank in done:
            continue
        if accepted >= args.want and not args.only:
            break
        ok, why, det = probe(c, rank, args)
        accepted += ok
        with open(out, "a") as w:
            w.write(f"{rank}\t{c['id']}\t{'yes' if ok else 'no'}\t{why}\t{json.dumps(det)}\n")
        print(f"[{accepted:2d}] #{rank} {c['id']}: {why}", flush=True)
    print(f"accepted {accepted}")


if __name__ == "__main__":
    main()
