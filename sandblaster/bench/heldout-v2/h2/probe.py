#!/usr/bin/env python3
"""H2-v2 probe (RULE.md section 5): candidates in the seeded order of
candidates.tsv, until 40 pass.

    PYTHONDONTWRITEBYTECODE=1 probe.py --work WORK --probe BIN --heavy HEAVY --target TARGET [--dir DIR] [--want 40] [--workers N] [--chunk K]

For each candidate (the first failing step is the reason):

1. extraction: sandblaster/mirx/extract.sh of the candidate's module, with
   --items (its item; every other module under the module path, and every
   inline module of the file, empty), --skip-fns (the type's other methods
   in the file), the verifying build scripts of codec and storage stubbed
   by their sources, and for a generic candidate its instance (RULE.md 3.1)
   through the toolchain's instance mechanism: a module of type aliases
   (`--inject __sb_h2v2_inst=..`, one alias per type parameter) and
   `--instance <bound>=__sb_h2v2_inst::T<k>` for the parameter's bounds (a
   bound shared by two parameters with different instances names the
   first; a parameter bounded only by `Sized` is named by it). The .sbmir
   must have a root for the candidate: the root whose span is the
   candidate's own line in its file;
2. callee closure: every workspace (`commonware_*`) function the root
   reaches through the calls the extraction resolved, and the same-crate
   constant items read; at most 32 functions in at most 12 files; a call
   the extraction could not resolve statically (`does not resolve`, a
   virtual call, a call through a function pointer) rejects. When the
   closure holds functions of other modules of the candidate's crate, the
   extraction is run again with those modules and items too (RULE.md 5.1);
3. size: the root's own body has a loop (a back edge of a depth-first walk
   from bb0, or a direct call of itself) or at least 10 statements;
4. reader: a generated DSL root declaring in place the candidate's file and
   the files of the closure's functions of its crate (each with `mir`,
   `in_place`, `items`, `unverified_fns`, `unverified_impls`, and the
   instance for a generic candidate) passes `driver::check`;
5. exec-only elaboration: every definition elaborated from the candidate
   is `Checked`.

Steps 4 and 5 run `heldout_probe` (sandblaster/front/examples), which never
calls the optimizer. The extractions of a chunk of candidates (`--chunk`) run
one after the other inside one admission slot (`heavy`, `--exec-batch`): the
same commands, in the same order per candidate, queued for the shared slots
once per chunk instead of once each. Results go to WORK/probe.tsv (one row per probed
candidate; a rerun resumes), extractions to WORK/mir, roots to WORK/roots.
No source file is edited (extract.sh only touches the package's lib.rs
mtime, as it always does).
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
import sample  # noqa: E402

REPO = sample.REPO
STUBS = "commonware_codec:varint.rs=codec/sandblaster/varint/varint.rs;commonware_storage:mmr-lowered__merkle__mmr__iterator.rs=storage/src/merkle/mmr/iterator.rs"
STORAGE_OWN_STUB = "mmr-lowered__merkle__mmr__iterator.rs=storage/src/merkle/mmr/iterator.rs"
TERMINATORS = {"goto", "switch", "call", "return", "unreachable", "assert", "drop", "resume"}
INST_MOD = "__sb_h2v2_inst"
MAX_FNS, MAX_FILES = 32, 12
csv.field_size_limit(1 << 30)


def read_tsv(path):
    with open(path) as f:
        return list(csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE))


def parse_file(path):
    src = open(os.path.join(REPO, path), encoding="utf-8").read()
    toks = sample.lex(src)
    out, mods = [], []
    ctx = {"testish": False, "kind": "free"}
    sample.SKIPPED.clear()
    sample.parse_items(toks, 0, len(toks), ctx, out, mods)
    return toks, out, ctx


def file_info(file, types, fns, exclude_names):
    """For the items of one file: the other methods of its types (inherent
    and of trait impls: --skip-fns / unverified_fns), the traits implemented
    for them (unverified_impls), its inline modules, and whether each item
    is declared plain `pub`."""
    toks, out, ctx = parse_file(file)
    skip, traits = set(), set()
    keep_traits = set()
    for ty in types:
        for g in out:
            if g.ctx.get("self_ty") != ty or g.ctx.get("kind") not in ("inherent", "trait_impl"):
                continue
            if (ty, g.name) in exclude_names:
                if g.ctx.get("kind") == "trait_impl":
                    keep_traits.add(g.ctx.get("trait"))
                continue
            skip.add(f"{ty}::{g.name}")
        for im in ctx.get("_impls", []):
            if im.get("kind") == "trait_impl" and im.get("self_ty") == ty and im.get("trait"):
                traits.add(im["trait"])
    traits -= keep_traits
    inline, stack = [], []
    for k, t in enumerate(toks):
        while stack and k > stack[-1][1]:
            stack.pop()
        if t.kind == "ident" and t.text == "mod" and k + 2 < len(toks) and toks[k + 1].kind == "ident" and toks[k + 2].kind == "punct" and toks[k + 2].text == "{":
            close = sample.close_of(toks, k + 2)
            stack.append((toks[k + 1].text, close))
            inline.append("::".join(n for n, _ in stack))
    pub = {}
    for it in list(types) + list(fns):
        if it in types:
            pub[it] = any(toks[k].kind == "ident" and toks[k].text == "pub" and toks[k + 1].kind == "ident" and toks[k + 1].text in ("struct", "enum", "union", "type")
                          and toks[k + 2].kind == "ident" and toks[k + 2].text == it for k in range(len(toks) - 2))
        else:
            pub[it] = any(g.name == it and g.ctx.get("kind") == "free" and g.sig and g.sig[0].text == "pub" and not (len(g.sig) > 1 and g.sig[1].text == "(") for g in out)
    return sorted(skip), sorted(traits), inline, pub


def descendant_modules(crate_dir, mp):
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
    roots = re.findall(r'^\(root "((?:[^"\\]|\\.)*)"\)', text, re.M)
    fns, cur, buf = {}, None, []
    for line in text.split("\n"):
        m = re.match(r'^\(fn "((?:[^"\\]|\\.)*)"', line)
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
            if op == "goto":
                blocks[cur] += [int(x) for x in re.findall(r"^    \(goto (\d+)", line)]
            elif op == "switch":
                blocks[cur] += [int(x) for x in re.findall(r"\((?:\d+|otherwise) (\d+)\)", line)]
            elif op in ("call", "assert", "drop"):
                tail = re.sub(r'\s*\(at "[^"]*" \d+ \d+\)', "", line).rstrip().rstrip(")").rstrip()
                m2 = re.search(r"\s(\d+)$", tail)
                if m2:
                    blocks[cur].append(int(m2.group(1)))
                if op == "call" and f'(fn "{name}")' in line:
                    self_call = True
        else:
            stmts += 1
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


def fn_meta(lines):
    """(kind, def path, span file, span line, item line) of one (fn ..) block."""
    head = "\n".join(lines[:4])
    kind = re.search(r"\(kind (\w+)\)", head)
    d = re.search(r'\(def "((?:[^"\\]|\\.)*)"\)', head)
    sp = re.search(r'\(span "([^"]*)" (\d+) \d+\)', head)
    item = next((l.strip() for l in lines[1:4] if l.strip().startswith("(item")), "")
    return (kind.group(1) if kind else None, d.group(1) if d else "", sp.group(1) if sp else None, int(sp.group(2)) if sp else None, item)


def find_root(cand, roots, fns):
    """The root whose span is the candidate's line in its file."""
    rel = cand["file"].split("/", 1)[1]  # crate-relative (`src/..`)
    line = int(cand["line"])
    hits = []
    for r in roots:
        k, d, f, l, _ = fn_meta(fns.get(r, []))
        if f == rel and l == line:
            hits.append(r)
    return hits[0] if len(hits) == 1 else (hits[0] if hits else None)


CALL = re.compile(r'\(call \((fn|unextracted|unsupported|leaf|diverge|intrinsic) "((?:[^"\\]|\\.)*)"')


def closure(root, fns, crate):
    """The callee closure (RULE.md 5.2): workspace functions reachable from
    the root, and the unresolved calls met on the way."""
    seen, todo, ws, unresolved, consts = {root}, [root], [], [], set()
    while todo:
        f = todo.pop()
        for line in fns.get(f, []):
            for m in CALL.finditer(line):
                kind, name = m.group(1), m.group(2)
                if kind == "unsupported" and ("does not resolve" in name or "virtual call" in name or "function pointer" in name or "shim without a body" in name):
                    unresolved.append(name)
                if kind == "fn" and name not in seen:
                    seen.add(name)
                    todo.append(name)
            for m in re.finditer(r'\(const-item (\(adt "[^"]*"\)|\w+) "([^"]+)"', line):
                consts.add(m.group(2))
    for f in seen - {root}:
        lines = fns.get(f, [])
        k, d, sf, sl, item = fn_meta(lines)
        dcrate = d.lstrip("<").split("::")[0]
        if dcrate.startswith("commonware_") and not item.startswith("(item closure") and not item.startswith("(item shim"):
            ws.append((f, d, dcrate, sf, sl, item))
    return ws, unresolved, sorted(consts)


def env(args, worker):
    e = dict(os.environ)
    e.update(HEAVY_SLOTS="2", CARGO_BUILD_JOBS="4", SANDBLASTER_MEM_LIMIT_GB="6", SANDBLASTER_GATE_WORKERS="2")
    e["SBMIR_TARGET_DIR"] = os.path.join(args.target, f"mirx-w{worker}")
    e["CARGO_TARGET_DIR"] = os.path.join(args.target, f"mirx-w{worker}")
    return e


def instance_opts(cand, work_dir):
    """--inject and --instance of a generic candidate (RULE.md 3.1 step 4);
    the lift's `instance` for the DSL root."""
    if cand.get("instance", "-") in ("-", ""):
        return [], []
    inst = json.loads(cand["instance"])
    aliases, mapping, lift = [], [], []
    claimed = {}
    for k, p in enumerate(inst["params"]):
        if p["kind"] != "type":
            continue
        alias = f"T{k}"
        aliases.append(f"pub type {alias} = {p['arg']};")
        traits = [t for t in p["traits"] if t != "std::marker::Sized"] or ["std::marker::Sized"]
        for t in traits:
            if t in claimed and claimed[t] != p["arg"]:
                continue
            if t in claimed:
                continue
            claimed[t] = p["arg"]
            mapping.append(f"{t}={INST_MOD}::{alias}")
            lift.append(f"{t.rsplit('::', 1)[-1]}: {p['arg']}")
    path = os.path.join(work_dir, f"{INST_MOD}.rs")
    with open(path, "w") as w:
        w.write("//! The rule-chosen instance of a generic H2-v2 candidate (RULE.md 3.1), generated by probe.py.\n" + "\n".join(aliases) + "\n")
    return ["--inject", f"{INST_MOD}={path}", "--instance", ",".join(mapping)], lift


class Done(Exception):
    pass


def extract(cand, out, args, worker, modules, items, skip, inst_args):
    """One extraction: a spec the batch executor runs (yielded by probe()),
    its result (returncode, stdout, stderr, seconds) sent back."""
    cmd = [os.path.join(REPO, "sandblaster/mirx/extract.sh"), cand["package"], ",".join(modules), out, "--items", ";".join(items), "--stubs", STUBS]
    if cand["package"] == "commonware-storage":
        cmd += ["--stub", STORAGE_OWN_STUB]
    if skip:
        cmd += ["--skip-fns", ",".join(skip)]
    cmd += inst_args
    return {"cmd": cmd, "env": {k: env(args, worker)[k] for k in ("SBMIR_TARGET_DIR", "CARGO_TARGET_DIR")}}


def exec_batch(spec_path, result_path):
    """Runs a batch of extractions one after the other (the probe runs this
    under the admission wrapper `heavy`, so the batch holds one slot)."""
    specs = json.load(open(spec_path))
    out = []
    for sp in specs:
        e = dict(os.environ)
        e.update(HEAVY_SLOTS="2", CARGO_BUILD_JOBS="4", SANDBLASTER_MEM_LIMIT_GB="6", SANDBLASTER_GATE_WORKERS="2")
        e.update(sp["env"])
        t = time.time()
        p = subprocess.run(sp["cmd"], cwd=REPO, env=e, capture_output=True, text=True)
        out.append({"returncode": p.returncode, "stdout": p.stdout[-20000:], "stderr": p.stderr[-20000:], "secs": time.time() - t})
        json.dump(out, open(result_path, "w"))
    json.dump(out, open(result_path, "w"))


class Res:
    def __init__(self, d):
        self.returncode, self.stdout, self.stderr, self.secs = d["returncode"], d["stdout"], d["stderr"], d["secs"]


def one_line(s, n=400):
    s = re.sub(r"\S*?/roots/r\d+/(?:[\w.-]+/)*?mono-wt/", "", s)
    s = re.sub(r"\S*?/roots/r\d+/", "<root>/", s)
    s = s.replace(REPO + "/", "")
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n]


def item_of(meta_item, name):
    """(self type name or None, fn name) from an `(item ..)` line."""
    m = re.match(r'\(item (inherent|impl|provided) \(adt "([^"]*)"\)', meta_item)
    if m:
        ty = re.sub(r"<.*", "", m.group(2)).split("::")[-1]
        return ty
    return None


def plan_files(cand, ws_fns, crate):
    """{file: {module, types, fns, names}}: the candidate's file and the
    files of the closure's functions of its crate (RULE.md 5.1, 5.4)."""
    files = {}

    def add(file, ty, fn):
        rel = f"{cand['crate_dir']}/{file}"
        e = files.setdefault(rel, {"module": sample.module_path(file), "types": set(), "fns": set(), "names": set()})
        if ty:
            e["types"].add(ty)
            e["names"].add((ty, fn))
        else:
            e["fns"].add(fn)

    rel = cand["file"].split("/", 1)[1]
    add(rel, cand["item"] if cand["kind"] != "fn" else None, cand["name"])
    for f, d, dcrate, sf, sl, item in ws_fns:
        if dcrate != crate or sf is None:
            continue
        fname = d.rsplit("::", 1)[-1]
        add(sf, item_of(item, fname), fname)
    return files


def planned_extraction(cand, files, infos):
    """(modules, items, skip-fns) of the extraction that names the
    candidate's item and its closure's items of its crate (RULE.md 5.1)."""
    mods = sorted({e["module"] for e in files.values()})
    items, skip_all = [], []
    for file, e in files.items():
        m = e["module"]
        items.append(f"{m}=" + ",".join(sorted(e["types"] | e["fns"])))
        for dm in descendant_modules(cand["crate_dir"], m):
            if dm not in mods:
                items.append(f"{dm}=")
        for il in infos[file][2]:
            items.append(f"{m}::{il}=")
        skip_all += infos[file][0]
    return mods, sorted(set(items)), sorted(set(skip_all))


def gen_root(cand, rank, mir_path, base, files, lift_inst, infos):
    """The DSL root declaring every planned file in place (RULE.md 5.4)."""
    d = os.path.join(base, f"r{rank:04d}")
    os.makedirs(d, exist_ok=True)
    tree = {}
    for file, e in files.items():
        parts = e["module"].split("::")
        node = tree
        for p in parts[:-1]:
            node = node.setdefault(p, {"__children": {}})["__children"]
        node.setdefault(parts[-1], {"__children": {}})["__lift"] = file
    texts = {}

    def decl(file, parts, children, child_files):
        e = files[file]
        skip, traits, inline, pub = infos[file]
        skip, traits = list(skip), list(traits)
        its = set(e["types"] | e["fns"])
        # a lifted child is lifted by `children`, with its parent's options
        for cf in child_files:
            its |= files[cf]["types"] | files[cf]["fns"]
            skip += infos[cf][0]
            traits += infos[cf][1]
        skip, traits = sorted(set(skip)), sorted(set(traits))
        # `mir` and `#[path]` are relative to the declaring file's directory
        # (mod.rs for a one-segment path, else `<parts[:-1]>.rs`)
        decl_dir = os.path.join(d, *parts[:-2]) if len(parts) >= 2 else d
        items = sorted(its)
        opts = [f'mir = "{os.path.relpath(mir_path, decl_dir)}"', "in_place", f'items = "{", ".join(items)}"']
        if children:
            opts.append(f'children = "{", ".join(children)}"')
        if lift_inst:
            opts.append(f'instance = "{", ".join(lift_inst)}"')
        if skip:
            opts.append(f'unverified_fns = "{", ".join(skip)}"')
        if traits:
            opts.append(f'unverified_impls = "{", ".join(traits)}"')
        host = os.path.join(REPO, file)
        return f"#[lift({', '.join(opts)})]\n#[path = \"{os.path.relpath(host, decl_dir)}\"]\npub mod {parts[-1]};\n"

    unsupported = []

    def walk(node, prefix):
        lines = []
        for name, sub in sorted(node.items()):
            parts = prefix + [name]
            if "__lift" in sub:
                # a lifted descendant must be a direct child (`children`)
                kids = sorted(k for k, v in sub["__children"].items() if "__lift" in v)
                deeper = [k for k, v in sub["__children"].items() if "__lift" not in v or v["__children"]]
                if deeper:
                    unsupported.append("::".join(parts))
                lines.append(decl(sub["__lift"], parts, kids, [sub["__children"][k]["__lift"] for k in kids]))
            else:
                lines.append(f"pub mod {name};\n")
                texts[os.path.join(d, *parts[:-1], name + ".rs") if prefix else os.path.join(d, name + ".rs")] = walk(sub["__children"], parts)
        return "".join(lines)

    top = "//! H2-v2 probe root (generated by sandblaster/bench/heldout-v2/h2/probe.py).\n#![forbid(unsafe_code)]\n\n" + walk(tree, [])
    ce = files[cand["file"]]
    if infos[cand["file"]][3].get(cand["item"]):
        top += f"\npub use {'::'.join(ce['module'].split('::'))}::{cand['item']};\n"
    texts[os.path.join(d, "mod.rs")] = top
    for p, t in texts.items():
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as w:
            w.write(t)
    return os.path.join(d, "mod.rs"), unsupported


def run_probe(root, cand, args, worker):
    mp = cand["module"]
    pre = f"crate::{mp}::{cand['name']}" if cand["kind"] == "fn" else f"crate::{mp}::{cand['item']}::{cand['name']}"
    # not cargo and not an extraction: run directly, its memory capped by
    # memguard (SANDBLASTER_MEM_LIMIT_GB), so the shared admission slots go to
    # the extractions
    cmd = [args.probe, root, pre]
    t = time.time()
    p = subprocess.run(cmd, cwd=REPO, env=env(args, worker), capture_output=True, text=True)
    line = next((l for l in p.stdout.splitlines() if l.startswith("{")), None)
    if line is None:
        return None, p, time.time() - t, pre
    return json.loads(line), p, time.time() - t, pre


def probe(cand, rank, args, worker):
    """(accepted, reason, details) for one candidate: a generator that yields
    each extraction it needs (a spec) and receives its result; its return
    value is the verdict."""
    if cand["module"] == "":
        return False, "probe 1 (extraction): in the crate root file; mirx extracts a module of the crate (SBMIR_MODULE) and the in-place lift declares one", {}
    crate = crate_name(cand["package"])
    wd = os.path.join(args.work, "mir", f"r{rank:04d}")
    os.makedirs(wd, exist_ok=True)
    inst_args, lift_inst = instance_opts(cand, wd)
    excl = {(cand["item"], cand["name"])} if cand["kind"] != "fn" else set()
    types = {cand["item"]} if cand["kind"] != "fn" else set()
    fns_ = {cand["name"]} if cand["kind"] == "fn" else set()
    skip, traits, inline, pub = file_info(cand["file"], types, fns_, excl)
    mp = cand["module"]
    items = [f"{mp}={cand['item']}"] + [f"{m}=" for m in descendant_modules(cand["crate_dir"], mp)] + [f"{mp}::{m}=" for m in inline]
    mir = os.path.join(wd, "x.sbmir")
    if os.path.exists(mir):
        os.remove(mir)
    spec = extract(cand, mir, args, worker, [mp], items, skip, inst_args)
    cmd = spec["cmd"]
    p = Res((yield spec))
    secs = p.secs
    det = {"extract_secs": round(secs, 1)}
    with open(mir + ".log", "w") as w:
        w.write(" ".join(cmd) + "\n\n" + p.stdout + "\n" + p.stderr)
    if p.returncode != 0 or not os.path.exists(mir):
        err = [l for l in (p.stderr + p.stdout).splitlines() if l.strip() and ("error" in l.lower() or "panicked" in l)]
        return False, "probe 1 (extraction): failed: " + one_line(err[0] if err else (p.stderr or p.stdout)[-300:]), det
    text = open(mir).read()
    roots, fns = sbmir_fns(text)
    root = find_root(cand, roots, fns)
    if root is None:
        # the extraction's note on a function of the candidate's name (one of its
        # item first, then a trait impl's when the candidate is a trait method)
        notes = [l for l in text.splitlines() if l.startswith("(note") and re.search(r"::" + re.escape(cand["name"]) + r"(::<[^\s]*>)?: ", l)]
        pick = [l for l in notes if re.search(r"\b" + re.escape(cand["item"]) + r"\b", l)] or [l for l in notes if (" as " in l) == (cand["kind"] == "trait_method")] or notes
        return False, "probe 1 (extraction): no MIR root for the candidate" + (": " + one_line(pick[0], 300) if pick else ""), det
    det["mir_root"] = root
    ws, unresolved, consts = closure(root, fns, crate)
    files_ = {(sf if dc == crate else f"{dc}:{d.rsplit('::', 1)[0]}") for _, d, dc, sf, _, _ in ws if sf or dc != crate}
    det.update(closure_fns=len(ws), closure_files=len(files_ | {cand["file"].split("/", 1)[1]}), closure_consts=len(consts))
    if unresolved:
        return False, "probe 2 (callee closure): unresolved call (RULE.md 5.2): " + one_line(unresolved[0], 300), det
    if len(ws) > MAX_FNS or len(files_ | {cand["file"].split("/", 1)[1]}) > MAX_FILES:
        return False, f"probe 2 (callee closure): callee closure too large (RULE.md 5.2): {len(ws)} functions in {det['closure_files']} files", det
    files = plan_files(cand, ws, crate)
    infos = {}
    for file, e in files.items():
        infos[file] = file_info(file, e["types"], e["fns"], e["names"])
    mods, items2, skip2 = planned_extraction(cand, files, infos)
    if (mods, items2, skip2) != ([mp], sorted(set(items)), sorted(set(skip))):
        # the closure's items (and their modules) too, and none of them left
        # out (RULE.md 5.1): the extraction again with them
        if "" in mods:
            return False, "probe 1 (extraction): the closure reaches the crate root file; mirx extracts modules of the crate (SBMIR_MODULE)", det
        os.remove(mir)
        spec = extract(cand, mir, args, worker, mods, items2, skip2, inst_args)
        cmd = spec["cmd"]
        p = Res((yield spec))
        secs = p.secs
        det["extract2_secs"] = round(secs, 1)
        with open(mir + ".log", "a") as w:
            w.write("\n\n" + " ".join(cmd) + "\n\n" + p.stdout + "\n" + p.stderr)
        if p.returncode != 0 or not os.path.exists(mir):
            err = [l for l in (p.stderr + p.stdout).splitlines() if l.strip() and ("error" in l.lower() or "panicked" in l)]
            return False, "probe 1 (extraction, with the closure's items): failed: " + one_line(err[0] if err else (p.stderr or p.stdout)[-300:]), det
        text = open(mir).read()
        roots, fns = sbmir_fns(text)
        root = find_root(cand, roots, fns)
        if root is None:
            return False, "probe 1 (extraction, with the closure's items): no MIR root for the candidate", det
    stmts, loop = body_shape(fns.get(root, []), root)
    det.update(statements=stmts, loop=loop)
    if not loop and stmts < 10:
        return False, f"probe 3 (size): no loop and {stmts} MIR statements (< 10)", det
    droot, unsupported = gen_root(cand, rank, mir, os.path.join(args.work, "roots"), files, lift_inst, infos)
    det["root_files"] = sorted(files)
    if unsupported:
        return False, "probe 4 (reader): the closure's files nest below a lifted module more than one level deep (" + ", ".join(unsupported) + "); the in-place lift declares a lifted module's children by `children` only", det
    res, pp, secs, pre = run_probe(droot, cand, args, worker)
    det["probe_secs"] = round(secs, 1)
    with open(os.path.join(os.path.dirname(droot), "probe.log"), "w") as w:
        w.write(pp.stdout + "\n" + pp.stderr)
    if res is None:
        return False, "probe 4 (reader): the probe did not finish: " + one_line(pp.stderr[-400:]), det
    if not res["front_end"]:
        errs = [l for l in res["errors"].splitlines() if "error[" in l]
        return False, "probe 4 (reader): driver::check refused: " + one_line(errs[0] if errs else res["errors"]), det
    defs = res["defs"]
    det["defs"] = [(d["name"], d["status"]) for d in defs]
    if not defs:
        return False, f"probe 5 (exec-only): no definition named {pre}" + (": elaboration errors: " + one_line(res["errors"], 300) if res["errors"] else ""), det
    bad = [d for d in defs if d["status"] != "Checked"]
    if bad:
        return False, "probe 5 (exec-only): " + one_line("; ".join(f"{d['name']}: {d['status']}" for d in bad[:3]), 400), det
    return True, f"accepted: {len(defs)} definition(s) Checked; {stmts} MIR statements, loop={loop}", det


def run_chunk(chunk, args, wid):
    """Probes a chunk of candidates: each probe's extractions are run in
    batches (one per round: every probe's first extraction, then the second
    ones), each batch under one admission slot (`heavy`), so the extractions
    of a chunk queue for the shared slots once instead of once each. Each
    candidate's steps, commands and verdict are those of probe() alone."""
    gens, pending, verdicts = {}, {}, {}
    for c in chunk:
        rank = int(c["rank"])
        g = probe(c, rank, args, wid)
        gens[rank] = g
        try:
            pending[rank] = next(g)
        except StopIteration as e:
            verdicts[rank] = e.value
    rnd = 0
    while pending:
        rnd += 1
        ranks = sorted(pending)
        bdir = os.path.join(args.work, "batches")
        os.makedirs(bdir, exist_ok=True)
        tag = f"w{wid}-{ranks[0]:04d}-{rnd}"
        spec_path, res_path = os.path.join(bdir, tag + ".spec.json"), os.path.join(bdir, tag + ".res.json")
        json.dump([pending[r] for r in ranks], open(spec_path, "w"))
        if os.path.exists(res_path):
            os.remove(res_path)
        p = subprocess.run([args.heavy, sys.executable, os.path.abspath(__file__), "--exec-batch", spec_path, res_path], cwd=REPO, env=env(args, wid), capture_output=True, text=True)
        res = json.load(open(res_path)) if os.path.exists(res_path) else []
        nxt = {}
        for k, r in enumerate(ranks):
            out = res[k] if k < len(res) else {"returncode": 1, "stdout": "", "stderr": "the extraction batch stopped before this extraction: " + p.stderr[-300:], "secs": 0.0}
            try:
                nxt[r] = gens[r].send(out)
            except StopIteration as e:
                verdicts[r] = e.value
        pending = nxt
    return verdicts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exec-batch", nargs=2, metavar=("SPEC", "RESULT"))
    ap.add_argument("--dir", default=HERE)
    ap.add_argument("--work")
    ap.add_argument("--probe")
    ap.add_argument("--heavy")
    ap.add_argument("--target")
    ap.add_argument("--want", type=int, default=40)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--chunk", type=int, default=24)
    ap.add_argument("--only", type=int, nargs="*")
    args = ap.parse_args()
    if args.exec_batch:
        exec_batch(*args.exec_batch)
        return
    cands = read_tsv(os.path.join(args.dir, "candidates.tsv"))
    for c in cands:
        c["crate_dir"] = c["file"].split("/")[0]
    os.makedirs(args.work, exist_ok=True)
    out = os.path.join(args.work, "probe.tsv")
    done = {}
    if os.path.exists(out):
        for r in read_tsv(out):
            done[int(r["rank"])] = r
    else:
        with open(out, "w") as w:
            w.write("rank\tid\taccepted\treason\tdetails\n")
    lock = threading.Lock()
    todo = [c for c in cands if int(c["rank"]) not in done and (not args.only or int(c["rank"]) in args.only)]
    state = {"accepted": {r for r, x in done.items() if x["accepted"] == "yes"}}

    def full():
        # 40 accepted with no unprobed candidate before the 40th (RULE.md 4)
        acc = sorted(state["accepted"])
        if len(acc) < args.want or args.only:
            return False
        last = acc[args.want - 1]
        return all(int(c["rank"]) in done or int(c["rank"]) > last for c in cands)

    def worker(wid):
        while True:
            with lock:
                if not todo or full():
                    return
                chunk = todo[:args.chunk]
                del todo[:args.chunk]
            try:
                verdicts = run_chunk(chunk, args, wid)
            except Exception as e:  # a probe bug is reported, never silently skipped
                verdicts = {int(c["rank"]): (False, f"probe error (infrastructure): {type(e).__name__}: {one_line(str(e), 300)}", {}) for c in chunk}
            with lock:
                for c in chunk:
                    rank = int(c["rank"])
                    ok, why, det = verdicts.get(rank, (False, "probe error (infrastructure): no verdict", {}))
                    done[rank] = {"accepted": "yes" if ok else "no"}
                    if ok:
                        state["accepted"].add(rank)
                    with open(out, "a") as w:
                        w.write(f"{rank}\t{c['id']}\t{'yes' if ok else 'no'}\t{why}\t{json.dumps(det)}\n")
                    print(f"[{len(state['accepted']):2d}] #{rank} {c['id']}: {why[:200]}", flush=True)

    ts = [threading.Thread(target=worker, args=(k,)) for k in range(args.workers)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    print(f"accepted {len(state['accepted'])}")


if __name__ == "__main__":
    main()
