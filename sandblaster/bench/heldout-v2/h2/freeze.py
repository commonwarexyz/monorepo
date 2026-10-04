#!/usr/bin/env python3
"""H2-v2 freeze (RULE.md sections 4 and 6): the sample from the probe's rows,
its MIR, instance modules and DSL roots, the probe and rejection lists, and
the sample manifest.

    PYTHONDONTWRITEBYTECODE=1 freeze.py --work WORK [--want 40]

Reads WORK/probe.tsv (probe.py) and candidates.tsv (sample.py, then
instance.py). Takes the first `want` accepted candidates in the seeded
order, copies each one's extraction to h2/mir/sNN.sbmir and its instance
module (generic candidates) to h2/inst/sNN.rs, writes its DSL root to
h2/roots/sNN/ (the probe's template, pointing at those copies) and writes:

* h2/probe.tsv: every probed candidate, accepted or not, with its reason;
* h2/rejections.tsv: the static and instance rejections plus the probe's;
* h2/sample.tsv: the sample, in order;
* h2/sample-manifest.toml: each sampled function, its instance, its
  extraction arguments, and the SHA-256 of its file and of every callee file
  of its crate lifted with it (RULE.md 6). The frozen ../manifest.toml is
  never edited.

No cargo; it runs nothing but file copies and hashing (and a read-only
`git diff` that the scope files are the source commit's).
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
import probe  # noqa: E402
import sample  # noqa: E402

REPO = sample.REPO


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def q(s):
    return json.dumps(s)  # a TOML basic string is a JSON string for these values


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--want", type=int, default=40)
    args = ap.parse_args()
    cands = {int(c["rank"]): c for c in probe.read_tsv(os.path.join(HERE, "candidates.tsv"))}
    for c in cands.values():
        c["crate_dir"] = c["file"].split("/")[0]
    rows = sorted(probe.read_tsv(os.path.join(args.work, "probe.tsv")), key=lambda r: int(r["rank"]))
    ranks = [int(r["rank"]) for r in rows]
    assert ranks == list(range(1, len(ranks) + 1)), "probe rows are not ranks 1..n in order"
    accepted = [r for r in rows if r["accepted"] == "yes"]
    chosen = accepted[:args.want]
    full = len(chosen) == args.want
    if not full:
        assert len(rows) == len(cands), f"fewer than {args.want} accepted, but only {len(rows)} of {len(cands)} candidates probed"
    sample.check_source_commit()

    for d in ("mir", "roots", "inst"):
        shutil.rmtree(os.path.join(HERE, d), ignore_errors=True)
    sample_rows = []
    for k, r in enumerate(chosen, 1):
        rank = int(r["rank"])
        c = cands[rank]
        slug = f"s{k:02d}"
        wd = os.path.join(args.work, "mir", f"r{rank:04d}")
        dst_mir = os.path.join(HERE, "mir", f"{slug}.sbmir")
        os.makedirs(os.path.dirname(dst_mir), exist_ok=True)
        shutil.copyfile(os.path.join(wd, "x.sbmir"), dst_mir)
        det = json.loads(r["details"])
        # the instance module (a generic candidate) and the extraction arguments
        inst_args, lift_inst = probe.instance_opts(c, os.path.join(HERE, "inst"))
        if inst_args:
            src = os.path.join(HERE, "inst", f"{probe.INST_MOD}.rs")
            os.replace(src, os.path.join(HERE, "inst", f"{slug}.rs"))
            inst_args[1] = f"{probe.INST_MOD}=sandblaster/bench/heldout-v2/h2/inst/{slug}.rs"
        # the files the probe declared (the candidate's and its closure's of its crate)
        excl = {(c["item"], c["name"])} if c["kind"] != "fn" else set()
        files = {}
        for fpath in det.get("root_files", [c["file"]]):
            files[fpath] = {"module": sample.module_path(fpath.split("/", 1)[1]), "types": set(), "fns": set(), "names": set()}
        # the closure's items per file are rebuilt from the frozen MIR as the probe built them
        text = open(dst_mir).read()
        roots, fns = probe.sbmir_fns(text)
        root = probe.find_root(c, roots, fns)
        ws, _, _ = probe.closure(root, fns, probe.crate_name(c["package"]))
        plan = probe.plan_files(c, ws, probe.crate_name(c["package"]))
        infos = {f: probe.file_info(f, e["types"], e["fns"], e["names"]) for f, e in plan.items()}
        droot, _ = probe.gen_root(c, 0, dst_mir, os.path.join(HERE, "roots"), plan, lift_inst, infos)
        final = os.path.join(HERE, "roots", slug)
        os.replace(os.path.dirname(droot), final)
        # extraction arguments, replayable (evaluate.py's round trip): the
        # probe's last extraction, which names the closure's items too
        mods, items, skip_all = probe.planned_extraction(c, plan, infos)
        extra = []
        if c["package"] == "commonware-storage":
            extra += ["--stub", probe.STORAGE_OWN_STUB]
        if skip_all:
            extra += ["--skip-fns", ",".join(skip_all)]
        extra += inst_args
        extract = {"modules": ",".join(mods), "items": ";".join(items), "extra": extra}
        kernel = f"crate::{c['module']}::{c['name']}" if c["kind"] == "fn" else f"crate::{c['module']}::{c['item']}::{c['name']}"
        sample_rows.append(dict(slug=slug, rank=rank, c=c, det=det, mir=os.path.relpath(dst_mir, HERE), root=os.path.relpath(os.path.join(final, "mod.rs"), HERE),
                                kernel=kernel, files=sorted(plan), extract=extract))
    chosen_ranks = {int(r["rank"]) for r in chosen}
    last = max(chosen_ranks) if full else None
    with open(os.path.join(HERE, "probe.tsv"), "w") as w:
        w.write("rank\tid\taccepted\tsampled\treason\tdetails\n")
        for r in rows:
            rank = int(r["rank"])
            sampled = "yes" if rank in chosen_ranks else ("no (after the 40th accepted)" if r["accepted"] == "yes" else "no")
            w.write(f"{rank}\t{r['id']}\t{r['accepted']}\t{sampled}\t{probe.one_line(r['reason'], 600)}\t{r['details']}\n")
    # rejections.tsv: the static and instance rows (sample.py, instance.py) plus the probe's
    keep = [l for l in open(os.path.join(HERE, "rejections.tsv")).read().splitlines()[1:] if l.startswith(("static\t", "instance\t"))]
    with open(os.path.join(HERE, "rejections.tsv"), "w") as w:
        w.write("stage\tid\tfile\tline\treason\n")
        for l in keep:
            w.write(l + "\n")
        for r in rows:
            if r["accepted"] != "yes":
                c = cands[int(r["rank"])]
                w.write(f"probe\t{c['id']}\t{c['file']}\t{c['line']}\t{probe.one_line(r['reason'], 600)}\n")
        for rank in sorted(cands):
            if rank > ranks[-1]:
                c = cands[rank]
                w.write(f"probe\t{c['id']}\t{c['file']}\t{c['line']}\tnot probed (sample full)\n")
    cols = ["slug", "rank", "id", "file", "line", "kind", "item", "name", "statements", "loop", "mir", "root", "kernel_name", "mir_root"]
    with open(os.path.join(HERE, "sample.tsv"), "w") as w:
        w.write("\t".join(cols) + "\n")
        for s in sample_rows:
            c, det = s["c"], s["det"]
            vals = [s["slug"], s["rank"], c["id"], c["file"], c["line"], c["kind"], c["item"], c["name"], det.get("statements", ""), det.get("loop", ""), s["mir"], s["root"], s["kernel"], det.get("mir_root", "")]
            w.write("\t".join(str(v) for v in vals) + "\n")
    write_manifest(sample_rows, rows, accepted, cands, full)
    print(f"sampled {len(sample_rows)} of {len(accepted)} accepted ({len(rows)} probed, {len(cands)} candidates)")


def write_manifest(sample_rows, rows, accepted, cands, full):
    L = []
    L.append("# The H2-v2 sample (RULE.md section 6), written by h2/freeze.py from the")
    L.append("# probe's rows. A new file beside the frozen ../manifest.toml (G6 refuses")
    L.append("# edits of that one); G6 records this one once written.")
    L.append("")
    L.append('rule = "h2-v2"')
    L.append(f"rule_sha256 = {q(sha(os.path.join(HERE, 'RULE.md')))}")
    L.append(f"seed = {q(sample.SEED)}")
    L.append(f"source_commit = {q(sample.SOURCE_COMMIT)}")
    L.append(f"candidates = {len(cands)}")
    L.append(f"probed = {len(rows)}")
    L.append(f"accepted = {len(accepted)}")
    L.append(f"sample_size = 40")
    L.append(f"sampled = {len(sample_rows)}")
    if len(sample_rows) < 40:
        L.append(f"shortfall = {40 - len(sample_rows)}")
        L.append("# fewer than 40 candidates passed the probe: H2-v2 is every one that did")
        L.append("# (RULE.md section 4). The rule is not widened; a wider rule is version 3.")
    if sample_rows:
        L.append(f"mir_rustc = {q(open(os.path.join(HERE, sample_rows[0]['mir'])).read().splitlines()[2].split(chr(34))[1])}")
    for s in sample_rows:
        c, det = s["c"], s["det"]
        L.append("")
        L.append("[[function]]")
        L.append(f"slug = {q(s['slug'])}")
        L.append(f"id = {q(c['id'])}")
        L.append(f"package = {q(c['package'])}")
        L.append(f"file = {q(c['file'])}")
        L.append(f"line = {c['line']}")
        L.append(f"kind = {q(c['kind'])}")
        L.append(f"item = {q(c['name'])}")
        L.append(f"self_type = {q(c['item'] if c['kind'] != 'fn' else '')}")
        L.append(f"file_sha256 = {q(sha(os.path.join(REPO, c['file'])))}")
        L.append(f"kernel_name = {q(s['kernel'])}")
        L.append(f"mir = {q(s['mir'])}")
        L.append(f"mir_root = {q(det.get('mir_root', ''))}")
        L.append(f"root = {q(s['root'])}")
        L.append(f"seeded_rank = {s['rank']}")
        L.append(f"mir_statements = {det.get('statements', 0)}")
        L.append(f"mir_loop = {'true' if det.get('loop') else 'false'}")
        inst = c.get("instance", "-")
        L.append(f"instance = {q(inst if inst not in ('', '-') else '')}")
        L.append(f"extract = {q(json.dumps(s['extract'], separators=(',', ':')))}")
        L.append(f"closure_functions = {det.get('closure_fns', 0)}")
        L.append(f"closure_files = {det.get('closure_files', 0)}")
        for f in s["files"]:
            L.append("[[function.lifted_file]]")
            L.append(f"path = {q(f)}")
            L.append(f"sha256 = {q(sha(os.path.join(REPO, f)))}")
    with open(os.path.join(HERE, "sample-manifest.toml"), "w") as w:
        w.write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
