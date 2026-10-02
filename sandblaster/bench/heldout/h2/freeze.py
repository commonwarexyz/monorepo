#!/usr/bin/env python3
"""H2 freeze (RULE.md sections 4 and 6): the sample from the probe's rows,
its MIR and DSL roots, the rejection list, and the held-out manifest.

    PYTHONDONTWRITEBYTECODE=1 freeze.py --work DIR [--want 40]

Reads DIR/probe.tsv (probe.py). Takes the first `want` accepted candidates in
the seeded order, copies each one's extraction to h2/mir/sNN.sbmir, writes
its DSL root to h2/roots/sNN/ (the probe's template, with paths relative to
this directory) and writes:

* h2/probe.tsv: every probed candidate, accepted or not, with its reason;
* h2/rejections.tsv: the static rejections (sample.py) plus the probe's;
* h2/sample.tsv: the sample, in order;
* ../manifest.toml: both halves of the held-out set (H1 and H2) with each
  file's SHA-256, the source commit, H2's seed and rule.

No cargo; it runs nothing but file copies and hashing.
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
HELDOUT = os.path.dirname(HERE)
SOURCE_COMMIT = "729ecd2a215bf034d1f70464a3f75730558ce505"
IN_SCOPE_DIRS = ["utils", "math", "stream", "p2p", "consensus", "storage/src/journal", "storage/src/ordinal", "storage/src/freezer"]


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
    rows = sorted(probe.read_tsv(os.path.join(args.work, "probe.tsv")), key=lambda r: int(r["rank"]))
    # the probe must have run in order from rank 1 with no gap (RULE.md section 4)
    ranks = [int(r["rank"]) for r in rows]
    assert ranks == list(range(1, len(ranks) + 1)), "probe rows are not ranks 1..n in order"
    accepted = [r for r in rows if r["accepted"] == "yes"]
    chosen = accepted[:args.want]
    full = len(chosen) == args.want
    last_rank = int(chosen[-1]["rank"]) if full else ranks[-1]

    for d in ("mir", "roots"):
        shutil.rmtree(os.path.join(HERE, d), ignore_errors=True)
    sample_rows = []
    for k, r in enumerate(chosen, 1):
        rank = int(r["rank"])
        c = cands[rank]
        slug = f"s{k:02d}"
        src_mir = os.path.join(args.work, "mir", f"r{rank:03d}.sbmir")
        dst_mir = os.path.join(HERE, "mir", f"{slug}.sbmir")
        os.makedirs(os.path.dirname(dst_mir), exist_ok=True)
        shutil.copyfile(src_mir, dst_mir)
        info = probe.file_info(c)
        root = probe.gen_root(c, k, dst_mir, None, info, os.path.join(HERE, "roots"), name=slug)
        final = os.path.dirname(root)
        det = json.loads(r["details"])
        sample_rows.append(dict(slug=slug, rank=rank, id=c["id"], package=c["package"], file=c["file"], line=c["line"], module=c["module"], kind=c["kind"],
                                item=c["item"], name=c["name"], mir_root=det.get("mir_root", ""), statements=det.get("statements", ""), loop=det.get("loop", ""),
                                defs=[n for n, _ in det.get("defs", [])], mir=os.path.relpath(dst_mir, HERE), root=os.path.relpath(os.path.join(final, "mod.rs"), HERE),
                                kernel_prefix=(f"crate::{c['module']}::{c['name']}" if c["kind"] == "fn" else f"crate::{c['module']}::{c['item']}::{c['name']}")))
    # probe.tsv: every probed candidate
    with open(os.path.join(HERE, "probe.tsv"), "w") as w:
        w.write("rank\tid\taccepted\tsampled\treason\tdetails\n")
        chosen_ranks = {int(r["rank"]) for r in chosen}
        for r in rows:
            rank = int(r["rank"])
            sampled = "yes" if rank in chosen_ranks else ("no (after the 40th accepted)" if r["accepted"] == "yes" else "no")
            w.write(f"{rank}\t{r['id']}\t{r['accepted']}\t{sampled}\t{probe.one_line(r['reason'], 600)}\t{r['details']}\n")
    # rejections.tsv: the static ones (sample.py rewrites the file) plus the probe's
    static = [l for l in open(os.path.join(HERE, "rejections.tsv")).read().splitlines()[1:] if l.startswith("static\t")]
    with open(os.path.join(HERE, "rejections.tsv"), "w") as w:
        w.write("stage\tid\tfile\tline\treason\n")
        for l in static:
            w.write(l + "\n")
        for r in rows:
            if r["accepted"] != "yes":
                c = cands[int(r["rank"])]
                w.write(f"probe\t{c['id']}\t{c['file']}\t{c['line']}\t{probe.one_line(r['reason'], 600)}\n")
        for rank in sorted(cands):
            if rank > ranks[-1]:
                c = cands[rank]
                w.write(f"probe\t{c['id']}\t{c['file']}\t{c['line']}\tnot probed (sample full)\n")
    # sample.tsv
    cols = ["slug", "rank", "id", "file", "line", "kind", "item", "name", "statements", "loop", "mir", "root", "kernel_prefix", "mir_root"]
    with open(os.path.join(HERE, "sample.tsv"), "w") as w:
        w.write("\t".join(cols) + "\n")
        for s in sample_rows:
            w.write("\t".join(str(s[c]) for c in cols) + "\n")

    # the in-scope sources must be the source commit's (read-only git)
    diff = subprocess.run(["git", "-C", REPO, "diff", "--quiet", SOURCE_COMMIT, "--"] + IN_SCOPE_DIRS, capture_output=True)
    assert diff.returncode == 0, "the in-scope sources differ from the source commit"
    write_manifest(sample_rows, rows, accepted, full, last_rank)
    print(f"sampled {len(sample_rows)} of {len(accepted)} accepted ({len(rows)} probed, {len(cands)} candidates)")


def files_under(d):
    out = []
    for root, dirs, files in os.walk(d):
        dirs[:] = sorted(x for x in dirs if x != "__pycache__")
        for fn in sorted(files):
            if fn == ".DS_Store" or fn.endswith(".pyc"):
                continue
            out.append(os.path.join(root, fn))
    return sorted(out)


def write_manifest(sample_rows, rows, accepted, full, last_rank):
    h1 = os.path.join(HELDOUT, "h1")
    L = []
    L.append("# The held-out evaluation set (fairness audit of 2026-10-02, evaluation")
    L.append("# protocol items 1-3). Written before anything was measured on it, and")
    L.append("# frozen by sandblaster/tools/gates/g6.sh (every file under")
    L.append("# sandblaster/bench/heldout/, this one included). Nobody looks at optimizer")
    L.append("# output or timings on it while building passes. An H function whose")
    L.append("# result drives an optimizer change moves to the development set; its")
    L.append("# replacement is drawn by the same rule (H2: the next accepted candidate")
    L.append("# in h2/probe.tsv's seeded order).")
    L.append("")
    L.append('date = "2026-10-02"')
    L.append(f"source_commit = {q(SOURCE_COMMIT)}")
    L.append("")
    L.append("[h1]")
    L.append('# 25 idioms, 30 functions written blind from an idiom list committed first')
    L.append('# (h1/idioms.md, hashed before any code), by an agent that read no optimizer')
    L.append('# source, corpus or optimizer output. Not derived from the monorepo: the')
    L.append('# files are pinned by their SHA-256 (written on top of source_commit, not')
    L.append('# committed to git when this manifest was written).')
    L.append('path = "sandblaster/bench/heldout/h1"')
    L.append('idioms = "idioms.md"')
    L.append(f"idioms_sha256 = {q(sha(os.path.join(h1, 'idioms.md')))}")
    L.append("functions = 30")
    for p in files_under(h1):
        L.append("")
        L.append("[[h1.file]]")
        L.append(f"path = {q(os.path.relpath(p, h1))}")
        L.append(f"sha256 = {q(sha(p))}")
    L.append("")
    L.append("[h2]")
    L.append("# real monorepo functions sampled by rule (h2/RULE.md) from crates no")
    L.append("# milestone targets; run through the exec-only path (no laws), as")
    L.append("# sandblaster/front/tests/opt_qmdb.rs runs the optimizer, from the DSL")
    L.append("# roots in h2/roots/ and the MIR in h2/mir/.")
    L.append('path = "sandblaster/bench/heldout/h2"')
    L.append('rule = "RULE.md"')
    L.append(f"rule_sha256 = {q(sha(os.path.join(HERE, 'RULE.md')))}")
    L.append(f'seed = "{sample.SEED}"')
    L.append("sample_size = 40")
    L.append(f"sampled = {len(sample_rows)}")
    L.append(f"candidates = {len(probe.read_tsv(os.path.join(HERE, 'candidates.tsv')))}")
    L.append(f"probed = {len(rows)}")
    L.append(f"accepted = {len(accepted)}")
    if len(sample_rows) < 40:
        L.append(f"shortfall = {40 - len(sample_rows)}")
        L.append("# fewer than 40 candidates passed the probe: H2 is every one that did")
        L.append("# (RULE.md section 4), and this rule has no replacement candidate left.")
        L.append("# A wider rule is a new, versioned rule with new files beside these;")
        L.append("# the coordinator decides (h2/PROBE-LOG.md).")
    L.append(f'mir_rustc = {q(open(os.path.join(HERE, sample_rows[0]["mir"])).read().splitlines()[2].split(chr(34))[1] if sample_rows else "")}')
    for s in sample_rows:
        L.append("")
        L.append("[[h2.function]]")
        L.append(f"slug = {q(s['slug'])}")
        L.append(f"id = {q(s['id'])}")
        L.append(f"file = {q(s['file'])}")
        L.append(f"line = {s['line']}")
        L.append(f"file_sha256 = {q(sha(os.path.join(REPO, s['file'])))}")
        L.append(f"kernel_name = {q(s['kernel_prefix'])}")
        L.append(f"mir = {q(s['mir'])}")
        L.append(f"root = {q(s['root'])}")
        L.append(f"seeded_rank = {s['rank']}")
        L.append(f"mir_statements = {s['statements']}")
        L.append(f"mir_loop = {'true' if s['loop'] else 'false'}")
    for p in files_under(HERE):
        L.append("")
        L.append("[[h2.file]]")
        L.append(f"path = {q(os.path.relpath(p, HERE))}")
        L.append(f"sha256 = {q(sha(p))}")
    with open(os.path.join(HELDOUT, "manifest.toml"), "w") as w:
        w.write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
