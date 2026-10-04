#!/usr/bin/env python3
"""prepare.py: the crate copies of the shipped-code harness (run.sh step 2).

    prepare.py --codec-out DIR --storage-out DIR [--base REV]

Writes `gen/` (not committed): one copy of commonware-codec and one of
commonware-storage per subject, each a package of this workspace under its
own name, so that the three subjects link into one binary:

* `orig`, `aa`: the original Commonware code, the two crates as they are at
  REV (default: the merge base of `main` and HEAD, where the sandblaster
  branch starts), read with `git archive` (read-only). `aa` is `orig` again:
  the A/A control.
* `shipped`: the code the sandblaster build ships, the two crates as in this
  worktree with the files a verified build writes to `OUT_DIR` in place of
  the includes that read them: codec's `src/varint.rs` includes the emitted
  module `varint.rs` of `--codec-out` (sandblaster's `compile_module`
  output: a header, the original body as-is, the rustc-checked host facts),
  storage's `src/merkle/mmr/mod.rs` includes the lowered copy
  `mmr-lowered__merkle__mmr__iterator.rs` of `--storage-out` (sandblaster's
  `compile_lifted` output; the other in-place files, and the verifier's,
  storage compiles from its own sources, as the copy does). Only the include
  paths change (`concat!(env!("OUT_DIR"), "/x")` becomes the copied file):
  rustc compiles the same text the host build compiles.

Every copy's manifest keeps its package metadata, features and
dependencies (inherited from this workspace's `[workspace.dependencies]`,
checked equal to the monorepo's) and drops what a library dependency never
builds (build script, build- and dev-dependencies). A storage copy depends
on the monorepo's own commonware-codec, as every other crate it links does
(cryptography's types implement that codec's traits): the varint rows time
the codec copies, the MMR and verifier rows the storage copies. Prints the
SHA-256 of every shipped file it copied.
"""
import argparse
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../.."))
GEN = os.path.join(HERE, "gen")
NAMES = {"codec": "commonware-codec", "storage": "commonware-storage"}
OUT_INCLUDE = re.compile(r'include!\(\s*concat!\(\s*env!\("OUT_DIR"\)\s*,\s*"/([^"]+)"\s*\)\s*\)')


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def git(*args):
    return subprocess.run(["git", "-C", REPO, *args], check=True, capture_output=True).stdout


def archive(rev, crate, dest):
    """The crate directory at `rev` (read-only `git archive`) into `dest`."""
    data = git("archive", "--format=tar", rev, crate)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(os.path.dirname(dest), filter="data")
    os.rename(os.path.join(os.path.dirname(dest), crate), dest)


def copy_tree(crate, dest):
    src = os.path.join(REPO, crate)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns("target", "fuzz", "benches", "tests", ".DS_Store"))


def manifest(dest, name):
    """The copy's Cargo.toml: renamed; no build script, build- or dev-dependencies."""
    p = os.path.join(dest, "Cargo.toml")
    text = open(p).read()
    out, keep = [], True
    for line in text.splitlines():
        m = re.match(r"^\[\[?([^\]]+)\]\]?", line)
        if m:
            sec = m.group(1)
            # (`[[bench]]`, `[[test]]`, `[[example]]` targets; lints change no code)
            keep = not (line.startswith("[[") or sec in ("build-dependencies", "dev-dependencies", "lints") or sec.endswith(".dev-dependencies") or sec.endswith(".build-dependencies") or sec.startswith("package.metadata"))
        if not keep:
            continue
        line = re.sub(r'^name = "commonware-(codec|storage)"', f'name = "{name}"', line)
        out.append(line)
    text = "\n".join(out) + "\n"
    # a package of this workspace, never published
    text = text.replace("publish = true", "publish = false")
    open(p, "w").write(text)
    for f in ("build.rs",):
        if os.path.exists(os.path.join(dest, f)):
            os.remove(os.path.join(dest, f))
    # the copies' own benches/tests/examples are never built (they are removed)
    for d in ("benches", "tests", "examples", "fuzz", "sandblaster"):
        shutil.rmtree(os.path.join(dest, d), ignore_errors=True)


def ship(dest, rel, out_dir):
    """`dest/rel`'s include of an `OUT_DIR` file replaced by the include of
    that file, copied beside it from `out_dir`."""
    p = os.path.join(dest, rel)
    text = open(p).read()
    m = OUT_INCLUDE.search(text)
    if not m:
        raise SystemExit(f"{rel}: no include of an OUT_DIR file")
    name = m.group(1)
    src = os.path.join(out_dir, name)
    if not os.path.exists(src):
        raise SystemExit(f"{src}: missing (build the crate first)")
    local = os.path.splitext(name)[0] + ".shipped.rs"
    shutil.copyfile(src, os.path.join(os.path.dirname(p), local))
    open(p, "w").write(OUT_INCLUDE.sub(f'include!("{local}")', text, count=1))
    return name, sha(src)


def check_workspace_deps():
    """This workspace's [workspace.dependencies] entries are the monorepo's,
    with each path made relative to here."""
    def section(text, name):
        m = re.search(r"^\[" + re.escape(name) + r"\]\n(.*?)(?=^\[|\Z)", text, re.M | re.S)
        return m.group(1) if m else ""

    def entries(body):
        return {m.group(1): m.group(2).strip() for m in re.finditer(r"^([A-Za-z0-9_-]+)\s*=\s*(.+)$", body, re.M)}

    mine = entries(section(open(os.path.join(HERE, "Cargo.toml")).read(), "workspace.dependencies"))
    theirs = entries(section(open(os.path.join(REPO, "Cargo.toml")).read(), "workspace.dependencies"))
    bad = []
    for k, v in mine.items():
        if k.startswith("sbx-") or k in ("subj_orig", "subj_aa", "subj_shipped"):
            continue
        want = theirs.get(k)
        if want is None:
            bad.append(f"{k}: not in the monorepo's [workspace.dependencies]")
            continue
        want = re.sub(r'path = "([^"]+)"', lambda m: f'path = "../../../{m.group(1)}"', want)
        if v != want:
            bad.append(f"{k}: here `{v}`, the monorepo `{want}`")
    if bad:
        raise SystemExit("Cargo.toml's [workspace.dependencies] differ from the monorepo's:\n  " + "\n  ".join(bad))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--codec-out", required=True, help="OUT_DIR of a verified build of commonware-codec")
    ap.add_argument("--storage-out", required=True, help="OUT_DIR of a verified build of commonware-storage")
    ap.add_argument("--base", default=None)
    args = ap.parse_args()
    check_workspace_deps()
    base = args.base or git("merge-base", "main", "HEAD").decode().strip()
    shutil.rmtree(GEN, ignore_errors=True)
    os.makedirs(GEN)
    for subj in ("orig", "aa", "shipped"):
        for crate in ("codec", "storage"):
            dest = os.path.join(GEN, subj, crate)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if subj == "shipped":
                copy_tree(crate, dest)
            else:
                archive(base, crate, dest)
            manifest(dest, f"sbx-ship-{subj}-{crate}")
    shipped = [
        ("codec", "src/varint.rs", args.codec_out),
        ("storage", "src/merkle/mmr/mod.rs", args.storage_out),
    ]
    lines = [f"base {base}"]
    for crate, rel, out in shipped:
        name, h = ship(os.path.join(GEN, "shipped", crate), rel, out)
        lines.append(f"shipped {crate} {rel} <- OUT_DIR/{name} sha256 {h}")
    # what the original files are: the merge base's, and equal to the shipped bodies
    lines.append(f"orig codec src/varint.rs sha256 {sha(os.path.join(GEN, 'orig', 'codec', 'src/varint.rs'))}")
    lines.append(f"orig storage src/merkle/mmr/iterator.rs sha256 {sha(os.path.join(GEN, 'orig', 'storage', 'src/merkle/mmr/iterator.rs'))}")
    open(os.path.join(GEN, "SOURCES.txt"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
