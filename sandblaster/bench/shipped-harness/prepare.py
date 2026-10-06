#!/usr/bin/env python3
"""prepare.py: the subjects of the measurement harness (run.sh step 1).

    prepare.py --probe DIR [--base REV] [--out-dir CRATE=DIR]...

Writes `gen/` (not committed):

* `gen/copies/<subject>/<crate>`: one copy of each crate the probe names
  (`DIR/crates`: `codec` = commonware-codec, `storage` = commonware-storage)
  per subject, each a package of this workspace under its own name
  (`sbx-<subject>-<crate>`), so that the three subjects link into one
  binary:
  * `orig`, `aa`: the crates as they are at REV (default: the merge base of
    `main` and HEAD), read with `git archive` (read-only). `aa` is `orig`
    again: the A/A control.
  * `wt`: the crates as they are in this worktree (uncommitted edits
    included). A source file that includes a file a build writes to
    `OUT_DIR` (codec's `src/varint.rs` includes the module a module-mode
    build emits: the verified module's source as-is after a header) needs
    `--out-dir CRATE=DIR`, the `OUT_DIR` of a build of that crate; the file
    is copied beside the source and included from there (only the include
    path changes, so rustc compiles the text the host build compiles).
    In-place modules (storage's) are compiled from their own sources.
* `gen/subj_<subject>/Cargo.toml`: the subjects (`subject/lib.rs` over that
  subject's copies, named `codec` and `storage`).
* `gen/probe.rs`, `gen/rows.rs`: the probe's two halves.
* `gen/SOURCES.txt`: the base commit, the worktree's HEAD and whether the
  copied crates have uncommitted edits, and the SHA-256 of every copied
  `OUT_DIR` file.

Every copy's manifest keeps its package metadata, features and
dependencies (inherited from this workspace's `[workspace.dependencies]`,
checked equal to the monorepo's) and drops what a library dependency never
builds (build script, build- and dev-dependencies). A storage copy depends
on the monorepo's own commonware-codec, as every other crate it links does.
"""
import argparse
import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../.."))
GEN = os.path.join(HERE, "gen")
CRATES = {"codec": "commonware-codec", "storage": "commonware-storage"}
SUBJECTS = ("orig", "aa", "wt")
OUT_INCLUDE = re.compile(r'include!\(\s*concat!\(\s*env!\("OUT_DIR"\)\s*,\s*"/([^"]+)"\s*\)\s*\)')


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def git(*args):
    return subprocess.run(["git", "-C", REPO, *args], check=True, capture_output=True).stdout


def archive(rev, crate, dest):
    """The crate directory at `rev` (read-only `git archive`) into `dest`."""
    data = git("archive", "--format=tar", rev, crate)
    tmp = dest + ".tmp"
    os.makedirs(tmp)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(tmp, filter="data")
    os.rename(os.path.join(tmp, crate), dest)
    shutil.rmtree(tmp)


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
            # (`[[bench]]`, `[[test]]`, `[[example]]` targets; `[lints]` stays:
            # `workspace = true`, this workspace's lints, which change no code)
            keep = not (line.startswith("[[") or sec in ("build-dependencies", "dev-dependencies") or sec.endswith(".dev-dependencies") or sec.endswith(".build-dependencies") or sec.startswith("package.metadata"))
        if not keep:
            continue
        line = re.sub(r'^name = "commonware-(codec|storage)"', f'name = "{name}"', line)
        out.append(line)
    text = "\n".join(out) + "\n"
    # a package of this workspace, never published
    text = text.replace("publish = true", "publish = false")
    open(p, "w").write(text)
    if os.path.exists(os.path.join(dest, "build.rs")):
        os.remove(os.path.join(dest, "build.rs"))
    # the copies' own benches/tests/examples and verification roots are never built
    for d in ("benches", "tests", "examples", "fuzz", "sandblaster"):
        shutil.rmtree(os.path.join(dest, d), ignore_errors=True)


def include_out_dir_files(dest, crate, out_dir):
    """Every include of an `OUT_DIR` file under `dest/src` replaced by the
    include of that file, copied beside it from `out_dir`. Returns
    [(relative source, file name, sha256)]."""
    found = []
    for root, _, files in os.walk(os.path.join(dest, "src")):
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(root, f)
            text = open(p).read()
            m = OUT_INCLUDE.search(text)
            if not m:
                continue
            rel = os.path.relpath(p, dest)
            name = m.group(1)
            if out_dir is None:
                raise SystemExit(f"{crate}/{rel} includes the build output `OUT_DIR/{name}`: pass --out-dir {crate}=<OUT_DIR of a build of {CRATES[crate]}>")
            src = os.path.join(out_dir, name)
            if not os.path.exists(src):
                raise SystemExit(f"{src}: missing (build {CRATES[crate]} first)")
            local = os.path.splitext(name)[0] + ".out.rs"
            shutil.copyfile(src, os.path.join(os.path.dirname(p), local))
            open(p, "w").write(OUT_INCLUDE.sub(f'include!("{local}")', text))
            found.append((rel, name, sha(src)))
    return found


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
        want = theirs.get(k)
        if want is None:
            bad.append(f"{k}: not in the monorepo's [workspace.dependencies]")
            continue
        want = re.sub(r'path = "([^"]+)"', lambda m: f'path = "../../../{m.group(1)}"', want)
        if v != want:
            bad.append(f"{k}: here `{v}`, the monorepo `{want}`")
    if bad:
        raise SystemExit("Cargo.toml's [workspace.dependencies] differ from the monorepo's:\n  " + "\n  ".join(bad))


SUBJECT_MANIFEST = """# A subject of the measurement harness (written by prepare.py): subject/lib.rs
# over the {subj} copies of the probe's crates. No build script, no profile of
# its own.
[package]
name = "subj_{subj}"
version = "0.1.0"
edition = "2024"
publish = false

[lib]
path = "../../subject/lib.rs"

[dependencies]
{deps}commonware-cryptography = {{ workspace = true, features = ["std"] }}
bytes = {{ workspace = true, features = ["std"] }}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True, help="a probe directory (probes/README)")
    ap.add_argument("--base", default=None, help="the original code's commit (default: the merge base of main and HEAD)")
    ap.add_argument("--out-dir", action="append", default=[], help="CRATE=DIR: the OUT_DIR of a build of CRATE (its includes of build output)")
    args = ap.parse_args()
    check_workspace_deps()
    crates = open(os.path.join(args.probe, "crates")).read().split()
    for c in crates:
        if c not in CRATES:
            raise SystemExit(f"{args.probe}/crates: unknown crate `{c}` (known: {', '.join(CRATES)})")
    out_dirs = dict(x.split("=", 1) for x in args.out_dir)
    base = args.base or git("merge-base", "main", "HEAD").decode().strip()
    base = git("rev-parse", base).decode().strip()
    shutil.rmtree(GEN, ignore_errors=True)
    os.makedirs(GEN)
    lines = [f"base {base}", f"worktree HEAD {git('rev-parse', 'HEAD').decode().strip()}"]
    for subj in SUBJECTS:
        deps = ""
        for crate in crates:
            dest = os.path.join(GEN, "copies", subj, crate)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if subj == "wt":
                copy_tree(crate, dest)
            else:
                archive(base, crate, dest)
            manifest(dest, f"sbx-{subj}-{crate}")
            if subj == "wt":
                for rel, name, h in include_out_dir_files(dest, crate, out_dirs.get(crate)):
                    lines.append(f"wt {crate} {rel} <- OUT_DIR/{name} sha256 {h}")
            deps += f'{crate} = {{ package = "sbx-{subj}-{crate}", path = "../copies/{subj}/{crate}" }}\n'
        os.makedirs(os.path.join(GEN, f"subj_{subj}"))
        open(os.path.join(GEN, f"subj_{subj}", "Cargo.toml"), "w").write(SUBJECT_MANIFEST.format(subj=subj, deps=deps))
    for crate in crates:
        dirty = git("status", "--porcelain", "--", crate).decode().strip()
        changed = git("diff", "--stat", base, "--", f"{crate}/src").decode().strip().splitlines()
        lines.append(f"wt {crate}: {'uncommitted edits' if dirty else 'clean'}; against base: {changed[-1].strip() if changed else 'no change under src/'}")
    for f in ("probe.rs", "rows.rs"):
        shutil.copyfile(os.path.join(args.probe, f), os.path.join(GEN, f))
    lines.append(f"probe {os.path.abspath(args.probe)} (crates: {' '.join(crates)})")
    open(os.path.join(GEN, "SOURCES.txt"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
