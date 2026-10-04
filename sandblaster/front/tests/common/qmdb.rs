//! The QMDB fixture (`sandblaster/fixtures/qmdb/sandblaster`) for the suites
//! that copy it into memory (to mutate it, or to mount part of it in a
//! smaller crate). Include it with
//! `#[path = "common/qmdb.rs"] mod qmdb;`; it depends on `std` only.
//!
//! * [`crate_files`]: the whole crate an instance root mounts — the exec
//!   files, `spec/`, `MODEL.rs`, `LAWS.rs`, `PROOF.rs` and the ghost
//!   standard library its roots mount from `front/stdlib` — at the paths
//!   they have in the repository, so the roots' `#[path]`s resolve in a
//!   `MemFs` as they do on disk.
//! * [`exec_source`]: one exec file without its §15 ghost lines, for a
//!   small crate that mounts that file alone.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The fixture's DSL directory, relative to the repository root (the
/// prefix of every path [`crate_files`] returns).
pub const DIR: &str = "sandblaster/fixtures/qmdb/sandblaster";

/// The ghost standard library the instance roots mount (`#[path =
/// "../../../front/stdlib/mod.rs"]`), relative to the repository root.
const STDLIB: &str = "sandblaster/front/stdlib";

/// The repository root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The fixture's DSL directory on disk.
pub fn dir() -> PathBuf {
    repo().join(DIR)
}

/// A file of the fixture's DSL directory.
pub fn read(file: &str) -> String {
    std::fs::read_to_string(dir().join(file)).unwrap_or_else(|e| panic!("{DIR}/{file}: {e}"))
}

fn rs_files(rel: &str, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(repo().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")).map(|e| e.unwrap().path()).collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.is_dir() {
            rs_files(&format!("{rel}/{name}"), out);
        } else if name.ends_with(".rs") {
            out.push((format!("{rel}/{name}"), std::fs::read_to_string(&p).unwrap()));
        }
    }
}

/// The vector files the sources name (`#[examples(file = "..")]`, relative
/// to the declaring file's directory; a `*` in the file name matches any
/// run of characters), as `(path, text)`.
fn vector_files(sources: &[(String, String)], out: &mut Vec<(String, String)>) {
    for (path, text) in sources {
        let dir = Path::new(path).parent().unwrap();
        for part in text.split("#[examples(file = \"").skip(1) {
            let rel = &part[..part.find('"').unwrap()];
            let target = normalize(&dir.join(rel));
            let (tdir, name) = (target.parent().unwrap().to_path_buf(), target.file_name().unwrap().to_string_lossy().into_owned());
            let mut entries: Vec<PathBuf> = std::fs::read_dir(repo().join(&tdir)).unwrap_or_else(|e| panic!("{}: {e}", tdir.display())).map(|e| e.unwrap().path()).collect();
            entries.sort();
            let (pre, post) = name.split_once('*').unwrap_or((&name, ""));
            let glob = name.contains('*');
            for e in entries {
                let n = e.file_name().unwrap().to_string_lossy().into_owned();
                if (glob && n.starts_with(pre) && n.ends_with(post) && n.len() >= pre.len() + post.len()) || (!glob && n == name) {
                    let key = tdir.join(&n).to_string_lossy().into_owned();
                    if !out.iter().any(|(p, _)| *p == key) {
                        out.push((key, std::fs::read_to_string(&e).unwrap()));
                    }
                }
            }
        }
    }
}

/// Lexically normalizes `a/./b/../c` to `a/c` (as `loader::normalize`).
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Every file the instance roots read: the `.rs` files of the fixture's DSL
/// directory and `spec/`, the ghost standard library, and the vector files
/// of their `#[examples(file = ..)]` (§15.7), as `(path, text)` with
/// repository-relative paths; the instance root `root` (`mod.rs` or
/// `n1.rs`) first, so `files[0]` is the crate root. Files the root does not
/// mount (the other instance's root, configuration and vectors) are
/// harmless.
pub fn crate_files(root: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    rs_files(DIR, &mut out);
    rs_files(STDLIB, &mut out);
    let sources = out.clone();
    vector_files(&sources, &mut out);
    let at = out.iter().position(|(p, _)| *p == format!("{DIR}/{root}")).unwrap_or_else(|| panic!("no instance root {DIR}/{root}"));
    let r = out.remove(at);
    out.insert(0, r);
    out
}

/// The entry of `file` (relative to [`DIR`], e.g. `verifier.rs` or
/// `spec/proof.rs`) in `files`.
pub fn entry<'f>(files: &'f mut [(String, String)], file: &str) -> &'f mut String {
    let key = format!("{DIR}/{file}");
    &mut files.iter_mut().find(|(p, _)| *p == key).unwrap_or_else(|| panic!("no {key}")).1
}

/// The exec file `file` of the fixture without its §15 ghost lines: the
/// `#[refines(..)]` and `#[view(..)]` annotations and the one-line
/// `proof! { .. }` steps. They name the crate's ghost modules (`spec`,
/// `model`, `proof`), which a crate mounting this file alone does not
/// have; every other line is the file's, unchanged (the erased lines are
/// removed, so items keep their doc comments and attributes adjacent).
/// For suites that read the exec code
/// only (exec-only elaboration and the optimizer, which do not check
/// refinements); the whole crate is [`crate_files`].
pub fn exec_source(file: &str) -> String {
    let text = read(file);
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let t = line.trim_start();
        let ghost = t.starts_with("#[refines(") || t.starts_with("#[view(") || t.starts_with("proof! {");
        if ghost {
            assert!(t.ends_with(")]") || t.ends_with('}'), "{file}: a ghost line that is not one line: {line}");
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    // nothing of the ghost layer is left in code (comments may name it)
    for (i, line) in out.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        for g in ["crate::spec", "crate::model", "crate::proof", "crate::laws", "super::spec", "super::model", "super::proof", "super::laws"] {
            assert!(!code.contains(g), "{file}:{}: still names the ghost layer after erasure: {line}", i + 1);
        }
    }
    out
}
