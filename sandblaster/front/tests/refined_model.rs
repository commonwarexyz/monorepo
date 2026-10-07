//! The verifier on bit-level code, on a small fixture (DESIGN.md, North
//! star: "the laws file is the definition; the code is free", and the
//! statements E1 and E2 of "code equals reference").
//!
//! A host crate's own file `src/a.rs` defines `min_u64(a, b)`. It is
//! verified in place, as written, from rustc's MIR, exactly as
//! `sandblaster::build::compile_lifted` runs it: the proofs, the five §15
//! gates, the function's MIR theorem (`L::thm`, the literal reading of its
//! MIR computes the structured reading) and the lift conformance check
//! against rustc's build of the host. The laws file holds the reference, a
//! ghost function `smaller(x, y)` over `Int` (the textbook
//! `if x < y { x } else { y }`, with known answers), and one law: on every
//! pair of `u64`s, `min_u64(a, b)` is `smaller(a, b)`. The proof file proves
//! the law; the kernel checks the proof.
//!
//! * `mir_fixtures/rm_orig`: the straightforward code (`if a < b { a } else
//!   { b }`). Its gates accept a lock, and it verifies against it.
//! * `mir_fixtures/rm_fast`: the same function written branch-free, as
//!   bit-level code often is (`b ^ ((a ^ b) & mask)`, `mask` all ones when
//!   `a < b`). The lock its gates accept is the straightforward version's,
//!   byte for byte (a different body changes no reviewed line), and it
//!   verifies against that lock with the same law and the same proof.
//! * `mir_fixtures/rm_wrong` (the negative twin): the branch-free code with a
//!   classic slip, the comparison bit used as the mask without negating it
//!   to all ones (so `min_u64(0, 2)` is 2). The same laws, proof and lock:
//!   the law is not proven, no lock can be accepted, and the build gives no
//!   verdict.
//!
//! Each build compiles a copy of the host crate (the conformance check):
//! seconds, not minutes.

#[path = "gated_util.rs"]
mod gated;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sandblaster_front::driver::{self, BuildOutcome};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;

/// The host file and rustc's MIR of it (`mir_fixtures/extract.py`).
type Code = (&'static str, &'static str);

const ORIG: Code = (include_str!("mir_fixtures/rm_orig/src/a.rs"), include_str!("mir_fixtures/rm_orig/a.sbmir"));
const BRANCH_FREE: Code = (include_str!("mir_fixtures/rm_fast/src/a.rs"), include_str!("mir_fixtures/rm_fast/a.sbmir"));
const WRONG: Code = (include_str!("mir_fixtures/rm_wrong/src/a.rs"), include_str!("mir_fixtures/rm_wrong/a.sbmir"));

const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[lift(in_place, mir = \"a.sbmir\")]\n#[path = \"../../src/a.rs\"]\nmod a;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n\npub use a::min_u64;\n";

/// The laws file: the reference (a ghost function with known answers) and
/// the law that the host function equals it on every input.
const LAWS: &str = r#"//! What `min_u64` guarantees: on every input it is the smaller of its
//! arguments. `smaller` is the reference, the textbook definition over
//! `Int`; the code may compute it any way it likes.
use sandblaster::prelude::*;
use crate::a::min_u64;

/// The smaller of two integers.
#[spec]
#[example(smaller(1, 2) == 1 && smaller(5, 3) == 3 && smaller(4, 4) == 4)]
pub fn smaller(x: Int, y: Int) -> Int {
    if x < y { x } else { y }
}

/// `min_u64` is the smaller of its arguments, for every pair of words.
#[law]
fn min_u64_is_the_smaller(a: u64, b: u64) {
    ensures(min_u64(a, b) as Int == smaller(a as Int, b as Int));
}
"#;

const PROOF: &str = r#"use sandblaster::prelude::*;
#[allow(unused_imports)]
use crate::a::min_u64;
#[allow(unused_imports)]
use crate::laws::smaller;

/// Each side of the comparison `a < b`: the mask is all ones (`a ^ b`
/// selected, so `b ^ (a ^ b)` is `a`) or zero (`b` itself). The original's
/// branch needs no word algebra; the same steps prove it.
#[proof]
fn min_u64_is_the_smaller(a: u64, b: u64) {
    unfold(min_u64);
    if a < b {
        assert(b ^ ((a ^ b) & 0xffff_ffff_ffff_ffff) == a, { bv(); });
        follows();
    } else {
        assert(b ^ ((a ^ b) & 0) == b, { bv(); });
        follows();
    }
}
"#;

const LAW: &str = "min_u64_is_the_smaller";
const LOCK: &str = "host/sandblaster/m/SPEC.lock";

/// The host crate with `code` as its `src/a.rs`, without a lock.
fn files(code: Code) -> Vec<(String, String)> {
    vec![
        ("host/Cargo.toml".into(), "[package]\nname = \"rm-host\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n".into()),
        ("host/src/lib.rs".into(), "//! The host crate.\nmod a;\npub use a::min_u64;\n".into()),
        ("host/src/a.rs".into(), code.0.into()),
        ("host/sandblaster/m/mod.rs".into(), ROOT.into()),
        ("host/sandblaster/m/a.sbmir".into(), code.1.into()),
        ("host/sandblaster/m/LAWS.rs".into(), LAWS.into()),
        ("host/sandblaster/m/PROOF.rs".into(), PROOF.into()),
    ]
}

fn with_lock(mut files: Vec<(String, String)>, lock: &str) -> Vec<(String, String)> {
    files.retain(|(p, _)| p != LOCK);
    files.push((LOCK.into(), lock.into()));
    files
}

/// A scratch directory: the crate, its target directories and its cache.
struct Scratch {
    dir: PathBuf,
    builds: usize,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("sandblaster-refined-model-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch { dir, builds: 0 }
    }

    /// The lock `sandblaster spec --accept` writes for `files` (every gate
    /// but the lock must pass), or why there is none.
    fn accept(&self, files: &[(String, String)]) -> Result<String, String> {
        let abs: Vec<(String, String)> = files.iter().map(|(p, t)| (self.dir.join(p).display().to_string(), t.clone())).collect();
        let root = self.dir.join("host/sandblaster/m/mod.rs").display().to_string();
        gated::accept_lock(&abs, &root, &TargetInfo::aarch64_apple_darwin())
    }

    /// An enforcing in-place build of `files` (written to disk, in a new
    /// target directory), as the facade's `compile_lifted` runs it.
    fn build(&mut self, files: &[(String, String)]) -> BuildOutcome {
        let _ = std::fs::remove_dir_all(self.dir.join("host"));
        for (p, t) in files {
            let f = self.dir.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, t).unwrap();
        }
        self.builds += 1;
        let out = self.dir.join(format!("target{}/out", self.builds));
        std::fs::create_dir_all(&out).unwrap();
        let mut e: HashMap<String, String> = [
            ("CARGO_MANIFEST_DIR", self.dir.join("host").display().to_string()),
            ("OUT_DIR", out.display().to_string()),
            ("CARGO_CFG_TARGET_ARCH", "aarch64".into()),
            ("CARGO_CFG_TARGET_FEATURE", "neon,sha2,sha3,aes".into()),
            ("CARGO_CFG_TARGET_ENDIAN", "little".into()),
            ("CARGO_CFG_TARGET_POINTER_WIDTH", "64".into()),
            ("SANDBLASTER_CACHE_DIR", self.dir.join("cache").display().to_string()),
            ("SANDBLASTER_CACHE_KEY", "test secret".into()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        for k in ["RUSTC", "CARGO"] {
            if let Ok(v) = std::env::var(k) {
                e.insert(k.into(), v);
            }
        }
        driver::build_lifted("sandblaster/m/mod.rs", "m", Some("refined-model-test-toolchain"), &|k| e.get(k).cloned(), &sandblaster_front::loader::RealFs)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn output<'o>(o: &'o BuildOutcome, name: &str) -> Option<&'o str> {
    o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == name)).map(|(_, c)| c.as_str())
}

/// A verdict: the record says the file was verified in place, every gate
/// (the theorem gate included) ran without an error, and the lift
/// conformance check passed.
#[track_caller]
fn verified(what: &str, o: &BuildOutcome) {
    assert!(o.ok, "{what}: no verdict:\n{}\n{:?}", o.stderr, o.cargo);
    let record = output(o, "m-verified.txt").unwrap_or_else(|| panic!("{what}: no record: {:?}", o.cargo));
    assert!(record.contains("VERIFIED + LIFTED IN PLACE") && record.contains("src/a.rs"), "{what}: {record}");
    let report = output(o, "m-report.json").unwrap_or_else(|| panic!("{what}: no report"));
    for gate in ["boundary", "examples", "sections", "law-rules", "lock", "mir-theorems", "lift-conformance"] {
        let at = report.find(&format!("\"gate\": \"{gate}\"")).unwrap_or_else(|| panic!("{what}: gate {gate} is not in the report:\n{report}"));
        let entry = &report[at..report[at..].find('}').map_or(report.len(), |e| at + e)];
        assert!(entry.contains("\"ran\": true") && entry.contains("\"errors\": 0"), "{what}: gate {gate}: {entry}");
    }
    assert!(!report.contains("\"mutation\""), "{what}: a build ran spec mutation");
}

/// `min_u64(a, b)` by the kernel evaluator: the reference semantics of the
/// code as the lift reads it from rustc's MIR (`sandblaster eval`).
fn eval(code: Code, a: u64, b: u64) -> String {
    let files = files(code);
    let fs = MemFs::from_files(files.iter().map(|(p, t)| (p.as_str(), t.as_str())));
    let c = driver::check(Path::new("host/sandblaster/m/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    driver::stage::eval_json(&c, "crate::a::min_u64", &format!("[{a}, {b}]")).unwrap_or_else(|e| panic!("eval: {e}")).trim().to_string()
}

/// A gate's note in a build's report (for the test's log).
fn gate_note(o: &BuildOutcome, gate: &str) -> String {
    let report = output(o, "m-report.json").unwrap_or_default();
    let Some(at) = report.find(&format!("\"gate\": \"{gate}\"")) else { return String::new() };
    report[at..].lines().find(|l| l.contains("\"note\"")).map(|l| l.trim().to_string()).unwrap_or_default()
}

#[test]
fn branch_free_code_meets_the_same_laws_and_a_wrong_variant_is_refused() {
    let mut s = Scratch::new("main");

    // the original: its gates accept a lock, and it verifies against it
    let lock = s.accept(&files(ORIG)).unwrap_or_else(|e| panic!("the original's gates:\n{e}"));
    assert!(lock.contains(&format!("law:crate::laws::{LAW}")) && lock.contains("boundary-fn:crate::a::min_u64"), "{lock}");
    let o = s.build(&with_lock(files(ORIG), &lock));
    verified("the original", &o);

    // the branch-free code: the same laws file, so the same lock byte for byte
    // (nothing for a reviewer to read), and a verdict against it with the
    // same proof
    assert_ne!(BRANCH_FREE.0, ORIG.0);
    let bf_lock = s.accept(&files(BRANCH_FREE)).unwrap_or_else(|e| panic!("the branch-free code's gates:\n{e}"));
    assert_eq!(bf_lock, lock, "a different body changes no locked byte");
    let o = s.build(&with_lock(files(BRANCH_FREE), &lock));
    verified("the branch-free code", &o);
    eprintln!("the branch-free code: {}\n  {}", gate_note(&o, "mir-theorems"), gate_note(&o, "lift-conformance"));

    // a wrong branch-free variant: the law is false for it (the kernel evaluator
    // gives 2 for `min_u64(0, 2)`, where the reference says 0), so it is not
    // proven, no lock can be accepted and the build against the lock gives
    // no verdict
    assert_eq!((eval(ORIG, 0, 2), eval(BRANCH_FREE, 0, 2), eval(WRONG, 0, 2)), ("0".to_string(), "0".to_string(), "2".to_string()));
    let e = s.accept(&files(WRONG)).expect_err("a wrong variant must not get a lock");
    assert!(e.contains(LAW), "the refusal names the law:\n{e}");
    let o = s.build(&with_lock(files(WRONG), &lock));
    assert!(!o.ok, "a wrong variant got a verdict: {:?}", o.cargo);
    assert!(o.stderr.contains(LAW), "the refusal names the law:\n{}", o.stderr);
    eprintln!("the wrong variant, refused:\n{}", o.stderr.lines().filter(|l| l.contains("error")).take(4).collect::<Vec<_>>().join("\n"));
    assert!(!o.outputs.iter().any(|(p, c)| p.ends_with("m-verified.txt") && c.contains("VERIFIED +")), "a verified record for a wrong variant");
}
