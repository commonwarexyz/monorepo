//! The verdict cache of in-place builds (`driver::in_place`,
//! `sandblaster::build::compile_lifted`): a host crate on disk whose
//! `src/a.rs` is verified in place (`mir_fixtures/ic_two`: `half` and `inc`,
//! their bodies rustc's MIR), with a path dependency outside its workspace,
//! a laws file (two spec functions with examples, a precondition, two laws),
//! a proof file and the lock its own gates accepted.
//!
//! * an unchanged rerun takes the cached verdict: in the same `OUT_DIR` by
//!   its key file, in a new one from the shared cache (every output byte for
//!   byte), and the lift conformance check does not run (no build runs
//!   spec mutation: it is the on-demand tool `sandblaster mutate`);
//! * each edit invalidates what it must, and only that (every edited build
//!   in a new `OUT_DIR`, the shared cache kept):
//!   - a law's statement: refused without a re-accepted lock (never the
//!     cached verdict); with it, the verdict is recomputed and the
//!     conformance pass is reused; a
//!     precondition re-runs the conformance check (it filters its inputs);
//!   - the host source: a host file that is not lifted, or a file of the path
//!     dependency, re-runs the conformance check (it compiles them); the
//!     lifted file without a new MIR extraction is refused;
//!   - the `.sbmir`: a text edit that keeps its meaning recomputes the
//!     verdict and nothing else; a different body fails the build;
//!   - the proof file: a new proven lemma recomputes the verdict and nothing
//!     else; a false one fails the build;
//!   - the lock: a comment recomputes the verdict and nothing else; a
//!     tampered root fails the build;
//! * a tampered cache entry is rejected and the crate verified again;
//! * the host inputs' digest reads the source tree and the path
//!   dependencies' files (not their tests), and the item key reads no law,
//!   lemma or proof.

#[path = "gated_util.rs"]
mod gated;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sandblaster_front::driver::{self, BuildOutcome};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;

const A: &str = include_str!("mir_fixtures/ic_two/src/a.rs");
const MIR: &str = include_str!("mir_fixtures/ic_two/a.sbmir");

const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[lift(in_place, mir = \"a.sbmir\")]\n#[path = \"../../src/a.rs\"]\nmod a;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n\npub use a::{half, inc};\n";

const LAWS: &str = r#"use sandblaster::prelude::*;
use crate::a::{half, inc};

/// Half of a number, rounded down.
#[spec]
#[example(halved(0) == 0 && halved(7) == 3 && halved(8) == 4)]
pub fn halved(x: Nat) -> Nat {
    x / 2
}

/// The number after `x`.
#[spec]
#[example(after(0) == 1 && after(41) == 42)]
pub fn after(x: Nat) -> Nat {
    x + 1
}

/// `inc` is called below the largest word.
#[lift_attach(crate::a::inc)]
fn inc_pre() {
    requires((x as Int) + 1 < pow2(64));
}

/// `half` rounds down.
#[law]
fn half_rounds_down(x: u64) {
    ensures(half(x) as Nat == halved(x as Nat));
}

/// `inc` gives the number after its argument.
#[law]
fn inc_is_after(x: u64) {
    requires((x as Int) + 1 < pow2(64));
    ensures(inc(x) as Nat == after(x as Nat));
}
"#;

const PROOF: &str = r#"use sandblaster::prelude::*;
#[allow(unused_imports)]
use crate::a::{half, inc};
#[allow(unused_imports)]
use crate::laws::{after, halved};

/// By the definitions.
#[proof]
fn half_rounds_down(x: u64) {
    follows();
}

/// By the definitions.
#[proof]
fn inc_is_after(x: u64) {
    follows();
}
"#;

const DEP: &str = "//! A path dependency of the host (outside its workspace).\npub fn seven() -> u8 {\n    7\n}\n";

/// The crate's files (relative to the scratch directory), without the lock.
fn base_files() -> Vec<(String, String)> {
    vec![
        ("host/Cargo.toml".into(), "[package]\nname = \"ic-host\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[dependencies]\nic-dep = { path = \"../dep\" }\n\n[workspace]\n".into()),
        ("host/src/lib.rs".into(), "//! The host crate.\nmod a;\npub use a::{half, inc};\n".into()),
        ("host/src/a.rs".into(), A.into()),
        ("host/sandblaster/m/mod.rs".into(), ROOT.into()),
        ("host/sandblaster/m/a.sbmir".into(), MIR.into()),
        ("host/sandblaster/m/LAWS.rs".into(), LAWS.into()),
        ("host/sandblaster/m/PROOF.rs".into(), PROOF.into()),
        ("dep/Cargo.toml".into(), "[package]\nname = \"ic-dep\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"src/lib.rs\"\n".into()),
        ("dep/src/lib.rs".into(), DEP.into()),
        ("dep/tests/t.rs".into(), "#[test]\nfn t() {\n    assert_eq!(ic_dep::seven(), 7);\n}\n".into()),
    ]
}

const LOCK: &str = "host/sandblaster/m/SPEC.lock";

fn with(files: &[(String, String)], path: &str, text: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = files.iter().filter(|(p, _)| p != path).cloned().collect();
    v.push((path.to_string(), text.to_string()));
    v
}

fn text<'f>(files: &'f [(String, String)], path: &str) -> &'f str {
    &files.iter().find(|(p, _)| p == path).unwrap_or_else(|| panic!("no {path}")).1
}

/// A scratch directory: the crate, the target directories and the cache.
struct Scratch {
    dir: PathBuf,
    builds: usize,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("sandblaster-ip-cache-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch { dir, builds: 0 }
    }

    fn cache(&self) -> PathBuf {
        self.dir.join("cache")
    }

    /// Writes `files` as the crate (removing the previous crate's files).
    fn write(&self, files: &[(String, String)]) {
        for d in ["host", "dep"] {
            let _ = std::fs::remove_dir_all(self.dir.join(d));
        }
        for (p, t) in files {
            let f = self.dir.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, t).unwrap();
        }
    }

    /// `files` with the lock its own gates accept (`sandblaster spec
    /// --accept` on the same files, at the same paths).
    fn accepted(&self, files: &[(String, String)]) -> Vec<(String, String)> {
        let abs: Vec<(String, String)> = files.iter().map(|(p, t)| (self.dir.join(p).display().to_string(), t.clone())).collect();
        let root = self.dir.join("host/sandblaster/m/mod.rs").display().to_string();
        let lock = gated::accept_lock(&abs, &root, &TargetInfo::aarch64_apple_darwin()).unwrap_or_else(|e| panic!("the gates reject the test crate:\n{e}"));
        with(files, LOCK, &lock)
    }

    fn out_dir(&mut self) -> PathBuf {
        self.builds += 1;
        self.dir.join(format!("target{}/out", self.builds))
    }

    /// An enforcing in-place build of `files` (written to disk) into
    /// `out` (a new target directory when `None`), as the facade's
    /// `compile_lifted` runs it; the outputs are written as the facade
    /// writes them.
    fn build(&mut self, files: &[(String, String)], out: Option<&Path>) -> (BuildOutcome, PathBuf) {
        self.write(files);
        let out = match out {
            Some(o) => o.to_path_buf(),
            None => self.out_dir(),
        };
        std::fs::create_dir_all(&out).unwrap();
        let mut e: HashMap<String, String> = [
            ("CARGO_MANIFEST_DIR", self.dir.join("host").display().to_string()),
            ("OUT_DIR", out.display().to_string()),
            ("CARGO_CFG_TARGET_ARCH", "aarch64".into()),
            ("CARGO_CFG_TARGET_FEATURE", "neon,sha2,sha3,aes".into()),
            ("CARGO_CFG_TARGET_ENDIAN", "little".into()),
            ("CARGO_CFG_TARGET_POINTER_WIDTH", "64".into()),
            ("SANDBLASTER_CACHE_DIR", self.cache().display().to_string()),
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
        let o = driver::build_lifted("sandblaster/m/mod.rs", "m", Some("in-place-cache-test-toolchain"), &|k| e.get(k).cloned(), &sandblaster_front::loader::RealFs);
        for (p, t) in &o.outputs {
            if let Some(d) = p.parent() {
                std::fs::create_dir_all(d).unwrap();
            }
            std::fs::write(p, t).unwrap();
        }
        (o, out)
    }
}

fn output<'o>(o: &'o BuildOutcome, name: &str) -> Option<&'o str> {
    o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == name)).map(|(_, c)| c.as_str())
}

/// Reused from the shared cache.
fn shared_hit(o: &BuildOutcome) -> bool {
    o.cargo.iter().any(|l| l.contains("reusing the verdict cache entry"))
}

/// Reused by the `OUT_DIR` key file.
fn local_hit(o: &BuildOutcome) -> bool {
    o.cargo.iter().any(|l| l.contains("verified in place, unchanged") && !l.contains("verdict cache entry"))
}

/// Whether the lift conformance check ran (it writes its harness, a copy of
/// the host crate, into its work directory; a replayed pass writes nothing).
fn conformance_ran(out: &Path) -> bool {
    out.join("m-conformance/crate/Cargo.toml").exists()
}

/// No spec mutant ran: the timing file has no mutation entry (spec
/// mutation is the on-demand tool, never part of a build).
fn no_mutation(o: &BuildOutcome) {
    let t = output(o, "m-timing.json").unwrap_or_else(|| panic!("no timing: {:?}", o.cargo));
    assert!(!t.contains("mutation"), "a build ran spec mutation: {t}");
}

fn verified(o: &BuildOutcome) -> bool {
    o.ok && o.outputs.iter().any(|(p, c)| p.ends_with("m-verified.txt") && c.contains("VERIFIED + LIFTED IN PLACE"))
}

/// A recomputed verdict (no reuse) that passed: the conformance check ran
/// or not as `conformance`; no spec mutant ran.
fn recomputed(what: &str, o: &BuildOutcome, out: &Path, conformance: bool) {
    assert!(verified(o), "{what}: the build failed:\n{}\n{:?}", o.stderr, o.cargo);
    assert!(!shared_hit(o) && !local_hit(o), "{what}: the verdict was reused: {:?}", o.cargo);
    assert_eq!(conformance_ran(out), conformance, "{what}: the conformance check ran: {}, expected {conformance}", conformance_ran(out));
    no_mutation(o);
}

/// A refused build, for the reason `why`: no verdict, nothing reused.
fn refused(what: &str, o: &BuildOutcome, why: &str) {
    assert!(!o.ok, "{what}: the build passed: {:?}", o.cargo);
    assert!(o.stderr.contains(why), "{what}: refused, but not because of `{why}`:\n{}", o.stderr);
    assert!(!shared_hit(o) && !local_hit(o), "{what}: a cached verdict was used: {:?}", o.cargo);
    assert!(!o.outputs.iter().any(|(p, c)| p.ends_with("m-verified.txt") && c.contains("VERIFIED +")), "{what}: a verified record");
}

#[test]
fn an_in_place_verdict_is_cached_and_each_edit_invalidates_what_it_must() {
    let mut s = Scratch::new("main");
    let base = s.accepted(&base_files());

    // the cold build: every gate and the conformance check run (no spec
    // mutant: mutation is the on-demand tool)
    let (cold, out1) = s.build(&base, None);
    assert!(verified(&cold), "{}\n{:?}", cold.stderr, cold.cargo);
    assert!(!shared_hit(&cold) && !local_hit(&cold) && conformance_ran(&out1));
    no_mutation(&cold);

    // an unchanged rerun in the same target directory: its key file
    let (again, _) = s.build(&base, Some(&out1));
    assert!(again.ok && local_hit(&again), "{:?}", again.cargo);
    // in a new target directory: the shared cache, every output byte for
    // byte, nothing run
    let (warm, out2) = s.build(&base, None);
    assert!(warm.ok && shared_hit(&warm), "{:?}\n{}", warm.cargo, warm.stderr);
    assert!(!conformance_ran(&out2) && !out2.join("m-conformance").exists(), "the conformance check ran");
    for (p, t) in &cold.outputs {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if name == "m-verdict.key" {
            continue;
        }
        assert_eq!(output(&warm, &name), Some(t.as_str()), "{name} is not the cached one");
    }
    // the key file: the same verdict key (its output digest is the
    // record's)
    let key_line = |o: &BuildOutcome| output(o, "m-verdict.key").and_then(|k| k.lines().find(|l| l.starts_with("key ")).map(str::to_string));
    assert!(key_line(&warm).is_some() && key_line(&warm) == key_line(&cold), "the key file");
    assert!(warm.outputs.iter().all(|(p, _)| p.starts_with(&out2)), "outputs go to the new OUT_DIR");
    // and that target directory now reuses by its key file
    let (again2, _) = s.build(&base, Some(&out2));
    assert!(again2.ok && local_hit(&again2), "{:?}", again2.cargo);

    // a law's statement (`inc_is_after`, sides swapped)
    let laws2 = LAWS.replace("ensures(inc(x) as Nat == after(x as Nat));", "ensures(after(x as Nat) == inc(x) as Nat);");
    assert_ne!(laws2, LAWS);
    let stale = with(&base, "host/sandblaster/m/LAWS.rs", &laws2);
    let (o, _) = s.build(&stale, None);
    refused("a law edited, the lock not re-accepted", &o, "error[spec-lock]: SPEC.lock: `law:crate::laws::inc_is_after` changed");
    let relocked = s.accepted(&with(&base_files(), "host/sandblaster/m/LAWS.rs", &laws2));
    let (o, out) = s.build(&relocked, None);
    recomputed("a law edited, the lock re-accepted", &o, &out, false);
    // a precondition in the laws file (and the law that needs it): the
    // conformance check decides which inputs it compares by it, so it runs
    let laws3 = LAWS.replace("(x as Int) + 1 < pow2(64)", "(x as Int) + 2 < pow2(64)");
    assert_eq!(laws3.matches("+ 2 < pow2(64)").count(), 2);
    let relocked = s.accepted(&with(&base_files(), "host/sandblaster/m/LAWS.rs", &laws3));
    let (o, out) = s.build(&relocked, None);
    recomputed("a precondition edited, the lock re-accepted", &o, &out, true);

    // the host source: a file that is not lifted, a file of the path
    // dependency (the copy of the host crate compiles both), the lifted
    // file without a new extraction of its MIR
    let lib2 = format!("{}/// Host code.\npub fn host_only() -> u8 {{\n    ic_dep_seven()\n}}\nfn ic_dep_seven() -> u8 {{\n    7\n}}\n", text(&base, "host/src/lib.rs"));
    let (o, out) = s.build(&with(&base, "host/src/lib.rs", &lib2), None);
    recomputed("a host file edited", &o, &out, true);
    let (o, out) = s.build(&with(&base, "dep/src/lib.rs", &DEP.replace("    7\n", "    8\n")), None);
    recomputed("a path dependency edited", &o, &out, true);
    let (o, _) = s.build(&with(&base, "host/src/a.rs", &A.replace("x / 2", "x >> 1")), None);
    refused("the lifted file edited, its MIR stale", &o, "changed since the MIR was extracted");
    // (the dependency's tests are not compiled into the copy: not an input)
    let (o, _) = s.build(&with(&base, "dep/tests/t.rs", "#[test]\nfn t() {}\n"), None);
    assert!(o.ok && shared_hit(&o), "a dependency's test file is not an input: {:?}", o.cargo);

    // the MIR: a text edit that keeps its meaning, and another body
    let (o, out) = s.build(&with(&base, "host/sandblaster/m/a.sbmir", &format!("{MIR};; a comment\n")), None);
    recomputed("the .sbmir edited (a comment)", &o, &out, false);
    let quarter = MIR.replace("(bin div (copy (p 1)) (int u64 2))", "(bin div (copy (p 1)) (int u64 4))");
    assert_ne!(quarter, MIR, "the fixture divides by the constant 2");
    let (o, _) = s.build(&with(&base, "host/sandblaster/m/a.sbmir", &quarter), None);
    refused("the .sbmir edited (another body)", &o, "unproven obligation [law-goal] in `crate::laws::half_rounds_down`");

    // the proof file: a new proven lemma, a false one
    let lemma = format!("{PROOF}\n/// Half of nothing.\n#[lemma]\nfn halved_zero() {{\n    ensures(halved(0) == 0);\n    follows();\n}}\n");
    let (o, out) = s.build(&with(&base, "host/sandblaster/m/PROOF.rs", &lemma), None);
    recomputed("a lemma added to the proof file", &o, &out, false);
    let wrong = lemma.replace("ensures(halved(0) == 0);", "ensures(halved(1) == 1);");
    let (o, _) = s.build(&with(&base, "host/sandblaster/m/PROOF.rs", &wrong), None);
    refused("a false lemma in the proof file", &o, "unproven obligation [ensures] in `crate::proof::halved_zero`");

    // the lock: a comment, a tampered root
    let lock = text(&base, LOCK).to_string();
    let (o, out) = s.build(&with(&base, LOCK, &format!("{lock}# a reviewer's note\n")), None);
    recomputed("a comment in the lock", &o, &out, false);
    let root_line = lock.lines().find(|l| l.starts_with("root ")).expect("the lock's root").to_string();
    let flipped = format!("root {}{}", if root_line.as_bytes()[5] == b'0' { '1' } else { '0' }, &root_line[6..]);
    let (o, _) = s.build(&with(&base, LOCK, &lock.replace(&root_line, &flipped)), None);
    refused("a tampered lock", &o, "the `root` line is not the hash");

    // the base crate again: still the cached verdict
    let (o, out) = s.build(&base, None);
    assert!(o.ok && shared_hit(&o) && !conformance_ran(&out), "{:?}", o.cargo);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn a_tampered_in_place_entry_is_rejected_and_the_crate_verified_again() {
    let mut s = Scratch::new("tamper");
    let base = s.accepted(&base_files());
    let (cold, _) = s.build(&base, None);
    assert!(verified(&cold), "{}", cold.stderr);
    let record = output(&cold, "m-verified.txt").unwrap().to_string();
    // the stored whole verdict
    let ns = s.cache().join("sandblaster-cache-1").join(driver::in_place::CACHE_NS);
    let entry = std::fs::read_dir(&ns).unwrap().flatten().flat_map(|d| std::fs::read_dir(d.path()).unwrap().flatten().map(|f| f.path()).collect::<Vec<_>>()).find(|p| !p.file_name().unwrap().to_string_lossy().starts_with('.')).expect("the in-place verdict was stored");
    let good = std::fs::read_to_string(&entry).unwrap();
    let evil = good.replacen("VERIFIED + LIFTED IN PLACE", "VERIFIED + LIFTED IN PLACe", 1);
    assert_ne!(evil, good);
    std::fs::write(&entry, &evil).unwrap();
    let (o, _) = s.build(&base, None);
    assert!(verified(&o) && !shared_hit(&o), "{:?}", o.cargo);
    assert!(o.cargo.iter().any(|l| l.contains("rejected")), "{:?}", o.cargo);
    assert_eq!(output(&o, "m-verified.txt"), Some(record.as_str()), "verified again to the same bytes");
    // (the conformance pass was reused; no spec mutant ran)
    no_mutation(&o);
    // the entry was repaired
    let (o, _) = s.build(&base, None);
    assert!(o.ok && shared_hit(&o), "{:?}", o.cargo);
    let _ = std::fs::remove_dir_all(&s.dir);
}

#[test]
fn the_host_inputs_read_the_tree_and_the_path_dependencies_and_the_item_key_reads_no_proof() {
    let s = Scratch::new("inputs");
    let base = s.accepted(&base_files());
    let digest = |files: &[(String, String)]| {
        s.write(files);
        let mut cfg = sandblaster_front::conform::Config::new(PathBuf::from("rustc"), s.dir.join("work"), "2024", "t");
        cfg.manifest_dir = Some(s.dir.join("host"));
        cfg.cargo = PathBuf::from(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        sandblaster_front::conform::host_inputs(&cfg).unwrap_or_else(|e| panic!("{e}")).text
    };
    let d0 = digest(&base);
    assert!(d0.contains("path-dep ic-dep "), "{d0}");
    assert_eq!(digest(&base), d0, "deterministic");
    // inputs: a host file, a lifted file, the dependency's source and manifest
    for (p, t) in [("host/src/lib.rs", "mod a;\n"), ("host/src/a.rs", "pub fn half(x: u64) -> u64 { x }\n"), ("dep/src/lib.rs", "pub fn seven() -> u8 { 8 }\n"), ("dep/Cargo.toml", "[package]\nname = \"ic-dep\"\nversion = \"0.1.1\"\nedition = \"2024\"\n")] {
        assert_ne!(digest(&with(&base, p, t)), d0, "{p} is an input");
    }
    // not inputs: the dependency's tests and documents nothing includes,
    // the DSL files (the item key and the front end's files cover those)
    for (p, t) in [("dep/tests/t.rs", "\n"), ("dep/README.md", "A document.\n"), ("dep/src/notes.md", "Notes.\n"), ("host/sandblaster/m/LAWS.rs", "\n")] {
        assert_eq!(digest(&with(&base, p, t)), d0, "{p} is not a host input");
    }
    // twin: a document the dependency's source includes is an input
    let doc = with(&with(&base, "dep/src/lib.rs", &format!("#![doc = include_str!(\"../README.md\")]\n{DEP}")), "dep/README.md", "A document.\n");
    let d1 = digest(&doc);
    assert_ne!(digest(&with(&doc, "dep/README.md", "A revised document.\n")), d1, "an included document is an input");
    // the item key: a law's statement and a proof are not part of it, a
    // spec function is
    let key = |laws: &str, proof: &str| {
        let files: Vec<(String, String)> = with(&with(&base, "host/sandblaster/m/LAWS.rs", laws), "host/sandblaster/m/PROOF.rs", proof).iter().map(|(p, t)| (s.dir.join(p).display().to_string(), t.clone())).collect();
        let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
        let c = driver::check(&s.dir.join("host/sandblaster/m/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
        assert!(c.ok(), "{}", c.render());
        sandblaster_front::conform::items_key(c.krate.as_ref().unwrap())
    };
    let k0 = key(LAWS, PROOF);
    assert_eq!(key(&LAWS.replace("ensures(inc(x) as Nat == after(x as Nat));", "ensures(after(x as Nat) == inc(x) as Nat);"), PROOF), k0, "a law's statement");
    assert_eq!(key(LAWS, &PROOF.replacen("    follows();\n", "    by_arithmetic();\n", 1)), k0, "a proof");
    assert_eq!(key(&LAWS.replace("/// Half of a number", "\n/// Half of a number"), PROOF), k0, "a position");
    assert_ne!(key(&LAWS.replace("    x / 2\n", "    (x + 1) / 2\n"), PROOF), k0, "a spec function the checkers may call");
    assert_ne!(key(&LAWS.replace("requires((x as Int) + 1 < pow2(64));\n}\n\n/// `half`", "requires((x as Int) + 2 < pow2(64));\n}\n\n/// `half`"), PROOF), k0, "a precondition");
    let _ = std::fs::remove_dir_all(&s.dir);
}

/// The environment that changes how cargo builds the conformance check's
/// copy of the host crate is part of the host inputs; where and how fast it
/// builds is not.
#[test]
fn the_build_environment_that_changes_the_copy_is_an_input() {
    let s = Scratch::new("env");
    s.write(&base_files());
    let digest = |env: &[(&str, &str)]| {
        let mut cfg = sandblaster_front::conform::Config::new(PathBuf::from("rustc"), s.dir.join("work"), "2024", "t");
        cfg.manifest_dir = Some(s.dir.join("host"));
        cfg.cargo = PathBuf::from(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        cfg.build_env = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        sandblaster_front::conform::host_inputs(&cfg).unwrap_or_else(|e| panic!("{e}")).text
    };
    let d0 = digest(&[]);
    for k in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_BOOTSTRAP", "CARGO_PROFILE_DEV_OVERFLOW_CHECKS", "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER", "CARGO_UNSTABLE_BUILD_STD"] {
        assert_ne!(digest(&[(k, "x")]), d0, "{k} is an input");
    }
    // negative twins: resource and location settings, other variables
    for k in ["CARGO_BUILD_JOBS", "CARGO_TARGET_DIR", "CARGO_HOME", "HOME", "SANDBLASTER_MEM_LIMIT_GB", "CARGO_FEATURE_STD"] {
        assert_eq!(digest(&[(k, "x")]), d0, "{k} is not an input");
    }
    let _ = std::fs::remove_dir_all(&s.dir);
}
