//! `sandblaster::build::compile`'s checks before verification (DESIGN.md §2,
//! §10.1), tested through `driver::build_verified` with an in-memory file
//! system: the `include!` line of `src/lib.rs`, the target from the
//! `CARGO_CFG_*` variables, front-end errors — and that no environment
//! variable turns a failing crate into emitted code (the phase-1 opt-in
//! `SANDBLASTER_PHASE1_UNVERIFIED` is gone; DESIGN.md §15.8).

mod common;

use std::collections::HashMap;

use common::HEADER;
use sandblaster_front::driver::{self, build_verified, BuildOutcome, LIB_RS_LINE};
use sandblaster_front::loader::MemFs;

fn env(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = [
        ("CARGO_MANIFEST_DIR", "/crate"),
        ("OUT_DIR", "/out"),
        ("CARGO_CFG_TARGET_ARCH", "aarch64"),
        ("CARGO_CFG_TARGET_FEATURE", "neon,sha2,sha3,aes"),
        ("CARGO_CFG_TARGET_ENDIAN", "little"),
        ("CARGO_CFG_TARGET_POINTER_WIDTH", "64"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in extra {
        m.insert(k.to_string(), v.to_string());
    }
    m
}

fn run(lib: &str, dsl: &str, extra: &[(&str, &str)]) -> BuildOutcome {
    let fs = MemFs::from_files([("/crate/src/lib.rs", lib), ("/crate/sandblaster/mod.rs", dsl), ("/crate/sandblaster/m.rs", "pub fn g() -> u32 { 1 }\n")]);
    let e = env(extra);
    build_verified("sandblaster/mod.rs", &|k| e.get(k).cloned(), &fs)
}

fn dsl() -> String {
    format!("{HEADER}mod m;\npub fn f(x: u32) -> u32 {{ x.wrapping_add(m::g()) }}\n")
}

fn emitted(o: &BuildOutcome) -> bool {
    o.outputs.iter().any(|(p, _)| p.ends_with("sandblaster.rs"))
}

#[test]
fn lib_rs_must_be_the_include_line() {
    assert!(driver::lib_rs_ok(LIB_RS_LINE));
    assert!(driver::lib_rs_ok("//! docs\n// comment\ninclude!(concat!(env!(\"OUT_DIR\"), \"/sandblaster.rs\")); /* trailing */\n"));
    assert!(driver::lib_rs_ok("include!( concat!( env!( \"OUT_DIR\" ), \"/sandblaster.rs\" ) );"));
    assert!(!driver::lib_rs_ok("include!(concat!(env!(\"OUT_DIR\"), \"/sandblaster.rs\"));\npub fn host() {}\n"));
    assert!(!driver::lib_rs_ok("pub fn host() {}"));
    let o = run("pub fn host() {}\n", &dsl(), &[]);
    assert!(!o.ok);
    assert!(o.stderr.contains("must contain exactly"), "{}", o.stderr);
    assert!(o.outputs.is_empty());
}

/// The removed phase-1 opt-in, and every other variable a build script
/// could set, never emit code for a crate that fails the gates: the
/// crate below verifies but has an exec function at the root, no
/// specification and no lock.
#[test]
fn no_environment_variable_emits_code_for_a_failing_crate() {
    for extra in [vec![], vec![("SANDBLASTER_PHASE1_UNVERIFIED", "1")], vec![("SANDBLASTER_MUTANTS_MAX", "0"), ("SANDBLASTER_MUTANTS_TIME_BUDGET", "0")], vec![("SANDBLASTER_STRICT_OPT", "0")], vec![("QMDB_ALLOW_TEST_ONLY", "1")]] {
        let o = run(LIB_RS_LINE, &dsl(), &extra);
        assert!(!o.ok, "{extra:?}: {}", o.stderr);
        assert!(!emitted(&o), "{extra:?}: code emitted");
        assert!(o.stderr.contains("failed the §15 gates"), "{extra:?}: {}", o.stderr);
        assert!(o.stderr.contains("error[boundary]"), "{extra:?}: {}", o.stderr);
        assert!(!o.cargo.iter().any(|l| l.contains("PHASE1")), "{:?}", o.cargo);
    }
}

#[test]
fn diagnostics_fail_the_build() {
    let bad = format!("{HEADER}pub fn f(x: u32) -> u64 {{ (1 << x) as u64 }}\n");
    let o = run(LIB_RS_LINE, &bad, &[]);
    assert!(!o.ok);
    assert!(o.outputs.is_empty());
    assert!(o.stderr.contains("sandblaster/mod.rs:3:"), "{}", o.stderr);
    assert!(o.stderr.contains("error[literal]"), "{}", o.stderr);
    // rerun-if-changed for every file read
    for f in ["/crate/src/lib.rs", "/crate/sandblaster/mod.rs"] {
        assert!(o.cargo.iter().any(|l| l == &format!("cargo::rerun-if-changed={f}")), "{:?}", o.cargo);
    }
}

#[test]
fn target_comes_from_cargo_cfg() {
    // an x86-only item is configured in for an x86 target: the front end
    // accepts it (the crate then fails the gates, not the front end)
    let src = format!("{HEADER}#[cfg(target_arch = \"x86_64\")] use core::arch::x86_64::*;\npub fn f() -> u32 {{ 1 }}\n");
    let o = run(LIB_RS_LINE, &src, &[("CARGO_CFG_TARGET_ARCH", "x86_64"), ("CARGO_CFG_TARGET_FEATURE", "sse,sse2")]);
    assert!(!o.ok && o.stderr.contains("failed the §15 gates"), "{}", o.stderr);
    let o = run(LIB_RS_LINE, &src, &[("CARGO_CFG_TARGET_POINTER_WIDTH", "32")]);
    assert!(!o.ok);
    assert!(o.stderr.contains("64-bit"), "{}", o.stderr);
    let e: HashMap<String, String> = HashMap::new();
    let fs = MemFs::new();
    let o = build_verified("sandblaster/mod.rs", &|k| e.get(k).cloned(), &fs);
    assert!(!o.ok && o.stderr.contains("CARGO_MANIFEST_DIR"));
}

/// `PROFILE.json` (optimizer design §10.4) is an input of the checked crate:
/// `driver::check` reads it through the file provider next to the root's
/// directory, the build re-runs when it changes, and a file that does not
/// parse is ignored with a warning (it only steers the optimizer's choices).
#[test]
fn the_profile_is_an_input_of_the_checked_crate() {
    let target = sandblaster_front::target::TargetInfo::aarch64_apple_darwin();
    let good = r#"{"format": "sandblaster-profile/1", "entries": [{"root": "sandblaster/mod.rs", "entry": "crate::f", "corpora": [], "fixtures": 1, "loops": [{"loop": "crate::m::g", "calls": 2, "samples": [["3"], ["7"]]}]}]}"#;
    let cases: [(Option<&str>, bool); 3] = [(None, false), (Some(good), true), (Some("{\"format\": \"other\"}"), false)];
    for (profile, parses) in cases {
        let d = dsl();
        let mut files = vec![("/crate/src/lib.rs", LIB_RS_LINE), ("/crate/sandblaster/mod.rs", d.as_str()), ("/crate/sandblaster/m.rs", "pub fn g() -> u32 { 1 }\n")];
        if let Some(p) = profile {
            files.push(("/crate/PROFILE.json", p));
        }
        let fs = MemFs::from_files(files.iter().copied());
        let c = driver::check(std::path::Path::new("/crate/sandblaster/mod.rs"), &fs, &target);
        assert!(c.ok(), "{}", c.render());
        match (&c.profile, profile) {
            (None, None) => {}
            (Some(p), Some(_)) => {
                assert_eq!(p.path, std::path::Path::new("/crate/PROFILE.json"));
                assert_eq!(p.parsed.is_ok(), parses, "{:?}", p.parsed.as_ref().err());
                let samples = p.loop_samples();
                assert_eq!(samples.get("crate::m::g").map(|s| s.len()), parses.then_some(2), "{samples:?}");
            }
            (p, _) => panic!("profile {:?} read as {:?}", profile, p.as_ref().map(|p| &p.path)),
        }
        let e = env(&[]);
        let o = build_verified("sandblaster/mod.rs", &|k| e.get(k).cloned(), &fs);
        let rerun = o.cargo.iter().any(|l| l == "cargo::rerun-if-changed=/crate/PROFILE.json");
        assert_eq!(rerun, profile.is_some(), "{:?}", o.cargo);
        let warned = o.cargo.iter().any(|l| l.starts_with("cargo::warning=sandblaster: profile `/crate/PROFILE.json` ignored"));
        assert_eq!(warned, profile.is_some() && !parses, "{:?}", o.cargo);
        // the profile never turns the failing crate (no spec, no lock) into code
        assert!(!o.ok && !emitted(&o), "{}", o.stderr);
    }
}
