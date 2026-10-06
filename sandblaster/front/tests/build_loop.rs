//! The build loop in a real workspace (DESIGN.md §2.1 *Re-runs*):
//!
//! * **watched paths**: a module-mode (lifted) build asks cargo to watch
//!   only paths that exist — never the lift prelude's
//!   virtual source-map paths, never a lock that does not exist yet — so an
//!   unchanged host crate does not re-run its build script on every cargo
//!   invocation (twin: the source map does hold such paths);
//! * **determinism**: two verifications of identical inputs in different
//!   `OUT_DIR`s (another profile, feature set or dependent crate) emit
//!   byte-identical code, report and lift-conformance key (twin: a source
//!   edit changes them);
//! * **the verifier context** (`driver::cache::verifier_context`): it is
//!   the same for `cargo build`, `cargo test`, a release build and a
//!   dependent crate's build of one module (so they share one verdict —
//!   shown end to end on a lifted module), and changes with the toolchain,
//!   `rustc`, or a result-relevant `SANDBLASTER_*` variable (twins); the
//!   toolchain never branches on `debug_assertions` (why the profile is not
//!   part of it);
//! * **the shared verdict cache**: a tampered or forged entry is rejected
//!   and the module re-verified to the same bytes (and the entry repaired);
//!   with the cache off nothing is reused;
//! * **refusals**: a lifted module whose proof is left open, or which has
//!   no lock, fails the host build and emits no module.
//!
//! The lifted bodies are rustc's MIR (the fixtures `mir_fixtures/opt_mbits`
//! and `bl_mbits_edited`).
//!
//! `cargo test --release -p sandblaster-front --test build_loop -- --test-threads=1`

#[path = "gated_util.rs"]
mod gated;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sandblaster_front::driver::cache::{verifier_context, Store, NOT_IDENTITY};
use sandblaster_front::driver::{self, BuildOutcome};
use sandblaster_front::loader::{FileProvider, MemFs};
use sandblaster_front::target::TargetInfo;

const M_ROOT: &str = "sandblaster/bits/mod.rs";
const M_MODULE: &str = "src/bits.rs";

const M_DSL_ROOT: &str = r#"//! A lifted module: `bits.rs` as written.
#![forbid(unsafe_code)]

#[lift(mir = "bits.sbmir")]
mod bits;

#[cfg(sandblaster)]
#[lift]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[lift]
#[path = "PROOF.rs"]
mod proof;

pub use bits::{clamp7, low_byte};
"#;

const M_BITS: &str = include_str!("mir_fixtures/opt_mbits/bits.rs");

const M_LAWS: &str = r#"//! What `bits.rs` guarantees.
use sandblaster::prelude::*;
use crate::bits::{clamp7, low_byte};

/// `clamp7` is the value modulo 8.
#[law]
fn clamp7_low_bits(x: u8) {
    ensures(clamp7(x) as Nat == (x as Nat) % 8);
}

/// `low_byte` is the value modulo 256.
#[law]
fn low_byte_mod(x: u32) {
    ensures(low_byte(x) as Nat == (x as Nat) % 256);
}
"#;

const M_PROOF: &str = r#"//! Proofs of LAWS.rs.
use sandblaster::prelude::*;
#[allow(unused_imports)]
use crate::bits::{clamp7, low_byte};

/// By the 256 cases.
#[proof]
fn clamp7_low_bits(x: u8) {
    by_cases(x, 0..=255);
}

/// A cast truncates.
#[proof]
fn low_byte_mod(x: u32) {
    follows();
}
"#;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sandblaster-build-loop-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A build script's environment: a real, writable `OUT_DIR` (the lift
/// conformance check compiles its harness there), the target, and the
/// verdict cache in `cache` (or off).
fn env(out: &Path, cache: Option<&Path>) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = [
        ("CARGO_MANIFEST_DIR", "/host"),
        ("CARGO_CFG_TARGET_ARCH", "aarch64"),
        ("CARGO_CFG_TARGET_FEATURE", "neon,sha2,sha3,aes"),
        ("CARGO_CFG_TARGET_ENDIAN", "little"),
        ("CARGO_CFG_TARGET_POINTER_WIDTH", "64"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    m.insert("OUT_DIR".into(), out.display().to_string());
    match cache {
        Some(c) => {
            m.insert("SANDBLASTER_CACHE_DIR".into(), c.display().to_string());
            m.insert("SANDBLASTER_CACHE_KEY".into(), "build-loop test secret".into());
        }
        None => {
            m.insert("SANDBLASTER_CACHE".into(), "off".into());
        }
    }
    m
}

/// A fixture file (`tests/mir_fixtures/<path>`), when it exists.
fn fixture(path: &str) -> Option<String> {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mir_fixtures").join(path)).ok()
}

fn m_files(bits: &str) -> Vec<(String, String)> {
    // rustc's MIR of `bits.rs` (the fixture whose source it is)
    let dir = if bits == M_BITS { "opt_mbits" } else { "bl_mbits_edited" };
    assert_eq!(fixture(&format!("{dir}/bits.rs")).as_deref(), Some(bits), "a fixture of this `bits.rs`");
    let dsl = vec![
        (format!("/host/{M_ROOT}"), M_DSL_ROOT.to_string()),
        ("/host/sandblaster/bits/bits.rs".to_string(), bits.to_string()),
        ("/host/sandblaster/bits/LAWS.rs".to_string(), M_LAWS.to_string()),
        ("/host/sandblaster/bits/PROOF.rs".to_string(), M_PROOF.to_string()),
        ("/host/sandblaster/bits/bits.sbmir".to_string(), fixture(&format!("{dir}/bits.sbmir")).expect("the fixture's MIR")),
    ];
    let mut files = gated::with_accepted_lock(&dsl, &format!("/host/{M_ROOT}"), &TargetInfo::aarch64_apple_darwin()).unwrap_or_else(|e| panic!("the gates reject the test crate:\n{e}"));
    let (docs, _) = driver::lifted::split_docs(bits);
    files.push(("/host/src/lib.rs".into(), "//! A host crate.\nmod bits;\npub fn both(x: u32) -> u8 { bits::clamp7(bits::low_byte(x)) }\n".into()));
    files.push((format!("/host/{M_MODULE}"), format!("{docs}{}\n", driver::module_include_line("bits"))));
    files
}

fn memfs(files: &[(String, String)]) -> MemFs {
    MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())))
}

fn m_build(files: &[(String, String)], context: Option<&str>, e: &HashMap<String, String>) -> BuildOutcome {
    driver::build_module(M_ROOT, M_MODULE, context, &|k| e.get(k).cloned(), &memfs(files))
}

fn output<'o>(o: &'o BuildOutcome, name: &str) -> &'o str {
    o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == name)).map(|(_, c)| c.as_str()).unwrap_or_else(|| panic!("no {name}: {:?}\n{}", o.cargo, o.stderr))
}

fn watched(o: &BuildOutcome) -> Vec<String> {
    o.cargo.iter().filter_map(|l| l.strip_prefix("cargo::rerun-if-changed=")).map(str::to_string).collect()
}

/// The lift conformance key of a report (`"lift_conformance": {… "key": "…"`).
fn conformance_key(report: &str) -> String {
    let at = report.find("\"lift_conformance\"").unwrap_or_else(|| panic!("no lift_conformance in {report}"));
    let rest = &report[at..];
    let k = rest.find("\"key\": \"").unwrap() + 8;
    rest[k..k + 64].to_string()
}

/// The first line where two texts differ, both versions.
fn first_difference(a: &str, b: &str) -> String {
    let (la, lb): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    let i = (0..la.len().max(lb.len())).find(|&i| la.get(i) != lb.get(i)).unwrap_or(0);
    format!("line {}:\n  first:  {}\n  second: {}", i + 1, la.get(i).unwrap_or(&"(none)"), lb.get(i).unwrap_or(&"(none)"))
}

fn reused_cache(o: &BuildOutcome) -> bool {
    o.cargo.iter().any(|l| l.contains("reusing the verdict cache entry"))
}

/// The environment of one build context: what cargo passes a build script
/// for `cargo build` / `cargo test` / `--release` / a dependent crate
/// differs only in variables the verifier context ignores.
fn process_vars(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = [("SANDBLASTER_MEM_LIMIT_GB", "6"), ("SANDBLASTER_GOAL_TIMEOUT_MS", "30000")].iter().map(|(k, x)| (k.to_string(), x.to_string())).collect();
    for (k, x) in extra {
        v.retain(|(kk, _)| kk != k);
        v.push((k.to_string(), x.to_string()));
    }
    v
}

const RUSTC_VV: &str = "rustc 1.95.0 (0000000 2026-01-01)\nbinary: rustc\nhost: aarch64-apple-darwin\n";

// ---------------------------------------------------------------------------
// watched paths
// ---------------------------------------------------------------------------

/// Module mode (a lifted module, whose source map holds the lift
/// prelude's virtual files): every watched file exists. Twin: the source
/// map does hold paths that do not exist, which the build used to watch
/// (cargo then re-ran codec's build script on every invocation).
#[test]
fn a_lifted_module_build_watches_only_paths_that_exist() {
    let files = m_files(M_BITS);
    let fs = memfs(&files);
    let out = scratch("watch");
    let o = m_build(&files, None, &env(&out, None));
    assert!(o.ok, "{}", o.stderr);
    let w = watched(&o);
    for p in &w {
        // the two watched directories exist on disk in a real build; the
        // in-memory provider knows only files
        if p == "/host/src" || p == "/host/sandblaster/bits" {
            continue;
        }
        assert!(fs.exists(Path::new(p)), "a watched path that does not exist: `{p}` (all: {w:?})");
    }
    for f in ["/host/sandblaster/bits/bits.rs", "/host/sandblaster/bits/LAWS.rs", "/host/sandblaster/bits/PROOF.rs", "/host/sandblaster/bits/SPEC.lock"] {
        assert!(w.iter().any(|p| p == f), "`{f}` is watched: {w:?}");
    }
    // twin: the front end did read files that do not exist
    let c = driver::check(Path::new(&format!("/host/{M_ROOT}")), &fs, &TargetInfo::aarch64_apple_darwin());
    let virtual_paths: Vec<String> = c.sm.files().map(|(_, f)| f.path.display().to_string()).filter(|p| !fs.exists(Path::new(p))).collect();
    assert!(!virtual_paths.is_empty() && virtual_paths.iter().all(|p| p.starts_with("<sandblaster lift prelude>")), "{virtual_paths:?}");
    assert!(virtual_paths.iter().all(|v| !w.contains(v)), "{w:?}");
    let _ = std::fs::remove_dir_all(&out);
}

// ---------------------------------------------------------------------------
// determinism and verdict sharing
// ---------------------------------------------------------------------------

/// Two verifications of the same lifted module in different `OUT_DIR`s,
/// without any cache (every proof, gate and the lift conformance check run
/// twice): the emitted file, the report and the conformance key are
/// byte-identical, and stay so when the lift conformance check's recorded
/// pass is replayed. Twin: a source edit
/// changes the emitted file and the key, so the comparison is not vacuous.
#[test]
fn verification_output_is_deterministic() {
    let files = m_files(M_BITS);
    let ctx = verifier_context("toolchain-a", Some(RUSTC_VV), &process_vars(&[])).unwrap();
    let (d1, d2, d3) = (scratch("det-1"), scratch("det-2"), scratch("det-3"));
    let a = m_build(&files, Some(&ctx), &env(&d1.join("debug/build/x/out"), None));
    let b = m_build(&files, Some(&ctx), &env(&d2.join("release/build/y/out"), None));
    assert!(a.ok && b.ok, "{}\n{}", a.stderr, b.stderr);
    assert!(a.cargo.iter().chain(&b.cargo).all(|l| !l.contains("reusing")), "both builds verified");
    for f in ["bits.rs", "bits-report.json"] {
        assert!(output(&a, f) == output(&b, f), "{f} differs between identical builds: {}", first_difference(output(&a, f), output(&b, f)));
    }
    let key = conformance_key(output(&a, "bits-report.json"));
    assert_eq!(key, conformance_key(output(&b, "bits-report.json")));
    assert!(output(&a, "bits.rs").contains(&format!("lift conformance passed (key {})", &key[..16])), "{}", output(&a, "bits.rs"));
    // a third verification in the first `OUT_DIR` (a verdict miss, e.g.
    // after a proof edit that was undone) replays the lift conformance
    // check's recorded pass instead of running it: the same bytes again
    let record = d1.join("debug/build/x/out/bits-conformance/conformance.key");
    let recorded = std::fs::metadata(&record).and_then(|m| m.modified()).expect("the pass was recorded");
    let a2 = m_build(&files, Some(&ctx), &env(&d1.join("debug/build/x/out"), None));
    assert!(a2.ok, "{}", a2.stderr);
    assert_eq!(std::fs::metadata(&record).and_then(|m| m.modified()).unwrap(), recorded, "the recorded pass was replayed, not re-run");
    for f in ["bits.rs", "bits-report.json"] {
        assert!(output(&a, f) == output(&a2, f), "{f} differs after a replayed conformance check: {}", first_difference(output(&a, f), output(&a2, f)));
    }
    // nothing of OUT_DIR leaks into what is emitted
    for f in ["bits.rs", "bits-report.json"] {
        assert!(!output(&a, f).contains(&d1.display().to_string()), "{f} names OUT_DIR");
    }
    // twin: an edited source
    let edited = m_files(&M_BITS.replace("/// The low byte of `x`.", "/// The low byte of `x` (edited)."));
    let c = m_build(&edited, Some(&ctx), &env(&d3.join("out"), None));
    assert!(c.ok, "{}", c.stderr);
    assert_ne!(output(&c, "bits.rs"), output(&a, "bits.rs"));
    assert_ne!(conformance_key(output(&c, "bits-report.json")), key);
    for d in [d1, d2, d3] {
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// `cargo build`, `cargo test`, `cargo build --release` and a dependent
/// crate's build run the build script with different binaries, features,
/// profiles and `OUT_DIR`s, but the same verifier context: the first build
/// verifies, the others reuse its verdict from the shared cache, byte for
/// byte (a tampered entry is recomputed: `tests/verdict_cache.rs`).
#[test]
fn one_verdict_serves_every_build_context() {
    let files = m_files(M_BITS);
    let cache = scratch("share-cache");
    let dev = verifier_context("toolchain-a", Some(RUSTC_VV), &process_vars(&[])).unwrap();
    let contexts = [
        ("test", process_vars(&[("CARGO_FEATURE_STD", "1"), ("PROFILE", "debug")])),
        ("release", process_vars(&[("PROFILE", "release"), ("OPT_LEVEL", "3"), ("SANDBLASTER_MEM_LIMIT_GB", "12"), ("SANDBLASTER_GATE_WORKERS", "2")])),
        ("dependent", process_vars(&[("CARGO_PKG_NAME", "commonware-storage"), ("SANDBLASTER_CACHE_DIR", "/elsewhere")])),
    ];
    let t0 = std::time::Instant::now();
    let cold = m_build(&files, Some(&dev), &env(&cache.join("debug/out"), Some(&cache)));
    let cold_ms = t0.elapsed().as_millis();
    assert!(cold.ok && !reused_cache(&cold), "{}", cold.stderr);
    for (what, vars) in &contexts {
        let ctx = verifier_context("toolchain-a", Some(RUSTC_VV), vars).unwrap();
        assert_eq!(ctx, dev, "{what}: the same context");
        let t = std::time::Instant::now();
        let o = m_build(&files, Some(&ctx), &env(&cache.join(format!("{what}/out")), Some(&cache)));
        let ms = t.elapsed().as_millis();
        assert!(o.ok && reused_cache(&o), "{what}: {:?}\n{}", o.cargo, o.stderr);
        eprintln!("{what}: verdict reused in {ms} ms (cold build {cold_ms} ms)");
        for f in ["bits.rs", "bits-report.json", "bits-timing.json"] {
            assert_eq!(output(&o, f), output(&cold, f), "{what}: {f}");
        }
    }
    // twins: another toolchain or a result-relevant variable is another
    // context (and is not served the verdict)
    let other = verifier_context("toolchain-b", Some(RUSTC_VV), &process_vars(&[])).unwrap();
    let o = m_build(&files, Some(&other), &env(&cache.join("other/out"), Some(&cache)));
    assert!(o.ok && !reused_cache(&o), "{:?}", o.cargo);
    let _ = std::fs::remove_dir_all(&cache);
}

/// The verdict entries of the shared cache in `dir`.
fn verdict_entries(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let root = dir.join("sandblaster-cache-1").join("verdict");
    for sub in std::fs::read_dir(&root).into_iter().flatten().flatten() {
        for f in std::fs::read_dir(sub.path()).into_iter().flatten().flatten() {
            if !f.file_name().to_string_lossy().starts_with('.') {
                out.push(f.path());
            }
        }
    }
    out.sort();
    out
}

/// A tampered or forged whole-verdict entry is rejected and the module
/// re-verified to the same bytes (and the entry repaired); with the cache
/// off nothing is reused.
#[test]
fn a_tampered_cache_entry_is_rejected_and_the_module_reverified() {
    let files = m_files(M_BITS);
    let cache = scratch("tamper-cache");
    let ctx = verifier_context("toolchain-a", Some(RUSTC_VV), &process_vars(&[])).unwrap();
    let cold = m_build(&files, Some(&ctx), &env(&cache.join("a/out"), Some(&cache)));
    assert!(cold.ok && !reused_cache(&cold), "{}", cold.stderr);
    let code = output(&cold, "bits.rs").to_string();
    let entry = verdict_entries(&cache).pop().expect("the verdict was stored");
    let good = std::fs::read_to_string(&entry).unwrap();
    // an unverified body with a recomputed payload hash: the MAC rejects it
    let evil = good.replacen("STATUS: VERIFIED", "STATUS: VERIFIEd", 1);
    assert_ne!(evil, good);
    std::fs::write(&entry, &evil).unwrap();
    let o = m_build(&files, Some(&ctx), &env(&cache.join("b/out"), Some(&cache)));
    assert!(o.ok && !reused_cache(&o), "{:?}", o.cargo);
    assert!(o.cargo.iter().any(|l| l.contains("rejected")), "{:?}", o.cargo);
    assert_eq!(output(&o, "bits.rs"), code, "re-verified to the same bytes");
    // the re-verification repaired the entry
    let again = m_build(&files, Some(&ctx), &env(&cache.join("c/out"), Some(&cache)));
    assert!(again.ok && reused_cache(&again), "{:?}", again.cargo);
    // a forged entry (another secret) is rejected the same way
    let forged = Store::open(cache.clone(), sandblaster_front::surface::sha256(b"not the key"));
    let key_name = entry.file_name().unwrap().to_string_lossy().to_string();
    forged.put("verdict", &key_name, &[("code", "pub fn clamp7(x: u8) -> u8 { x }\n"), ("report", "{}"), ("timing", "{}")]).unwrap();
    let o = m_build(&files, Some(&ctx), &env(&cache.join("d/out"), Some(&cache)));
    assert!(o.ok && !reused_cache(&o) && output(&o, "bits.rs") == code, "{:?}", o.cargo);
    // the cache off: nothing is reused
    let mut off = env(&cache.join("e/out"), Some(&cache));
    off.insert("SANDBLASTER_CACHE".into(), "off".into());
    let o = m_build(&files, Some(&ctx), &off);
    assert!(o.ok && !reused_cache(&o), "{:?}", o.cargo);
    let _ = std::fs::remove_dir_all(&cache);
}

// ---------------------------------------------------------------------------
// refusals
// ---------------------------------------------------------------------------

/// Module mode's negative twins on a lifted module (the positive twins are
/// the other tests here): a law whose proof is left open, and a missing
/// lock, each fail the host build, and no module is emitted.
#[test]
fn a_failing_proof_or_gate_emits_no_module() {
    let files = m_files(M_BITS);
    let out = scratch("refuse");
    let no_module = |o: &BuildOutcome| !o.ok && !o.outputs.iter().any(|(p, _)| p.file_name().is_some_and(|f| f == "bits.rs"));
    // a proof left open (the lock still matches: only the proof fails)
    let open: Vec<(String, String)> = files.iter().map(|(p, t)| (p.clone(), if p.ends_with("PROOF.rs") { t.replace("    by_cases(x, 0..=255);\n", "    todo();\n") } else { t.clone() })).collect();
    assert_ne!(open, files);
    let o = m_build(&open, None, &env(&out, None));
    assert!(no_module(&o), "an open proof emitted the module: {:?}", o.cargo);
    assert!(o.stderr.contains("clamp7_low_bits"), "the refusal names the law:\n{}", o.stderr);
    // no lock
    let unlocked: Vec<(String, String)> = files.iter().filter(|(p, _)| !p.ends_with("SPEC.lock")).cloned().collect();
    let o = m_build(&unlocked, None, &env(&out, None));
    assert!(no_module(&o), "a crate without a lock emitted the module: {:?}", o.cargo);
    assert!(o.stderr.contains("error[spec-lock]"), "{}", o.stderr);
    let _ = std::fs::remove_dir_all(&out);
}

/// What enters the verifier context and what does not.
#[test]
fn the_verifier_context_names_what_determines_a_result() {
    let base = verifier_context("tc", Some(RUSTC_VV), &process_vars(&[])).unwrap();
    assert!(base.starts_with("sandblaster-verifier/2\ntoolchain tc\n"), "{base}");
    assert!(base.contains("overflow-checks on\n"), "this test build has overflow checks: {base}");
    assert!(base.contains("SANDBLASTER_GOAL_TIMEOUT_MS=30000\n") && !base.contains("SANDBLASTER_MEM_LIMIT_GB"), "{base}");
    // the same: resource and cache settings, cargo's per-context variables,
    // the order of the environment
    let mut same = process_vars(&[("CARGO_FEATURE_ARBITRARY", "1"), ("OUT_DIR", "/x"), ("PROFILE", "release"), ("DEBUG", "false")]);
    for k in NOT_IDENTITY {
        same.push((k.to_string(), "anything".into()));
    }
    same.reverse();
    assert_eq!(verifier_context("tc", Some(RUSTC_VV), &same).unwrap(), base);
    // twins: the toolchain, rustc, a result-relevant variable
    assert_ne!(verifier_context("tc2", Some(RUSTC_VV), &process_vars(&[])).unwrap(), base);
    assert_ne!(verifier_context("tc", Some("rustc 1.96.0\n"), &process_vars(&[])).unwrap(), base);
    assert_ne!(verifier_context("tc", None, &process_vars(&[])).unwrap(), base);
    assert_ne!(verifier_context("tc", Some(RUSTC_VV), &process_vars(&[("SANDBLASTER_GOAL_TIMEOUT_MS", "1")])).unwrap(), base);
    assert_ne!(verifier_context("tc", Some(RUSTC_VV), &process_vars(&[("SANDBLASTER_X_SIGMA", "1")])).unwrap(), base);
    // no toolchain identity: nothing is reused
    assert_eq!(verifier_context("", Some(RUSTC_VV), &process_vars(&[])), None);
    assert_eq!(verifier_context("  ", Some(RUSTC_VV), &process_vars(&[])), None);
}

/// The profile (`debug_assertions`) is not part of the context because the
/// toolchain never branches on it: its `debug_assert!`s can only add a
/// panic, and a failed build stores nothing. This scan keeps that true
/// (twin: the scanner finds a `cfg!(debug_assertions)`).
#[test]
fn the_toolchain_never_branches_on_debug_assertions() {
    fn branches(text: &str) -> bool {
        // code only: `//` comments (docs included) may mention the cfg
        let code: String = text.lines().map(|l| l.split("//").next().unwrap_or("")).collect::<Vec<_>>().join("\n");
        let t: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        ["cfg!(debug_assertions", "cfg(debug_assertions", "cfg(not(debug_assertions", "cfg_attr(debug_assertions"].iter().any(|p| t.contains(p))
    }
    fn scan(dir: &Path, hits: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                scan(&p, hits);
            } else if p.extension().is_some_and(|x| x == "rs") && branches(&std::fs::read_to_string(&p).unwrap()) {
                hits.push(p);
            }
        }
    }
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut hits = Vec::new();
    for d in ["front/src", "kernel/src", "targets/src", "memguard/src", "sandblaster/src"] {
        scan(&base.join(d), &mut hits);
    }
    assert!(hits.is_empty(), "the toolchain branches on debug_assertions (make the profile part of the verifier context): {hits:?}");
    assert!(branches("if cfg!( debug_assertions ) { 1 } else { 2 }") && branches("#[cfg(not(debug_assertions))]\nfn f() {}"));
    assert!(!branches("let _ = format!(\"#[cfg({})]\", \"debug_assertions\");\n/// never `cfg(debug_assertions)`\n"));
}
