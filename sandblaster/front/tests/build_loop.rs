//! The build loop in a real workspace (DESIGN.md §2.1 *Re-runs*):
//!
//! * **watched paths**: a module-mode (lifted) or crate-mode build asks
//!   cargo to watch only paths that exist — never the lift prelude's
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
//! * **the optimizer's summary** states why each kept function kept its
//!   source text.
//!
//! The lifted bodies are rustc's MIR (the fixtures `mir_fixtures/opt_mbits`,
//! shared with tests/lift_opt.rs, and `bl_mbits_edited`), and so are those
//! the lifted round trip reads back (`rt.sbmir`, extracted from the copy a
//! build writes, `OUT_DIR/bits-roundtrip__bits.rs`).
//!
//! `cargo test --release -p sandblaster-front --test build_loop -- --test-threads=1`

#[path = "gated_util.rs"]
mod gated;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sandblaster_front::driver::cache::{verifier_context, NOT_IDENTITY};
use sandblaster_front::driver::lowered::{LowerOutcome, LowerRecord, LoweredModule};
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
    // rustc's MIR of `bits.rs` and of the round trip's copy (the fixture
    // whose source it is)
    let dir = if bits == M_BITS { "opt_mbits" } else { "bl_mbits_edited" };
    assert_eq!(fixture(&format!("{dir}/bits.rs")).as_deref(), Some(bits), "a fixture of this `bits.rs`");
    let mut dsl = vec![
        (format!("/host/{M_ROOT}"), M_DSL_ROOT.to_string()),
        ("/host/sandblaster/bits/bits.rs".to_string(), bits.to_string()),
        ("/host/sandblaster/bits/LAWS.rs".to_string(), M_LAWS.to_string()),
        ("/host/sandblaster/bits/PROOF.rs".to_string(), M_PROOF.to_string()),
        ("/host/sandblaster/bits/bits.sbmir".to_string(), fixture(&format!("{dir}/bits.sbmir")).expect("the fixture's MIR")),
    ];
    if let Some(rt) = fixture(&format!("{dir}/rt.sbmir")) {
        dsl.push(("/host/sandblaster/bits/bits.roundtrip__bits.sbmir".to_string(), rt));
    }
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
    let mut v: Vec<(String, String)> = [("SANDBLASTER_MEM_LIMIT_GB", "6"), ("SANDBLASTER_STRICT_OPT", "0")].iter().map(|(k, x)| (k.to_string(), x.to_string())).collect();
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

/// Crate mode: a lock that does not exist yet is not watched (its
/// creation changes the watched root directory); once it exists it is.
#[test]
fn crate_mode_watches_the_lock_only_once_it_exists() {
    let root = "sandblaster/prog/mod.rs";
    let src = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n/// Doubles, wrapping.\npub fn twice(x: u8) -> u8 {\n    x.wrapping_mul(2)\n}\n";
    let files = vec![("/host/src/lib.rs".to_string(), format!("{}\n", driver::LIB_RS_LINE)), (format!("/host/{root}"), src.to_string())];
    let out = scratch("crate-watch");
    let e = env(&out, None);
    let lock = "/host/sandblaster/prog/SPEC.lock".to_string();
    let o = driver::build_verified_with(root, None, &|k| e.get(k).cloned(), &memfs(&files));
    let w = watched(&o);
    assert!(w.contains(&format!("/host/{root}")) && w.contains(&"/host/sandblaster/prog".to_string()), "{w:?}");
    assert!(!w.contains(&lock), "a missing lock is not watched: {w:?}");
    // twin: with the lock present it is watched
    let mut with_lock = files.clone();
    with_lock.push((lock.clone(), "sandblaster-spec-lock/1\n".into()));
    let o = driver::build_verified_with(root, None, &|k| e.get(k).cloned(), &memfs(&with_lock));
    assert!(watched(&o).contains(&lock), "{:?}", watched(&o));
    let _ = std::fs::remove_dir_all(&out);
}

// ---------------------------------------------------------------------------
// determinism and verdict sharing
// ---------------------------------------------------------------------------

/// Two verifications of the same lifted module in different `OUT_DIR`s,
/// without any cache (every proof, gate, the lift conformance check, the
/// optimizer and the lowering run twice): the emitted file, the report and
/// the conformance key are byte-identical, and stay so when the lift
/// conformance check's recorded pass is replayed. Twin: a source edit
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
    if std::env::var_os("SANDBLASTER_DUMP_ROUNDTRIP_COPIES").is_some()
        && let Some((_, t)) = c.outputs.iter().find(|(p, _)| p.ends_with("bits-roundtrip__bits.rs"))
    {
        std::fs::write(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mir_fixtures/bl_mbits_edited/rt.rs"), t).unwrap();
    }
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

/// What enters the verifier context and what does not.
#[test]
fn the_verifier_context_names_what_determines_a_result() {
    let base = verifier_context("tc", Some(RUSTC_VV), &process_vars(&[])).unwrap();
    assert!(base.starts_with("sandblaster-verifier/2\ntoolchain tc\n"), "{base}");
    assert!(base.contains("overflow-checks on\n"), "this test build has overflow checks: {base}");
    assert!(base.contains("SANDBLASTER_STRICT_OPT=0\n") && !base.contains("SANDBLASTER_MEM_LIMIT_GB"), "{base}");
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
    assert_ne!(verifier_context("tc", Some(RUSTC_VV), &process_vars(&[("SANDBLASTER_STRICT_OPT", "1")])).unwrap(), base);
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

// ---------------------------------------------------------------------------
// the optimizer's summary
// ---------------------------------------------------------------------------

fn kept(f: &str, why: &str) -> LowerRecord {
    LowerRecord { function: f.into(), outcome: LowerOutcome::Kept(why.into()) }
}

/// The summary counts the kept functions by their real reason, most
/// frequent first; a rewritten module says how many were rewritten.
#[test]
fn the_optimizer_summary_states_why_functions_were_kept() {
    // the reasons exactly as `driver::lowered` states them
    let generic = "a generic function with buffer state (the dispatch call does not thread the state yet; FRICTION)";
    let reader = "a parameter with state other than one `&mut impl Buf`, or one `&mut impl BufMut` of a function without a result: lowering of that state passing is not built yet";
    let low = LoweredModule {
        records: vec![
            kept("crate::v::a", generic),
            kept("crate::v::b", generic),
            kept("crate::v::c", generic),
            kept("crate::v::d", reader),
            kept("crate::v::e", "the residual is not 3% cheaper than the source (portable model: 10 vs 10 milli-cycles)"),
            kept("crate::v::f", "the residual is not 3% cheaper than the source (portable model: 7 vs 7 milli-cycles)"),
            kept("crate::v::g", "not specialized: symbolic execution failed: a loop"),
            kept("crate::v::h", "a method"),
        ],
        ..Default::default()
    };
    let s = driver::gates::lowering_note(&low);
    assert_eq!(
        s,
        "optimized: none of the 8 source function(s) rewritten, the source is emitted as-is; source kept: 3 generic with buffer state (the per-type dispatch does not thread the state yet), 2 residual not 3% cheaper, 1 methods (receivers are not lowered yet), 1 not specialized (symbolic execution failed), 1 other state passing (`&mut` or `dyn` parameters, two buffers, a `BufMut` writer with a result; lowering not built yet)"
    );
    // twins: the old wording blamed every kept function on its residual,
    // and later called generic and `Buf` reader lowering unbuilt (both are
    // built: per-type dispatch, reader lowering)
    assert!(!s.contains("is cheaper and printable"));
    assert!(!s.contains("needs a per-type dispatch the lift reads") && !s.contains("`impl Buf` readers"), "{s}");
    // every generic refusal of `driver::lowered` has its class
    assert_eq!(
        driver::gates::kept_reason_class("a generic function without a by-value parameter of type `T` (the dispatch needs one as its receiver; FRICTION)"),
        "generic without a by-value parameter of its type (the per-type dispatch needs one as its receiver)"
    );
    for why in ["a generic function whose parameter is not bounded by one trait", "a generic function with other than one type parameter bounded by one trait"] {
        assert_eq!(driver::gates::kept_reason_class(why), "generic beyond one type parameter bounded by one trait (no per-type dispatch)");
    }
    // a generic function's failed instance is classed by the instance's reason, not per type
    assert_eq!(
        driver::gates::kept_reason_class("instance `u16`: the residual is not 3% cheaper than the source (portable model: 9 vs 9 milli-cycles)"),
        "generic instance: residual not 3% cheaper"
    );
    assert_eq!(driver::gates::kept_reason_class("instance `u8`: not specialized: a loop"), "generic instance: not specialized (a loop)");
    // a rewritten module
    let mut low2 = low.clone();
    low2.records.push(LowerRecord { function: "crate::v::z".into(), outcome: LowerOutcome::Lowered { rung: "Driven".into(), cost_source: 10, cost_residual: 5, helpers: vec![], via: String::new() } });
    low2.compared = 2;
    let s2 = driver::gates::lowering_note(&low2);
    assert!(s2.starts_with("optimized: 1 of 9 source function(s) rewritten to their residuals (lifted round trip: 2 definition(s) compared); source kept: 3 generic with buffer state"), "{s2}");
    // an unknown reason is shown up to its details
    assert_eq!(driver::gates::kept_reason_class("the source already uses the name `x`"), "the source already uses the name `x`");
    assert_eq!(driver::gates::kept_reason_class("the residual cannot be printed as Rust: a loop"), "residual not printable as Rust");
    // a whole-step failure is named
    let low3 = LoweredModule { note: Some("no crate".into()), ..Default::default() };
    assert_eq!(driver::gates::lowering_note(&low3), "optimized: none of the 0 source function(s) rewritten, the source is emitted as-is; nothing lowered: no crate");
}
