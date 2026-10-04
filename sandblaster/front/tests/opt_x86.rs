//! QMDB optimized for `x86_64-apple-darwin` (test-only exec-only path), on
//! both instance roots: `n1.rs` (N = 1, the pinned fixtures) and `mod.rs`
//! (N = 32, the production instance, `sandblaster/fixtures/qmdb/fixtures-n32`).
//! `compress_shani` is elaborated against the SHA-NI core models and its
//! `VariantEquiv` is kernel-proven; its models are validated natively on the
//! Zen 5 CPU of AVX-512 host round 0 (`sandblaster-targets/evidence/x86_64.json`,
//! DESIGN.md §9.2), so it forms the variant set `{sha_sse2_ssse3_sse4_1}`:
//! every caller up to `verify` is cloned (kernel-checked equal) and the
//! boundary dispatches — statically when the features are enabled at compile
//! time, else by `is_x86_feature_detected!`, else the portable code. The
//! public API of the output is the source's. The output is compiled for
//! x86_64 and, where the host can run it, run on every fixture of the
//! instance; under Rosetta 2, which has no SHA-NI, the run-time check must
//! pick the portable path. A variant whose evidence is withheld
//! (`evidence::withhold`) is still left out of the emitted code (fail closed).

mod common;

#[path = "common/qmdb.rs"]
mod qmdb;
#[path = "common/api.rs"]
mod api;

use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

use common::*;
use sandblaster_front::driver;
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::{MemFs, RealFs};
use sandblaster_front::opt::{OptOptions, Outcome};
use sandblaster_front::target::TargetInfo;
use sandblaster_targets::evidence;
use sandblaster_targets::registry::Arch as evidence_arch;

/// One QMDB elaboration at a time in this process (each needs a few GB).
static HEAVY: Mutex<()> = Mutex::new(());

/// The SHA-NI intrinsic models `compress_shani` calls.
const SHA_NI_MODELS: &[&str] = &["_mm_sha256rnds2_epu32", "_mm_sha256msg1_epu32", "_mm_sha256msg2_epu32"];

/// The variant set of `compress_shani` (named after its feature list).
const SET: &str = "sha_sse2_ssse3_sse4_1";

/// Every variant set of the x86 emission when the feature-only sets have
/// host evidence, in dispatch preference order (plan O8): `v4`
/// (feature-only, with the SHA-NI variant), SHA-NI with the feature-only
/// `v3_scalar` features, SHA-NI alone, `v3_scalar` alone.
const SETS: [&str; 4] = ["v4", "sha_sse2_ssse3_sse4_1_v3", SET, "v3_scalar"];

/// The feature-only sets of the x86 emission.
const FEATURE_ONLY: [&str; 3] = ["v4", "sha_sse2_ssse3_sse4_1_v3", "v3_scalar"];

/// The N = 1 instance with the feature-only sets' host evidence granted (a
/// test hook: no host has run them yet), so the whole feature-only pipeline
/// runs: evidence, pricing before cloning, clones, lemmas, dispatch and
/// self-test.
#[test]
fn qmdb_x86_64_sha_ni_is_proven_and_dispatched() {
    // the N = 1 instance: the pinned N = 1 fixtures
    x86_instance("n1.rs", "opt-qmdb-x86_64", "sandblaster/fixtures/qmdb/fixtures", "fixtures 32 accepted 29", true, |code| {
        assert!(code.contains("pub(crate) const CHUNK_BYTES: usize = 1usize;"), "N = 1 chunks");
    });
}

/// The production instance (N = 32) on x86_64: the strict optimizer, the
/// SHA-NI variant (proven, dispatched), the round trip of the 32-byte
/// kernels (`hash_32` partial-chunk digest, `hash_64` graft) and every
/// `sandblaster/fixtures/qmdb/fixtures-n32` proof under Rosetta (portable path).
#[test]
fn qmdb_n32_x86_64_production_instance() {
    x86_instance("mod.rs", "opt-qmdb-n32-x86_64", "sandblaster/fixtures/qmdb/fixtures-n32", "fixtures 490 accepted 245", false, |code| {
        assert!(code.contains("pub(crate) const CHUNK_BYTES: usize = 32usize;") && code.contains("l1_chunk: &[u8; 32usize]"), "N = 32 chunks");
        // (the modules are private since §15 S5: the re-exports of `config`
        // are printed crate-visible, like the module itself)
        assert!(code.contains("pub(crate) use crate::__sandblaster::sha256::hash_32 as hash_chunk;") && code.contains("pub(crate) use crate::__sandblaster::sha256::hash_64 as hash_graft;"), "config re-exports");
    });
}

/// A `pub use` of a function the evidence gate leaves out follows its
/// target: it is not printed, and the round trip reports it as a public
/// API difference (not a failure, like the target itself). Every x86_64
/// model is validated now, so the SHA-NI models' evidence is withheld for
/// this build (`evidence::withhold`, downgrade only; process-wide, so it is
/// taken under `HEAVY`, which every QMDB build of this binary holds).
#[test]
fn a_reexport_of_a_not_emitted_variant_is_an_api_difference() {
    let _g = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let _withheld = evidence::withhold(evidence_arch::X86_64, SHA_NI_MODELS);
    // the production sources (every file the root mounts: `qmdb::crate_files`)
    // with `verifier` public again (its layout before §15 S5 made the
    // modules private; the §15.8 boundary gate, not run here, refuses it)
    // and re-exporting the SHA-NI variant: a public re-export outside the
    // root's `pub use` list
    let mut files = qmdb::crate_files("mod.rs");
    let root_text = qmdb::entry(&mut files, "mod.rs");
    assert!(root_text.contains("\nmod verifier;\n"));
    *root_text = root_text.replacen("\nmod verifier;\n", "\npub mod verifier;\n", 1);
    qmdb::entry(&mut files, "verifier.rs").push_str("\n#[cfg(all(target_arch = \"x86_64\", target_endian = \"little\"))]\npub use super::sha256::compress_shani as compress_fast;\n");
    let fs = MemFs::from_files(files.iter().map(|(p, t)| (p.as_str(), t.as_str())));
    let root = files[0].0.clone();
    let c = driver::check(Path::new(&root), &fs, &TargetInfo::x86_64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    assert!(c.reexports.iter().any(|r| r.name == "compress_fast"), "{:?}", c.reexports);
    let k = c.krate.as_ref().unwrap();
    let em = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        driver::stage::optimize_emit_mode(&c, &mut out, &root, "", &OptOptions { strict: true, ..Default::default() }, true).unwrap()
    });
    assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
    assert!(em.opt.not_emitted.iter().any(|(f, _)| f.ends_with("compress_shani")), "{:?}", em.opt.not_emitted);
    assert!(em.roundtrip.is_empty(), "{:?}", em.roundtrip);
    let d = &em.roundtrip_stats.api_differences;
    assert!(d.len() == 1 && d[0].contains("crate::verifier::compress_fast") && d[0].contains("crate::sha256::compress_shani"), "{d:?}");
    assert!(!em.code.contains("compress_fast"), "the re-export of a not-emitted function is printed");
    // the config re-exports are still printed and compared
    assert_eq!(em.roundtrip_stats.reexports, 2, "{:?}", em.roundtrip_stats);
}

/// Elaborates (exec only) and optimizes (strict) `sandblaster/fixtures/qmdb/sandblaster/<root>`
/// for x86_64, checks what every x86_64 instance must satisfy, then `code`
/// on the emitted text; compiles it for x86_64 and runs every fixture of
/// `fixtures` (the summary line must start with `expect`) where the host
/// can execute x86_64 code. `granted`: the feature-only sets' host evidence
/// is granted by a test hook; otherwise the committed evidence decides
/// (no host has run them: they are not generated, fail closed).
fn x86_instance(root: &str, tmp_name: &str, fixtures: &str, expect: &str, granted: bool, code: impl Fn(&str) + Send + Sync) {
    let _g = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let rel = format!("sandblaster/fixtures/qmdb/sandblaster/{root}");
    let root_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(&rel);
    let target = TargetInfo::x86_64_apple_darwin();
    let c = driver::check(&root_path, &RealFs, &target);
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let em = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let hooks = granted.then(|| std::sync::Arc::new(sandblaster_front::opt::hooks::OptTestHooks { set_evidence: FEATURE_ONLY.iter().map(|s| s.to_string()).collect(), ..Default::default() }));
        driver::stage::optimize_emit_mode(&c, &mut out, &rel, "", &OptOptions { strict: true, hooks, ..Default::default() }, true).unwrap()
    });
    let o = &em.opt;
    let sets: Vec<&str> = if granted { SETS.to_vec() } else { vec![SET] };
    for v in &o.variants {
        println!("variant {}: equivalence {:?}; dispatched {}; {}", v.variant, v.equivalence.as_ref().map(|x| &x.0), v.dispatched, v.note);
        for (m, s) in &v.evidence {
            println!("    {m}: {s}");
        }
    }
    for st in &o.sets {
        println!("set {{{}}}: {:?}", st.name, st.feature_set);
    }
    for d in &o.dispatchers {
        println!("dispatcher {} -> {:?}", d.name, d.variants.iter().map(|(st, i)| format!("{}:{}", st.name, o.print.item(*i).path)).collect::<Vec<_>>());
    }
    let specialized: Vec<&str> = o.fns.iter().filter(|r| matches!(r.outcome, Outcome::Specialized { .. })).map(|r| r.name.as_str()).collect();
    println!("{}/{} specialized: {specialized:?}", specialized.len(), o.fns.len());
    assert!(o.errors.is_empty(), "{:?}", o.errors);
    assert!(em.roundtrip.is_empty(), "{:?}", em.roundtrip);
    // VariantEquiv is kernel-checked, every model is validated on hardware
    // (the SHA-NI ones natively on Zen 5), and the variant is dispatched
    let shani = o.variants.iter().find(|v| v.variant.ends_with("compress_shani")).expect("compress_shani");
    assert!(shani.equivalence.is_ok(), "VariantEquiv(compress_shani, compress) not proven: {shani:?}");
    assert!(shani.dispatched, "SHA-NI must be dispatched: {shani:?}");
    assert!(!shani.evidence.is_empty() && shani.evidence.iter().all(|(_, st)| st == "validated (native)"), "{:?}", shani.evidence);
    for m in SHA_NI_MODELS {
        assert!(shani.evidence.iter().any(|(n, _)| n == m), "{m} not among {:?}", shani.evidence);
    }
    assert!(o.not_emitted.is_empty(), "{:?}", o.not_emitted);
    // the variant sets (the SHA-NI set and the plan O8 feature-only sets),
    // their clones kernel-checked equal to the originals, and a boundary
    // dispatcher for `verify` trying them in preference order
    let names: Vec<&str> = o.sets.iter().map(|st| st.name.as_str()).collect();
    assert_eq!(names, sets, "the variant sets");
    if !granted {
        // plan O8 with host evidence: no host has run the feature-only sets'
        // clones, so they are not generated (and never dispatched)
        for st in FEATURE_ONLY {
            assert!(o.not_cloned.iter().any(|(f, set, why)| f == "*" && set == st && why.contains("no host evidence")), "{st}: {:?}", o.not_cloned);
        }
        assert!(!em.code.contains("kat_v3_scalar") && !em.code.contains("__v4(") && !em.code.contains("has_v3_scalar"), "a feature-only set without host evidence is emitted");
    }
    let sha = o.sets.iter().find(|st| st.name == SET).unwrap();
    for f in ["sha", "sse2", "ssse3", "sse4.1"] {
        assert!(sha.feature_set.iter().any(|x| x == f), "{f} not in {:?}", sha.feature_set);
    }
    for st in &o.sets {
        let n = o.clones.iter().filter(|cl| cl.set == st.name).count();
        // the SHA-NI sets clone every caller of `compress`; `v3_scalar` the
        // callers of the bit-count users (`shape`, …) up to `verify`
        let min = if st.name == "v3_scalar" { 5 } else { 30 };
        assert!(n >= min, "{}: {n} clones", st.name);
        assert!(o.clones.iter().any(|cl| cl.set == st.name && cl.clone == format!("crate::verifier::verify__{}", st.name)), "{}: no clone of verify", st.name);
    }
    assert!(o.clones.iter().all(|cl| sets.contains(&cl.set.as_str()) && cl.related.is_ok() && cl.lemma.is_some()), "{:?}", o.clones);
    let verify = o.dispatchers.iter().find(|d| d.name == "verify").expect("a dispatcher for `verify`");
    assert_eq!(verify.variants.iter().map(|(st, _)| st.name.as_str()).collect::<Vec<_>>(), sets, "verify's dispatch order");
    // plan O8: `shape`'s feature-only clones exist
    for st in ["v4", "v3_scalar"].into_iter().filter(|_| granted) {
        assert!(o.clones.iter().any(|cl| cl.clone == format!("crate::merkle::shape__{st}")), "no shape__{st}");
    }
    // the fixed-shape kernels are specialized: both compressions, and the
    // hashes above them per variant (portable and SHA-NI clone)
    let mut kernels = vec!["crate::sha256::compress".to_string(), "crate::sha256::compress_shani".to_string()];
    for f in ["crate::sha256::hash_64", "crate::merkle::node_digest", "crate::merkle::leaf_digest"] {
        kernels.extend([f.to_string(), format!("{f}__{SET}")]);
    }
    for name in &kernels {
        assert!(specialized.contains(&name.as_str()), "{name} not specialized");
    }
    // the emitted `verify`: the SHA-NI clone statically when its features
    // are enabled, else after the run-time check, else the portable code
    for needle in [
        format!("return unsafe {{ crate::__sandblaster::verifier::verify__{SET}(a0__arg, a1__arg, a2__arg, a3__arg) }};"),
        format!("if crate::__sandblaster::__dispatch::has_{SET}() {{"),
        "crate::__sandblaster::verifier::verify__portable(a0__arg, a1__arg, a2__arg, a3__arg)".to_string(),
        "::std::arch::is_x86_feature_detected!(\"sha\")".to_string(),
        "#[target_feature(enable = \"sha,sse2,ssse3,sse4.1\")]".to_string(),
        // plan O8: the known-answer self-test, run inside the cached detection
        format!("&& unsafe {{ kat_{SET}() }}"),
    ] {
        assert!(em.code.contains(&needle), "missing from the emitted code: {needle}");
    }
    // the feature-only sets' self-test and clones (with host evidence)
    for needle in ["::core::hint::black_box(::core::arch::x86_64::_lzcnt_u64(one)) == 63u64", "#[target_feature(enable = \"popcnt,lzcnt,bmi1,bmi2\")]"] {
        assert_eq!(em.code.contains(needle), granted, "{needle}");
    }
    for m in SHA_NI_MODELS {
        assert!(em.code.contains(&format!("::core::arch::x86_64::{m}(")), "{m} not emitted");
    }
    // the public API is the source's (nothing is left out)
    let src = api::source_api(&root_path, &api::disk, &target);
    let out = api::generated_api(&em.code, &target);
    assert_eq!(src, out, "{root}: the generated public API differs from the source's:\n{}", api::diff(&src, &out));
    // the public API is the root's `pub use` list (§15.8: the modules are
    // private, so the SHA-NI variant is emitted but not public)
    for f in ["verify", "verify_fixed", "Digest"] {
        assert!(out.iter().any(|e| e.path == f), "{f} missing from the generated API: {out:?}");
    }
    assert!(!out.iter().any(|e| e.path.contains("::")), "a module path is public: {out:?}");
    code(&em.code);
    // compile for x86_64; run the fixtures if the host can execute it
    let dir = tmp(tmp_name);
    std::fs::write(dir.join("sandblaster.rs"), &em.code).unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let main = format!(
        r#"include!({gen:?});
#[allow(dead_code)]
#[path = {fx:?}]
mod fixture;
fn main() {{
    let files = fixture::fixture_files(std::path::Path::new({dir:?})).unwrap();
    let mut n = 0;
    let mut accepted = 0;
    for f in &files {{
        let fx = fixture::load_fixture(f.to_str().unwrap(), None).unwrap();
        let b = fx.bytes();
        let got = verify(&b.root, &b.key, &b.value, &b.proof);
        assert_eq!(got, fx.expected, "{{}}", fx.name_lossy());
        n += 1;
        accepted += usize::from(got);
    }}
    println!("fixtures {{n}} accepted {{accepted}}");
    // the dispatcher's run-time decision agrees with the CPU
    let dispatch = crate::__sandblaster::__dispatch::has_{set}();
    let cpu = std::arch::is_x86_feature_detected!("sha") && std::arch::is_x86_feature_detected!("sse2") && std::arch::is_x86_feature_detected!("ssse3") && std::arch::is_x86_feature_detected!("sse4.1");
    assert_eq!(dispatch, cpu);
    println!("dispatch {set} {{dispatch}}");
{v3check}}}
"#,
        gen = dir.join("sandblaster.rs"),
        fx = repo.join("sandblaster/fixtures/qmdb/baseline/src/fixture.rs"),
        dir = repo.join(fixtures),
        set = SET,
        // plan O8: the feature-only set, when generated (its self-test passes
        // wherever the CPU reports the features)
        v3check = if granted {
            r#"    let v3 = crate::__sandblaster::__dispatch::has_v3_scalar();
    let cpu3 = std::arch::is_x86_feature_detected!("popcnt") && std::arch::is_x86_feature_detected!("lzcnt") && std::arch::is_x86_feature_detected!("bmi1") && std::arch::is_x86_feature_detected!("bmi2");
    assert_eq!(v3, cpu3);
    println!("dispatch v3_scalar {v3}");
"#
        } else {
            ""
        },
    );
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let st = Command::new("rustc")
        .env("CARGO_MANIFEST_DIR", repo.join("sandblaster/fixtures/qmdb/baseline"))
        .args(["--edition", "2024", "--target", "x86_64-apple-darwin", "-C", "overflow-checks=on", "-C", "debug-assertions=on", "--cap-lints", "warn", "-o"])
        .arg(dir.join("qmdb_x86"))
        .arg(dir.join("main.rs"))
        .output()
        .expect("rustc");
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    match Command::new(dir.join("qmdb_x86")).output() {
        Ok(run) if run.status.success() => {
            let out = String::from_utf8_lossy(&run.stdout);
            println!("{out}");
            assert!(out.starts_with(expect), "{out}");
            let dispatch = out.lines().find_map(|l| l.strip_prefix(&format!("dispatch {SET} "))).expect("the dispatch line");
            if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
                // x86_64 code runs under Rosetta 2 here, which has no SHA-NI:
                // the dispatcher must pick the portable path
                assert_eq!(dispatch, "false", "under Rosetta 2 the SHA-NI clone must not be selected");
            }
        }
        Ok(run) => panic!("{}", String::from_utf8_lossy(&run.stderr)),
        Err(e) => eprintln!("cannot run x86_64 binaries on this host ({e}); compiled only"),
    }
}
