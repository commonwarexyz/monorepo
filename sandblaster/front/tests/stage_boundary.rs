//! The stage boundary (DESIGN.md §15.8): stage output — the toolchain's own
//! runs (`driver::stage`), which skip the §15 gates — can never pass for a
//! crate verdict.
//!
//! * Stage output carries `STATUS: STAGE OUTPUT (…)`, never `VERIFIED`.
//! * Every consumer of crate output in the repository (the `build.rs` files
//!   that copy a generated file into another crate) refuses stage output
//!   and output modified for testing, and accepts a crate verdict's header;
//!   the optimizer corpus's harness (`cgen`) accepts exactly the corpus
//!   root's stage output and nothing else. Each `build.rs` is compiled with
//!   rustc and run as cargo would run it.
//! * The report of a stage run never says `VERIFIED`.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::*;
use sandblaster_front::driver::{self, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::target::TargetInfo;

const SRC: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\npub fn f(x: u8) -> u8 { x ^ 1 }\n";

/// The optimized stage output of a one-function crate printed as if from
/// `root_display` (so that the consumers' root checks pass and only the
/// status line decides).
fn stage_output(root_display: &str) -> String {
    let fs = MemFs::from_files([("r/mod.rs", SRC)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let built = driver::stage::verify_and_optimize(&c, &VerifyOptions::default(), &OptOptions::default(), root_display);
    assert!(built.v.proofs_ok, "{}", built.v.diags.render(&c.sm));
    let em = built.emit.unwrap().unwrap();
    assert!(em.roundtrip.is_empty(), "{:?}", em.roundtrip);
    em.code
}

fn with_status(code: &str, status: &str) -> String {
    let mut lines: Vec<&str> = code.lines().collect();
    lines[1] = status;
    lines.join("\n") + "\n"
}

#[test]
fn stage_output_and_reports_never_claim_a_verdict() {
    let code = stage_output("r/mod.rs");
    assert_eq!(code.lines().nth(1), Some("// STATUS: STAGE OUTPUT (not a crate verdict: the §15 gates did not run)"));
    assert!(!code.contains("VERIFIED"), "{}", &code[..400.min(code.len())]);
    let fs = MemFs::from_files([("r/mod.rs", SRC)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    let built = driver::stage::verify_and_optimize(&c, &VerifyOptions::default(), &OptOptions::default(), "r/mod.rs");
    let report = driver::stage::report_json(&c, &built.v, &built.law_audit, "r/mod.rs", built.emit.as_ref().and_then(|r| r.as_ref().ok()), Some(&built.spec), Some(&built.spec15));
    assert!(report.contains("\"status\": \"PROOFS CHECKED (stage run, no crate verdict: the §15 gates did not run)\""), "{report}");
    assert!(!report.contains("\"status\": \"VERIFIED"), "{report}");
    assert!(driver::stage::summary(&c, &built.v).contains("status: PROOFS CHECKED (stage run"));
    // the unoptimized stage print too
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions::default());
    let text = driver::stage::emit_stage(&c, &v, "r/mod.rs").unwrap();
    assert_eq!(text.lines().nth(1), Some("// STATUS: STAGE OUTPUT (not a crate verdict: the §15 gates did not run)"));
    // and the crate path, on the same crate, has no verdict: it fails the
    // boundary gate (an exec function at the root) and has no lock
    let b = driver::build_crate(&c, driver::LockUse::Enforce, "r/mod.rs");
    assert!(b.verdict.is_none() && b.permit.is_none());
    assert!(b.report.contains("\"status\": \"NOT VERIFIED\""), "{}", b.report);
}

/// One consumer: a `build.rs`, the variable naming the generated file, and
/// the DSL root its header must name.
struct Consumer {
    build_rs: &'static str,
    var: &'static str,
    root: &'static str,
    /// Accepts the stage output of its root (only the corpus harness).
    stage: bool,
}

// The QMDB port's consumers (its benchmark, oracle and host-kit crates, and
// tools/asmcheck) stayed behind in the toolchain's previous repository when
// it moved into the monorepo; the consumers left are the ones in this tree.
const CONSUMERS: &[Consumer] = &[
    Consumer { build_rs: "bench/opt-corpus/cgen/build.rs", var: "OPT_CORPUS_GENERATED_RS", root: "tests/opt_corpus/dsl/mod.rs", stage: true },
];

/// The toolchain's directory (`sandblaster/` in the monorepo).
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Compiles a `build.rs` into a binary.
fn compile(c: &Consumer, dir: &Path) -> PathBuf {
    let bin = dir.join("build-script");
    let out = Command::new("rustc").args(["--edition", "2024", "--cap-lints", "allow", "-o"]).arg(&bin).arg(repo().join(c.build_rs)).env("CARGO_PKG_NAME", "consumer").output().expect("rustc");
    assert!(out.status.success(), "{} does not compile:\n{}", c.build_rs, String::from_utf8_lossy(&out.stderr));
    bin
}

/// Runs the compiled build script on `text` (as the generated file);
/// `true` when it accepted it (exit 0 and `OUT_DIR` written).
fn accepts(c: &Consumer, bin: &Path, dir: &Path, text: &str) -> bool {
    let generated = dir.join("gen.rs");
    std::fs::write(&generated, text).unwrap();
    let out_dir = dir.join("out");
    let _ = std::fs::remove_dir_all(&out_dir);
    std::fs::create_dir_all(&out_dir).unwrap();
    let st = Command::new(bin).env(c.var, &generated).env("OUT_DIR", &out_dir).env("CARGO_MANIFEST_DIR", dir).env_remove("QMDB_ALLOW_TEST_ONLY").output().unwrap();
    let written = std::fs::read_dir(&out_dir).unwrap().next().is_some();
    st.status.success() && written
}

#[test]
fn every_consumer_of_crate_output_refuses_stage_and_modified_output() {
    for c in CONSUMERS {
        let dir = tmp(&format!("stage-boundary-{}", c.build_rs.replace('/', "-")));
        let bin = compile(c, &dir);
        let stage = stage_output(&format!("/repo/sandblaster/front/{}", c.root));
        let verdict_header = with_status(&stage, "// STATUS: VERIFIED + OPTIMIZED (phase 3): every definition was elaborated to core and checked by the");
        let modified = with_status(&stage, "// STATUS: MODIFIED FOR TESTING (portable dispatch forced)");
        let unverified = with_status(&stage, "// STATUS: UNVERIFIED (phase 1): proofs, obligations and the optimizer have NOT run.");
        let phase2 = with_status(&stage, "// STATUS: VERIFIED (phase 2): every definition was elaborated to core and checked by the");
        assert_eq!(accepts(c, &bin, &dir, &stage), c.stage, "{}: stage output", c.build_rs);
        assert_eq!(accepts(c, &bin, &dir, &verdict_header), !c.stage, "{}: a crate verdict's header", c.build_rs);
        assert!(!accepts(c, &bin, &dir, &modified), "{}: output modified for testing", c.build_rs);
        assert!(!accepts(c, &bin, &dir, &unverified), "{}: phase-1 output", c.build_rs);
        assert!(!accepts(c, &bin, &dir, &phase2), "{}: an old phase-2 header", c.build_rs);
        // and no variable changes that
        let generated = dir.join("gen.rs");
        std::fs::write(&generated, &stage).unwrap();
        let out_dir = dir.join("out-env");
        std::fs::create_dir_all(&out_dir).unwrap();
        let st = Command::new(&bin).env(c.var, &generated).env("OUT_DIR", &out_dir).env("CARGO_MANIFEST_DIR", &dir).env("QMDB_ALLOW_TEST_ONLY", "1").output().unwrap();
        assert_eq!(st.status.success(), c.stage, "{}: QMDB_ALLOW_TEST_ONLY=1 must change nothing", c.build_rs);
    }
}

/// The emission-chain cross-check (`driver::gates::emission_chain`) finds
/// nothing wrong in the optimizer's output for the `simd` sample (a NEON
/// variant proven by `VariantEquiv` and dispatched, multiversioned clones
/// with their equality lemmas, specialized functions), and flags a
/// dispatched variant whose proof record is missing.
#[test]
fn the_emission_chain_of_a_dispatched_variant_checks() {
    use sandblaster_front::loader::RealFs;
    let root = samples().join("simd/mod.rs");
    let c = driver::check(&root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let (clean, tampered, dispatched) = sandblaster_front::elab::with_big_stack(|| {
        let mut chain = sandblaster_front::elab::ProverChain::standard();
        let mut out = sandblaster_front::elab::elaborate(k, &mut chain, &Default::default());
        let mut em = driver::stage::optimize_emit(&c, &mut out, "samples/simd/mod.rs", "", &OptOptions { strict: true, ..Default::default() }).unwrap();
        let clean = driver::gates::emission_chain(&out, &em);
        let dispatched = em.opt.variants.iter().filter(|v| v.dispatched).count();
        for v in em.opt.variants.iter_mut().filter(|v| v.dispatched) {
            v.equivalence = Err("removed by the test".into());
        }
        (clean, driver::gates::emission_chain(&out, &em), dispatched)
    });
    assert!(dispatched > 0, "the sample dispatches its NEON variant");
    assert!(clean.is_empty(), "{clean:?}");
    assert!(tampered.iter().any(|f| f.contains("is dispatched without a proven equivalence")), "{tampered:?}");
}
