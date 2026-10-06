//! The stage boundary (DESIGN.md §15.8): stage runs — the toolchain's own
//! steps (`driver::stage`), which skip the §15 gates — can never pass for a
//! crate verdict.
//!
//! * The report and the summary of a stage run never say `VERIFIED`.
//! * The crate path on the same crate has no verdict when a gate fails, and
//!   module mode refuses a crate in sandblaster's own dialect (it has no
//!   code to emit).

mod common;

use std::path::Path;

use common::*;
use sandblaster_front::driver::{self, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;

const SRC: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\npub fn f(x: u8) -> u8 { x ^ 1 }\n";

#[test]
fn stage_reports_never_claim_a_verdict() {
    let fs = MemFs::from_files([("r/mod.rs", SRC)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let built = driver::stage::verify_checked(&c, &VerifyOptions::default());
    assert!(built.v.proofs_ok, "{}", built.v.diags.render(&c.sm));
    let report = driver::stage::report_json(&c, &built.v, &built.law_audit, "r/mod.rs", Some(&built.spec), Some(&built.spec15));
    assert!(report.contains("\"status\": \"PROOFS CHECKED (stage run, no crate verdict: the §15 gates did not run)\""), "{report}");
    assert!(!report.contains("\"status\": \"VERIFIED"), "{report}");
    assert!(driver::stage::summary(&c, &built.v).contains("status: PROOFS CHECKED (stage run"));
    // the front-end report says what it is
    let front = driver::stage::front_end_report_json(&c, "r/mod.rs");
    assert!(front.contains("\"status\": \"UNVERIFIED (phase 1)\""), "{front}");
    // and the crate path, on the same crate, has no verdict: it fails the
    // boundary gate (an exec function at the root) and has no lock
    let b = driver::build_crate(&c, driver::LockUse::Enforce, "r/mod.rs");
    assert!(b.verdict.is_none() && b.permit.is_none());
    assert!(b.report.contains("\"status\": \"NOT VERIFIED\""), "{}", b.report);
}

/// Module mode refuses a crate in sandblaster's own dialect (it has nothing
/// to emit).
#[test]
fn module_mode_refuses_a_dialect_crate() {
    let root = format!("{HEADER}mod m;\npub use m::f;\n");
    let files = vec![("/c/sandblaster/mod.rs".to_string(), root), ("/c/sandblaster/m.rs".to_string(), "use sandblaster::prelude::*;\n/// Flips the low bit.\npub fn f(x: u8) -> u8 { x ^ 1 }\n".to_string())];
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, t)| (p.as_str(), t.as_str())).collect();
    let fs = MemFs::from_files(refs.iter().copied());
    let c = driver::check(Path::new("/c/sandblaster/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let b = driver::build_crate(&c, driver::LockUse::Enforce, "/c/sandblaster/mod.rs");
    // without a lock the lock gate fails: no verdict
    assert!(b.verdict.is_none(), "{}", b.summary(&c));
    // module mode refuses a crate with no lifted module before any proof
    let env = |k: &str| match k {
        "CARGO_MANIFEST_DIR" => Some("/c".to_string()),
        "OUT_DIR" => Some("/out".to_string()),
        "CARGO_CFG_TARGET_ARCH" => Some("aarch64".to_string()),
        "CARGO_CFG_TARGET_FEATURE" => Some("neon".to_string()),
        "CARGO_CFG_TARGET_ENDIAN" => Some("little".to_string()),
        "CARGO_CFG_TARGET_POINTER_WIDTH" => Some("64".to_string()),
        _ => None,
    };
    let mut with_module = files.clone();
    with_module.push(("/c/src/lib.rs".into(), "mod m;\n".into()));
    with_module.push(("/c/src/m.rs".into(), driver::module_include_line("m")));
    let fs = MemFs::from_files(with_module.iter().map(|(p, t)| (p.as_str(), t.as_str())));
    let o = driver::build_module("sandblaster/mod.rs", "src/m.rs", None, &env, &fs);
    assert!(!o.ok && o.stderr.contains("lifts no Rust module"), "{}", o.stderr);
}
