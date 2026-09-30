//! The QMDB port through the verified pipeline (phase-2 acceptance):
//!
//! * every portable exec definition of `sandblaster/fixtures/qmdb/sandblaster` (its N = 1 instance
//!   root `n1.rs`, which the fixtures and the Bend corpora are for) — and, on aarch64,
//!   the SHA-2 hardware variant through the target semantics — is
//!   elaborated and kernel-checked, with **every** obligation proven; the
//!   full obligation inventory is written to
//!   `$CARGO_TARGET_TMPDIR/qmdb-obligations.json`;
//! * the kernel evaluation of `verify` (the reference semantics) on every
//!   fixture in `sandblaster/fixtures/qmdb/fixtures` equals the fixture's `expected`, which the
//!   baseline crate's tests assert is what the natively compiled sources
//!   return (`sandblaster/fixtures/qmdb/baseline/tests`).
//!
//! The ghost modules (`LAWS.rs`, `PROOF.rs`) are phase 3; their front-end
//! diagnostics are tolerated here, and they are not elaborated (test-only
//! `exec_only`).

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::{Path, PathBuf};

use sandblaster_front::diag::Severity;
use sandblaster_front::driver::{self, Checked, ProverSet, VerifyOptions};
use sandblaster_front::elab::{self, DefStatus, OblStatus};
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

fn qmdb_root() -> PathBuf {
    // the N = 1 instance: `sandblaster/fixtures/qmdb/fixtures` are N = 1 proofs (`mod.rs` is N = 32)
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/n1.rs")
}

fn fixtures() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/fixtures");
    let mut v: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| (p.file_name().unwrap().to_string_lossy().to_string(), std::fs::read_to_string(&p).unwrap()))
        .collect();
    v.sort();
    v
}

/// A string field of a flat JSON object.
fn field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let i = json.find(&format!("\"{key}\""))?;
    let rest = &json[i + key.len() + 2..];
    let rest = rest[rest.find(':')? + 1..].trim_start();
    if let Some(r) = rest.strip_prefix('"') {
        Some(&r[..r.find('"')?])
    } else {
        let end = rest.find([',', '}', '\n']).unwrap_or(rest.len());
        Some(rest[..end].trim())
    }
}

fn check_qmdb() -> Checked {
    let c = driver::check(&qmdb_root(), &RealFs, &TargetInfo::aarch64_apple_darwin());
    // only the phase-3 ghost modules may carry front-end errors
    for d in c.diags.list.iter().filter(|d| d.severity == Severity::Error) {
        let file = c.sm.path(d.span.file).display().to_string();
        assert!(file.ends_with("PROOF.rs") || file.ends_with("LAWS.rs"), "front-end error outside the ghost modules:\n{}", d.render(&c.sm));
    }
    assert!(c.krate.is_some());
    c
}

#[test]
fn qmdb_exec_code_is_kernel_checked_with_every_obligation_proven() {
    let c = check_qmdb();
    let k = c.krate.as_ref().unwrap();
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: true };
    let v = driver::stage::verify(k, &opts);
    let report = driver::stage::report_json(&c, &v, &[], "sandblaster/fixtures/qmdb/sandblaster/n1.rs", None, None, None);
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("qmdb-obligations.json");
    std::fs::write(&out, &report).unwrap();
    let st = v.stats();
    println!("QMDB: {} definitions, {} obligations ({} proven: by {:?}), report {}", v.defs.len(), st.total, st.proven, st.by_prover, out.display());
    for (kind, total, proven) in &st.by_kind {
        println!("  {kind}: {proven}/{total}");
    }
    assert!(v.failed_defs().is_empty(), "definitions not checked:\n{}", util::explain(&c, &v));
    assert_eq!(st.failed + st.todo, 0, "unproven obligations:\n{}", util::explain(&c, &v));
    // the portable API and the hardware variant are among them
    for name in ["crate::verifier::verify", "crate::sha256::compress", "crate::merkle::shape", "crate::merkle::shape_go", "crate::codec::uint", "crate::codec::uint64"] {
        assert_eq!(util::status_of(&v, name), &DefStatus::Checked, "{name}");
    }
    assert!(v.defs.iter().any(|d| d.name.starts_with("crate::sha256::compress::loop#")), "loop helpers are definitions");
    assert!(v.defs.iter().any(|d| d.name == "crate::sha256::compress_sha2" && d.status == DefStatus::Checked), "the aarch64 SHA-2 variant is elaborated through the target semantics");
    // every obligation of the inventory is reported with its status
    assert_eq!(report.matches("\"status\": \"proven\"").count(), st.total, "{report}");
    assert!(st.total > 400, "the QMDB inventory has hundreds of obligations");
}

#[test]
fn kernel_evaluation_of_verify_matches_the_fixtures() {
    let c = check_qmdb();
    let k = c.krate.as_ref().unwrap();
    let mut fx = fixtures();
    assert!(fx.len() >= 30, "fixtures found: {}", fx.len());
    // `QMDB_FIXTURES=n` evaluates only the first n (for quick local runs)
    if let Some(n) = std::env::var("QMDB_FIXTURES").ok().and_then(|n| n.parse::<usize>().ok()) {
        fx.truncate(n);
    }
    if let Ok(skip) = std::env::var("QMDB_FIXTURES_SKIP").map(|n| n.parse::<usize>().unwrap_or(0)) {
        fx.drain(..skip.min(fx.len()));
    }
    let cases: Vec<(String, String, bool)> = fx
        .iter()
        .map(|(name, json)| {
            let hex = |key: &str| format!("\"0x{}\"", field(json, key).unwrap_or_else(|| panic!("{name}: no {key}")));
            let args = format!("[{},{},{},{}]", hex("root"), hex("key"), hex("value"), hex("proof"));
            let expected = field(json, "expected").unwrap() == "true";
            (name.clone(), args, expected)
        })
        .collect();
    let opts = VerifyOptions { provers: ProverSet::Basic, exec_only: true };
    let results: Vec<(String, Result<String, String>, bool)> = driver::stage::with_elaboration(k, &opts, |out| {
        assert!(out.verified(), "QMDB exec code not verified");
        cases
            .iter()
            .map(|(name, args, expected)| {
                let t = std::time::Instant::now();
                let r = driver::stage::eval_in(out, k, "crate::verifier::verify", args);
                println!("  {name}: {:?} in {:?}", r, t.elapsed());
                (name.clone(), r, *expected)
            })
            .collect()
    });
    let mut bad = Vec::new();
    let (mut accepted, mut rejected) = (0, 0);
    for (name, got, expected) in &results {
        match got {
            Ok(v) if v == if *expected { "true" } else { "false" } => {
                if *expected {
                    accepted += 1
                } else {
                    rejected += 1
                }
            }
            other => bad.push(format!("{name}: kernel {other:?}, expected {expected}")),
        }
    }
    println!("kernel evaluation of verify: {accepted} accepted, {rejected} rejected, as expected");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert!(accepted > 0 && (rejected > 0 || std::env::var("QMDB_FIXTURES").is_ok()));
}

#[test]
fn obligation_records_carry_spans_kinds_and_provers() {
    let c = check_qmdb();
    let k = c.krate.as_ref().unwrap();
    let opts = VerifyOptions { provers: ProverSet::Basic, exec_only: true };
    let v = driver::stage::verify(k, &opts);
    for o in &v.obligations {
        assert!(!o.span.is_dummy(), "obligation {} of {} has no span", o.id, o.def);
        assert!(matches!(o.status, OblStatus::Proven { .. }), "{} [{}] unproven", o.def, elab::obl::kind_name(&o.kind));
    }
    let kinds: std::collections::BTreeSet<&str> = v.obligations.iter().map(|o| elab::obl::kind_name(&o.kind)).collect();
    // (no loop of the port has user invariants any more: the peak search
    // `merkle::shape_go` is tail recursive, its invariants are `requires`,
    // i.e. `callee-requires`; invariant obligations are covered by
    // `elab_obligations` and `elab_pipeline`)
    for kind in ["overflow", "underflow", "index-bounds", "slice-range", "callee-requires", "termination", "stack-depth"] {
        assert!(kinds.contains(kind), "no `{kind}` obligation in QMDB; kinds: {kinds:?}");
    }
}

/// Both instance roots on x86_64: `n1.rs` and the production `mod.rs`
/// (N = 32).
#[test]
fn qmdb_on_x86_64_elaborates_the_sha_ni_variant() {
    for root in [qmdb_root(), Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/mod.rs")] {
        let c = driver::check(&root, &RealFs, &TargetInfo::x86_64_apple_darwin());
        for d in c.diags.list.iter().filter(|d| d.severity == Severity::Error) {
            let file = c.sm.path(d.span.file).display().to_string();
            assert!(file.ends_with("PROOF.rs") || file.ends_with("LAWS.rs"), "{}", d.render(&c.sm));
        }
        let k = c.krate.as_ref().unwrap();
        let v = driver::stage::verify(k, &VerifyOptions { provers: ProverSet::Basic, exec_only: true });
        assert!(v.failed_defs().is_empty(), "{}: {}", root.display(), util::explain(&c, &v));
        assert_eq!(v.stats().failed, 0, "{}: {}", root.display(), util::explain(&c, &v));
        let shani = v.defs.iter().find(|d| d.name == "crate::sha256::compress_shani").map(|d| d.status.clone());
        println!("{}: compress_shani: {shani:?}", root.display());
        assert!(matches!(shani, Some(DefStatus::Checked) | Some(DefStatus::Deferred(_))), "{shani:?}");
    }
}
