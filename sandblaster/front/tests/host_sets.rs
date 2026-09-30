//! Host runs of the x86 feature-only variant sets (plan O8; optimizer
//! headroom report, "Dispatch of the feature-only sets"): the harness of the
//! host kit's `sets` stage (`tools/host-kit/run.sh --stages sets`).
//!
//! A feature-only set (`v3_scalar`, `v4`, SHA-NI with `v3_scalar`) is
//! generated and dispatched only when the evidence record says a host has
//! run its clones (`sandblaster_targets::evidence::SetRecord`). This harness
//! produces those runs: it emits the QMDB verifier (N = 1 and N = 32) for
//! x86_64 with the sets' evidence granted by a test hook (the only way to
//! get their clones before any host has run them), compiles it natively,
//! and runs, for every set, its clones directly (the dispatch forced)
//! against the portable code:
//!
//! * `qmdb-fixtures-n1` / `qmdb-fixtures-n32`: `verify__<set>` on every
//!   fixture of `sandblaster/fixtures/qmdb/fixtures` / `sandblaster/fixtures/qmdb/fixtures-n32`, against the
//!   fixture's expected verdict;
//! * `shape-differential-n1` / `-n32`: `merkle::shape__<set>` against
//!   `merkle::shape__portable` on corner and pseudo-random inputs (the bit
//!   counts of the closed form).
//!
//! Each set runs in its own process: on a CPU without the set's features
//! the process may die on an illegal instruction, which is reported as
//! `crashed` (the host kit then records nothing for a CPU that does not
//! report the features, and a failure for one that does). The results go
//! to `$HOST_SETS_OUT` (JSON lines: set, features, suite, cases,
//! mismatches, crashed), which the host kit records with
//! `sandblaster-targets-evidence --record-set` under the CPU's key: a run on
//! a CPU that does not report every feature of the set is `diagnostic`,
//! never evidence.
//!
//! Environment: `HOST_SETS_OUT` (default: a file in the test's temporary
//! directory), `HOST_SETS_TARGET` (the rustc target; default
//! `x86_64-unknown-linux-gnu` on Linux, `x86_64-apple-darwin` elsewhere),
//! `HOST_SETS_SHAPE_CASES` (random `shape` cases, default 10^6),
//! `HOST_SETS_INSTANCES` (default `n1,n32`).
//!
//! Run: `cargo test -p sandblaster-front --release --test host_sets -- --ignored --nocapture`.

mod common;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use common::tmp;
use sandblaster_front::driver;
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::RealFs;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::opt::hooks::OptTestHooks;
use sandblaster_front::target::TargetInfo;

/// The x86 feature-only sets.
const FEATURE_ONLY: [&str; 3] = ["v4", "sha_sse2_ssse3_sse4_1_v3", "v3_scalar"];

#[test]
#[ignore = "a host-kit harness: emits, compiles and runs the QMDB verifier on this CPU (minutes)"]
fn host_set_runs() {
    let target = std::env::var("HOST_SETS_TARGET").unwrap_or_else(|_| if cfg!(target_os = "linux") { "x86_64-unknown-linux-gnu".into() } else { "x86_64-apple-darwin".into() });
    let out = std::env::var("HOST_SETS_OUT").map(std::path::PathBuf::from).unwrap_or_else(|_| tmp("host-sets").join("results.jsonl"));
    let cases: u64 = std::env::var("HOST_SETS_SHAPE_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let instances = std::env::var("HOST_SETS_INSTANCES").unwrap_or_else(|_| "n1,n32".into());
    let mut lines: Vec<String> = Vec::new();
    for inst in instances.split(',').filter(|s| !s.is_empty()) {
        let (root, fixtures) = match inst {
            "n1" => ("n1.rs", "sandblaster/fixtures/qmdb/fixtures"),
            "n32" => ("mod.rs", "sandblaster/fixtures/qmdb/fixtures-n32"),
            other => panic!("unknown instance `{other}`"),
        };
        lines.extend(run_instance(inst, root, fixtures, &target, cases));
    }
    if let Some(d) = out.parent() {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(&out, lines.join("\n") + "\n").unwrap();
    println!("results in {}", out.display());
}

/// Emits, compiles and runs one instance; returns its result lines.
fn run_instance(inst: &str, root: &str, fixtures: &str, target: &str, cases: u64) -> Vec<String> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rel = format!("sandblaster/fixtures/qmdb/sandblaster/{root}");
    let c = driver::check(&repo.join(&rel), &RealFs, &TargetInfo::x86_64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let em = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let hooks = OptTestHooks { set_evidence: FEATURE_ONLY.iter().map(|s| s.to_string()).collect(), ..Default::default() };
        driver::stage::optimize_emit_mode(&c, &mut out, &rel, "", &OptOptions { strict: true, hooks: Some(Arc::new(hooks)), ..Default::default() }, true).unwrap()
    });
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    let sets: Vec<(String, Vec<String>)> = em.opt.sets.iter().filter(|s| FEATURE_ONLY.contains(&s.name.as_str())).map(|s| (s.name.clone(), s.feature_set.clone())).collect();
    assert!(!sets.is_empty(), "no feature-only set generated: {:?}", em.opt.not_cloned);
    let dir = tmp(&format!("host-sets-{inst}"));
    std::fs::write(dir.join("sandblaster.rs"), &em.code).unwrap();
    // one function per set: its clones against the portable code
    let mut runs = String::new();
    let mut arms = String::new();
    for (name, _) in &sets {
        runs.push_str(&format!(
            r#"
#[allow(unsafe_code)]
fn run_{name}(files: &[std::path::PathBuf], cases: u64) {{
    let (mut n, mut bad) = (0u64, 0u64);
    for f in files {{
        let fx = fixture::load_fixture(f.to_str().unwrap(), None).unwrap();
        let b = fx.bytes();
        let got = unsafe {{ crate::__sandblaster::verifier::verify__{name}(&b.root, &b.key, &b.value, &b.proof) }};
        n += 1;
        bad += u64::from(got != fx.expected);
    }}
    println!("suite qmdb-fixtures-{inst} cases {{n}} mismatches {{bad}}");
    let (mut n, mut bad) = (0u64, 0u64);
    let mut check = |leaves: u64, index: u64| {{
        let a = unsafe {{ crate::__sandblaster::merkle::shape__{name}(leaves, index) }};
        let p = crate::__sandblaster::merkle::shape__portable(leaves, index);
        n += 1;
        bad += u64::from(a != p);
    }};
    let corners = [0u64, 1, 2, 3, 4, 5, 7, 8, 63, 64, 65, (1 << 32) - 1, 1 << 32, (1 << 62) - 1, 1 << 62, (1 << 62) + 1, u64::MAX];
    for &l in &corners {{
        for &i in &corners {{
            check(l, i);
        }}
    }}
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..cases {{
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let leaves = (s >> (s % 64)) % ((1u64 << 62) + 2);
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let index = if leaves == 0 {{ s % 4 }} else {{ (s >> 1) % (leaves + 2) }};
        check(leaves, index);
    }}
    println!("suite shape-differential-{inst} cases {{n}} mismatches {{bad}}");
}}
"#
        ));
        arms.push_str(&format!("        \"{name}\" => run_{name}(&files, cases),\n"));
    }
    let main = format!(
        r#"include!({gen:?});
#[allow(dead_code)]
#[path = {fx:?}]
mod fixture;
{runs}
fn main() {{
    let mut args = std::env::args().skip(1);
    let set = args.next().expect("a set");
    let cases: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let files = fixture::fixture_files(std::path::Path::new({dir:?})).unwrap();
    match set.as_str() {{
{arms}        other => panic!("unknown set {{other}}"),
    }}
}}
"#,
        gen = dir.join("sandblaster.rs"),
        fx = repo.join("sandblaster/fixtures/qmdb/baseline/src/fixture.rs"),
        dir = repo.join(fixtures),
    );
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let bin = dir.join("host_sets");
    let st = Command::new("rustc")
        .env("CARGO_MANIFEST_DIR", repo.join("sandblaster/fixtures/qmdb/baseline"))
        .args(["--edition", "2024", "--target", target, "-O", "-C", "overflow-checks=on", "-C", "debug-assertions=on", "--cap-lints", "warn", "-o"])
        .arg(&bin)
        .arg(dir.join("main.rs"))
        .output()
        .expect("rustc");
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    let mut lines = Vec::new();
    for (name, features) in &sets {
        let feats = features.iter().map(|f| format!("\"{f}\"")).collect::<Vec<_>>().join(", ");
        let run = Command::new(&bin).arg(name).arg(cases.to_string()).output();
        let (stdout, crashed) = match &run {
            Ok(r) if r.status.success() => (String::from_utf8_lossy(&r.stdout).to_string(), false),
            Ok(r) => (String::from_utf8_lossy(&r.stdout).to_string(), true),
            Err(e) => panic!("cannot run {}: {e}", bin.display()),
        };
        println!("set {name} ({inst}){}:\n{stdout}", if crashed { " CRASHED" } else { "" });
        let mut seen = false;
        for l in stdout.lines() {
            let w: Vec<&str> = l.split_whitespace().collect();
            if let ["suite", suite, "cases", n, "mismatches", m] = w[..] {
                seen = true;
                lines.push(format!("{{\"set\": \"{name}\", \"features\": [{feats}], \"suite\": \"{suite}\", \"cases\": {n}, \"mismatches\": {m}, \"crashed\": false}}"));
            }
        }
        if crashed || !seen {
            lines.push(format!("{{\"set\": \"{name}\", \"features\": [{feats}], \"suite\": \"qmdb-fixtures-{inst}\", \"cases\": 0, \"mismatches\": 0, \"crashed\": true}}"));
        }
    }
    lines
}
