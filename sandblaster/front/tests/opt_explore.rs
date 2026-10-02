//! Today's stuck reasons and outcomes (docs/optimizer-plan.md O1, item 4):
//!
//! * `qmdb_stuck_reasons_match_explore_txt`: the symbolic execution of the
//!   QMDB hot spots (`sandblaster/fixtures/qmdb/sandblaster/mod.rs`, exec code) gets stuck exactly
//!   where the design says (design §2.1, `research/optdesign/explore.txt`,
//!   normalized into `opt_explore.expected`: timings dropped).
//! * `corpus_outcomes_match_the_manifest`: every corpus function's optimizer
//!   outcome is the `today.<function>` entry of `opt_corpus/corpus.toml`, and
//!   the strict corpus build has no optimizer warning (gate G2).
//!
//! Each later milestone changes these expectations deliberately (and says so
//! in its report); an accidental change fails here.
//!
//! **Development-set regression tests** (fairness audit of 2026-10-02,
//! J16): QMDB and the corpus are the programs the optimizer was built on
//! (much of the corpus restates QMDB, codec and storage shapes). These pins
//! catch accidental changes; they are not evidence of generality, and an
//! optimizer change justified only by moving a `today.*` entry is not
//! merged (DESIGN.md §8.2 item 11). They pin no timing.
//!
//! `explore_qmdb_residuals` (ignored) is the original development harness:
//! `OPT_EXPLORE=f,g OPT_OPAQUE=h OPT_DUMP=1 cargo test --test opt_explore -- --ignored --nocapture`.

use std::path::Path;
use std::time::Instant;

use sandblaster_front::driver::{self, VerifyOptions};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::RealFs;
use sandblaster_front::opt::{symex, OptOptions, Outcome};
use sandblaster_front::target::TargetInfo;

#[path = "opt_corpus/manifest.rs"]
mod manifest;

/// The functions of `explore.txt`, in its order.
const QMDB_FUNCTIONS: [&str; 11] = [
    "crate::merkle::shape",
    "crate::merkle::shape_go",
    "crate::codec::uint64",
    "crate::codec::uint64_go",
    "crate::codec::location",
    "crate::merkle::reconstruct_finish",
    "crate::merkle::root",
    "crate::merkle::bag_prefix",
    "crate::verifier::verify_fixed",
    "crate::verifier::canonical",
    "crate::merkle::path",
];

/// `explore.txt`'s lines for `names` (no opaque callees, full dumps),
/// without the timings.
fn explore(root: &Path, names: &[&str]) -> String {
    let c = driver::check(root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        assert!(out.defs.iter().all(|d| d.status == elab::DefStatus::Checked), "the exec code must verify");
        let index_g = out.env.lookup_global("seq::index").unwrap();
        let mut s = String::new();
        for n in names {
            let g = out.env.lookup_global(n).unwrap_or_else(|| panic!("{n}: no global"));
            let opaque = |_: sandblaster_kernel::term::GlobalId| false;
            let r = symex::symex(&out.env, g, &opaque, 1 << 30).unwrap_or_else(|e| panic!("{n}: {e}"));
            let a = symex::analyze(&out.env, &r.value, &opaque, index_g);
            s.push_str(&format!("{n}: {} steps; {} nodes {:?}; stuck: {:?}\n", r.steps, a.nodes, a.by_kind, a.stuck));
            s.push_str(&format!("{}\n", symex::debug_dag(&out.env, &r.value, 400)));
        }
        format!("{}\n", s.trim_end_matches('\n'))
    })
}

#[test]
fn qmdb_stuck_reasons_match_explore_txt() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let got = explore(&dir.join("../../sandblaster/fixtures/qmdb/sandblaster/mod.rs"), &QMDB_FUNCTIONS);
    let want = std::fs::read_to_string(dir.join("tests/opt_explore.expected")).unwrap();
    if got != want {
        let tmp = std::env::temp_dir().join("opt_explore.actual");
        std::fs::write(&tmp, &got).unwrap();
        for (i, (g, w)) in got.lines().zip(want.lines()).enumerate() {
            if g != w {
                panic!("stuck reasons changed (line {}):\n  expected: {}\n  actual:   {}\nfull output: {} (update tests/opt_explore.expected only for a deliberate change)", i + 1, &w[..w.len().min(300)], &g[..g.len().min(300)], tmp.display());
            }
        }
        panic!("stuck reasons changed (length differs); full output: {}", tmp.display());
    }
}

#[test]
fn corpus_outcomes_match_the_manifest() {
    let programs = manifest::load();
    let root = manifest::corpus_dir().join("dsl/mod.rs");
    let c = driver::check(&root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let t = Instant::now();
    let built = driver::stage::verify_and_optimize(&c, &VerifyOptions::default(), &OptOptions { strict: true, ..Default::default() }, "opt_corpus/dsl/mod.rs");
    assert!(built.v.proofs_ok, "the corpus must verify");
    let em = built.emit.expect("optimized").expect("emitted");
    println!("corpus: verified and optimized in {:?}; {} functions", t.elapsed(), em.opt.fns.len());
    // gate G2: no optimizer warning or error, clean round trip
    assert!(em.opt.warnings.is_empty(), "optimizer warnings: {:?}", em.opt.warnings);
    assert!(em.opt.errors.is_empty(), "optimizer errors: {:?}", em.opt.errors);
    assert!(em.roundtrip.is_empty(), "round trip: {:?}", em.roundtrip);
    let mut expected: std::collections::BTreeMap<String, (String, String)> = Default::default();
    for p in &programs {
        for f in &p.functions {
            assert!(p.today.contains_key(f), "{}: `today` has no entry for {f}", p.id());
        }
        for (f, o) in &p.today {
            expected.insert(f.clone(), (p.id().to_string(), o.clone()));
        }
    }
    let mut bad = Vec::new();
    for f in &em.opt.fns {
        let got = match &f.outcome {
            Outcome::Specialized { .. } if f.rung == Some(sandblaster_front::opt::Rung::Driven) => {
                if f.candidates.iter().any(|c| c.rung == sandblaster_front::opt::Rung::StraightLine && c.reason.contains("superseded")) {
                    "Specialized (driven; straight-line superseded)".to_string()
                } else {
                    "Specialized (driven)".to_string()
                }
            }
            // a Σ2 loop summary (plan O6)
            Outcome::Specialized { .. } if matches!(f.rung, Some(sandblaster_front::opt::Rung::ClosedForm | sandblaster_front::opt::Rung::EarlyExit | sandblaster_front::opt::Rung::SetBits)) => {
                let what = match f.rung {
                    Some(sandblaster_front::opt::Rung::ClosedForm) => "closed form",
                    Some(sandblaster_front::opt::Rung::SetBits) => "set-bit iteration",
                    _ => "early exit",
                };
                if f.candidates.iter().any(|c| c.rung == sandblaster_front::opt::Rung::StraightLine && c.reason.contains("superseded")) {
                    format!("Specialized ({what}; straight-line superseded)")
                } else {
                    format!("Specialized ({what})")
                }
            }
            // an aegraph rewrite of the straight-line residual (plan O8)
            Outcome::Specialized { .. } if f.rung == Some(sandblaster_front::opt::Rung::Rewritten) => {
                if f.candidates.iter().any(|c| c.rung == sandblaster_front::opt::Rung::StraightLine && c.reason.contains("superseded")) {
                    "Specialized (rewritten; straight-line superseded)".to_string()
                } else {
                    "Specialized (rewritten)".to_string()
                }
            }
            Outcome::Specialized { .. } => "Specialized".to_string(),
            Outcome::Unspecialized { reason, .. } => format!("Unspecialized: {reason}"),
        };
        match expected.remove(&f.name) {
            Some((_, want)) if want == got => {}
            Some((id, want)) => bad.push(format!("{id} {}: expected `{want}`, got `{got}`", f.name)),
            None => bad.push(format!("{}: not listed in corpus.toml (got `{got}`)", f.name)),
        }
        // today's report schema: a specialization is linked by conversion on
        // the straight-line rung or by its kernel-checked equality lemma on
        // the driven rung (O4) or a loop summary (O6)
        match &f.outcome {
            Outcome::Specialized { .. } => {
                match (&f.link, &f.rung) {
                    (Some(sandblaster_front::opt::Link::Conversion), Some(sandblaster_front::opt::Rung::StraightLine)) => {}
                    (Some(sandblaster_front::opt::Link::Lemma(l)), Some(sandblaster_front::opt::Rung::Driven | sandblaster_front::opt::Rung::ClosedForm | sandblaster_front::opt::Rung::EarlyExit | sandblaster_front::opt::Rung::SetBits | sandblaster_front::opt::Rung::Rewritten)) => assert_eq!(l, &format!("{}__residual::equiv", f.name), "{}", f.name),
                    other => panic!("{}: unexpected link and rung {other:?}", f.name),
                }
                assert!(f.candidates.iter().any(|c| c.chosen), "{}", f.name);
            }
            Outcome::Unspecialized { .. } => assert!(f.link.is_none() && f.rung.is_none(), "{}", f.name),
        }
        // exported facts (plan O6): only from a loop summary, each a
        // kernel-checked fact lemma of the function
        if !f.facts_exported.is_empty() {
            assert!(matches!(f.rung, Some(sandblaster_front::opt::Rung::ClosedForm | sandblaster_front::opt::Rung::EarlyExit | sandblaster_front::opt::Rung::SetBits)), "{}: facts without a loop summary", f.name);
            assert!(f.facts_exported.iter().all(|x| x.starts_with(&format!("{}::fact#", f.name))), "{}: {:?}", f.name, f.facts_exported);
        }
    }
    for (f, (id, want)) in &expected {
        bad.push(format!("{id} {f}: listed in corpus.toml (`{want}`) but not optimized"));
    }
    assert!(bad.is_empty(), "corpus outcomes differ from corpus.toml:\n{}", bad.join("\n"));
}

#[test]
#[ignore]
fn explore_qmdb_residuals() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/mod.rs");
    let c = driver::check(&root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let t = Instant::now();
        let out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        println!("elaborated in {:?}; verified={}", t.elapsed(), out.defs.iter().all(|d| d.status == elab::DefStatus::Checked));
        let index_g = out.env.lookup_global("seq::index").unwrap();
        let names = std::env::var("OPT_EXPLORE").unwrap_or_else(|_| "crate::sha256::compress_sha2,crate::sha256::compress,crate::sha256::hash_64,crate::merkle::fold,crate::merkle::node_digest,crate::sha256::to_bytes,crate::merkle::graft,crate::verifier::update_operation".into());
        for n in names.split(',') {
            let Some(g) = out.env.lookup_global(n) else {
                println!("{n}: no global");
                continue;
            };
            let opaque = |h: sandblaster_kernel::term::GlobalId| std::env::var("OPT_OPAQUE").map(|s| s.split(',').any(|x| out.env.lookup_global(x) == Some(h))).unwrap_or(false);
            let t = Instant::now();
            match symex::symex(&out.env, g, &opaque, 1 << 30) {
                Ok(s) => {
                    let a = symex::analyze(&out.env, &s.value, &opaque, index_g);
                    println!("{n}: {} steps in {:?}; {} nodes {:?}; stuck: {:?}", s.steps, t.elapsed(), a.nodes, a.by_kind, a.stuck);
                    if std::env::var_os("OPT_DUMP").is_some() {
                        println!("{}", symex::debug_dag(&out.env, &s.value, 400));
                    }
                }
                Err(e) => println!("{n}: error {e}"),
            }
        }
    });
}
