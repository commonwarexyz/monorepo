//! The optimizer on the QMDB port (exec code; the laws are verified by the
//! build, the test-only exec-only path skips them here), on both instance
//! roots: `n1.rs` (N = 1, replaying the pinned fixtures and the Bend corpus)
//! and `mod.rs` (N = 32, production, replaying `sandblaster/fixtures/qmdb/fixtures-n32`).
//!
//! **Development-set regression tests** (fairness audit of 2026-10-02,
//! J16): the outcomes pinned here (rung `ClosedForm` for `shape`, the driven
//! helpers, the facts reaching the verify path) are decisions on the
//! program the optimizer was developed on. They catch accidental changes;
//! they are not evidence that the optimizer is general or fast, and a
//! change that only keeps them passing is not justified by them (DESIGN.md
//! §8.2 item 11). They pin no timing.

mod common;

use std::path::Path;
use std::time::Instant;

use common::*;

use sandblaster_front::driver;
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::RealFs;
use sandblaster_front::opt::{OptOptions, Outcome};
use sandblaster_front::target::TargetInfo;

/// The N = 1 instance (the Bend configuration): the fixed-shape hashes of
/// its graft (`hash_33`) and partial chunk (`hash_1`) are specialized, and
/// the pinned fixtures and the Bend corpus agree.
#[test]
fn qmdb_optimizer_report() {
    optimize_instance("n1.rs", "opt-qmdb", &["crate::sha256::hash_33__sha2", "crate::sha256::hash_1__sha2"], |code| {
        // N = 1: the graft takes a one-byte chunk
        assert!(code.contains("pub const CHUNK_BYTES: usize = 1usize;") && code.contains("l1_chunk: &[u8; 1usize]"), "N = 1 chunks");
    }, |dir| run_fixtures(dir, "sandblaster/fixtures/qmdb/fixtures", Some("sandblaster/fixtures/qmdb/baseline/tests/data/bend_verify.json"), Some("fixtures 32 accepted 29")));
}

/// The production instance (N = 32, docs/prod-domain-plan.md §5): the graft
/// is `hash_64` and the partial-chunk digest `hash_32`, both specialized per
/// variant; the code is monomorphic (`[u8; 32]` chunks); `sandblaster/fixtures/qmdb/fixtures-n32`
/// agrees. (Named so that `qmdb/bench/generate.sh`'s filter `qmdb_optimizer_report`
/// selects only the N = 1 test.)
#[test]
fn qmdb_n32_production_optimizer() {
    optimize_instance("mod.rs", "opt-qmdb-n32", &["crate::sha256::hash_32__sha2", "crate::sha256::hash_32"], |code| {
        // N = 32: monomorphic code, the graft takes a 32-byte chunk
        assert!(code.contains("pub const CHUNK_BYTES: usize = 32usize;") && code.contains("l1_chunk: &[u8; 32usize]"), "N = 32 chunks");
    }, |dir| run_fixtures(dir, "sandblaster/fixtures/qmdb/fixtures-n32", None, None));
}

/// Elaborates (exec only), optimizes (strict) and prints the instance root
/// `sandblaster/fixtures/qmdb/sandblaster/<root>`, reports the optimizer's decisions, checks what
/// every instance must satisfy (VariantEquiv kernel-checked and dispatched,
/// clones related, the shared fixed-shape hashes and `extra` specialized,
/// static dispatch, unchecked indexing, round trip), then `code` on the
/// emitted text and `run` on the output directory.
fn optimize_instance(root: &str, tmp_name: &str, extra: &[&str], code: impl Fn(&str) + Send + Sync, run: impl Fn(&Path) + Send + Sync) {
    let rel = format!("sandblaster/fixtures/qmdb/sandblaster/{root}");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(&rel);
    let c = driver::check(&path, &RealFs, &TargetInfo::aarch64_apple_darwin());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let t = Instant::now();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        println!("elaborated in {:?}", t.elapsed());
        let t = Instant::now();
        let em = driver::stage::optimize_emit_mode(&c, &mut out, &rel, "", &OptOptions { strict: true, ..Default::default() }, true).unwrap();
        println!("optimized + printed + round trip in {:?}", t.elapsed());
        let dir = tmp(tmp_name);
        std::fs::write(dir.join("sandblaster.rs"), &em.code).unwrap();
        println!("generated code: {} ({} lines)", dir.join("sandblaster.rs").display(), em.code.lines().count());
        let rs = &em.roundtrip_stats;
        println!("round trip: {} definitions compared, {} skeletons, {} glue items, {} failures, {}ms", rs.compared, rs.skeletons, rs.glue, rs.failures.len(), rs.millis);
        for f in rs.failures.iter().take(20) {
            println!("  RT FAILURE: {f}");
        }
        let o = &em.opt;
        for v in &o.variants {
            println!("variant {} ≡ {}: {:?}; dispatched={} ({})", v.variant, v.implements, v.equivalence, v.dispatched, v.note);
            for (m, s) in &v.evidence {
                println!("    evidence {m}: {s}");
            }
        }
        for s in &o.sets {
            println!("set {{{}}}: {:?}", s.name, s.feature_set);
        }
        for cl in &o.clones {
            println!("clone {} ~ {}: {:?}; lemma {:?}", cl.clone, cl.original, cl.related, cl.lemma);
        }
        for f in &o.fns {
            match &f.outcome {
                Outcome::Specialized { nodes, calls, .. } => println!("  Specialized   {} ({} nodes, calls {:?}) {}ms", f.name, nodes, calls, f.millis),
                Outcome::Unspecialized { reason, failure } => println!("  Unspecialized {}: {}{} {}ms", f.name, if *failure { "FAILURE " } else { "" }, reason, f.millis),
            }
        }
        for d in &o.dispatchers {
            println!("dispatcher {} -> {:?}", d.name, d.variants.iter().map(|(s, i)| format!("{}:{}", s.name, o.print.item(*i).path)).collect::<Vec<_>>());
        }
        for w in &o.warnings {
            println!("warning: {w}");
        }
        for e in &o.errors {
            println!("error: {e}");
        }
        assert!(o.errors.is_empty(), "optimizer errors (strict mode)");
        // VariantEquiv is kernel-checked and SHA2 is dispatched
        let v = o.variants.iter().find(|v| v.variant.ends_with("compress_sha2")).expect("compress_sha2");
        assert!(v.dispatched && v.equivalence.is_ok(), "{v:?}");
        // every clone has its kernel-checked equality lemma
        assert!(o.clones.len() >= 30 && o.clones.iter().all(|c| c.related.is_ok() && c.lemma.is_some()), "{:?}", o.clones);
        // the fixed-shape hashes are specialized, per variant
        let shared = ["crate::sha256::hash_64__sha2", "crate::sha256::hash_72__sha2", "crate::sha256::hash_73__sha2", "crate::merkle::node_digest__sha2", "crate::merkle::leaf_digest__sha2", "crate::sha256::compress", "crate::sha256::compress_sha2"];
        for f in shared.iter().chain(extra) {
            assert!(o.fns.iter().any(|r| r.name == *f && matches!(r.outcome, Outcome::Specialized { .. })), "{f} not specialized");
        }
        // hopeless driven attempts end early (gate G9: optimizer time): a
        // leaf the proof builder cannot close is refused within its own
        // budget (`verify`: the leaf compares `a && (b && …)` with
        // `(a && b) && …` under a kept call of the driven `verify_inputs`;
        // 181 ms of reading back the unfolded verifier before), and a
        // function whose residual would keep `as_chunks` is refused before
        // driving (`graft__sha2` inlines `compress_sha2`: 1.2M steps of
        // symbolic SHA-2 rounds before)
        let driven_reason = |name: &str| -> String {
            let f = o.fns.iter().find(|r| r.name == name).unwrap_or_else(|| panic!("{name}: no report"));
            f.candidates.iter().find(|c| c.rung == sandblaster_front::opt::Rung::Driven).map(|c| c.reason.clone()).unwrap_or_else(|| panic!("{name}: no driven candidate"))
        };
        let why = driven_reason("crate::verifier::verify");
        assert!(why.contains("a leaf of the process tree is not closed within its budget"), "verify: {why}");
        for (name, needle) in [("crate::merkle::graft__sha2", "`crate::sha256::compress_sha2`, which it inlines, applies `slice::as_chunks`"), ("crate::sha256::hash", "its body applies `slice::as_chunks`")] {
            let why = driven_reason(name);
            assert!(why.contains(needle) && why.contains("which a residual cannot print"), "{name}: {why}");
        }
        // the emitted code has the dispatched SHA2 path and unchecked indexing
        assert!(em.code.contains("return unsafe { crate::__sandblaster::verifier::verify__sha2("), "static dispatch");
        assert!(em.code.contains("::core::arch::aarch64::vsha256hq_u32("));
        assert!(em.code.contains("get_unchecked("));
        assert!(em.roundtrip.is_empty(), "round trip failed:\n{}", em.roundtrip.join("\n"));
        // plan O6: `shape` exports its loop's facts (kernel-checked fact
        // lemmas), and they reach the verify path: `merkle::reconstruct`
        // (and its SHA2 clone, the dispatched path) is driven through
        // `reconstruct_shape` and `reconstruct_checked`, whose
        // `height > MAX_HEIGHT` check the fact `height <= 62` decides
        let shape = o.fns.iter().find(|r| r.name == "crate::merkle::shape").expect("shape");
        for needle in ["height <= 62", "before + after <= 61", "index < width"] {
            assert!(shape.facts_exported.iter().any(|x| x.contains(needle)), "shape's facts: {:?}", shape.facts_exported);
        }
        // plan O6: `shape`'s loop is summarized by the closed form, linked
        // by a kernel-checked lemma through the summary lemma of `shape_go`
        let shape_why = shape.candidates.iter().find(|c| c.chosen).map(|c| c.reason.clone()).unwrap_or_default();
        assert!(shape.rung == Some(sandblaster_front::opt::Rung::ClosedForm) && matches!(shape.link, Some(sandblaster_front::opt::Link::Lemma(_))), "shape: rung {:?}, link {:?}: {shape_why}", shape.rung, shape.link);
        assert!(shape_why.contains("closed form, summary lemma `crate::merkle::shape_go::summary`"), "shape: {shape_why}");
        // its kernel steps are reported, within the per-loop budget
        let spent = shape.budgets_used.loopsum_steps;
        assert!(spent > 0 && spent <= sandblaster_front::opt::loopsum::LoopConfig::default().steps_per_loop, "shape's loop-summary steps: {spent}");
        let body_of = |f: &str, head: &str| -> String {
            let head = format!("fn {f}({head}");
            let start = em.code.find(&head).unwrap_or_else(|| panic!("no residual of merkle::{f}"));
            let end = em.code[start..].find("\n        }\n").map(|e| start + e).unwrap_or(em.code.len());
            em.code[start..end].to_string()
        };
        for f in ["reconstruct__portable", "reconstruct__sha2"] {
            let body = body_of(f, "l0_index: u64");
            // (the tail call of `reconstruct_finish` stays a call: its
            // instantiation there decides nothing, drive/process.rs
            // `fact_trial`)
            assert!(body.contains("merkle::shape(") && (body.contains("merkle::path") || body.contains("merkle::reconstruct_finish__")), "merkle::{f} is driven through the chain:\n{body}");
            assert!(!body.contains("> 64u32") && !body.contains("reconstruct_checked"), "merkle::{f}: the height check is decided by the facts:\n{body}");
        }
        // plan O7: `reconstruct_finish` bags through the segment helper of
        // `root` (no peak buffer), per variant
        for (f, seg) in [("reconstruct_finish__portable", "merkle::root__seg0("), ("reconstruct_finish__sha2", "merkle::root__sha2__seg0(")] {
            let body = body_of(f, "l0_leaves: u64");
            assert!(body.contains(seg) && !body.contains("[[0u8; 32usize]; 62usize]"), "merkle::{f} calls its segment helper `{seg}`:\n{body}");
        }
        for f in ["crate::merkle::reconstruct_finish", "crate::merkle::reconstruct_finish__sha2"] {
            let r = o.fns.iter().find(|r| r.name == f).unwrap_or_else(|| panic!("{f}: no report"));
            assert!(matches!(r.outcome, Outcome::Specialized { .. }) && matches!(r.link, Some(sandblaster_front::opt::Link::Lemma(_))), "{f} is driven: {:?}", r.candidates);
        }
        code(&em.code);
        run(&dir);
    });
}

/// Compiles the generated file with rustc (overflow checks, debug
/// assertions: `get_unchecked` precondition checks abort loudly) and runs
/// every fixture of `fixtures` (a directory, repo-relative) through
/// `verify` and, if given, the Bend 2 oracle corpus `corpus` (whose cases
/// refer to those fixtures). With `expect`, the summary line must start with
/// it.
fn run_fixtures(dir: &Path, fixtures: &str, corpus: Option<&str>, expect: Option<&str>) {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixtures = repo.join(fixtures);
    let fixture_rs = repo.join("sandblaster/fixtures/qmdb/baseline/src/fixture.rs");
    let corpus = corpus.map(|c| repo.join(c).display().to_string()).unwrap_or_default();
    let main = format!(
        r#"include!({gen:?});
#[allow(dead_code)]
#[path = {fx:?}]
mod fixture;
use fixture::{{Json, bytes_from_hex, parse_json}};
fn number(case: &Json, key: &str) -> u64 {{
    match case.get(key) {{
        Some(Json::Number(text)) => text.parse().unwrap(),
        Some(Json::String(units)) => String::from_utf16(units).unwrap().parse().unwrap(),
        other => panic!("{{key}}: {{other:?}}"),
    }}
}}
fn main() {{
    let files = fixture::fixture_files(std::path::Path::new({dir:?})).unwrap();
    let fixtures: Vec<fixture::Fixture> = files.iter().map(|f| fixture::load_fixture(f.to_str().unwrap(), None).unwrap()).collect();
    let mut accepted = 0;
    for fx in &fixtures {{
        let b = fx.bytes();
        let got = verify(&b.root, &b.key, &b.value, &b.proof);
        assert_eq!(got, fx.expected, "{{}}", fx.name_lossy());
        accepted += usize::from(got);
    }}
    let mut cases_run = 0;
    let corpus_path: &str = {corpus:?};
    if !corpus_path.is_empty() {{
        let text = std::fs::read_to_string(corpus_path).unwrap();
        let corpus = parse_json(&text).unwrap();
        let Some(Json::Array(cases)) = corpus.get("cases") else {{ panic!("no cases") }};
        let hex = |case: &Json, key: &str| -> Vec<u8> {{
            let Some(Json::String(units)) = case.get(key) else {{ panic!("{{key}}") }};
            bytes_from_hex(&String::from_utf16(units).unwrap()).unwrap()
        }};
        for (i, case) in cases.iter().enumerate() {{
            let fixture = &fixtures[number(case, "fixture") as usize];
            let value = fixture.bytes().value;
            let (root, key, proof) = (hex(case, "root"), hex(case, "key"), hex(case, "proof"));
            let Some(&Json::Bool(expected)) = case.get("expected") else {{ panic!("expected") }};
            assert_eq!(verify(&root, &key, &value, &proof), expected, "bend case {{i}}");
            cases_run += 1;
        }}
    }}
    println!("fixtures {{}} accepted {{}} bend-cases {{}}", fixtures.len(), accepted, cases_run);
}}
"#,
        gen = dir.join("sandblaster.rs"),
        fx = fixture_rs,
        dir = fixtures,
        corpus = corpus,
    );
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let out = rustc_run(&dir.join("main.rs"), &dir.join("qmdb_opt"), &["-C".into(), "target-cpu=native".into()]);
    eprintln!("{out}");
    match expect {
        Some(e) => assert!(out.starts_with(e), "{out}"),
        // every fixture agreed (asserted in `main`); some of them accept
        None => assert!(out.starts_with("fixtures ") && !out.contains(" accepted 0 "), "{out}"),
    }
}
