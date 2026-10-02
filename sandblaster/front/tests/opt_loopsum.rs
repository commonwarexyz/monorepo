//! Σ2 loop summaries (docs/optimizer-plan.md O6; optimizer design §7):
//! the summarizer's stages on QMDB's `shape_go` and the corpus loops —
//! one-step analysis, classes, traces, synthesis, the per-literal lemma
//! chain (kernel-checked) — and the optimizer's use of them (the loop
//! helper, `rung = ClosedForm`).
//!
//! **Development-set regression tests** (fairness audit of 2026-10-02,
//! J16): `shape_go` is QMDB's, the `p*` loops are corpus programs. These
//! pins catch accidental changes, not evidence of generality (DESIGN.md
//! §8.2 item 11). `set_bit_iteration_at_32_bits` is a width-coverage test
//! of the generalized set-bit rung (J6), written with the change: not a
//! held-out measurement.
//!
//! `cargo test --release -p sandblaster-front --test opt_loopsum -- --test-threads=1 --nocapture`

use std::path::Path;
use std::time::Instant;

use sandblaster_front::driver;
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::loopsum::{self, LoopConfig, LoopKey};
use sandblaster_front::target::TargetInfo;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::Lvl;
use sandblaster_kernel::value::{Arg, Budget, VEnv};

/// A top-level item (with its doc comments and attributes) of a source file.
fn item(src: &str, marker: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let i = lines.iter().position(|l| l.starts_with(marker)).unwrap_or_else(|| panic!("no item `{marker}`"));
    let mut start = i;
    while start > 0 && (lines[start - 1].starts_with("///") || lines[start - 1].starts_with("#[")) {
        start -= 1;
    }
    let (mut depth, mut end, mut opened) = (0i32, i, false);
    for (j, l) in lines.iter().enumerate().skip(i) {
        for c in l.chars() {
            match c {
                '{' => {
                    depth += 1;
                    opened = true
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        end = j;
        if (opened && depth == 0) || (!opened && l.trim_end().ends_with(';')) {
            break;
        }
    }
    // the §15 `#[refines(..)]` and `#[view(..)]` annotations name the
    // fixture's `model` module, which these in-memory copies do not carry
    // (the QMDB fixture gained them with its spec); the optimizer reads
    // neither, so they are dropped from the copy
    lines[start..=end].iter().filter(|l| !(l.starts_with("#[refines(") || l.starts_with("#[view("))).copied().collect::<Vec<_>>().join("\n")
}

fn repo(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn elaborate(items: &[String]) -> Env {
    let src = format!("#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n{}\n", items.join("\n\n"));
    let fs = MemFs::from_files([("r/mod.rs", src.as_str())]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let mut chain = ProverChain::standard();
    let out = elab::elaborate(c.krate.as_ref().unwrap(), &mut chain, &elab::Options { exec_only: true, ..Default::default() });
    for d in &out.defs {
        assert_eq!(d.status, elab::DefStatus::Checked, "{}", d.name);
    }
    out.env
}

/// The key of `func args` where `args` is core text over the dynamic
/// names `dyn_names` (their values fresh variables).
fn key(env: &Env, func: &str, args: &[&str], dyn_names: &[&str]) -> LoopKey {
    let def = env.lookup_global(func).unwrap();
    let mut vals = Vec::new();
    for a in args {
        if let Some(i) = dyn_names.iter().position(|n| n == a) {
            vals.push(Arg::Rel(std::rc::Rc::new(sandblaster_kernel::value::Value::Neu(sandblaster_kernel::value::Neutral {
                head: sandblaster_kernel::value::Head::Var(Lvl(i as u32)),
                spine: vec![],
            }))));
        } else {
            let t = env.parse_term(&[], a).unwrap_or_else(|e| panic!("{a}: {e}"));
            let v = env.eval(&VEnv::default(), Lvl(0), &t, &mut Budget { steps: 1_000_000 }).unwrap();
            vals.push(Arg::Rel(v));
        }
    }
    loopsum::key_of(env, def, &vals).expect("a loop key").0
}

fn big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || {
            sandblaster_kernel::util::set_stack_limit(900 << 20);
            f()
        })
        .unwrap()
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e))
}

/// Analysis, spec and lemma chain of one loop; returns (lemmas closed, K).
fn summarize(env: &mut Env, k: &LoopKey, prefix: &str) -> (usize, u32) {
    let cfg = LoopConfig::default();
    let t0 = Instant::now();
    let a = loopsum::analyze(env, k, &cfg).unwrap_or_else(|e| panic!("analysis: {e}"));
    eprintln!("[loopsum] analysis {:?}: {}", t0.elapsed(), loopsum::invariant::describe(&a.plan, env));
    let spec = loopsum::spec_of(env, &a.plan, prefix).unwrap_or_else(|e| panic!("spec: {e}"));
    let kk = spec.k;
    if std::env::var_os("LOOPSUM_SHOW").is_some() {
        for j in [0, kk / 2, kk] {
            let bs = spec.binders(j);
            eprintln!("-- lemma_{j} binders:");
            for (n, t) in bs {
                eprintln!("   {n} : {t}");
            }
            eprintln!("   lhs: {}\n   res: {}", spec.lhs[j as usize], spec.res);
        }
    }
    let t1 = Instant::now();
    let (lemmas, stats) = loopsum::lemmas::build_chain(env, &spec, prefix, 5_000_000_000, None).unwrap_or_else(|e| panic!("chain: {e}"));
    let closed = lemmas.iter().filter(|x| x.is_some()).count();
    eprintln!("[loopsum] chain {:?}: {closed}/{} lemmas; {} steps\n{}", t1.elapsed(), kk + 1, stats.total(), stats.report());
    if let Some(f) = &stats.first_failure {
        eprintln!("[loopsum] first failure: {f}");
    }
    (closed, kk)
}

fn shape_env() -> Env {
    let merkle = repo("sandblaster/fixtures/qmdb/sandblaster/merkle.rs");
    elaborate(&[item(&merkle, "pub const MAX_LEAVES"), item(&merkle, "pub struct Shape"), item(&merkle, "pub fn shape("), item(&merkle, "pub(crate) fn shape_go(")])
}

#[test]
fn shape_go_closed_form() {
    let (closed, k) = big_stack(|| {
        let mut env = shape_env();
        let k = key(&env, "crate::shape_go", &["63u32", "t", "L", "4611686018427387904u64", "0u64", "0u64", "0u32", "None[crate::Shape]"], &["t", "L"]);
        summarize(&mut env, &k, "t::shape_go::sum")
    });
    assert_eq!(closed as u32, k + 1);
}

fn corpus_env(items: &[&str]) -> Env {
    let p = repo("sandblaster/front/tests/opt_corpus/dsl/mod.rs");
    elaborate(&items.iter().map(|m| item(&p, m)).collect::<Vec<_>>())
}

#[test]
fn p4_find_block_closed_form() {
    let (closed, k) = big_stack(|| {
        let mut env = corpus_env(&["pub struct Block", "fn find_block_go(", "pub fn find_block("]);
        let k = key(&env, "crate::find_block_go", &["64u32", "t", "n", "9223372036854775808u64", "0u64", "0u32", "None[crate::Block]"], &["t", "n"]);
        summarize(&mut env, &k, "t::find_block_go::sum")
    });
    assert_eq!(closed as u32, k + 1);
}

#[test]
fn p1_bit_length_closed_form() {
    let (closed, k) = big_stack(|| {
        let mut env = corpus_env(&["fn bit_length_go(", "pub fn bit_length("]);
        let k = key(&env, "crate::bit_length_go", &["64u32", "x", "0u32"], &["x"]);
        summarize(&mut env, &k, "t::bit_length_go::sum")
    });
    assert_eq!(closed as u32, k + 1);
}

#[test]
fn p2_floor_pow2_closed_form() {
    let (closed, k) = big_stack(|| {
        let mut env = corpus_env(&["fn floor_pow2_go(", "pub fn floor_pow2("]);
        let k = key(&env, "crate::floor_pow2_go", &["64u32", "x", "9223372036854775808u64"], &["x"]);
        summarize(&mut env, &k, "t::floor_pow2_go::sum")
    });
    assert_eq!(closed as u32, k + 1);
}

#[test]
fn p6_varint_len_closed_form() {
    let (closed, k) = big_stack(|| {
        let mut env = corpus_env(&["fn varint_len_go(", "pub fn varint_len("]);
        let k = key(&env, "crate::varint_len_go", &["x", "0u32"], &["x"]);
        summarize(&mut env, &k, "t::varint_len_go::sum")
    });
    assert_eq!(closed as u32, k + 1);
}

#[test]
fn p11_trailing_zeros_closed_form() {
    let (closed, k) = big_stack(|| {
        let mut env = corpus_env(&["fn tz_go(", "pub fn trailing_zeros_loop("]);
        let k = key(&env, "crate::tz_go", &["64u32", "x", "0u32"], &["x"]);
        summarize(&mut env, &k, "t::tz_go::sum")
    });
    assert_eq!(closed as u32, k + 1);
}

// ---------------------------------------------------------------------------
// The optimizer's use of the summaries (the loop helper, `rung = ClosedForm`).
// ---------------------------------------------------------------------------

use std::sync::Arc;

use sandblaster_front::driver::OptimizedEmit;
use sandblaster_front::opt::hooks::OptTestHooks;
use sandblaster_front::opt::{Link, OptOptions, Outcome, Rung};

/// Elaborates (exec code), optimizes (strict) and prints `src`.
fn optimize_src(src: &str, loops: LoopConfig) -> OptimizedEmit {
    let fs = MemFs::from_files([("r/mod.rs", src)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        assert!(out.obligations.iter().all(|o| o.proven()), "the sample must verify");
        let opts = OptOptions { strict: true, loops, hooks: Some(Arc::new(OptTestHooks::default())), ..Default::default() };
        let em = driver::stage::optimize_emit_mode(&c, &mut out, "r/mod.rs", "", &opts, true).unwrap();
        assert!(em.opt.errors.is_empty(), "optimizer errors: {:?}", em.opt.errors);
        assert!(em.roundtrip.is_empty(), "round trip: {:?}", em.roundtrip);
        em
    })
}

fn report<'a>(em: &'a OptimizedEmit, name: &str) -> &'a sandblaster_front::opt::FnReport {
    em.opt.fns.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no report for {name}"))
}

/// The printed item `fn name(` (up to the next item at the same indent).
fn body_of(code: &str, name: &str) -> String {
    let head = format!("fn {name}(");
    let mut out = String::new();
    let mut on = false;
    let mut indent = 0usize;
    for line in code.lines() {
        if !on && line.contains(&head) {
            on = true;
            indent = line.len() - line.trim_start().len();
        }
        if on {
            out.push_str(line);
            out.push('\n');
            if line.trim_start().starts_with('}') && line.len() - line.trim_start().len() == indent {
                break;
            }
        }
    }
    out
}

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

fn shape_src() -> String {
    let merkle = repo("sandblaster/fixtures/qmdb/sandblaster/merkle.rs");
    format!("{HEADER}{}\n\n{}\n\n{}\n\n{}\n", item(&merkle, "pub const MAX_LEAVES"), item(&merkle, "pub struct Shape"), item(&merkle, "pub fn shape("), item(&merkle, "pub(crate) fn shape_go("))
}

#[test]
fn shape_is_emitted_as_its_closed_form() {
    let em = optimize_src(&shape_src(), LoopConfig::default());
    let f = report(&em, "crate::shape");
    for c in &f.candidates {
        println!("{:?} chosen={} {} {:?}", c.rung, c.chosen, c.reason.chars().take(1200).collect::<String>(), c.rejected_by);
    }
    println!("{}", body_of(&em.code, "shape"));
    println!("{}", body_of(&em.code, "shape_go__closed"));
    assert!(matches!(f.outcome, Outcome::Specialized { .. }));
    assert_eq!(f.rung, Some(Rung::ClosedForm));
    assert!(matches!(f.link, Some(Link::Lemma(_))));
    let b = body_of(&em.code, "shape");
    assert!(b.contains("shape_go__closed"), "{b}");
    assert!(!body_of(&em.code, "shape_go__closed").contains("shape_go("), "the helper has no loop");
    // its `# Safety` doc states the loop's `requires` with the static
    // arguments substituted: only the helper's own parameters are named
    // (formerly the source text, naming `fuel`, `start`, `position` and
    // `before`, which the helper does not have)
    let lines: Vec<&str> = em.code.lines().collect();
    let at = lines.iter().position(|l| l.contains("fn shape_go__closed(")).expect("the helper");
    let doc: Vec<&str> = lines[..at].iter().rev().take_while(|l| l.trim_start().starts_with("#[")).copied().collect();
    let doc = doc.join("\n");
    println!("{doc}");
    assert!(doc.contains("# Safety") && doc.contains("l2_remaining"), "{doc}");
    for gone in ["fuel", "start", "position", "before", "as ()"] {
        assert!(!doc.contains(gone), "the doc names `{gone}`: {doc}");
    }
    // the report accounts for the summary's kernel steps, within the per-loop
    // budget (`LoopConfig::steps_per_loop`, over the whole summary)
    let spent = f.budgets_used.loopsum_steps;
    assert!(spent > 0 && spent <= LoopConfig::default().steps_per_loop, "loop-summary steps {spent}");
}

/// `steps_per_loop` bounds the whole summary (analysis, lemma chain, links,
/// facts, fallback rungs), not only the chain: with too few steps the loop
/// is kept, the report says why, and what was spent stays within the
/// limit (up to the analysis' fixed evaluation budgets).
#[test]
fn loop_summary_step_budget() {
    let limit = 2_000_000;
    let em = optimize_src(&shape_src(), LoopConfig { steps_per_loop: limit, ..LoopConfig::default() });
    let f = report(&em, "crate::shape");
    for c in &f.candidates {
        println!("{:?} chosen={} {} {:?}", c.rung, c.chosen, c.reason.chars().take(1200).collect::<String>(), c.rejected_by);
    }
    assert_ne!(f.rung, Some(Rung::ClosedForm), "a summary within {limit} steps");
    assert!(f.candidates.iter().any(|c| c.reason.contains("step budget")), "{:?}", f.candidates);
    assert!(em.opt.errors.is_empty(), "running out of steps is not an optimizer fault: {:?}", em.opt.errors);
    let spent = f.budgets_used.loopsum_steps;
    assert!(spent > 0 && spent <= 2 * limit, "loop-summary steps {spent}");
}

/// The per-crate registries (loop summaries, exported facts, guard
/// specializations) are emptied when the optimizer's run ends: a later
/// elaboration on the same thread (another crate) does not see this
/// crate's facts in the elaborator's `dep_match` hook.
#[test]
fn registries_are_emptied_when_the_run_ends() {
    let src = shape_src();
    let fs = MemFs::from_files([("r/mod.rs", src.as_str())]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let (exported, after) = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let opts = OptOptions { strict: true, hooks: Some(Arc::new(OptTestHooks::default())), ..Default::default() };
        let em = driver::stage::optimize_emit_mode(&c, &mut out, "r/mod.rs", "", &opts, true).unwrap();
        let exported = em.opt.fns.iter().find(|f| f.name == "crate::shape").map(|f| f.facts_exported.len()).unwrap_or(0);
        (exported, sandblaster_front::opt::facts::any())
    });
    assert!(exported > 0, "shape exports its facts during the run");
    assert!(!after, "the facts registry is empty after the run");
}

// ---------------------------------------------------------------------------
// Profiles (`sandblaster profile`, PROFILE.json; optimizer design §10.4).
// ---------------------------------------------------------------------------

/// The collector observes every loop head call with its actual arguments
/// (and the resumed evaluation computes the entry's value); the file round
/// trips and Σ2 reads the samples back.
#[test]
fn profile_records_loop_calls() {
    use sandblaster_front::opt::cost::profile::{self, Entry, Profile};
    let src = format!("{}\npub fn two(leaves: u64, a: u64, b: u64) -> bool {{\n    let x = shape(leaves, a);\n    let y = shape(leaves, b);\n    x.is_some() && y.is_some()\n}}\n", shape_src());
    let fs = MemFs::from_files([("r/mod.rs", src.as_str())]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let (calls, value, heads) = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let heads = profile::loop_heads(k, &out.fn_globals, &sandblaster_front::opt::drive::DriveConfig::default());
        let (calls, v) = profile::collect(&out, k, "two", "[7, 3, 9]", &heads).unwrap();
        let v = out.env.print_term(&[], &out.env.quote(Lvl(0), &v, false));
        (calls, v, heads.len())
    });
    assert_eq!(heads, 1, "shape_go is the only loop head");
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(calls[0].0, "crate::shape_go");
    assert_eq!(&calls[0].1[..3], &["63", "3", "7"]);
    assert_eq!(&calls[1].1[..3], &["63", "9", "7"]);
    // index 9 ≥ 7 leaves: the second shape is None, so `two` is false
    assert!(value.contains("false"), "{value}");
    let mut loops = profile::Loops::new();
    for (l, a) in calls {
        let e = loops.entry(l).or_default();
        e.0 += 1;
        e.1.insert(a);
    }
    let p = Profile { entries: vec![Entry { root: "r/mod.rs".into(), entry: "two".into(), corpora: vec!["fx".into()], fixtures: 1, loops }] };
    let text = p.to_json();
    assert_eq!(Profile::parse(&text).unwrap(), p, "{text}");
    let s = p.loop_samples();
    assert_eq!(s["crate::shape_go"][0][..3], [Some(63), Some(3), Some(7)]);
}

// ---------------------------------------------------------------------------
// Fallback rungs (design §7.6): with synthesis off, the early exit.
// ---------------------------------------------------------------------------

#[test]
fn shape_early_exit_without_synthesis() {
    let em = optimize_src(&shape_src(), LoopConfig { synthesis: false, ..LoopConfig::default() });
    let f = report(&em, "crate::shape");
    for c in &f.candidates {
        println!("{:?} chosen={} {} {:?}", c.rung, c.chosen, c.reason.chars().take(1500).collect::<String>(), c.rejected_by);
    }
    println!("{}", body_of(&em.code, "shape"));
    println!("{}", body_of(&em.code, "shape_go__early_entry"));
    println!("{}", body_of(&em.code, "shape_go__early"));
    assert!(matches!(f.outcome, Outcome::Specialized { .. }));
    assert_eq!(f.rung, Some(Rung::EarlyExit));
    assert!(matches!(f.link, Some(Link::Lemma(_))));
    let h = body_of(&em.code, "shape_go__early");
    assert!(h.contains("target < ") || h.contains("l1_target <"), "the stop test: {h}");
}

// ---------------------------------------------------------------------------
// Exported facts (design §6.4 "output facts"; plan O6: `height ≤ 62`,
// `before + after ≤ 61`, `index < width`), used by callers.
// ---------------------------------------------------------------------------

/// The facts `shape` exports (kernel-checked lemmas `shape::fact#k`) prune
/// a caller's checks on the shape's fields: the height bound and the
/// peak-count bound.
#[test]
fn shape_exports_facts_that_prune_a_callers_checks() {
    let src = format!(
        "{}\npub fn height_of(leaves: u64, index: u64) -> Option<u32> {{\n    match shape(leaves, index) {{\n        None => None,\n        Some(s) => {{\n            if s.height > 64 {{\n                return None;\n            }}\n            if (s.before as u64) + (s.after as u64) >= 62 {{\n                return None;\n            }}\n            Some(s.height)\n        }}\n    }}\n}}\n",
        shape_src()
    );
    let em = optimize_src(&src, LoopConfig::default());
    let f = report(&em, "crate::shape");
    println!("facts: {:?}", f.facts_exported);
    let has = |needle: &str| f.facts_exported.iter().any(|x| x.contains(needle));
    assert!(has("height <= 62"), "{:?}", f.facts_exported);
    assert!(has("before + after <= 61"), "{:?}", f.facts_exported);
    assert!(has("index < width"), "{:?}", f.facts_exported);
    let g = report(&em, "crate::height_of");
    for c in &g.candidates {
        println!("{:?} chosen={} {}", c.rung, c.chosen, c.reason.chars().take(800).collect::<String>());
    }
    let b = body_of(&em.code, "height_of");
    println!("{b}");
    assert!(matches!(g.link, Some(Link::Lemma(_))), "{:?}", g.candidates);
    assert!(!b.contains("64u32") && !b.contains("62u64"), "both checks are decided by the facts:\n{b}");
}

/// The proof cache (plan O5) changes neither the output nor the report: a
/// warm build, whose loop summary takes its lemma chain and fact chain
/// from the cache, charges each cached proof the steps its build took, so
/// `budgets_used.loopsum_steps` (and the step budget it counts against)
/// is the cold build's. It used to be lower on a hit (gate G1 compared a
/// cold and a warm report and found them different).
#[test]
fn loop_summary_steps_do_not_depend_on_the_proof_cache() {
    let src = format!(
        "{}\npub fn height_of(leaves: u64, index: u64) -> Option<u32> {{\n    match shape(leaves, index) {{\n        None => None,\n        Some(s) => {{\n            if s.height > 64 {{\n                return None;\n            }}\n            Some(s.height)\n        }}\n    }}\n}}\n",
        shape_src()
    );
    let dir = std::env::temp_dir().join(format!("sandblaster-loopsum-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let run = |dir: &Path| -> OptimizedEmit {
        let fs = MemFs::from_files([("r/mod.rs", src.as_str())]);
        let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
        assert!(c.ok(), "{}", c.render());
        let dir = dir.to_path_buf();
        elab::with_big_stack(move || {
            let k = c.krate.as_ref().unwrap();
            let mut chain = ProverChain::standard();
            let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
            let opts = OptOptions { strict: true, cache_dir: Some(dir), ..Default::default() };
            let em = driver::stage::optimize_emit_mode(&c, &mut out, "r/mod.rs", "", &opts, true).unwrap();
            assert!(em.opt.errors.is_empty(), "optimizer errors: {:?}", em.opt.errors);
            em
        })
    };
    let cold = run(&dir);
    let stored = std::fs::read_dir(&dir).map(|d| d.count()).unwrap_or(0);
    let warm = run(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    let f = report(&cold, "crate::shape");
    assert_eq!(f.rung, Some(Rung::ClosedForm), "{:?}", f.candidates);
    assert!(f.facts_exported.iter().any(|x| x.contains("height <= 62")), "the fact chain ran: {:?}", f.facts_exported);
    assert!(stored > 0, "the cold build stored its proofs");
    assert_eq!(warm.code, cold.code, "a warm build emits the cold build's code");
    for (a, b) in cold.opt.fns.iter().zip(&warm.opt.fns) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.budgets_used, b.budgets_used, "{}: the budgets of a warm build are the cold build's", a.name);
        assert_eq!(format!("{:?}", a.candidates), format!("{:?}", b.candidates), "{}", a.name);
    }
    assert!(f.budgets_used.loopsum_steps > 0);
}

/// A callee whose check the facts decide but whose driven residual cannot
/// be printed (a buffer): the call becomes a call of its guard helper (the
/// source without the check, `requires` the check's negation, linked by a
/// kernel-checked lemma).
#[test]
fn facts_reach_a_callees_guard() {
    let src = format!(
        "{}\npub fn finish(before: u32, after: u32, x: u64) -> Option<u64> {{\n    let n = (before as u64) + (after as u64);\n    if n >= 62 {{\n        return None;\n    }}\n    let mut buf = [0u64; 62];\n    buf[n as usize] = x;\n    Some(buf[0] ^ buf[61])\n}}\n\npub fn use_it(leaves: u64, index: u64, x: u64) -> Option<u64> {{\n    let s = shape(leaves, index)?;\n    finish(s.before, s.after, x)\n}}\n",
        shape_src()
    );
    let em = optimize_src(&src, LoopConfig::default());
    let g = report(&em, "crate::use_it");
    for c in &g.candidates {
        println!("{:?} chosen={} {}", c.rung, c.chosen, c.reason.chars().take(800).collect::<String>());
    }
    let b = body_of(&em.code, "use_it");
    println!("{b}");
    // the check is gone from the path: the call is its guard helper's
    assert!(em.code.lines().any(|l| l.contains("fn finish__g0")), "a guard helper: {:?}", g.candidates);
    let h = body_of(&em.code, "finish__g0");
    println!("{h}");
    assert!(b.contains("finish__g0"), "{b}");
    assert!(!h.contains(">= 62u64") && !b.contains(">= 62u64"), "the guard helper has no check:\n{h}");
    assert!(g.candidates.iter().any(|c| c.chosen && c.reason.contains("guards decided by facts")), "{:?}", g.candidates);
}

// ---------------------------------------------------------------------------
// Generated loops (`for`) as Σ2 heads, the threshold regime (corpus P13).
// ---------------------------------------------------------------------------

/// Corpus P13 (`rank_above`: a `for` loop counting the set bits of `n` at
/// positions above `k`): its generated loop helper is summarized — a
/// `MaskedCount` counter, the closed form `k < 63 ? cnt(n >> (k + 1)) : 0`
/// with its symbolic shift proven per literal by the threshold regime.
#[test]
fn p13_rank_above_closed_form() {
    let dsl = repo("sandblaster/front/tests/opt_corpus/dsl/mod.rs");
    let src = format!("{HEADER}{}\n", item(&dsl, "pub fn rank_above("));
    let em = optimize_src(&src, LoopConfig::default());
    let f = report(&em, "crate::rank_above");
    for c in &f.candidates {
        println!("{:?} chosen={} {}", c.rung, c.chosen, c.reason.chars().take(1500).collect::<String>());
    }
    println!("{}", body_of(&em.code, "rank_above"));
    println!("{}", body_of(&em.code, "rank_above__loop0__closed"));
    assert!(matches!(f.outcome, Outcome::Specialized { .. }));
    assert_eq!(f.rung, Some(Rung::ClosedForm), "{:?}", f.candidates);
    let h = body_of(&em.code, "rank_above__loop0__closed");
    assert!(h.contains("count_ones") && !h.contains("for ") && !h.contains("loop {"), "{h}");
    assert!(body_of(&em.code, "rank_above").contains("rank_above__loop0__closed"));
}

// ---------------------------------------------------------------------------
// The set-bit iteration rung (design §7.6 rung 3) and its enumeration
// lemmas (design §7.5, symbolic fuel).
// ---------------------------------------------------------------------------

#[test]
fn shape_set_bit_iteration() {
    let em = optimize_src(&shape_src(), LoopConfig { synthesis: false, prefer_set_bits: true, ..LoopConfig::default() });
    let f = report(&em, "crate::shape");
    for c in &f.candidates {
        println!("{:?} chosen={} {} {:?}", c.rung, c.chosen, c.reason.chars().take(1500).collect::<String>(), c.rejected_by);
    }
    println!("{}", body_of(&em.code, "shape"));
    println!("{}", body_of(&em.code, "shape_go__bits"));
    assert!(matches!(f.outcome, Outcome::Specialized { .. }));
    assert_eq!(f.rung, Some(Rung::SetBits), "{:?}", f.candidates);
    let h = body_of(&em.code, "shape_go__bits");
    assert!(h.contains("leading_zeros"), "the jump to the next set bit: {h}");
    assert!(f.candidates.iter().any(|c| c.reason.contains("::bits::idle") && c.reason.contains("::bits::equiv")), "{:?}", f.candidates);
}


/// The set-bit rung at another width (fairness audit J6: it used to accept
/// only 64-bit digit variables, the width of QMDB's `shape_go`). A 32-bit
/// binary-digit walk written for this test — the widths `2^30, …, 1`,
/// largest first, counting the widths that fit — gets the rung with its
/// jump stated at `31 + s₀ − lz(v)`, and its enumeration lemmas are
/// kernel-checked. A width-coverage test of the generalized rung, not a
/// held-out measurement.
#[test]
fn set_bit_iteration_at_32_bits() {
    let src = format!(
        "{HEADER}
/// The widths of `n` (below `2^31`) that fit, largest first: one width per call.
#[requires(fuel <= 31)]
#[requires((count as Int) + (fuel as Int) <= 31)]
#[decreases(fuel)]
pub(crate) fn digits_go(fuel: u32, n: u32, width: u32, count: u32) -> u32 {{
    if fuel == 0 {{
        return count;
    }}
    if n < width {{
        digits_go(fuel - 1, n, width / 2, count)
    }} else {{
        digits_go(fuel - 1, n - width, width / 2, count + 1)
    }}
}}

pub fn digits(n: u32) -> u32 {{
    if n >= (1u32 << 31u32) {{
        return 0;
    }}
    digits_go(31, n, 1u32 << 30u32, 0)
}}
"
    );
    let em = optimize_src(&src, LoopConfig { synthesis: false, prefer_set_bits: true, ..LoopConfig::default() });
    let f = report(&em, "crate::digits");
    for c in &f.candidates {
        println!("{:?} chosen={} {} {:?}", c.rung, c.chosen, c.reason.chars().take(1500).collect::<String>(), c.rejected_by);
    }
    println!("{}", body_of(&em.code, "digits"));
    println!("{}", body_of(&em.code, "digits_go__bits"));
    assert!(matches!(f.outcome, Outcome::Specialized { .. }), "{:?}", f.candidates);
    assert_eq!(f.rung, Some(Rung::SetBits), "{:?}", f.candidates);
    let h = body_of(&em.code, "digits_go__bits");
    assert!(h.contains("leading_zeros"), "the jump to the next set bit: {h}");
    assert!(f.candidates.iter().any(|c| c.reason.contains("::bits::idle") && c.reason.contains("::bits::equiv")), "{:?}", f.candidates);
}
