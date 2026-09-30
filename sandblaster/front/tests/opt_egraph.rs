//! The aegraph and its rule library (docs/optimizer-plan.md O8; optimizer
//! design §10.1, §10.5):
//!
//! * the rule library (`lemmas/rules/*.core`, `lemmas/cong.core`, written by
//!   `sandblaster-rulegen`) loads, i.e. the kernel checks every lemma, and a
//!   wrong rule does not load;
//! * the P3 idiom (a 64-step bit sum) becomes `count_ones`, linked by a
//!   kernel-checked lemma (rung `Rewritten`), and the rewritten code agrees
//!   with the source;
//! * a rule library that fails its kernel check is reported (a warning, an
//!   error in strict mode) and not used at all, not even the rules that
//!   loaded before the failing one;
//! * regions without a trigger never reach `bvnorm` or the library;
//! * determinism: the tuning evidence is an input that changes choices (a
//!   tuning file that makes `count_ones` expensive keeps the bit sum), two
//!   builds with the same inputs are byte-identical, and the choice inputs'
//!   hash keys the proof cache.

use std::path::Path;
use std::sync::Arc;

use sandblaster_front::driver::{self, OptimizedEmit};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::cost::tuning::Tuning;
use sandblaster_front::opt::egraph::rules;
use sandblaster_front::opt::{Link, OptOptions, Outcome, Rung};
use sandblaster_front::target::TargetInfo;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::value::Budget;

const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

/// The P3 idiom (corpus P3): 64 bit extractions summed in `u32`.
pub fn popcount_loop(x: u64) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        c = c.wrapping_add(((x >> i) & 1) as u32);
    }
    c
}

/// The same bits summed from the top: a different order, the same sum
/// modulo word algebra (bvnorm).
pub fn popcount_down(x: u64) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        c = c.wrapping_add(((x >> (63 - i)) & 1) as u32);
    }
    c
}

/// Not the idiom (bit 0 dropped): no rule may apply.
pub fn popcount_high(x: u64) -> u32 {
    let mut c: u32 = 0;
    for i in 1..64u32 {
        c = c.wrapping_add(((x >> i) & 1) as u32);
    }
    c
}

/// No trigger at all.
pub fn mix(a: u64, b: u64) -> u64 {
    (a ^ b).rotate_left(7u32).wrapping_add(a & b)
}
"#;

fn build(tuning: Arc<Tuning>) -> OptimizedEmit {
    build_with(SRC, OptOptions { strict: true, tuning, ..Default::default() }).unwrap()
}

fn build_with(src: &str, opts: OptOptions) -> Result<OptimizedEmit, String> {
    let fs = MemFs::from_files([("p/mod.rs", src)]);
    let c = driver::check(Path::new("p/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let unproven: Vec<String> = out.obligations.iter().filter(|o| !o.proven()).map(|o| format!("{:?}", o)).collect();
        assert!(unproven.is_empty(), "the sample must verify: {}", unproven.join("\n").chars().take(2000).collect::<String>());
        driver::stage::optimize_emit_mode(&c, &mut out, "p/mod.rs", "", &opts, true)
    })
}

fn body<'a>(code: &'a str, f: &str) -> &'a str {
    let at = code.find(&format!("pub fn {f}(")).unwrap_or_else(|| panic!("no {f}"));
    let rest = &code[at..];
    &rest[..rest.find("\n    }\n").unwrap_or(rest.len())]
}

#[test]
fn the_rule_library_loads_and_a_wrong_rule_does_not() {
    elab::with_big_stack(|| {
        let mut env = Env::with_prelude();
        sandblaster_front::auto::lemmas::load(&mut env).unwrap();
        let t = std::time::Instant::now();
        rules::ensure(&mut env).unwrap_or_else(|e| panic!("{e}"));
        println!("rule library checked in {:?}", t.elapsed());
        for n in ["rules::count_ones_sum_u64_u32", "rules::count_ones_sum_u8_u8", "rules::count_ones_sum_usize_usize", "cong::add_l_u64", "cong::shr_r_u32"] {
            assert!(env.lookup_global(n).is_some(), "{n} not loaded");
        }
        let idx = rules::index(&env);
        assert!(idx.len() >= 9, "{} rules", idx.len());
        // a wrong rule: the P3 statement with bit 0 dropped, the correct proof
        let text = rules::BITSUM_CORE;
        let start = text.find("def[lemma] rules::count_ones_sum_u64_u32 :").unwrap();
        let end = start + text[start..].find("\n\n").unwrap_or(text.len() - start);
        let good = &text[start..end];
        let bad = good.replacen("rules::count_ones_sum_u64_u32", "rules::wrong_sum", 1).replacen("#cast_u64_u32(#and_u64(#wshr_u64(x, 0u32), 1u64))", "0u32", 1);
        assert_ne!(good, bad);
        let mut env2 = Env::with_prelude();
        sandblaster_front::auto::lemmas::load(&mut env2).unwrap();
        rules::ensure(&mut env2).unwrap();
        let r = env2.load_core(&bad, &mut Budget { steps: 4_000_000_000 });
        assert!(r.is_err(), "a wrong rule must not load");
        println!("wrong rule rejected: {}", r.unwrap_err().to_string().chars().take(200).collect::<String>());
    });
}

#[test]
fn the_bit_sum_idiom_becomes_count_ones() {
    let em = build(Tuning::shared());
    assert!(em.opt.errors.is_empty() && em.opt.warnings.is_empty() && em.roundtrip.is_empty(), "{:?} {:?} {:?}", em.opt.errors, em.opt.warnings, em.roundtrip);
    for f in ["popcount_loop", "popcount_down"] {
        let r = em.opt.fns.iter().find(|x| x.name == format!("crate::{f}")).unwrap();
        println!("{f}: {:?} {:?}\n  {}", r.rung, r.link, r.candidates.iter().find(|c| c.chosen).map(|c| c.reason.as_str()).unwrap_or(""));
        assert!(matches!(r.outcome, Outcome::Specialized { .. }));
        assert_eq!(r.rung, Some(Rung::Rewritten), "{f}");
        assert_eq!(r.link, Some(Link::Lemma(format!("crate::{f}__residual::equiv"))), "{f}");
        let chosen = r.candidates.iter().find(|c| c.chosen).unwrap();
        assert!(chosen.reason.contains("rules::count_ones_sum_u64_u32"), "{}", chosen.reason);
        assert!(r.candidates.iter().any(|c| c.rung == Rung::StraightLine && c.reason.contains("superseded")), "the conversion-linked residual is superseded");
        let b = body(&em.code, f);
        assert!(b.contains("<u64>::count_ones(") && !b.contains("wrapping_add"), "{f}:\n{b}");
    }
    // not the idiom: the straight-line residual stays
    let r = em.opt.fns.iter().find(|x| x.name == "crate::popcount_high").unwrap();
    assert_eq!(r.rung, Some(Rung::StraightLine));
    assert!(!body(&em.code, "popcount_high").contains("count_ones"));
    let r = em.opt.fns.iter().find(|x| x.name == "crate::mix").unwrap();
    assert_eq!(r.rung, Some(Rung::StraightLine));
    // the emitted code agrees with the source on corners and random inputs
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("opt-egraph");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("gen.rs"), &em.code).unwrap();
    let main = format!(
        r#"include!({gen:?});
fn main() {{
    let mut xs: Vec<u64> = vec![0, 1, u64::MAX, 1 << 63, 0x0123_4567_89ab_cdef];
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..10000 {{ s ^= s << 13; s ^= s >> 7; s ^= s << 17; xs.push(s); }}
    for x in xs {{
        assert_eq!(popcount_loop(x), x.count_ones());
        assert_eq!(popcount_down(x), x.count_ones());
        assert_eq!(popcount_high(x), (x >> 1).count_ones());
    }}
    println!("ok");
}}
"#,
        gen = dir.join("gen.rs")
    );
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let st = std::process::Command::new("rustc").args(["--edition", "2024", "-O", "--cap-lints", "warn", "-o"]).arg(dir.join("p3")).arg(dir.join("main.rs")).output().unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    let run = std::process::Command::new(dir.join("p3")).output().unwrap();
    assert!(run.status.success() && String::from_utf8_lossy(&run.stdout).contains("ok"), "{}", String::from_utf8_lossy(&run.stderr));
}

/// A corrupted rule file (verifier repro): `count_ones_sum_u64_u32` made
/// false (its bit-0 term replaced by `0u32`). The library is loaded when
/// the first trigger fires and fails its kernel check there. The failure
/// is reported (a warning; an error in strict mode), and no rule of the
/// library is used for the rest of the build: `pc16` would match
/// `count_ones_sum_u16_u32`, a rule that loads before the bad one, but it
/// keeps its straight-line residual too.
#[test]
fn a_rule_library_that_fails_its_check_is_reported_and_not_used() {
    const SRC16: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

/// A 16-step bit sum (rule `count_ones_sum_u16_u32`).
pub fn pc16(x: u16) -> u32 {
    let mut c: u32 = 0;
    for i in 0..16u32 {
        c = c.wrapping_add(((x >> i) & 1) as u32);
    }
    c
}

/// The P3 idiom (rule `count_ones_sum_u64_u32`).
pub fn popcount_loop(x: u64) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        c = c.wrapping_add(((x >> i) & 1) as u32);
    }
    c
}
"#;
    let good = rules::BITSUM_CORE;
    let start = good.find("def[lemma] rules::count_ones_sum_u64_u32 :").unwrap();
    let u16_at = good.find("def[lemma] rules::count_ones_sum_u16_u32 :").unwrap();
    assert!(u16_at < start, "the u16 rule loads before the corrupted one");
    let bad = format!("{}{}", &good[..start], good[start..].replacen("#cast_u64_u32(#and_u64(#wshr_u64(x, 0u32), 1u64))", "0u32", 1));
    assert_ne!(bad, good);
    let files = vec![("cong.core".to_string(), rules::CONG_CORE.to_string()), ("rules/bitsum.core".to_string(), bad)];
    let hooks = Arc::new(sandblaster_front::opt::hooks::OptTestHooks { rule_files: Some(files), ..Default::default() });
    // the control: the committed library rewrites both
    let ok = build_with(SRC16, OptOptions { strict: true, ..Default::default() }).unwrap();
    for f in ["crate::pc16", "crate::popcount_loop"] {
        assert_eq!(ok.opt.fns.iter().find(|x| x.name == f).unwrap().rung, Some(Rung::Rewritten), "{f}");
    }
    // not strict: a warning, and nothing rewritten
    let em = build_with(SRC16, OptOptions { hooks: Some(hooks.clone()), ..Default::default() }).unwrap();
    println!("warnings: {:?}", em.opt.warnings);
    assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
    let w: Vec<&String> = em.opt.warnings.iter().filter(|w| w.contains("rule library failed its kernel check")).collect();
    assert_eq!(w.len(), 1, "reported once: {:?}", em.opt.warnings);
    assert!(w[0].contains("lemmas/rules/bitsum.core"), "{}", w[0]);
    for f in ["crate::pc16", "crate::popcount_loop"] {
        let r = em.opt.fns.iter().find(|x| x.name == f).unwrap();
        assert_eq!(r.rung, Some(Rung::StraightLine), "{f}: a half-loaded library must not be used");
    }
    assert!(!em.code.contains("<u16>::count_ones(") && !em.code.contains("<u64>::count_ones("), "no rewrite");
    // strict: an error
    match build_with(SRC16, OptOptions { strict: true, hooks: Some(hooks), ..Default::default() }) {
        Ok(em) => assert!(em.opt.errors.iter().any(|e| e.contains("rule library failed its kernel check")), "{:?}", em.opt.errors),
        Err(e) => assert!(e.contains("rule library failed its kernel check"), "{e}"),
    }
    // and `ensure` on an environment the failed load left half-filled
    // refuses instead of reporting success
    elab::with_big_stack(|| {
        let mut env = Env::with_prelude();
        sandblaster_front::auto::lemmas::load(&mut env).unwrap();
        let bad = format!("{}{}", &good[..start], good[start..].replacen("#cast_u64_u32(#and_u64(#wshr_u64(x, 0u32), 1u64))", "0u32", 1));
        assert!(rules::ensure_files(&mut env, [("cong.core", rules::CONG_CORE), ("rules/bitsum.core", bad.as_str())]).is_err());
        assert!(env.lookup_global("rules::count_ones_sum_u16_u32").is_some(), "the rules before the failure did load");
        let again = rules::ensure(&mut env);
        assert!(again.as_ref().is_err_and(|e| e.contains("partly loaded")), "{again:?}");
    });
}

#[test]
fn tuning_changes_choices_and_nothing_else_does() {
    let a = build(Tuning::shared());
    let b = build(Tuning::shared());
    assert_eq!(a.code, b.code, "same inputs, same output");
    // a tuning file on which `count_ones` is very expensive (a 200-cycle
    // `cnt`): the rewrite is no longer 3% cheaper, the bit sum stays
    let texts: Vec<(String, String)> = sandblaster_targets::evidence::tuning::COMMITTED
        .iter()
        .map(|(n, t)| {
            let t = if n.contains("aarch64") { t.replace("\"op.cnt_v8b.latency_cycles\": {\n      \"value\": 1.9652", "\"op.cnt_v8b.latency_cycles\": {\n      \"value\": 200.0") } else { t.to_string() };
            (n.to_string(), t)
        })
        .collect();
    let slow = Tuning::from_texts(texts).unwrap();
    assert_ne!(slow.hash, Tuning::shared().hash, "the tuning hash covers the change");
    let mut o1 = OptOptions::default();
    let mut o2 = OptOptions::default();
    o2.tuning = Arc::new(slow.clone());
    assert_ne!(sandblaster_front::opt::choice_inputs_hash(&o1), sandblaster_front::opt::choice_inputs_hash(&o2), "the proof cache is keyed by it");
    o1.loops.profile.insert("crate::f".into(), vec![vec![Some(1)]]);
    assert_ne!(sandblaster_front::opt::choice_inputs_hash(&o1), sandblaster_front::opt::choice_inputs_hash(&OptOptions::default()), "and by the profile");
    let c = build(Arc::new(slow));
    let r = c.opt.fns.iter().find(|x| x.name == "crate::popcount_loop").unwrap();
    assert_eq!(r.rung, Some(Rung::StraightLine), "with an expensive count_ones the rewrite is not chosen");
    assert!(!body(&c.code, "popcount_loop").contains("count_ones"));
    assert_ne!(a.code, c.code);
}

/// `cong_irr` (design §10.1): a rewrite whose subterm is an operand of a
/// checked operation whose proof mentions it is lifted to that operation
/// (`cong::add_l_u32`); the kernel checks the resulting link. (The aegraph's
/// regions are proof-free by construction — `opt::egraph::quote_region` —
/// so this path is exercised directly.)
#[test]
fn cong_irr_lifts_a_rewrite_out_of_a_checked_operation() {
    use sandblaster_front::opt::egraph::explain;
    use sandblaster_kernel::term::{DefDecl, DefKind, Recursion, Rel};
    use sandblaster_kernel::util::mk;
    elab::with_big_stack(|| {
        let mut env = Env::with_prelude();
        sandblaster_front::auto::lemmas::load(&mut env).unwrap();
        rules::ensure(&mut env).unwrap();
        let r = rules::index(&env).into_iter().find(|r| r.name == "rules::count_ones_sum_u64_u32").unwrap();
        let lemma = rules::lemma(&env, &r.name).unwrap();
        let lhs_text = env.print_term(&[std::rc::Rc::from("x")], &r.lhs);
        // f x = chain(x) + 0, a checked add whose proof mentions the chain
        let c_text = format!("#add_u32({lhs_text}, 0u32; linarith([]; Eq(Bool, #le_int(#iadd(#cast_u32_int({lhs_text}), #cast_u32_int(0u32)), 4294967295int), true); []))");
        let src = format!("def[spec] t::f : (x : U64) -> U32 :=\n  fun (x : U64) => {c_text}\n");
        env.load_core(&src, &mut Budget { steps: 4_000_000_000 }).unwrap_or_else(|e| panic!("{e}"));
        let f = env.lookup_global("t::f").unwrap();
        let c0 = env.parse_term(&["x"], &c_text).unwrap();
        let target = sandblaster_front::elab::tm::subst0(&r.lhs, &mk::var(0));
        let rhs = sandblaster_front::elab::tm::subst0(&r.rhs, &mk::var(0));
        let rw = explain::Rewrite { target: target.clone(), ty: mk::int_ty(sandblaster_kernel::term::Width::U32), rule: r.name.clone(), lemma, sigma: vec![mk::var(0)], lhs: target, rhs };
        let fx = mk::apps(mk::global(f), [(Rel::Rel, mk::var(0))]);
        let ret = mk::int_ty(sandblaster_kernel::term::Width::U32);
        let mut ex = explain::Explanations::default();
        let (proof, ck) = explain::chain(&env, &mut ex, &c0, &[rw], &ret, &fx).unwrap();
        let shown = env.print_term(&[std::rc::Rc::from("x")], &ck);
        assert!(shown.contains("#count_ones_u64(x)") && shown.contains("#add_u32("), "{shown}");
        let pshown = env.print_term(&[std::rc::Rc::from("x")], &proof);
        assert!(pshown.contains("cong::add_l_u32"), "the rewrite is lifted: {}", pshown.chars().take(400).collect::<String>());
        let ty = mk::pi("x", Rel::Rel, mk::int_ty(sandblaster_kernel::term::Width::U64), mk::eq(ret.clone(), ck.clone(), fx.clone()));
        let body = mk::lam("x", Rel::Rel, mk::int_ty(sandblaster_kernel::term::Width::U64), proof);
        let d = DefDecl { name: std::rc::Rc::from("t::f_rewritten"), kind: DefKind::Lemma, ty, body, recursion: Recursion::None, arity: 1, opaque: true };
        env.add_def(d, &mut Budget { steps: 2_000_000_000 }).unwrap_or_else(|e| panic!("the kernel rejected the lifted explanation: {e}"));
    });
}

/// Headroom fix review: the feature-only sets were priced before cloning on
/// the originals' residuals, which the aegraph chose under the portable
/// model. `bs8`'s bit sum is kept on portable (`count_ones` is "not 3%
/// cheaper" there), so both tables priced the same residual equally and
/// `v4` and `v3_scalar` were not generated, although under `v3_scalar`'s
/// model the clone becomes `count_ones` at about a third of the cost (O8
/// kept these sets). A function with an aegraph match now counts as paying
/// before cloning, and the check on the clones decides.
#[test]
fn pricing_before_cloning_keeps_a_set_whose_clone_the_aegraph_rewrites() {
    use sandblaster_front::opt::hooks::OptTestHooks;
    const BS8: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn bs8(x: u8) -> u32 {
    ((x.wrapping_shr(0u32) & 1u8) as u32).wrapping_add((x.wrapping_shr(1u32) & 1u8) as u32).wrapping_add((x.wrapping_shr(2u32) & 1u8) as u32).wrapping_add((x.wrapping_shr(3u32) & 1u8) as u32).wrapping_add((x.wrapping_shr(4u32) & 1u8) as u32).wrapping_add((x.wrapping_shr(5u32) & 1u8) as u32).wrapping_add((x.wrapping_shr(6u32) & 1u8) as u32).wrapping_add((x.wrapping_shr(7u32) & 1u8) as u32).wrapping_add(x.leading_zeros())
}
"#;
    let fs = MemFs::from_files([("r/mod.rs", BS8)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::x86_64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let hooks = OptTestHooks { set_evidence: ["v4", "v3_scalar"].iter().map(|s| s.to_string()).collect(), ..Default::default() };
    let em = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        assert!(out.obligations.iter().all(|o| o.proven()));
        driver::stage::optimize_emit_mode(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: true, hooks: Some(Arc::new(hooks)), ..Default::default() }, true).unwrap()
    });
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    let sets: Vec<&str> = em.opt.sets.iter().map(|s| s.name.as_str()).collect();
    println!("sets: {sets:?}\nnot cloned: {:?}", em.opt.not_cloned);
    // the original keeps the bit sum (portable model) ...
    let orig = body(&em.code, "bs8");
    assert!(!orig.contains("count_ones"), "{orig}");
    // ... and `v3_scalar` is generated, its clone rewritten to `count_ones`
    assert!(sets.contains(&"v3_scalar"), "v3_scalar not generated: {:?}", em.opt.not_cloned);
    let at = em.code.find("fn bs8__v3_scalar(").expect("no bs8__v3_scalar");
    let clone = &em.code[at..at + em.code[at..].find("\n}\n").unwrap_or(em.code.len() - at)];
    assert!(clone.contains("count_ones"), "{clone}");
    let r = em.opt.fns.iter().find(|x| x.name.ends_with("bs8__v3_scalar")).expect("a report for the clone");
    assert_eq!(r.rung, Some(Rung::Rewritten));
}
