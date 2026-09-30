//! Σ3 sequence summaries (optimizer design §8, plan O7): the lemma library
//! `lemmas/seq.core`, segment normalization, consumer driving over segments,
//! and the must-reject tests R5 and R9.

use sandblaster_kernel::api::Env;
use sandblaster_kernel::value::Budget;

/// The prelude, the lemma library and `seq.core` (read from disk when
/// `SEQ_CORE_PATH` is set: a development loop without recompiling).
fn env_with_seq() -> Result<Env, String> {
    let mut env = Env::try_with_prelude().map_err(|e| e.to_string())?;
    sandblaster_front::auto::lemmas::load(&mut env).map_err(|e| e.to_string())?;
    match std::env::var("SEQ_CORE_PATH") {
        Ok(p) => {
            let text = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
            let text = sandblaster_kernel::expand_templates(&text).map_err(|e| e.to_string())?;
            let mut b = Budget { steps: 4_000_000_000 };
            env.load_core(&text, &mut b).map_err(|e| format!("seq.core: {e}"))?;
        }
        Err(_) => sandblaster_front::opt::seqsum::ensure_lemmas(&mut env)?,
    }
    Ok(env)
}

#[test]
fn seq_core_loads() {
    let t = std::time::Instant::now();
    match env_with_seq() {
        Ok(env) => {
            let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/lemmas/seq.core")).unwrap();
            let names: Vec<&str> = text.lines().filter_map(|l| l.strip_prefix("def[lemma] ").or_else(|| l.strip_prefix("def[spec] "))).filter_map(|l| l.split_whitespace().next()).collect();
            assert!(names.len() > 10);
            for n in &names {
                assert!(env.lookup_global(n).is_some(), "{n} missing");
            }
            eprintln!("{} seq lemmas", names.len());
            eprintln!("seq.core loaded in {:?}", t.elapsed());
        }
        Err(e) => panic!("{e}"),
    }
}

mod norm {
    use std::rc::Rc;

    use sandblaster_front::auto::AutoConfig;
    use sandblaster_front::auto::lemmas::LemmaDb;
    use sandblaster_front::auto::search::Engine;
    use sandblaster_front::auto::state::{Origin, St};
    use sandblaster_front::opt::seqsum::segments::{EngineOracle, Ids, Norm, Piece};
    use sandblaster_kernel::api::{Ctx, Env};
    use sandblaster_kernel::term::{PrimOp, Rel, Tm, Width};
    use sandblaster_kernel::util::mk;
    use sandblaster_kernel::value::Budget;

    fn cast(u: Tm) -> Tm {
        mk::prim(PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![u], vec![])
    }
    fn iadd(a: Tm, b: Tm) -> Tm {
        mk::prim(PrimOp::IAdd, vec![a, b], vec![])
    }
    fn ilit(n: i64) -> Tm {
        mk::lit(Width::Int, n)
    }

    /// `(s : &[u64]) (d : u64) (t : &[u64]) (.h : len s + len t < 62)`.
    fn ctx(env: &Env) -> (St, Tm, Tm, Tm) {
        let mut b = Budget { steps: 1_000_000 };
        let mut st = St::new(env, &Ctx::default(), 0);
        let slice = env.lookup_global("Slice").unwrap();
        let sty = mk::apps(mk::global(slice), [(Rel::Rel, mk::int_ty(Width::U64))]);
        let tv = st.eval(env, &sty, &mut b).unwrap();
        st.push_raw(env, Rc::from("s"), Rel::Rel, tv.clone());
        let u = st.eval(env, &mk::int_ty(Width::U64), &mut b).unwrap();
        st.push_raw(env, Rc::from("d"), Rel::Rel, u);
        st.push_raw(env, Rc::from("t"), Rel::Rel, tv);
        let (s, t) = (st.var(0), st.var(2));
        let h = mk::eq_bool(env.bool_ind(), mk::prim(PrimOp::Lt(Width::Int), vec![iadd(cast(mk::fst(s.clone())), cast(mk::fst(t.clone()))), ilit(62)], vec![]), true);
        let hv = st.eval(env, &h, &mut b).unwrap();
        let lvl = st.depth();
        st.push_raw(env, Rc::from("h"), Rel::Irr, hv.clone());
        st.add_ctx_fact(lvl, hv, Origin::Split);
        let (s, d, t) = (st.var(0), st.var(1), st.var(2));
        (st, s, d, t)
    }

    fn check(env: &Env, st: &St, l: &Tm, expect: &[&str]) {
        let ids = Ids::new(env).expect("seq ids");
        let cfg = AutoConfig { self_check: false, ..AutoConfig::default() };
        let mut db = LemmaDb::default();
        db.refresh(env);
        let mut b = Budget { steps: 200_000_000 };
        let mut e = Engine::new(env, &mut b, &cfg, &db, vec![], st.depth());
        let mut o = EngineOracle::new(&mut e, st);
        let t = mk::int_ty(Width::U64);
        let mut n = Norm { env, ids: &ids, t: t.clone(), oracle: &mut o };
        let r = n.norm(l).unwrap_or_else(|err| panic!("normalization failed: {err} ({err:?})"));
        let kinds: Vec<&str> = r.pieces.iter().map(Piece::kind).collect();
        assert_eq!(kinds, expect);
        let c = n.canon(&r.pieces);
        let list = mk::ind(ids.list, vec![t]);
        let goal = mk::eq(list, l.clone(), c);
        let mut b2 = Budget { steps: 1_000_000_000 };
        let gv = st.eval(env, &goal, &mut b2).unwrap();
        env.check(&st.ctx, r.proof.as_ref().unwrap(), &gv, &mut b2).unwrap_or_else(|err| panic!("the kernel rejects the proof: {err}"));
    }

    #[test]
    fn peak_buffer_normal_form() {
        let env = super::env_with_seq().unwrap();
        let (st, s, d, t) = ctx(&env);
        let ids = Ids::new(&env).unwrap();
        let u64t = mk::int_ty(Width::U64);
        let g = |f: sandblaster_kernel::term::GlobalId, args: Vec<Tm>| mk::apps(mk::global(f), args.into_iter().map(|a| (Rel::Rel, a)));
        let sl = mk::fst(mk::snd(s.clone()));
        let tl = mk::fst(mk::snd(t.clone()));
        let nb = cast(mk::fst(s.clone()));
        let na = cast(mk::fst(t.clone()));
        let rep = g(ids.replicate, vec![u64t.clone(), ilit(62), mk::lit(Width::U64, 0)]);
        // C₁ = take(rep, 0) ++ (B ++ drop(rep, nb)); C₁' = update(C₁, nb, d);
        // C₂ = take(C₁', nb+1) ++ (A ++ drop(C₁', nb+1+na)); take(drop(C₂, 0), nb+1+na)
        let c1 = g(ids.append, vec![u64t.clone(), g(ids.take, vec![u64t.clone(), rep.clone(), ilit(0)]), g(ids.append, vec![u64t.clone(), sl.clone(), g(ids.drop, vec![u64t.clone(), rep.clone(), nb.clone()])])]);
        let c1u = g(ids.update, vec![u64t.clone(), c1, nb.clone(), d.clone()]);
        let m = iadd(iadd(nb.clone(), ilit(1)), na.clone());
        let c2 = g(ids.append, vec![u64t.clone(), g(ids.take, vec![u64t.clone(), c1u.clone(), iadd(nb.clone(), ilit(1))]), g(ids.append, vec![u64t.clone(), tl.clone(), g(ids.drop, vec![u64t.clone(), c1u, m.clone()])])]);
        let l = g(ids.take, vec![u64t.clone(), g(ids.drop, vec![u64t.clone(), c2, ilit(0)]), m]);
        check(&env, &st, &l, &["Seg", "Elem", "Seg"]);
    }

    #[test]
    fn suffix_of_segments() {
        let env = super::env_with_seq().unwrap();
        let (st, s, d, t) = ctx(&env);
        let ids = Ids::new(&env).unwrap();
        let u64t = mk::int_ty(Width::U64);
        let g = |f: sandblaster_kernel::term::GlobalId, args: Vec<Tm>| mk::apps(mk::global(f), args.into_iter().map(|a| (Rel::Rel, a)));
        let sl = mk::fst(mk::snd(s.clone()));
        let tl = mk::fst(mk::snd(t.clone()));
        let cons = mk::ctor(ids.list, 1, vec![u64t.clone()], vec![d.clone(), tl.clone()]);
        let segs = g(ids.append, vec![u64t.clone(), sl.clone(), cons]);
        // with no fact about `len s`, dropping one element is undecided
        let l = g(ids.drop, vec![u64t.clone(), segs, ilit(1)]);
        let cfg = AutoConfig { self_check: false, ..AutoConfig::default() };
        let mut db = LemmaDb::default();
        db.refresh(&env);
        let mut b = Budget { steps: 200_000_000 };
        let mut e = Engine::new(&env, &mut b, &cfg, &db, vec![], st.depth());
        let mut o = EngineOracle::new(&mut e, &st);
        let mut n = Norm { env: &env, ids: &ids, t: u64t.clone(), oracle: &mut o };
        assert!(matches!(n.norm(&l), Err(sandblaster_front::opt::seqsum::segments::NormErr::Undecided(_))));
    }
}

mod pipeline {
    use std::path::Path;
    use std::sync::Arc;

    use sandblaster_front::driver::{self, Checked, OptimizedEmit};
    use sandblaster_front::elab::{self, ProverChain};
    use sandblaster_front::loader::MemFs;
    use sandblaster_front::opt::hooks::OptTestHooks;
    use sandblaster_front::opt::{Link, OptOptions, Outcome, Rung};
    use sandblaster_front::target::TargetInfo;

    fn check_src(src: &str) -> Checked {
        let fs = MemFs::from_files([("r/mod.rs", src)]);
        let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
        assert!(c.ok(), "{}", c.render());
        c
    }

    /// Elaborates (exec code), optimizes (strict unless `lax`) and prints `src`.
    pub fn optimize_with(src: &str, opts: OptOptions) -> OptimizedEmit {
        let c = check_src(src);
        let k = c.krate.as_ref().unwrap();
        elab::with_big_stack(|| {
            let mut chain = ProverChain::standard();
            let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
            assert!(out.obligations.iter().all(|o| o.proven()), "the sample must verify");
            driver::stage::optimize_emit_mode(&c, &mut out, "r/mod.rs", "", &opts, true).unwrap()
        })
    }

    pub fn optimize(src: &str) -> OptimizedEmit {
        let em = optimize_with(src, OptOptions { strict: true, hooks: Some(Arc::new(OptTestHooks::default())), ..Default::default() });
        assert!(em.opt.errors.is_empty(), "optimizer errors: {:?}", em.opt.errors);
        assert!(em.roundtrip.is_empty(), "round trip: {:?}", em.roundtrip);
        em
    }

    pub fn report<'a>(em: &'a OptimizedEmit, name: &str) -> &'a sandblaster_front::opt::FnReport {
        em.opt.fns.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no report for {name}"))
    }

    pub fn body_of(code: &str, name: &str) -> String {
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

    pub fn show(em: &OptimizedEmit) {
        for f in &em.opt.fns {
            match &f.outcome {
                Outcome::Specialized { nodes, .. } => println!("  {}: Specialized {nodes} nodes {:?} {:?}", f.name, f.link, f.rung),
                Outcome::Unspecialized { reason, .. } => println!("  {}: Unspecialized: {}", f.name, reason.chars().take(300).collect::<String>()),
            }
            for c in &f.candidates {
                if !c.chosen {
                    println!("      {:?}: {} ({:?})", c.rung, c.reason.chars().take(600).collect::<String>(), c.rejected_by);
                }
            }
        }
    }

    pub fn driven(em: &OptimizedEmit, name: &str) -> bool {
        let f = report(em, name);
        matches!(f.outcome, Outcome::Specialized { .. }) && f.rung == Some(Rung::Driven) && matches!(f.link, Some(Link::Lemma(_)))
    }

    pub const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

    pub const CONCAT_FOLD: &str = "
fn mix(acc: u64, x: u64) -> u64 {
    (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
}

#[decreases(xs.len())]
fn fold_mix(xs: &[u64], acc: u64) -> u64 {
    match xs {
        [] => acc,
        [h, t @ ..] => fold_mix(t, mix(acc, *h)),
    }
}

pub const CAP: usize = 256;

pub fn concat_fold(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    let na = a.len();
    let nb = b.len();
    if na + nb >= CAP {
        return None;
    }
    let mut buf = [0u64; CAP];
    buf[0..na].copy_from_slice(a);
    buf[na] = mid;
    buf[na + 1..na + 1 + nb].copy_from_slice(b);
    Some(fold_mix(&buf[0..na + 1 + nb], 0))
}
";

    /// P7: the buffer disappears; the fold runs over the pieces.
    #[test]
    fn concat_fold_is_fused() {
        let src = format!("{HEADER}{CONCAT_FOLD}");
        let em = optimize(&src);
        show(&em);
        let b = body_of(&em.code, "concat_fold");
        println!("{b}");
        println!("{}", body_of(&em.code, "fold_mix__seg0"));
        assert!(driven(&em, "crate::concat_fold"));
        assert!(!b.contains("[0u64; 256usize]"), "the buffer is gone: {b}");
    }

    /// Two shapes of one consumer: `[Seg, Elem, Seg]` (created and named
    /// first) and then `[Seg, Seg]`, whose key sorts before it. Each helper
    /// keeps the number its entry got when it was created, so the two names
    /// differ (a helper once was named by its key's position in the
    /// registry, so the second reused the first's name and no code was
    /// emitted for the crate).
    #[test]
    fn two_shapes_of_one_consumer_get_distinct_helpers() {
        let src = format!(
            "{HEADER}{}",
            "
fn mix(acc: u64, x: u64) -> u64 {
    (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
}

#[decreases(xs.len())]
fn fold_mix(xs: &[u64], acc: u64) -> u64 {
    match xs {
        [] => acc,
        [h, t @ ..] => fold_mix(t, mix(acc, *h)),
    }
}

pub const CAP: usize = 64;

pub fn with_mid(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    let na = a.len();
    let nb = b.len();
    if na + nb >= CAP {
        return None;
    }
    let mut buf = [0u64; CAP];
    buf[0..na].copy_from_slice(a);
    buf[na] = mid;
    buf[na + 1..na + 1 + nb].copy_from_slice(b);
    Some(fold_mix(&buf[0..na + 1 + nb], 0))
}

pub fn without_mid(a: &[u64], b: &[u64]) -> Option<u64> {
    let na = a.len();
    let nb = b.len();
    if na + nb >= CAP {
        return None;
    }
    let mut buf = [0u64; CAP];
    buf[0..na].copy_from_slice(a);
    buf[na..na + nb].copy_from_slice(b);
    Some(fold_mix(&buf[0..na + nb], 0))
}
"
        );
        let em = optimize(&src);
        show(&em);
        assert!(driven(&em, "crate::with_mid"));
        assert!(driven(&em, "crate::without_mid"));
        let helpers: Vec<&str> = em.code.lines().filter_map(|l| l.split("fn ").nth(1)).filter_map(|s| s.split('(').next()).filter(|n| n.starts_with("fold_mix__seg")).collect();
        let mut distinct = helpers.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), helpers.len(), "every helper is printed once: {helpers:?}");
        assert!(distinct.len() >= 2, "one helper per shape: {helpers:?}");
        for f in ["with_mid", "without_mid"] {
            let b = body_of(&em.code, f);
            assert!(!b.contains("[0u64; 64usize]"), "the buffer of {f} is gone: {b}");
        }
        // the helper each caller calls is the one of its shape
        let called = |f: &str| -> Vec<String> { distinct.iter().filter(|h| body_of(&em.code, f).contains(&format!("{h}("))).map(|h| h.to_string()).collect() };
        let (w, wo) = (called("with_mid"), called("without_mid"));
        assert_eq!(w.len(), 1, "with_mid calls one helper: {w:?}");
        assert_eq!(wo.len(), 1, "without_mid calls one helper: {wo:?}");
        assert_ne!(w, wo, "the two shapes call different helpers");
    }
}

/// Consumers read through the prelude's element read (`[.., last]`,
/// `xs[n / 2]`) and the segment normal form's failures.
mod consumers {
    use super::pipeline::*;
    use sandblaster_front::opt::Outcome;
    use std::process::Command;

    const SRC: &str = "
fn mix(acc: u64, x: u64) -> u64 {
    (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
}

/// Last element (non-recursive, `[.., last]`).
fn last_of(xs: &[u64]) -> u64 {
    match xs {
        [] => 0,
        [.., l] => *l,
    }
}

/// Middle element.
fn middle(xs: &[u64]) -> u64 {
    let n = xs.len();
    if n == 0 {
        return 0;
    }
    let h = n / 2;
    if h < n { xs[h] } else { 0 }
}

pub const CAP: usize = 64;

pub fn b6_last(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    let na = a.len();
    let nb = b.len();
    if na + nb >= CAP {
        return None;
    }
    let mut buf = [0u64; CAP];
    buf[0..na].copy_from_slice(a);
    buf[na] = mid;
    buf[na + 1..na + 1 + nb].copy_from_slice(b);
    Some(last_of(&buf[0..na + 1 + nb]))
}

pub fn b7_middle(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    let na = a.len();
    let nb = b.len();
    if na + nb >= CAP {
        return None;
    }
    let mut buf = [0u64; CAP];
    buf[0..na].copy_from_slice(a);
    buf[na] = mid;
    buf[na + 1..na + 1 + nb].copy_from_slice(b);
    Some(middle(&buf[0..na + 1 + nb]))
}
";

    /// The emitted code of `em` next to `reference` (plain Rust), compiled
    /// by rustc and compared on `calls` (`M::` stands for the module): the
    /// mismatches, or the compiler's error.
    fn differential(tag: &str, code: &str, reference: &str, calls: &[String]) -> Vec<String> {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("opt-seqsum").join(tag);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sandblaster.rs"), code).unwrap();
        let mut main = String::from("#![allow(warnings)]\ninclude!(\"sandblaster.rs\");\nmod reference {\n");
        main.push_str(reference);
        main.push_str("\n}\nfn main() {\n");
        for call in calls {
            let a = call.replace("M::", "crate::");
            let b = call.replace("M::", "crate::reference::");
            main.push_str(&format!("    {{ let a = format!(\"{{:?}}\", {a}); let b = format!(\"{{:?}}\", {b}); if a != b {{ println!(\"MISMATCH {{a}} {{b}}\"); }} }}\n"));
        }
        main.push_str("    println!(\"done\");\n}\n");
        std::fs::write(dir.join("main.rs"), &main).unwrap();
        let exe = dir.join("gen");
        let st = Command::new("rustc").args(["--edition", "2024", "--cap-lints", "allow", "-C", "overflow-checks=on", "-C", "debug-assertions=on", "-o"]).arg(&exe).arg(dir.join("main.rs")).output().expect("rustc");
        if !st.status.success() {
            return vec![format!("COMPILE ERROR: {}", String::from_utf8_lossy(&st.stderr))];
        }
        let run = Command::new(&exe).output().unwrap();
        let out = String::from_utf8_lossy(&run.stdout).to_string();
        let mut bad: Vec<String> = out.lines().filter(|l| l.starts_with("MISMATCH")).map(String::from).collect();
        if !run.status.success() || !out.contains("done") {
            bad.push(format!("RUN FAILED: {}", String::from_utf8_lossy(&run.stderr)));
        }
        bad
    }

    /// A consumer that reads `[.., last]` or `xs[n / 2]` (the prelude's
    /// element read, unfolded, binds its element type `let T = U64`): its
    /// segment helper's lemma used `T` unshifted under a binder, and the
    /// kernel refused it (TypeMismatch, "expected `Type`, found `Sigma`…"),
    /// an optimizer fault. The element type is now resolved through its
    /// `let`s: both callers are driven, the buffer is gone, and the emitted
    /// code agrees with the source.
    #[test]
    fn last_and_middle_consumers_are_proven() {
        let src = format!("{HEADER}{SRC}");
        let em = optimize(&src);
        show(&em);
        for (f, helper) in [("b6_last", "last_of__seg"), ("b7_middle", "middle__seg")] {
            assert!(driven(&em, &format!("crate::{f}")), "{f} is driven");
            let b = body_of(&em.code, f);
            assert!(!b.contains("[0u64; 64usize]"), "the buffer of {f} is gone: {b}");
            assert!(b.contains(helper), "{f} calls its segment helper: {b}");
        }
        let reference = SRC.replace("#[decreases(xs.len())]\n", "");
        let mut calls = Vec::new();
        let slices = ["&[]", "&[1]", "&[1, 2]", "&[1, 2, 3, 4, 5]", "&[9; 40]"];
        for a in slices {
            for b in slices {
                for f in ["b6_last", "b7_middle"] {
                    calls.push(format!("M::{f}({a}, 77, {b})"));
                }
            }
        }
        let bad = differential("last-middle", &em.code, &reference, &calls);
        assert!(bad.is_empty(), "{bad:#?}");
    }

    /// A segment helper that cannot be built (here: not printable, its
    /// consumer writes an array at a symbolic position) is recorded as
    /// failed, and its caller is driven again with the call kept, as for
    /// fold helpers and loops. It used to end the caller's driving ("not
    /// driven: a segment specialization failed"), losing whatever else the
    /// caller's tree had decided (a guard specialization of the same call,
    /// plan O6 × O7). Here the kept call is not printable either, so the
    /// caller keeps its source; the report says why, and it is not a fault.
    #[test]
    fn a_failed_segment_helper_keeps_the_call() {
        let src = format!(
            "{HEADER}{}",
            "
fn mix(acc: u64, x: u64) -> u64 {
    (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
}

#[decreases(xs.len())]
fn fold_mix(xs: &[u64], acc: u64) -> u64 {
    match xs {
        [] => acc,
        [h, t @ ..] => fold_mix(t, mix(acc, *h)),
    }
}

fn g(xs: &[u64], k: u64) -> u64 {
    let mut buf = [0u64; 8];
    buf[(k % 8) as usize] = 7;
    fold_mix(xs, buf[0] ^ buf[7])
}

pub fn pre(xs: &[u64], x: u64, k: u64) -> u64 {
    if xs.len() >= 8 {
        return 0;
    }
    let mut buf = [0u64; 9];
    buf[0] = x;
    buf[1..1 + xs.len()].copy_from_slice(xs);
    g(&buf[0..1 + xs.len()], k)
}
"
        );
        let em = optimize(&src);
        show(&em);
        let f = report(&em, "crate::pre");
        assert!(matches!(f.outcome, Outcome::Unspecialized { failure: false, .. }), "{:?}", f.outcome);
        let cand = f.candidates.iter().find(|c| c.rung == sandblaster_front::opt::Rung::Driven).expect("a driven candidate");
        assert!(!cand.reason.contains("not driven: a segment specialization failed"), "{cand:?}");
        assert!(cand.reason.contains("a segment specialization was not built, the call kept"), "{cand:?}");
        assert!(cand.rejected_by.is_none(), "{cand:?}");
    }
}

/// The QMDB regression gate (O7): the production instance's
/// `reconstruct_finish` no longer builds its peak buffer; the bagging runs
/// over the pieces `before ‖ [peak] ‖ after`.
mod qmdb {
    use std::path::Path;

    use sandblaster_front::driver;
    use sandblaster_front::elab::{self, ProverChain};
    use sandblaster_front::loader::RealFs;
    use sandblaster_front::opt::{Link, OptOptions, Outcome, Rung};
    use sandblaster_front::target::TargetInfo;

    use super::pipeline::body_of;

    #[test]
    #[ignore = "the full QMDB instance (run explicitly, --test-threads=1)"]
    fn reconstruct_finish_is_fused() {
        let rel = "sandblaster/fixtures/qmdb/sandblaster/mod.rs";
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel);
        let c = driver::check(&path, &RealFs, &TargetInfo::aarch64_apple_darwin());
        let k = c.krate.as_ref().unwrap();
        elab::with_big_stack(|| {
            let mut chain = ProverChain::standard();
            let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
            let t = std::time::Instant::now();
            let em = driver::stage::optimize_emit_mode(&c, &mut out, rel, "", &OptOptions { strict: false, ..Default::default() }, true).unwrap();
            println!("optimized in {:?}", t.elapsed());
            let names = ["crate::merkle::reconstruct_finish", "crate::merkle::root", "crate::merkle::bag_prefix", "crate::merkle::fold_back", "crate::merkle::uint64", "crate::merkle::location", "crate::merkle::parse"];
            for f in &em.opt.fns {
                if !(names.contains(&f.name.as_str()) || f.name.contains("__seg") || f.name.contains("reconstruct")) {
                    continue;
                }
                match &f.outcome {
                    Outcome::Specialized { nodes, .. } => println!("  {}: Specialized {nodes} nodes {:?} {:?} {}ms", f.name, f.link, f.rung, f.millis),
                    Outcome::Unspecialized { reason, .. } => println!("  {}: Unspecialized: {}", f.name, reason.chars().take(600).collect::<String>()),
                }
                for c in &f.candidates {
                    if !c.chosen {
                        println!("      {:?}: {} ({:?})", c.rung, c.reason.chars().take(800).collect::<String>(), c.rejected_by);
                    }
                }
            }
            for e in &em.opt.errors {
                println!("error: {}", e.chars().take(800).collect::<String>());
            }
            let b = body_of(&em.code, "reconstruct_finish");
            println!("{b}");
            for line in em.code.lines().filter(|l| l.contains("fn ") && l.contains("__seg")) {
                let name = line.split("fn ").nth(1).and_then(|s| s.split('(').next()).unwrap_or("");
                println!("{}", body_of(&em.code, name));
            }
            if let Ok(dir) = std::env::var("O7_EMIT") {
                std::fs::write(Path::new(&dir).join("sandblaster.rs"), &em.code).unwrap();
            }
            let f = em.opt.fns.iter().find(|f| f.name == "crate::merkle::reconstruct_finish").expect("reconstruct_finish");
            assert!(matches!(f.outcome, Outcome::Specialized { .. }) && f.rung == Some(Rung::Driven) && matches!(f.link, Some(Link::Lemma(_))), "reconstruct_finish is driven");
            assert!(!b.contains("[[0u8; 32usize]; 62usize]"), "the buffer is gone");
        });
    }
}
