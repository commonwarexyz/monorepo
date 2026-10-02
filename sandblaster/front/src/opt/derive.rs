//! Derived links of multiversioned clones (optimizer design §9.4).
//!
//! A multiversioned clone `f' = f__<set>` is `f` with its calls renamed
//! (`multiversion`). Driving `f'` usually rebuilds `f`'s residual `R` up to
//! the renaming: the driver sees the same body, and the renamed callees have
//! the same summaries. The clone is still driven, printed and elaborated as
//! always (so what is emitted is exactly the driver's result); only the
//! proof of its link changes. Before the proof builder runs, the link of
//! the clone's residual `R'` is tried by transitivity, every step a
//! kernel-checked lemma:
//!
//! ```text
//! R' x̄ = R x̄      mirror (`mirror::prove_clone`): the two bodies are the
//!                  same up to renamed calls, closed by the callees' clone
//!                  lemmas and the derived segment helpers' lemmas below
//! R x̄  = f x̄      f's driven lemma `f__residual::equiv`
//! f x̄  = f' x̄     the clone lemma `f'::clone_equiv`, reversed
//! ```
//!
//! committed as `f'__residual::equiv : Π x̄. Eq(R, R' x̄, f' x̄)`, the name and
//! statement the proof builder would commit (the emission chain checks it
//! the same way). When the bodies differ beyond the renaming, `mirror`
//! gives up (or the kernel rejects the lemma) and the proof builder proves
//! the link from the process tree, as before.
//!
//! A segment helper `h'` of a clone consumer `g'` whose original `g` has a
//! helper `h` of the same shape gets its entry lemma the same way:
//!
//! ```text
//! h' ā = h ā       mirror, a recursive helper by induction on its measure
//! h ā  = E ā       h's entry lemma
//! E ā  = E' ā      mirror of the two entries (`g'::clone_equiv`), reversed
//! ```
//!
//! and `h' = h` is recorded for the mirror proofs of its callers.
//!
//! Nothing is trusted from `f` or `h` beyond their kernel-checked lemmas:
//! the kernel checks every mirror lemma and every link in the clone's own
//! context, and the residual is the clone's own.

use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Recursion as KRecursion, Rel, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::Budget;

use super::seqsum::drive::SegKey;
use super::{Ctx, mirror, symex};
use crate::elab;
use crate::hir::ItemId;

/// The kernel step budget of each derived lemma (a mirror lemma, an entry
/// mirror, a link): a derivation that needs more falls back to the proof
/// builder. The kernel checks a lemma about `f x̄` by comparing the unfolded
/// bodies it mentions, so a derivation through a residual that reaches
/// large straight-line code (a verifier function whose callees inline
/// SHA-256 rounds) can cost more than the proof builder's own proof; the
/// cap keeps those on the builder (deterministically: steps, never time).
const DERIVED_STEPS: u64 = 200_000;

/// A driven residual's link is derived only when its original's proof has
/// at least this many term nodes. The kernel checks a derived link (and
/// the mirror lemma under it) by comparing the two residuals' unfolded
/// bodies, so it costs about what a small proof costs; it pays where the
/// proof builder's proof is large (Σ3 normal forms, linear-arithmetic
/// certificates, many splits). QMDB (N = 32): `reconstruct_finish` 12,409
/// nodes, derived 54k kernel steps against 554k for the proof;
/// `reconstruct` 7,684 and `verify_decoded` 370 nodes, where the derived
/// route took more than the proof (726k and 1.08M steps against 793k and
/// 551k). Segment helpers (loops: the kernel stops unfolding at the
/// recursion) are always derived. Calibrated on QMDB only (the threshold
/// sits between those two functions) until a second workload and the
/// held-out set re-check it.
const DERIVE_MIN_PROOF_NODES: usize = 10_000;

/// A driven function's admitted residual and its link (recorded by
/// `drive_one`).
#[derive(Clone, Copy, Debug)]
pub struct DrivenInfo {
    pub residual: GlobalId,
    /// `Π x̄. Eq(R, residual x̄, f x̄)`.
    pub lemma: GlobalId,
}

/// Tries the link `lemma : Π x̄. Eq(R, rg x̄, g x̄)` of the clone `id`'s
/// driven residual `rg` by transitivity through its original's (see the
/// module docs). `None`: `id` is not a clone of a function with a driven
/// residual.
pub(super) fn residual_link(cx: &mut Ctx<'_>, id: ItemId, rg: GlobalId, g: GlobalId, lemma: &str) -> Option<Result<(), String>> {
    let (o, _) = cx.clone_of.get(&id)?.clone();
    let info = *cx.driven_info.get(&o)?;
    let g_o = *cx.out.fn_globals.get(&o)?;
    let clone_lemma = cx.clone_lemmas.get(&g).filter(|(orig, _)| *orig == g_o).map(|(_, l)| *l)?;
    // (only where the original needed a large proof, see
    // `DERIVE_MIN_PROOF_NODES`)
    if elab::tm::size_capped(&cx.out.env.global_body(info.lemma)?, DERIVE_MIN_PROOF_NODES) < DERIVE_MIN_PROOF_NODES {
        return None;
    }
    let eq = mirror::EqIds::new(&cx.out.env)?;
    let budget = DERIVED_STEPS;
    let mut lemmas = cx.clone_lemmas.clone();
    lemmas.extend(cx.helper_pairs.iter().map(|(k, v)| (*k, *v)));
    let body = cx.out.env.global_body(rg)?;
    let mname = format!("{}::mirror_equiv", cx.global_name(rg));
    let t0 = std::time::Instant::now();
    let m = match mirror::prove_clone(&mut cx.out.env, rg, info.residual, &body, &KRecursion::None, &lemmas, eq, &mname, budget) {
        Ok(m) => m,
        Err(e) => return Some(Err(format!("the residual is not the original's renamed: {e}"))),
    };
    let t1 = t0.elapsed();
    let r = derived_link(&mut cx.out.env, rg, g, info.residual, g_o, m, info.lemma, clone_lemma, eq, lemma, budget).map(|_| ());
    if std::env::var_os("SANDBLASTER_OPT_TIMING").is_some() {
        eprintln!("opt: timing {lemma}: derived (mirror {t1:?}, link {:?}, {})", t0.elapsed() - t1, if r.is_ok() { "ok" } else { "failed" });
    }
    Some(r)
}

/// Tries the entry lemma `name : Π ā. Eq(R, hg ā, entry ā)` of the segment
/// helper `hg` of `key` (whose consumer is a clone) through the helper of
/// the original consumer with the same shape (see the module docs);
/// `captured`: `hg`'s pre-commit definitions (a recursive helper's
/// self-calls). `None`: the consumer is not a clone, or its original has no
/// such helper.
pub(super) fn seg_helper_link(cx: &mut Ctx<'_>, key: &SegKey, hg: GlobalId, entry: GlobalId, name: &str, captured: &[elab::generated::GenDef]) -> Option<Result<GlobalId, String>> {
    let consumer = cx.out.fn_globals.iter().find(|(_, g)| **g == key.def).map(|(i, _)| *i)?;
    let (o, _) = cx.clone_of.get(&consumer)?.clone();
    let g_o = *cx.out.fn_globals.get(&o)?;
    let orig = cx.summaries.seg.entries.get(&SegKey { def: g_o, pos: key.pos, shape: key.shape.clone() })?.clone();
    let h = orig.helper?;
    let eq = mirror::EqIds::new(&cx.out.env)?;
    let budget = DERIVED_STEPS;
    let mut lemmas = cx.clone_lemmas.clone();
    lemmas.extend(cx.helper_pairs.iter().map(|(k, v)| (*k, *v)));
    let r = (|| {
        let (pre, rec) = pre_of(&cx.out.env, hg, captured)?;
        let path = cx.global_name(hg);
        let m = mirror::prove_clone(&mut cx.out.env, hg, h.global, &pre, &rec, &lemmas, eq, &format!("{path}::mirror_equiv"), budget).map_err(|e| format!("the helper is not the original's renamed: {e}"))?;
        // E ā = E' ā: the entries differ only in their consumer
        let entry_body = cx.out.env.global_body(entry).ok_or("an entry without a body")?;
        let cename = format!("{}::clone_equiv", cx.global_name(entry));
        let ce = mirror::prove_clone(&mut cx.out.env, entry, orig.entry, &entry_body, &KRecursion::None, &lemmas, eq, &cename, budget).map_err(|e| format!("the entries: {e}"))?;
        let link = derived_link(&mut cx.out.env, hg, entry, h.global, orig.entry, m, h.lemma, ce, eq, name, budget)?;
        Ok((m, link))
    })();
    Some(r.map(|(m, link)| {
        cx.helper_pairs.insert(hg, (h.global, m));
        link
    }))
}

/// The pre-commit body and recursion of the definition `g` (captured when
/// it is recursive; else its committed body, which has no self-call).
fn pre_of(env: &Env, g: GlobalId, captured: &[elab::generated::GenDef]) -> Result<(Tm, KRecursion), String> {
    match captured.iter().find(|d| d.global == g) {
        Some(d) => Ok((d.body.clone(), d.recursion.clone())),
        None if symex::is_recursive(env, g) => Err("a recursive helper's pre-commit body was not captured".into()),
        None => Ok((env.global_body(g).ok_or("no body")?, KRecursion::None)),
    }
}

/// Commits `name : Π ā. Eq(R, xp ā, yp ā)` over `xp`'s telescope from
/// `m : Π ā. Eq(R, xp ā, x ā)`, `l : Π ā. Eq(R, x ā, y ā)` and
/// `c : Π ā. Eq(R, yp ā, y ā)`: `λā. trans(m ā, trans(l ā, sym(c ā)))`.
#[allow(clippy::too_many_arguments)]
fn derived_link(env: &mut Env, xp: GlobalId, yp: GlobalId, x: GlobalId, y: GlobalId, m: GlobalId, l: GlobalId, c: GlobalId, eq: mirror::EqIds, name: &str, budget: u64) -> Result<GlobalId, String> {
    let tele = symex::telescope(env, xp).ok_or("no telescope")?;
    let n = tele.binders.len();
    let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
    let app = |g: GlobalId| mk::apps(mk::global(g), args.clone());
    let r = tele.ret.clone();
    let rel = |t: Tm| (Rel::Rel, t);
    let trans = |a: Tm, b: Tm, c: Tm, p: Tm, q: Tm| mk::apps(mk::global(eq.trans), [rel(r.clone()), rel(a), rel(b), rel(c), rel(p), rel(q)]);
    let sym_c = mk::apps(mk::global(eq.sym), [rel(r.clone()), rel(app(yp)), rel(app(y)), rel(app(c))]);
    let inner = trans(app(x), app(y), app(yp), app(l), sym_c);
    let mut body = trans(app(xp), app(x), app(yp), app(m), inner);
    let mut ty = mk::eq(r.clone(), app(xp), app(yp));
    for (nm, rl, dom) in tele.binders.iter().rev() {
        ty = mk::pi(nm, *rl, dom.clone(), ty);
        body = mk::lam(nm, *rl, dom.clone(), body);
    }
    let d = DefDecl { name: Rc::from(name), kind: DefKind::Lemma, ty, body, recursion: KRecursion::None, arity: n as u32, opaque: true };
    let mut b = Budget { steps: budget };
    env.add_def(d, &mut b).map_err(|e| e.to_string().chars().take(600).collect())
}

