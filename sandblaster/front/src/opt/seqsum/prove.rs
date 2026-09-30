//! The proof of a leaf the segment normal form rewrote (`Step::Seq`).
//!
//! The goal is `Eq(R, L, S)`: `L` the residual's leaf (calls of segment
//! specializations, element reads and sub-slices of the pieces), `S` the
//! source's (reads and slices of the assembled buffer), both terms in the
//! proof's context (`let`s of either side are context binders, resolved
//! through the proof builder's `let` table). The proof is a **congruence
//! walk** over the two terms:
//!
//! * convertible subterms: `refl`;
//! * the helper's own back-edge at the head of `L` (proving a helper's
//!   lemma): the induction hypothesis `rec(ā; d) : Eq(R, H ā, E ā)`; another
//!   helper's call: its lemma `Eq(A, H ā, E ā)`; an entry `E ā`: its body
//!   (definitionally equal);
//! * two slices: their lists are equal by their normal forms
//!   ([`Norm::lists_eq`]), lifted by `slice::ext`;
//! * two element reads (or a read and a value): the elements the normal
//!   form finds, equal ([`Norm::elem_eq`]);
//! * applications of one global (or one primitive, one constructor): the
//!   arguments pairwise, joined by `transport`s whose motives replace one
//!   argument of the source's application.
//!
//! Nothing here is trusted: the kernel checks the lemma the proof is part
//! of.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use sandblaster_kernel::term::{GlobalId, Idx, Lvl, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::Value;

use super::segments::{Elem, EngineOracle, Ids, Norm, head_app};
use crate::auto::search::Engine;
use crate::auto::state::St;
use crate::auto::util::shift;
use crate::opt::proof::build::OwnFold;

/// What the leaf proof needs from the proof builder.
pub struct LeafCtx<'w> {
    /// The function whose lemma is being proven (a residual or a helper).
    pub res: GlobalId,
    /// Proving a segment helper's own lemma: its measure (back-edges).
    pub own: Option<&'w OwnFold>,
    /// Entries and fold recursions by global: `(helper, lemma)`.
    pub folds: &'w HashMap<GlobalId, (GlobalId, GlobalId)>,
    /// The values of the `let`s in scope, by level (each at the depth of its
    /// level).
    pub let_terms: &'w HashMap<u32, Tm>,
}

type R<T> = Result<T, String>;

/// An application rebuilt from its arguments.
type Rebuild<'f> = dyn Fn(&[(Rel, Tm)]) -> Tm + 'f;

thread_local! {
    /// Meter steps by activity (traces).
    static PROFILE: std::cell::RefCell<std::collections::BTreeMap<&'static str, (u64, u64)>> = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

/// Runs `f`, charging the meter steps it spends to `what` (traces).
fn prof<T>(what: &'static str, f: impl FnOnce() -> T) -> T {
    let a = crate::auto::meter::available();
    let t = std::time::Instant::now();
    let r = f();
    let used = a.saturating_sub(crate::auto::meter::available());
    let us = t.elapsed().as_micros() as u64;
    PROFILE.with(|p| {
        let mut p = p.borrow_mut();
        let e = p.entry(what).or_default();
        e.0 += used;
        e.1 += us;
    });
    r
}

/// The profile so far, reset.
fn take_profile() -> String {
    PROFILE.with(|p| {
        let m = std::mem::take(&mut *p.borrow_mut());
        m.iter().map(|(k, (s, us))| format!("{k}: {s} steps {us} us")).collect::<Vec<_>>().join(", ")
    })
}

/// The proof of `Eq(R, L, S)` (see the module docs).
pub fn leaf(cx: &LeafCtx<'_>, e: &mut Engine<'_>, st: &St, r: &Tm, l: &Tm, s: &Tm) -> R<Tm> {
    let env = e.env;
    let ids = Ids::new(env).filter(Ids::has_lemmas).ok_or("the seq lemmas are not loaded")?;
    let helpers: HashMap<GlobalId, (GlobalId, GlobalId)> = cx.folds.iter().map(|(ent, (h, lm))| (*h, (*ent, *lm))).collect();
    let mut entries: HashSet<GlobalId> = cx.folds.keys().copied().collect();
    if let Some(o) = cx.own {
        entries.insert(o.def);
    }
    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
        let names = st.names();
        eprintln!("opt: proof: seq leaf goal (meter {} left, {:?})\n  L = {}\n  S = {}", crate::auto::meter::available(), crate::auto::meter::exhausted(), env.print_term(&names, l).chars().take(1500).collect::<String>(), env.print_term(&names, s).chars().take(1500).collect::<String>());
    }
    let w = Congr { cx, ids, helpers, entries, oracle: Rc::default() };
    // the own back-edge at the head of `L`
    let lr = w.resolve(st, l);
    let (l1, p1) = match (cx.own, head_app(&lr)) {
        (Some(own), Some((g, args))) if g == cx.res => {
            let arg_tms: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
            let dec = prof("decrease", || decrease(e, st, own, &arg_tms))?;
            (mk::apps(mk::global(own.def), args), Some(Rc::new(Term::Rec { args: arg_tms, proof: Some(dec) }) as Tm))
        }
        _ => (lr, None),
    };
    // the R9 fault: the back-edge's induction step claimed (`refl`)
    if let Some(rec) = &p1
        && super::fault_fold_swap()
    {
        return Ok(trans(r, l, &l1, s, rec, &mk::refl(r.clone(), l1.clone())));
    }
    let p = w.prove(e, st, r, &l1, s, 0).inspect_err(|err| {
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
            eprintln!("opt: proof: seq leaf failed: {err} (meter {} left, {:?}; {})", crate::auto::meter::available(), crate::auto::meter::exhausted(), take_profile());
        }
    })?;
    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
        eprintln!("opt: proof: seq leaf proven ({})", take_profile());
    }
    // the leaf's proof checked here, before it goes into the lemma: the
    // walk's rules are untrusted, and a proof the kernel refuses is a proof
    // not found (the helper or the function keeps its source, not an
    // optimizer fault), never a lemma the kernel rejects at its commit. A
    // must-reject run (R5, R9: a claim the builder trusts) skips it, so the
    // kernel judges the lemma.
    if !super::fault_active() {
        // (a budget of its own: the check never starves the proof)
        let mut b = sandblaster_kernel::value::Budget { steps: 1 << 28 };
        let goal = mk::eq(r.clone(), l1.clone(), s.clone());
        let venv = env.ctx_venv(&st.ctx);
        let verdict = env.eval(&venv, Lvl(st.depth()), &goal, &mut b).map_err(|err| format!("{err:?}")).and_then(|gv| env.check(&st.ctx, &p, &gv, &mut b).map_err(|err| err.to_string()));
        if let Err(err) = verdict {
            if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() || std::env::var_os("SANDBLASTER_OPT_SEQ_CHECK").is_some() {
                eprintln!("opt: proof: seq leaf rejected: {err}");
                // (the claims whose certificate the kernel searches)
                crate::elab::tm::any_node(&p, &mut |n| {
                    if let Term::Linarith { cert, goal, .. } = n
                        && cert.is_empty()
                    {
                        eprintln!("  claim: {}", env.print_term(&st.names(), goal).chars().take(400).collect::<String>());
                    }
                    false
                });
            }
            return Err(format!("the leaf's proof does not check ({})", err.chars().take(300).collect::<String>()));
        }
    }
    match p1 {
        Some(rec) => Ok(trans(r, l, &l1, s, &rec, &p)),
        None => Ok(p),
    }
}

struct Congr<'c, 'w> {
    cx: &'c LeafCtx<'w>,
    ids: Ids,
    helpers: HashMap<GlobalId, (GlobalId, GlobalId)>,
    entries: HashSet<GlobalId>,
    /// The oracles' decisions and facts at the leaf's state (shared).
    oracle: Rc<std::cell::RefCell<super::segments::OracleCache>>,
}

/// Recursion depth of the walk.
const MAX_DEPTH: u32 = 64;

impl Congr<'_, '_> {
    /// `t` with a `let`-bound variable at its head replaced by its value
    /// (repeatedly).
    fn resolve(&self, st: &St, t: &Tm) -> Tm {
        let d = st.depth();
        let mut t = t.clone();
        for _ in 0..64 {
            let Term::Var(Idx(i)) = &*t else { break };
            let Some(lvl) = d.checked_sub(1 + i) else { break };
            // (the table outlives sibling branches: only a `let` binder of
            // this context reads it)
            if st.ctx.entries.get(lvl as usize).is_none_or(|en| en.def.is_none()) {
                break;
            }
            let Some(def) = self.cx.let_terms.get(&lvl) else { break };
            t = shift(def, (d - lvl) as i64);
        }
        t
    }

    /// `t` with every `let`-bound variable replaced by its value (for the
    /// normal form, which reads list structure through them).
    fn resolve_deep(&self, st: &St, t: &Tm) -> Tm {
        let d = st.depth();
        let mut fuel = 4096u32;
        fn go(this: &Congr<'_, '_>, st: &St, t: &Tm, d: u32, fuel: &mut u32) -> Tm {
            crate::auto::util::map_term(t, 0, &mut |x, k| match &**x {
                Term::Var(Idx(i)) if *i >= k => {
                    let lvl = (d + k).checked_sub(1 + i)?;
                    if lvl >= d || *fuel == 0 || st.ctx.entries.get(lvl as usize).is_none_or(|en| en.def.is_none()) {
                        return None;
                    }
                    let def = this.cx.let_terms.get(&lvl)?;
                    *fuel -= 1;
                    // the value at its level's depth, resolved there, then
                    // shifted to here
                    let inner = go(this, st, def, lvl, fuel);
                    Some(shift(&inner, (d + k - lvl) as i64))
                }
                _ => None,
            })
        }
        go(self, st, t, d, &mut fuel)
    }

    fn conv(&self, e: &mut Engine<'_>, st: &St, a: &Tm, b: &Tm) -> bool {
        prof("conv", || self.conv_(e, st, a, b))
    }

    fn conv_(&self, e: &mut Engine<'_>, st: &St, a: &Tm, b: &Tm) -> bool {
        e.settle();
        let venv = e.env.ctx_venv(&st.ctx);
        let (Ok(av), Ok(bv)) = (e.env.eval(&venv, Lvl(st.depth()), a, e.b), e.env.eval(&venv, Lvl(st.depth()), b, e.b)) else { return false };
        e.settle();
        e.env.conv(Lvl(st.depth()), &av, &bv, e.b).unwrap_or(false)
    }

    /// The type term of `t`.
    fn type_of(&self, e: &mut Engine<'_>, st: &St, t: &Tm) -> R<Tm> {
        e.settle();
        let ty = e.env.infer(&st.ctx, t, e.b).map_err(|err| format!("a subterm's type: {err}"))?;
        Ok(e.env.quote_typed(&st.ctx, &ty, None, false))
    }

    fn is_slice_ty(&self, e: &Engine<'_>, ty: &Tm) -> bool {
        if let Some((g, _)) = head_app(ty) {
            return e.env.global_name(g).as_deref() == Some("Slice");
        }
        matches!(&**ty, Term::Sigma { fst, .. } if matches!(&**fst, Term::IntTy(Width::Usize)))
    }

    fn is_read(&self, t: &Tm) -> bool {
        head_app(t).is_some_and(|(g, a)| g == self.ids.index && a.len() == 5)
    }

    /// `s[i]` / `a[i]` as the `seq::index` read it is (δ), else `t`.
    fn as_read(&self, e: &Engine<'_>, t: &Tm) -> Tm {
        match head_app(t) {
            Some((g, args)) if (g == self.ids.slice_index && args.len() == 4) || (g == self.ids.array_index && args.len() == 5) => unfold(e, g, &args).unwrap_or_else(|| t.clone()),
            _ => t.clone(),
        }
    }

    /// `Eq(ty, l, s)`.
    fn prove(&self, e: &mut Engine<'_>, st: &St, ty: &Tm, l: &Tm, s: &Tm, depth: u32) -> R<Tm> {
        if depth > MAX_DEPTH {
            return Err("the leaf's terms nest too deeply".into());
        }
        if self.conv(e, st, l, s) {
            return Ok(mk::refl(ty.clone(), l.clone()));
        }
        let lr = self.as_read(e, &self.resolve(st, l));
        let sr = self.as_read(e, &self.resolve(st, s));
        // a helper call on the residual's side: its lemma, then its entry
        if let Some((h, args)) = head_app(&lr)
            && let Some((ent, lemma)) = self.helpers.get(&h).copied()
        {
            let u = mk::apps(mk::global(ent), args.clone());
            let inst = mk::apps(mk::global(lemma), args);
            let q = self.prove(e, st, ty, &u, s, depth + 1)?;
            return Ok(trans(ty, &lr, &u, s, &inst, &q));
        }
        // an entry: its body (definitionally equal)
        if let Some((g, args)) = head_app(&lr)
            && self.entries.contains(&g)
            && e.env.global_arity(g) == Some(args.len() as u32)
            && let Some(body) = unfold(e, g, &args)
        {
            return self.prove(e, st, ty, &body, s, depth + 1);
        }
        if self.is_slice_ty(e, ty) {
            return self.slices(e, st, &lr, &sr);
        }
        if self.is_read(&lr) || self.is_read(&sr) {
            return prof("elements", || self.elements(e, st, ty, &lr, &sr));
        }
        // one head: the arguments pairwise
        if let (Some((g1, a1)), Some((g2, a2))) = (head_app(&lr), head_app(&sr))
            && g1 == g2
            && a1.len() == a2.len()
        {
            let rebuild = |xs: &[(Rel, Tm)]| mk::apps(mk::global(g1), xs.iter().cloned());
            return self.args(e, st, ty, &lr, &a1, &a2, &rebuild, depth);
        }
        if let (Term::Prim { op: o1, args: a1, proofs: p1 }, Term::Prim { op: o2, args: a2, .. }) = (&*lr, &*sr)
            && o1 == o2
            && a1.len() == a2.len()
            && p1.is_empty()
        {
            let op = *o1;
            let xs: Vec<(Rel, Tm)> = a1.iter().map(|a| (Rel::Rel, a.clone())).collect();
            let ys: Vec<(Rel, Tm)> = a2.iter().map(|a| (Rel::Rel, a.clone())).collect();
            let rebuild = |xs: &[(Rel, Tm)]| mk::prim(op, xs.iter().map(|(_, a)| a.clone()).collect(), vec![]);
            return self.args(e, st, ty, &lr, &xs, &ys, &rebuild, depth);
        }
        if let (Term::Ctor { ind: i1, ctor: c1, params, args: a1 }, Term::Ctor { ind: i2, ctor: c2, args: a2, .. }) = (&*lr, &*sr)
            && i1 == i2
            && c1 == c2
            && a1.len() == a2.len()
        {
            let (ind, ctor, params) = (*i1, *c1, params.clone());
            let xs: Vec<(Rel, Tm)> = a1.iter().map(|a| (Rel::Rel, a.clone())).collect();
            let ys: Vec<(Rel, Tm)> = a2.iter().map(|a| (Rel::Rel, a.clone())).collect();
            let rebuild = |xs: &[(Rel, Tm)]| mk::ctor(ind, ctor, params.clone(), xs.iter().map(|(_, a)| a.clone()).collect());
            return self.args(e, st, ty, &lr, &xs, &ys, &rebuild, depth);
        }
        // different heads: unfold a transparent, non-recursive definition at
        // the head of one side (definitionally equal), the source's first
        for (side, other, source) in [(&sr, &lr, true), (&lr, &sr, false)] {
            if let Some((g, args)) = head_app(side)
                && head_app(other).is_none_or(|(g2, _)| g2 != g)
                && e.env.global_opaque(g) == Some(false)
                && e.env.global_kind(g) != Some(sandblaster_kernel::term::DefKind::Intrinsic)
                && e.env.global_arity(g) == Some(args.len() as u32)
                && !crate::opt::symex::is_recursive(e.env, g)
                && let Some(body) = unfold(e, g, &args)
            {
                return if source { self.prove(e, st, ty, &lr, &body, depth + 1) } else { self.prove(e, st, ty, &body, &sr, depth + 1) };
            }
        }
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
            let names = st.names();
            eprintln!("opt: proof: seq: sides differ\n  L = {}\n  S = {}", e.env.print_term(&names, &lr).chars().take(1500).collect::<String>(), e.env.print_term(&names, &sr).chars().take(1500).collect::<String>());
        }
        Err("the leaf's sides differ where the normal form does not apply".into())
    }

    /// `Eq(ty, f(x̄), f(ȳ))` from the arguments (relevant ones; irrelevant
    /// ones are the source's, which conversion ignores).
    #[allow(clippy::too_many_arguments)]
    fn args(&self, e: &mut Engine<'_>, st: &St, ty: &Tm, l: &Tm, xs: &[(Rel, Tm)], ys: &[(Rel, Tm)], rebuild: &Rebuild<'_>, depth: u32) -> R<Tm> {
        // start from `f(x̄)` with the source's irrelevant arguments
        let mut cur: Vec<(Rel, Tm)> = xs.iter().zip(ys).map(|((r1, x), (_, y))| (*r1, if *r1 == Rel::Irr { y.clone() } else { x.clone() })).collect();
        let mut p = mk::refl(ty.clone(), l.clone());
        for i in 0..xs.len() {
            if xs[i].0 == Rel::Irr {
                continue;
            }
            let (x, y) = (&xs[i].1, &ys[i].1);
            if self.conv(e, st, x, y) {
                continue;
            }
            let a_ty = self.type_of(e, st, y)?;
            let q = self.prove(e, st, &a_ty, x, y, depth + 1)?;
            // z. Eq(ty, l, f(y₁ … y_{i−1}, z, x_{i+1} …))
            let mut hole: Vec<(Rel, Tm)> = cur.iter().map(|(r, t)| (*r, shift(t, 1))).collect();
            hole[i] = (Rel::Rel, mk::var(0));
            let motive = mk::eq(shift(ty, 1), shift(l, 1), rebuild(&hole));
            p = Rc::new(Term::Transport { ty: a_ty, lhs: x.clone(), rhs: y.clone(), eq: q, motive, val: p });
            cur[i] = (Rel::Rel, y.clone());
        }
        Ok(p)
    }

    /// Two slices: their lists by the normal form, then `slice::ext`.
    fn slices(&self, e: &mut Engine<'_>, st: &St, l: &Tm, s: &Tm) -> R<Tm> {
        let env = e.env;
        let list_of = |t: &Tm| mk::fst(mk::snd(t.clone()));
        let (la, lb) = prof("resolve", || (self.resolve_deep(st, &list_of(l)), self.resolve_deep(st, &list_of(s))));
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
            let names = st.names();
            eprintln!("opt: proof: seq: slices\n  l = {}\n  s = {}\n  la = {}\n  lb = {}", env.print_term(&names, l).chars().take(600).collect::<String>(), env.print_term(&names, s).chars().take(600).collect::<String>(), env.print_term(&names, &la).chars().take(600).collect::<String>(), env.print_term(&names, &lb).chars().take(600).collect::<String>());
        }
        let t = self.resolve_deep(st, &elem_of_list(e, st, &self.ids, &lb)?);
        let mut o = EngineOracle::with_cache(e, st, self.oracle.clone());
        let mut n = Norm { env, ids: &self.ids, t: t.clone(), oracle: &mut o };
        let q = prof("lists_eq", || n.lists_eq(&la, &lb))
            .map_err(|err| {
                if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                    let names = st.names();
                    eprintln!("opt: proof: seq: lists\n  la = {}\n  lb = {}", env.print_term(&names, &la).chars().take(2000).collect::<String>(), env.print_term(&names, &lb).chars().take(4000).collect::<String>());
                    if let super::segments::NormErr::Undecided(c) = &err {
                        eprintln!("  undecided: {}", env.print_term(&names, &strip_proofs(c)).chars().take(3000).collect::<String>());
                    }
                }
                format!("the slices' lists: {err}")
            })?
            .ok_or("no proof")?;
        Ok(mk::apps(mk::global(self.ids.slice_ext), [(Rel::Rel, t), (Rel::Rel, l.clone()), (Rel::Rel, s.clone()), (Rel::Irr, q)]))
    }

    /// Two elements (a read or a value on each side).
    fn elements(&self, e: &mut Engine<'_>, st: &St, ty: &Tm, l: &Tm, s: &Tm) -> R<Tm> {
        let env = e.env;
        let (ea, pa) = self.element(e, st, ty, l)?;
        let (eb, pb) = self.element(e, st, ty, s)?;
        let mut o = EngineOracle::with_cache(e, st, self.oracle.clone());
        let mut n = Norm { env, ids: &self.ids, t: ty.clone(), oracle: &mut o };
        let qe = n.elem_eq(&ea, &eb).map_err(|err| format!("two reads: {err}"))?.ok_or("no proof")?;
        let (ta, tb) = (n.elem_tm(&ea), n.elem_tm(&eb));
        let back = sym(ty, s, &tb, &pb);
        let tail = trans(ty, &ta, &tb, s, &qe, &back);
        Ok(trans(ty, l, &ta, s, &pa, &tail))
    }

    /// The element a read finds, with `Eq(ty, t, element)`.
    fn element(&self, e: &mut Engine<'_>, st: &St, ty: &Tm, t: &Tm) -> R<(Elem, Tm)> {
        let env = e.env;
        if !self.is_read(t) {
            return Ok((Elem::Val(t.clone()), mk::refl(ty.clone(), t.clone())));
        }
        let (_, args) = head_app(t).ok_or("a read")?;
        let (tt, l, i, h0, h1) = (args[0].1.clone(), args[1].1.clone(), args[2].1.clone(), args[3].1.clone(), args[4].1.clone());
        let l = self.resolve_deep(st, &l);
        // the element type through its `let`s (a read unfolded from the
        // prelude's `slice::index` binds it, `let T = U64`): the terms below
        // use it under binders (motives, congruences) unshifted, which is
        // right only for a closed type
        let tt = self.resolve_deep(st, &tt);
        if !super::segments::closed(&tt) {
            return Err("a read whose element type is not closed".into());
        }
        let mut o = EngineOracle::with_cache(e, st, self.oracle.clone());
        let mut n = Norm { env, ids: &self.ids, t: tt.clone(), oracle: &mut o };
        let r = n.norm(&l).map_err(|err| format!("a read's list: {err}"))?;
        let c = n.canon(&r.pieces);
        let pl = r.proof.clone().ok_or("no proof")?;
        let list_ty = mk::ind(self.ids.list, vec![tt.clone()]);
        let bound_c = Rc::new(Term::Transport {
            ty: list_ty,
            lhs: l.clone(),
            rhs: c.clone(),
            eq: pl.clone(),
            motive: mk::eq_bool(self.ids.bool_ind, mk::prim(PrimOp::Lt(Width::Int), vec![shift(&i, 1), n.len(mk::var(0))], vec![]), true),
            val: h1.clone(),
        }) as Tm;
        let step = mk::apps(
            mk::global(self.ids.lemma("seq::index_list_eq")),
            [(Rel::Rel, tt.clone()), (Rel::Rel, l.clone()), (Rel::Rel, c.clone()), (Rel::Rel, i.clone()), (Rel::Irr, pl), (Rel::Irr, h0.clone()), (Rel::Irr, h1.clone()), (Rel::Irr, bound_c.clone())],
        );
        let (el, pe) = n.index_p(&r.pieces, &i, &h0, &bound_c).map_err(|err| format!("a read: {err}"))?;
        let et = n.elem_tm(&el);
        let mid = n.index(c, i, h0, bound_c);
        Ok((el, trans(ty, t, &mid, &et, &step, &pe.ok_or("no proof")?)))
    }
}

/// `def`'s body at `args` (a full application), by substitution.
fn unfold(e: &Engine<'_>, def: GlobalId, args: &[(Rel, Tm)]) -> Option<Tm> {
    let mut body = e.env.global_body(def)?;
    for _ in 0..args.len() {
        body = match &*body {
            Term::Lam { body, .. } => body.clone(),
            _ => return None,
        };
    }
    let arg_tms: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
    Some(crate::opt::proof::steps::subst_n(&body, &arg_tms))
}

fn sym(a: &Tm, x: &Tm, y: &Tm, p: &Tm) -> Tm {
    Rc::new(Term::Transport { ty: a.clone(), lhs: x.clone(), rhs: y.clone(), eq: p.clone(), motive: mk::eq(shift(a, 1), mk::var(0), shift(x, 1)), val: mk::refl(a.clone(), x.clone()) })
}

fn trans(a: &Tm, x: &Tm, y: &Tm, z: &Tm, p: &Tm, q: &Tm) -> Tm {
    Rc::new(Term::Transport { ty: a.clone(), lhs: y.clone(), rhs: z.clone(), eq: q.clone(), motive: mk::eq(shift(a, 1), shift(x, 1), mk::var(0)), val: p.clone() })
}

/// The decrease proof of the own back-edge at `args`.
fn decrease(e: &mut Engine<'_>, st: &St, own: &OwnFold, args: &[Tm]) -> R<Tm> {
    let d = st.depth();
    if args.len() != own.arity as usize {
        return Err("a back-edge with an unexpected argument count".into());
    }
    let m_args = crate::opt::proof::steps::subst_n(&own.measure, args);
    let m_params = shift(&own.measure, (d - own.arity) as i64);
    e.settle();
    let w = match &*e.env.infer(&st.ctx, &m_args, e.b).map_err(|err| format!("the measure: {err}"))? {
        Value::IntTy(w) => *w,
        _ => return Err("a measure that is not an integer".into()),
    };
    let bi = e.env.bool_ind();
    let lt = mk::eq_bool(bi, mk::prim(PrimOp::Lt(w), vec![m_args.clone(), m_params], vec![]), true);
    // linear in the pieces' lengths: `linarith` over the facts and the
    // slices' length facts first (cheap), the automation otherwise
    let ids = Ids::new(e.env);
    let solve = |e: &mut Engine<'_>, goal: &Tm| -> R<Tm> {
        e.settle();
        let gv = st.eval(e.env, goal, e.b).map_err(|err| format!("evaluation: {err:?}"))?;
        if let (Some(ids), Value::Eq { lhs, .. }, Term::Eq { lhs: c, .. }) = (&ids, &*gv, &**goal)
            && let Some((true, p)) = super::segments::lin_decide(e, ids, st, c, lhs)
        {
            return Ok(p);
        }
        match e.solve(st, gv, true) {
            Ok(Some(p)) => Ok(p),
            _ => Err("the measure does not decrease at a back-edge (not proven)".into()),
        }
    };
    if w != Width::Int {
        return solve(e, &lt);
    }
    let ge0 = mk::eq_bool(bi, mk::prim(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, 0), m_args], vec![]), true);
    let p0 = solve(e, &ge0)?;
    let p1 = solve(e, &lt)?;
    Ok(mk::pair(mk::sigma("_", Rel::Rel, ge0, shift(&lt, 1)), p0, p1))
}

/// The element type of a list term.
fn elem_of_list(e: &mut Engine<'_>, st: &St, ids: &Ids, l: &Tm) -> R<Tm> {
    e.settle();
    let ty = e.env.infer(&st.ctx, l, e.b).map_err(|err| format!("a list's type: {err}"))?;
    match &*ty {
        Value::Ind { ind, params } if *ind == ids.list && params.len() == 1 => Ok(ids.refold(&e.env.quote_typed(&st.ctx, &params[0], None, false))),
        _ => Err("a slice whose list is not a list".into()),
    }
}

/// `t` without its proofs (for traces).
pub fn strip_proofs(t: &Tm) -> Tm {
    fn go(t: &Tm) -> Tm {
        crate::auto::util::map_term(t, 0, &mut |x, _| match &**x {
            Term::Prim { op, args, proofs } if !proofs.is_empty() => Some(mk::prim(*op, args.iter().map(go).collect(), vec![])),
            Term::App { rel: Rel::Irr, fun, .. } => Some(go(fun)),
            Term::Linarith { .. } => Some(Rc::new(Term::Erased)),
            _ => None,
        })
    }
    go(t)
}
