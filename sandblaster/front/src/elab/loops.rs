//! Loops (DESIGN.md §7.4, normative desugaring). Every loop becomes a
//! measure-recursive helper definition named `<fn>::loop#k` (`k` =
//! `LoopInfo::index`, source order within the function):
//!
//! * `for i in a..b { B }` ≡ `if a < b { f::loop#k(a, M.., R..) } else {
//!   M.. }` where the helper has parameters: the function's type
//!   parameters, `i`, the locals `M` the loop assigns (sorted by id), the
//!   locals `R` it reads (sorted by id; the loop bounds' variables
//!   included); requires `a ≤ i` (when `a` is expressible over the
//!   parameters), `i < b`, every fact in scope at the loop head whose
//!   variables are all parameters, and the user invariants; body `B; let
//!   i' = i + 1; <h_next: the invariants at i', M'>; if i' < b { rec(i',
//!   M'.., R..) } else { M'.. }`; measure `b − i` (over `Int`). The
//!   invariants at `i + 1` are proven once, before the branch
//!   ([`Elab::next_invariants`]): the recursive call (preservation) and the
//!   exit (the post-loop lemma) both use them.
//! * `for i in a..=b` adds `done: bool` after `i` (mirroring
//!   `RangeInclusive`): `if a ≤ b { loop#k(a, false, ..) } else { M.. }`,
//!   body `if done { M.. } else { B; if i < b { rec(i + 1, false, M'..) }
//!   else { rec(i, true, M'..) } }`, requires `a ≤ i ≤ b`, measure `(b − i)
//!   + (done ? 0 : 1)`; no overflow at `b = MAX`.
//! * `while c { B }` with `decreases(e)`: parameters `M, R`; requires facts
//!   and invariants; body `if c { B; rec(M'.., R..) } else { M.. }`; measure
//!   `e`; the call is unconditional.
//!
//! The helper returns `M` (a tuple, the single value, or `()`); the call
//! site binds it and continues with the new SSA versions. Invariant entry
//! (at the call site) and preservation (at `rec`) are obligations.
//!
//! # Post-loop facts
//!
//! Nothing is asserted after the loop about `a` and `b`; the invariants
//! hold there by a lemma. The post-state statement `Post(v)` of a loop
//! says what holds of the helper's result `v` (the mutated locals): the
//! invariants at the exit index — `i := b` for `a..b`; for `a..=b`, `i :=
//! b + 1`, exactly over `Int` when the invariants use `i` only as `i as
//! Int` (also for `b = MAX`), else under the premise `b < MAX` — and for
//! `while` `¬c` (`a = true → ¬b` for `a && b`, `a = false ∧ ¬b` for `a ||
//! b`). Only propositions are stated (a disjunction in its implication
//! form, [`Elab::propify`]). `for` statements have the binders `z` (the
//! index), `ret` and `hz : z = b`, so the same statement can be proven at
//! another index and moved to `b` by a transport: the exit of `a..b` is
//! proven at `i + 1` (the shape of preservation), the empty range at `a`
//! (the shape of entry).
//!
//! * `f::loop#k::ensures : Π(params)(h :Irr requires)[(hd :Irr done =
//!   false)]. Squash(Post(f::loop#k params h))` (`Squash(P) = Σ(_ : Unit)
//!   ×Irr P`) is proven by walking the helper body ([`Elab::walk_body`],
//!   shared with `f::ensures`): the exits are `InvariantExit` obligations
//!   (one per conjunct, proven irrelevantly — the squash carries them —
//!   first from the proofs the helper already has at the sibling position,
//!   [`Hints`]), every recursive call is the induction hypothesis `rec(args;
//!   measure proof)` (measure recursion with the helper's measure), the
//!   final call `H(b, true, M')` of `a..=b` unfolds to `M'` by `delta`.
//!   A generated conjunct (`¬c`, the implication form of a disjunction)
//!   that cannot be proven is left out, with a warning, and the lemma built
//!   again.
//! * The call site binds `h_loop :Irr [a ≤ b →] Post(J)` after the join
//!   `let loop = J` (`J` = `if a < b { H(a, ..) } else { M }`; `loop` is
//!   `J` by definition), proven by mirroring `J` into a squash and opening
//!   it: the lemma in the `true` arm, the statement at `a` moved to `b` in
//!   the `false` arm (the empty range; `InvariantExit`). The elaboration
//!   context states it about the destructured locals ([`Elab::post_fact`]).
//!   The premise is left out when `a` is the literal `0` or `a ≤ b` holds
//!   by evaluation.
//! * A `for` loop without invariants has no lemma.
//! * Nothing comes for free: the lemma is kernel-checked and applied to the
//!   entry proofs, so an invariant that fails at entry, preservation or
//!   exit fails the build, and a helper or lemma that does not check binds
//!   no fact.

use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

use sandblaster_kernel::term::{DefKind, GlobalId, Lvl, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::{mk, shift, shift_from};

use super::ensures::{strip_lams, WalkGoal};
use super::exec::{Answer, K};
use super::items::{lam_tele, pi_tele, TBinder};
use super::{internal, unsupported, Elab, FnState, Mode, RecInfo, Val, R};
use crate::hir::*;
use crate::prover::{FactOrigin, FactRef, ObligationKind};
use crate::span::Span;
use crate::visit::{self, Visitor};

/// A continuation given the levels of the facts `h_next`
/// ([`Elab::next_invariants`]).
type NextK<'k, 'a> = dyn FnMut(&mut Elab<'a>, &[Option<u32>]) -> R<Tm> + 'k;

/// Locals referenced by an expression.
fn free_locals(e: &Expr) -> BTreeSet<LocalId> {
    struct V(BTreeSet<LocalId>);
    impl Visitor for V {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Local(l) = &e.kind {
                self.0.insert(*l);
            }
            visit::walk_expr(self, e);
        }
    }
    let mut v = V(BTreeSet::new());
    v.expr(e);
    v.0
}

/// A helper binder: name, relevance, type term (at its own depth).
struct Binder {
    name: String,
    rel: Rel,
    ty: Tm,
}

impl<'a> Elab<'a> {
    /// A loop in exec code (see the module docs).
    pub fn loop_(&mut self, l: &'a Loop, k: &mut K<'_, 'a>) -> R<Tm> {
        // the invariant facts of values projected in the bounds, invariants,
        // measure and condition (elaborated in pure contexts, §15.3) are
        // bound before the loop: its entry obligations and the helper's
        // carried facts see them
        let mut es: Vec<&Expr> = l.info.invariants.iter().chain(l.info.decreases.iter()).collect();
        match &l.kind {
            LoopKind::ForRange { lo, hi, .. } => es.extend([lo, hi]),
            LoopKind::While { cond } => es.push(cond),
        }
        let span = l.span;
        self.prebind_inv_facts(&es, &[], span, &mut |s| s.loop_inner(l, &mut *k))
    }

    fn loop_inner(&mut self, l: &'a Loop, k: &mut K<'_, 'a>) -> R<Tm> {
        let span = l.span;
        if let Some(g) = l.info.read.iter().find(|x| self.f.scope.ghost_locals.contains_key(x)) {
            let name = self.local_decl(*g).name.clone();
            return unsupported(span, format!("this loop mentions the `#[ghost]` parameter `{name}`; loops over ghost parameters are not supported yet (state the fact before the loop with `proof! {{ assert(..); }}` over exec values)"));
        }
        let in_scope = |me: &Self, x: &LocalId| me.f.scope.locals.contains_key(x);
        let mutated: Vec<LocalId> = l.info.mutated.iter().copied().filter(|x| in_scope(self, x)).collect();
        let loop_var = match &l.kind {
            LoopKind::ForRange { var, .. } => *var,
            LoopKind::While { .. } => None,
        };
        let mut read: BTreeSet<LocalId> = l.info.read.iter().copied().collect();
        if let LoopKind::ForRange { lo, hi, .. } = &l.kind {
            for x in free_locals(hi) {
                if mutated.contains(&x) {
                    return unsupported(hi.span, "the loop bound depends on a variable the loop assigns; bind the bound to a local first");
                }
                read.insert(x);
            }
            for x in free_locals(lo) {
                if !mutated.contains(&x) {
                    read.insert(x);
                }
            }
        }
        let mut read: BTreeSet<LocalId> = read.into_iter().filter(|x| in_scope(self, x) && !mutated.contains(x) && Some(*x) != loop_var).collect();
        // read locals defined by a `let` whose (proof-free) definition is
        // carried as an equation (e.g. `let k = n.min(xs.len())` for
        // `for i in 0..k { xs[i] }`): the locals of the definition are read
        // too
        loop {
            let mut more = Vec::new();
            for x in &read {
                if let Some((_, lvls)) = self.local_def(*x) {
                    for l in lvls {
                        if let Some((id, _)) = self.f.scope.locals.iter().find(|(_, v)| **v == l)
                            && !read.contains(id)
                            && !mutated.contains(id)
                            && Some(*id) != loop_var
                        {
                            more.push(*id);
                        }
                    }
                }
            }
            if more.is_empty() {
                break;
            }
            read.extend(more);
        }
        let read: Vec<LocalId> = read.into_iter().collect();
        // the helper
        let (helper, hinfo) = self.loop_helper(l, &mutated, &read)?;
        let unit = Ty::unit();
        let jt = self.join_ty(&unit, &mutated);
        // the post-loop lemma `f::loop#k::ensures`
        let lemma = self.post_lemma(l, helper, &hinfo, &mutated, &read, &jt);
        // the call site: a join over the mutated locals
        let answer = Answer::Ty(jt.clone());
        let saved_answer = std::mem::replace(&mut self.f.answer, jt.clone());
        let res = self.loop_call(l, helper, &mutated, &read, &answer, span);
        self.f.answer = saved_answer;
        let jterm = res?;
        let jv = Val::new(jterm.clone(), self.depth());
        let jty = self.ty(&jt, span)?;
        let mutated2 = mutated.clone();
        // the join binder: the local itself when the loop assigns one local
        // (so goals after the loop print its name), else `loop`
        let jname = match mutated.as_slice() {
            [x] => self.local_decl(*x).name.clone(),
            _ => "loop".to_string(),
        };
        self.let_in(&jname, Rel::Rel, jty, jterm, &mut |s, lj| match &lemma {
            None => s.destructure_loop(lj, &jt, &mutated2, 0, span, k),
            // after the loop: the post-loop fact, then the rest
            Some(e) => s.destructure_loop(lj, &jt, &mutated2, 0, span, &mut |s, u| s.post_fact(l, e, &jv, &mutated2, &jt, &mut |s| k(s, u.clone()))),
        })
    }

    /// The definition of a `let`-bound local, as a proof-free term at the
    /// local's level, with the levels it mentions (`None` for parameters,
    /// definitions carrying proofs, and non-`let` locals).
    pub fn local_def(&self, x: LocalId) -> Option<(Tm, Vec<u32>)> {
        let lvl = *self.f.scope.locals.get(&x)?;
        let e = self.f.scope.ctx.entries.get(lvl as usize)?;
        let sandblaster_kernel::value::Arg::Rel(v) = e.def.as_ref()? else { return None };
        let t = self.env.quote(sandblaster_kernel::term::Lvl(lvl), v, false);
        use sandblaster_kernel::term::Term;
        let proofs = super::tm::any_node(&t, &mut |n| {
            matches!(n, Term::Linarith { .. } | Term::Absurd { .. } | Term::Transport { .. } | Term::Delta { .. } | Term::Unfold { .. } | Term::Axiom { .. } | Term::Rec { .. } | Term::Erased | Term::BvRefl { .. } | Term::Refl { .. })
                || matches!(n, Term::Prim { proofs, .. } if !proofs.is_empty())
                || matches!(n, Term::App { rel: Rel::Irr, .. } | Term::Lam { .. } | Term::Match { .. })
        });
        if proofs || super::tm::size_capped(&t, 200) >= 200 {
            return None;
        }
        let mut lvls = Vec::new();
        let _ = super::tm::map_post(&t, 0, &mut |n, b| {
            if let Term::Var(sandblaster_kernel::term::Idx(i)) = &*n
                && *i >= b
            {
                lvls.push(lvl - 1 - (*i - b));
            }
            Some(n)
        });
        lvls.sort();
        lvls.dedup();
        Some((t, lvls))
    }

    fn destructure_loop(&mut self, lj: u32, jt: &Ty, mutated: &[LocalId], i: usize, span: Span, k: &mut K<'_, 'a>) -> R<Tm> {
        if mutated.len() == 1 {
            self.f.scope.locals.insert(mutated[0], lj);
        }
        if mutated.len() <= 1 || i == mutated.len() {
            let u = self.unit_val();
            return self.cont(k, u);
        }
        let Ty::Tuple(comps) = jt else { return internal(span, "loop join type") };
        let (ind, params) = self.ind_of(jt, span)?;
        let l = mutated[i];
        let fty = self.ty(&comps[i], span)?;
        let pr = self.proj(ind, params, self.f.scope.var(lj), i, comps.len(), fty.clone());
        let name = self.local_decl(l).name.clone();
        self.let_in(&name, Rel::Rel, fty, pr, &mut |s, lvl| {
            s.f.scope.locals.insert(l, lvl);
            s.destructure_loop(lj, jt, mutated, i + 1, span, k)
        })
    }

    /// The tuple of the current values of `ls`.
    fn locals_tuple(&mut self, ls: &[LocalId], span: Span) -> R<Tm> {
        let mut vals = Vec::new();
        let mut tys = Vec::new();
        for l in ls {
            vals.push(self.local_tm(*l, span)?);
            tys.push(self.ty(&self.local_decl(*l).ty, span)?);
        }
        if vals.len() == 1 {
            return Ok(vals.pop().unwrap());
        }
        self.tuple_val(tys, vals, span)
    }

    /// The call site: `if a < b { helper(..) } else { M }` (for), `helper(..)`
    /// (while).
    fn loop_call(&mut self, l: &'a Loop, helper: GlobalId, mutated: &[LocalId], read: &[LocalId], answer: &Answer, span: Span) -> R<Tm> {
        let ngen = self.f.ngen;
        let mut targs: Vec<Tm> = (0..ngen).map(|i| self.f.scope.var(i)).collect();
        match &l.kind {
            LoopKind::ForRange { lo, hi, inclusive, .. } => {
                let lo_t = self.pure_loop_value(lo)?;
                let hi_t = self.pure_loop_value(hi)?;
                let w = match lo.ty.peel_refs() {
                    Ty::Uint(u) => u.width(),
                    _ => return internal(span, "loop bound type"),
                };
                let test = mk::prim(if *inclusive { PrimOp::Le(w) } else { PrimOp::Lt(w) }, vec![lo_t.clone(), hi_t], vec![]);
                let d0 = self.depth();
                let lo_v = Val::new(lo_t, d0);
                let incl = *inclusive;
                self.if_then_else(test, answer, span, &mut |s, b| {
                    if !b {
                        return s.locals_tuple(mutated, span);
                    }
                    let d = s.depth();
                    let mut args: Vec<Tm> = (0..ngen).map(|i| s.f.scope.var(i)).collect();
                    args.push(lo_v.at(d));
                    if incl {
                        args.push(s.bool_lit(false));
                    }
                    for x in mutated.iter().chain(read) {
                        args.push(s.local_tm(*x, span)?);
                    }
                    s.helper_app(helper, args, span)
                })
            }
            LoopKind::While { .. } => {
                for x in mutated.iter().chain(read) {
                    targs.push(self.local_tm(*x, span)?);
                }
                self.helper_app(helper, targs, span)
            }
        }
    }

    /// `helper args proofs` (entry obligations).
    fn helper_app(&mut self, helper: GlobalId, args: Vec<Tm>, span: Span) -> R<Tm> {
        let ty = self.env.global_type(helper).ok_or_else(|| super::ElabError { span, msg: "loop helper without type".into(), kind: super::ErrKind::Internal })?;
        let kinds = self.helper_kinds.get(&helper).cloned().unwrap_or_default();
        let kinds = kinds.into_iter().map(|k| if k == ObligationKind::InvariantPreserve { ObligationKind::InvariantEntry } else { k }).collect::<Vec<_>>();
        let (app, _, _) = self.apply_tele(&ty, args, Some(mk::global(helper)), None, &|i| kinds.get(i).cloned().unwrap_or(ObligationKind::WellFormed), span)?;
        Ok(app)
    }

    /// A loop bound (evaluated once at the loop head; must not bind).
    fn pure_loop_value(&mut self, e: &'a Expr) -> R<Tm> {
        let d = self.depth();
        let mut out = None;
        let _ = self.in_pure(|s| {
            s.expr(e, &mut |s, v| {
                out = Some(v.clone());
                Ok(s.unit_val())
            })
        })?;
        match out {
            Some(v) if v.depth == d => Ok(v.at(d)),
            _ => unsupported(e.span, "loop bounds must be simple expressions (no blocks or branches)"),
        }
    }

    /// Builds and adds the helper definition.
    fn loop_helper(&mut self, l: &'a Loop, mutated: &[LocalId], read: &[LocalId]) -> R<(GlobalId, HelperInfo)> {
        let span = l.span;
        let name = format!("{}::loop#{}", self.f_root_name(), l.info.index);
        // facts of the parent that mention only parameters of the helper
        let parent_scope = self.f.scope.clone();
        let parent_ngen = self.f.ngen;
        let mut param_levels: HashMap<u32, usize> = HashMap::new(); // parent level -> helper param position
        for i in 0..parent_ngen {
            param_levels.insert(i, i as usize);
        }
        // helper state
        let mut st = FnState::new(name.clone(), self.f.item, self.f.locals, span);
        st.ngen = parent_ngen;
        st.mode = Mode::Exec;
        st.opaque = self.f.opaque;
        let parent = std::mem::replace(&mut self.f, st);
        let res = self.loop_helper_inner(l, mutated, read, &parent, &parent_scope, &mut param_levels, span);
        let helper_state = std::mem::replace(&mut self.f, parent);
        // merge helper-created helpers (nested loops) into the parent
        self.f.helpers.extend(helper_state.helpers.iter().map(|(k, v)| (*k, *v)));
        let (ty, body, arity, (measure, width), kinds) = res?;
        let failed = helper_state.failed;
        if failed {
            self.f.failed = true;
        }
        let g = self.add_definition(&name, DefKind::LoopHelper, self.f.item, ty, body, Recursion::Measure { measure: measure.clone() }, arity, helper_state.opaque, failed, span)?;
        let checked = self.defs.last().is_some_and(|d| d.global == Some(g) && d.status == super::DefStatus::Checked);
        self.f.helpers.insert(l.info.index, g);
        self.helper_kinds.insert(g, kinds);
        Ok((g, HelperInfo { name, arity, measure, width, checked }))
    }

    /// The kernel name of the function whose loops are being numbered.
    fn f_root_name(&self) -> String {
        match self.f.name.find("::loop#") {
            Some(i) => self.f.name[..i].to_string(),
            None => self.f.name.clone(),
        }
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn loop_helper_inner(&mut self, l: &'a Loop, mutated: &[LocalId], read: &[LocalId], parent: &FnState<'a>, parent_scope: &super::Scope, param_levels: &mut HashMap<u32, usize>, span: Span) -> R<(Tm, Tm, u32, (Tm, Width), Vec<ObligationKind>)> {
        let mut binders: Vec<Binder> = Vec::new();
        let mut kinds: Vec<ObligationKind> = Vec::new(); // per irrelevant binder
        macro_rules! bind {
            ($name:expr, $rel:expr, $ty:expr) => {{
                let ty: Tm = $ty;
                let lvl = self.push($name, $rel, &ty, None)?;
                binders.push(Binder { name: $name.to_string(), rel: $rel, ty });
                lvl
            }};
        }
        for i in 0..parent.ngen {
            let n = parent_scope.ctx.entries[i as usize].name.to_string();
            bind!(&n, Rel::Rel, mk::ty());
        }
        let (var_ty, inclusive) = match &l.kind {
            LoopKind::ForRange { lo, inclusive, .. } => (Some(lo.ty.peel_refs().clone()), *inclusive),
            LoopKind::While { .. } => (None, false),
        };
        let mut i_lvl = None;
        let mut done_lvl = None;
        if let (Some(t), LoopKind::ForRange { var, .. }) = (&var_ty, &l.kind) {
            let n = var.map(|v| self.local_decl(v).name.clone()).unwrap_or_else(|| "_i".into());
            let tt = self.ty(t, span)?;
            let lv = bind!(&n, Rel::Rel, tt);
            if let Some(v) = var {
                self.f.scope.locals.insert(*v, lv);
            }
            i_lvl = Some(lv);
            if inclusive {
                let b = mk::bool_ty(self.p.bool_);
                done_lvl = Some(bind!("done", Rel::Rel, b));
            }
        }
        for x in mutated.iter().chain(read) {
            let decl = self.local_decl(*x);
            let t = self.ty(&decl.ty, span)?;
            let n = decl.name.clone();
            let lv = bind!(&n, Rel::Rel, t);
            self.f.scope.locals.insert(*x, lv);
            if let Some(pl) = parent_scope.locals.get(x) {
                param_levels.insert(*pl, lv as usize);
            }
        }
        // the invariant facts of the parameters (§15.3): hints of every
        // proof slot of the helper — its type (bounds, invariants, measure)
        // is built before any body binder
        for x in mutated.iter().chain(read) {
            let Some(lv) = self.f.scope.local(*x) else { continue };
            let lty = self.local_decl(*x).ty.clone();
            let v = Val::new(self.f.scope.var(lv), self.depth());
            self.add_inv_hints(&v, &lty, span)?;
        }
        // range requires
        let mut lo_hi: Option<(Tm, Tm, Width)> = None;
        if let (Some(iv), LoopKind::ForRange { lo, hi, .. }) = (i_lvl, &l.kind) {
            let w = match lo.ty.peel_refs() {
                Ty::Uint(u) => u.width(),
                _ => return internal(span, "loop variable type"),
            };
            let lo_t = self.pure_loop_value(lo);
            let hi_t = self.pure_loop_value(hi)?;
            if let Ok(lo_t) = lo_t {
                let g = self.holds(mk::prim(PrimOp::Le(w), vec![lo_t.clone(), self.f.scope.var(iv)], vec![]));
                let lv = bind!("h_lo", Rel::Irr, g.clone());
                self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lv), origin: FactOrigin::Invariant, span });
                self.f.scope.fact_tys.insert(lv, g);
                kinds.push(ObligationKind::WellFormed);
            }
            let hi_now = self.pure_loop_value(hi)?;
            let op = if inclusive { PrimOp::Le(w) } else { PrimOp::Lt(w) };
            let g = self.holds(mk::prim(op, vec![self.f.scope.var(iv), hi_now], vec![]));
            let lv = bind!("h_hi", Rel::Irr, g.clone());
            self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lv), origin: FactOrigin::Invariant, span });
            self.f.scope.fact_tys.insert(lv, g);
            kinds.push(ObligationKind::WellFormed);
            lo_hi = Some((mk::lit(w, 0u8), hi_t, w));
        }
        // parent facts over the helper's read parameters. A fact that
        // mentions a mutated local (or a local a mutated one aliases at the
        // loop head, `let mut v = x;`) describes the state on entry only: it
        // is not an invariant, so it is not required at every iteration (it
        // would make the recursive calls unprovable) and not carried.
        let mut read_levels: HashMap<u32, usize> = param_levels.clone();
        for x in mutated.iter() {
            if let Some(pl) = parent_scope.locals.get(x) {
                read_levels.remove(pl);
            }
        }
        let mut facts: Vec<(u32, Tm)> = parent_scope.fact_tys.iter().map(|(l, t)| (*l, t.clone())).collect();
        facts.sort_by_key(|f| f.0);
        for (fl, fty) in facts {
            if let Some(t) = super::tm::rename_levels(&fty, fl, &read_levels, self.depth()) {
                let lv = bind!("h_fact", Rel::Irr, t.clone());
                self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lv), origin: FactOrigin::Requires, span });
                self.f.scope.fact_tys.insert(lv, t);
                kinds.push(ObligationKind::WellFormed);
            }
        }
        // equations of `let`-defined read locals (see `loop_`)
        for x in read {
            let saved_scope = std::mem::replace(&mut self.f.scope, parent_scope.clone());
            let def = self.local_def(*x);
            self.f.scope = saved_scope;
            let Some((dt, _)) = def else { continue };
            let Some(pl) = parent_scope.locals.get(x) else { continue };
            let Some(def_h) = super::tm::rename_levels(&dt, *pl, param_levels, self.depth()) else { continue };
            let Some(&xl) = param_levels.get(pl) else { continue };
            let decl = self.local_decl(*x);
            let t = self.ty(&decl.ty, span)?;
            let eq = mk::eq(t, self.f.scope.var(xl as u32), def_h);
            let lv = bind!("h_def", Rel::Irr, eq.clone());
            self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lv), origin: FactOrigin::LetDef, span });
            self.f.scope.fact_tys.insert(lv, eq);
            kinds.push(ObligationKind::WellFormed);
        }
        // invariants; for `a..=b` they are required only while `done` is
        // false (`h_inv : done == false → p`): the final call with `done ==
        // true` runs no iteration, so the invariant need not hold there
        let mut guarded_invs: Vec<(u32, Tm, Span)> = Vec::new();
        for inv in &l.info.invariants {
            let p = self.prop(inv)?;
            match done_lvl {
                None => {
                    let lv = bind!("h_inv", Rel::Irr, p.clone());
                    self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lv), origin: FactOrigin::Invariant, span: inv.span });
                    self.f.scope.fact_tys.insert(lv, p);
                }
                Some(dl) => {
                    let d = self.depth();
                    let not_done = mk::eq(mk::bool_ty(self.p.bool_), self.f.scope.var(dl), self.bool_lit(false));
                    let gty = mk::pi("e", Rel::Irr, not_done, sandblaster_kernel::util::shift(&p, 1));
                    let lv = bind!("h_inv", Rel::Irr, gty);
                    guarded_invs.push((lv, Val::new(p, d).tm, inv.span));
                }
            }
            kinds.push(ObligationKind::InvariantPreserve);
        }
        let arity = self.depth();
        // result type
        let unit = Ty::unit();
        let rt = self.join_ty(&unit, mutated);
        let rty = self.ty(&rt, span)?;
        // measure (a term at depth `arity`)
        let (measure, mw) = match &l.kind {
            LoopKind::ForRange { hi, .. } => {
                let (_, _, w) = lo_hi.clone().ok_or_else(|| super::ElabError { span, msg: "for loop without bounds".into(), kind: super::ErrKind::Internal })?;
                // re-elaborated at depth `arity` (the measure's context)
                let hi_t = self.pure_loop_value(hi)?;
                let iv = self.f.scope.var(i_lvl.unwrap());
                let to_int = |t: Tm| mk::prim(PrimOp::Cast { from: w, to: Width::Int }, vec![t], vec![]);
                let base = mk::prim(PrimOp::ISub, vec![to_int(hi_t), to_int(iv)], vec![]);
                let m = match done_lvl {
                    None => base,
                    Some(dl) => {
                        let d = self.f.scope.var(dl);
                        let one_if_not_done = std::rc::Rc::new(sandblaster_kernel::term::Term::Match {
                            ind: self.p.bool_,
                            params: vec![],
                            scrut: d,
                            motive: mk::int_ty(Width::Int),
                            arms: vec![mk::arm(&[], mk::lit(Width::Int, 1u8)), mk::arm(&[], mk::lit(Width::Int, 0u8))],
                        });
                        mk::prim(PrimOp::IAdd, vec![base, one_if_not_done], vec![])
                    }
                };
                (m, Width::Int)
            }
            LoopKind::While { .. } => {
                let dec = l.info.decreases.as_ref().ok_or_else(|| super::ElabError { span, msg: "`while` without `decreases`".into(), kind: super::ErrKind::Internal })?;
                let m = self.pure_loop_value(dec)?;
                let w = self.width_of(&dec.ty, dec.span)?;
                (m, w)
            }
        };
        // the full type
        let mut ty = rty;
        for b in binders.iter().rev() {
            ty = mk::pi(&b.name, b.rel, b.ty.clone(), ty);
        }
        self.f.rec = Some(RecInfo { item: None, ty: ty.clone(), arity, measure: Some((measure.clone(), mw)) });
        self.f.answer = rt.clone();
        self.f.ret = rt.clone();
        // body
        let body = self.loop_body(l, mutated, read, i_lvl, done_lvl, lo_hi.as_ref().map(|x| x.2), &kinds, &guarded_invs, span)?;
        let mut lam = body;
        for b in binders.iter().rev() {
            lam = mk::lam(&b.name, b.rel, b.ty.clone(), lam);
        }
        Ok((ty, lam, arity, (measure, mw), kinds))
    }

    #[allow(clippy::too_many_arguments)]
    fn loop_body(&mut self, l: &'a Loop, mutated: &[LocalId], read: &[LocalId], i_lvl: Option<u32>, done_lvl: Option<u32>, w: Option<Width>, kinds: &[ObligationKind], guarded_invs: &[(u32, Tm, Span)], span: Span) -> R<Tm> {
        let answer = Answer::Ty(self.f.answer.clone());
        let kinds = kinds.to_vec();
        let after_body = |s: &mut Elab<'a>| -> R<Tm> {
            // B has run: recurse or return M'
            match (&l.kind, i_lvl, w) {
                (LoopKind::ForRange { hi, inclusive, .. }, Some(iv), Some(w)) => {
                    let hi_t = s.pure_loop_value(hi)?;
                    let i = s.f.scope.var(iv);
                    let one = mk::lit(w, 1u8);
                    if *inclusive {
                        let test = mk::prim(PrimOp::Lt(w), vec![i.clone(), hi_t], vec![]);
                        let d0 = s.depth();
                        let iv0 = Val::new(i, d0);
                        s.if_then_else(test, &answer, span, &mut |s, b| {
                            let d = s.depth();
                            let i = iv0.at(d);
                            let next = if b { s.checked_prim(PrimOp::Add(w), vec![i, one.clone()], ObligationKind::Overflow, span)? } else { i };
                            let done = s.bool_lit(!b);
                            s.rec_iter(Some(next), Some(done), mutated, read, &kinds, &[], span)
                        })
                    } else {
                        let d0 = s.depth();
                        let next = s.checked_prim(PrimOp::Add(w), vec![i, one], ObligationKind::Overflow, span)?;
                        let nv = Val::new(next, d0);
                        let hv = Val::new(hi_t, d0);
                        // the invariants at `i + 1`, proven once before the
                        // branch: the recursive call (preservation) and the
                        // exit (the post-loop lemma) both use these facts
                        let var = match &l.kind {
                            LoopKind::ForRange { var, .. } => *var,
                            LoopKind::While { .. } => None,
                        };
                        s.next_invariants(l, var, &nv, w, &mut |s, pre| {
                            let d = s.depth();
                            let test = mk::prim(PrimOp::Lt(w), vec![nv.at(d), hv.at(d)], vec![]);
                            s.if_then_else(test, &answer, span, &mut |s, b| {
                                if b {
                                    let n = nv.at(s.depth());
                                    s.rec_iter(Some(n), None, mutated, read, &kinds, pre, span)
                                } else {
                                    s.locals_tuple(mutated, span)
                                }
                            })
                        })
                    }
                }
                (LoopKind::While { .. }, _, _) => s.rec_iter(None, None, mutated, read, &kinds, &[], span),
                _ => internal(span, "loop shape"),
            }
        };
        match (&l.kind, done_lvl) {
            (LoopKind::ForRange { .. }, None) => self.block(&l.body, &mut |s, _| after_body(s)),
            (LoopKind::ForRange { .. }, Some(dl)) => {
                let done = self.f.scope.var(dl);
                self.if_then_else(done, &answer, span, &mut |s, b| {
                    if b {
                        s.locals_tuple(mutated, span)
                    } else {
                        // `done == false` (the path equation just pushed):
                        // the invariants hold
                        let e_lvl = s.f.scope.facts.last().map(|f| f.lvl.0).ok_or_else(|| super::ElabError { span, msg: "missing path equation".into(), kind: super::ErrKind::Internal })?;
                        s.with_invariants(guarded_invs, e_lvl, 0, &mut |s| s.block(&l.body, &mut |s, _| after_body(s)))
                    }
                })
            }
            (LoopKind::While { cond }, _) => self.expr(cond, &mut |s, vc| {
                let c = vc.at(s.depth());
                s.if_then_else(c, &answer, span, &mut |s, b| if b { s.block(&l.body, &mut |s, _| after_body(s)) } else { s.locals_tuple(mutated, span) })
            }),
        }
    }

    /// Adds the facts `p` of the guarded invariants `h_inv : done == false →
    /// p` (inclusive ranges), given the path equation at level `e_lvl`.
    fn with_invariants(&mut self, invs: &[(u32, Tm, Span)], e_lvl: u32, k: usize, body: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some((h_lvl, p, sp)) = invs.get(k) else { return body(self) };
        let d = self.depth();
        let ty = Val::new(p.clone(), *h_lvl).at(d);
        let proof = mk::apps(self.f.scope.var(*h_lvl), [(Rel::Irr, self.f.scope.var(e_lvl))]);
        self.fact_in("h_inv", ty, proof, FactOrigin::Invariant, *sp, &mut |s| s.with_invariants(invs, e_lvl, k + 1, body))
    }

    /// `rec(i', [done'], M'.., R.., proofs)` for the helper being built.
    /// `pre`: per invariant, the level of a fact already proving it for
    /// these arguments ([`Elab::next_invariants`]), used as its proof.
    #[allow(clippy::too_many_arguments)]
    fn rec_iter(&mut self, next: Option<Tm>, done: Option<Tm>, mutated: &[LocalId], read: &[LocalId], kinds: &[ObligationKind], pre: &[Option<u32>], span: Span) -> R<Tm> {
        let r = self.f.rec.clone().ok_or_else(|| super::ElabError { span, msg: "loop recursion outside a helper".into(), kind: super::ErrKind::Internal })?;
        let mut args: Vec<Tm> = (0..self.f.ngen).map(|i| self.f.scope.var(i)).collect();
        args.extend(next);
        args.extend(done);
        for x in mutated.iter().chain(read) {
            args.push(self.local_tm(*x, span)?);
        }
        let all = if pre.iter().all(|p| p.is_none()) {
            self.apply_tele(&r.ty, args, None, None, &|i| kinds.get(i).cloned().unwrap_or(ObligationKind::WellFormed), span)?.1
        } else {
            self.apply_rec(&r.ty, args, kinds, pre, span)?
        };
        let (m, w) = r.measure.clone().unwrap();
        let proof = self.measure_proof(&m, w, r.arity, &all, span)?;
        Ok(std::rc::Rc::new(sandblaster_kernel::term::Term::Rec { args: all, proof: Some(proof) }))
    }

    /// [`Elab::apply_tele`] for a recursive call whose invariant proofs may
    /// be given (`pre`, fact levels per invariant): a given proof is used
    /// when the kernel accepts it for the instantiated binder (a variable:
    /// a cheap check), else the binder is an obligation as usual.
    fn apply_rec(&mut self, ty: &Tm, args: Vec<Tm>, kinds: &[ObligationKind], pre: &[Option<u32>], span: Span) -> R<Vec<Tm>> {
        let mut all: Vec<Tm> = Vec::new();
        let mut it = args.into_iter().peekable();
        let (mut hyp_i, mut inv_i) = (0usize, 0usize);
        let mut t = ty.clone();
        while let Term::Pi { rel, dom, cod, .. } = &*t.clone() {
            let arg = match rel {
                Rel::Rel if it.peek().is_some() => it.next().unwrap(),
                Rel::Rel => break,
                Rel::Irr => {
                    let target = super::tm::subst_closed(dom, &all);
                    let kind = kinds.get(hyp_i).cloned().unwrap_or(ObligationKind::WellFormed);
                    hyp_i += 1;
                    let mut given = None;
                    if kind == ObligationKind::InvariantPreserve {
                        if let Some(Some(lvl)) = pre.get(inv_i) {
                            let v = self.f.scope.var(*lvl);
                            let tv = self.eval(&target)?;
                            if self.check_proof_in(&self.f.scope.ctx, &v, &target, &tv, false).is_ok() {
                                given = Some(v);
                            }
                        }
                        inv_i += 1;
                    }
                    match given {
                        Some(v) => v,
                        None => self.prove(kind, span, &target, false)?,
                    }
                }
            };
            all.push(arg);
            t = cod.clone();
            if it.peek().is_none() && !matches!(&*t, Term::Pi { rel: Rel::Irr, .. }) {
                break;
            }
        }
        if it.next().is_some() {
            return internal(span, "too many arguments for the loop helper's telescope");
        }
        Ok(all)
    }

    /// The invariants of `a..b` at the next index `i + 1` (`nv`) for the
    /// state after the body, as facts `h_next`, then `k` with their levels
    /// (per invariant; `None` for one that is not proven here). Proven once
    /// before the branch on `i + 1 < b`, they serve both the recursive call
    /// (preservation, `i + 1 < b`) and the exit (`i + 1 = b`, the post-loop
    /// lemma reuses them, [`Hints`]) — together exactly what the two
    /// require. An invariant whose statement or proof fails here (e.g. one
    /// that needs `i + 1 < b`) is left to the two places, where its
    /// failure is reported as a preservation or an exit failure; nothing of
    /// the attempt is recorded.
    fn next_invariants(&mut self, l: &'a Loop, var: Option<LocalId>, nv: &Val, w: Width, k: &mut NextK<'_, 'a>) -> R<Tm> {
        if l.info.invariants.is_empty() {
            return k(self, &[]);
        }
        let name = var.map(|v| self.local_decl(v).name.clone()).unwrap_or_else(|| "_i".into());
        let n = nv.at(self.depth());
        self.let_in(&name, Rel::Rel, mk::int_ty(w), n, &mut |s, lvl| {
            let old = var.and_then(|v| s.f.scope.locals.get(&v).copied());
            if let Some(v) = var {
                s.f.scope.locals.insert(v, lvl);
            }
            s.next_facts(l, 0, var, old, &mut Vec::new(), k)
        })
    }

    fn next_facts(&mut self, l: &'a Loop, j: usize, var: Option<LocalId>, old: Option<u32>, pre: &mut Vec<Option<u32>>, k: &mut NextK<'_, 'a>) -> R<Tm> {
        let Some(inv) = l.info.invariants.get(j) else {
            // the loop variable is `i` again for the call and the rest
            let saved = self.f.scope.clone();
            if let (Some(v), Some(o)) = (var, old) {
                self.f.scope.locals.insert(v, o);
            }
            let r = k(self, pre);
            self.f.scope = saved;
            return r;
        };
        let (nobl, ndiag, failed) = (self.obligations.len(), self.diags.list.len(), self.f.failed);
        let saved = self.f.scope.clone();
        let attempt = (|| -> R<Option<(Tm, Tm)>> {
            let p = self.prop(inv)?;
            if !self.obligations[nobl..].iter().all(|o| o.proven()) {
                return Ok(None);
            }
            let pr = self.prove(ObligationKind::InvariantPreserve, inv.span, &p, false)?;
            Ok(self.obligations[nobl..].iter().all(|o| o.proven()).then_some((p, pr)))
        })();
        self.f.scope = saved;
        match attempt {
            Ok(Some((p, pr))) => {
                let rel = self.fact_rel();
                let saved = self.f.scope.clone();
                let lvl = self.push_fact("h_next", &p, Some(&pr), FactOrigin::Invariant, inv.span)?;
                // not a fact for the next invariants' proofs (each is proven
                // on its own, as at the recursive call) nor for the rest of
                // the body: only the recursive call and the exit use it
                self.f.scope.hidden.insert(lvl);
                pre.push(Some(lvl));
                let body = self.next_facts(l, j + 1, var, old, pre, k);
                pre.pop();
                self.f.scope = saved;
                Ok(mk::let_("h_next", rel, p, pr, body?))
            }
            _ => {
                self.obligations.truncate(nobl);
                self.diags.list.truncate(ndiag);
                self.f.failed = failed;
                pre.push(None);
                let r = self.next_facts(l, j + 1, var, old, pre, k);
                pre.pop();
                r
            }
        }
    }
}

// ----------------------------------------------------------------------
// post-loop facts (DESIGN.md §7.4; see the module docs)
// ----------------------------------------------------------------------

/// What the post-loop lemma needs about a built helper.
struct HelperInfo {
    name: String,
    /// Number of binders of the helper.
    arity: u32,
    /// The termination measure (a term at depth `arity`) and its width.
    measure: Tm,
    width: Width,
    /// The helper was added to the kernel (every obligation proven).
    checked: bool,
}

/// The post-loop lemma of a loop, for its call site.
struct PostLemma {
    global: GlobalId,
    /// The loop helper.
    helper: GlobalId,
    /// `a..=b`: the lemma takes `done = false` as a last hypothesis.
    incl: bool,
    /// The statement's form, decided once, in the lemma.
    shape: StmtShape,
}

/// The decisions about the form of a post-state statement, made when the
/// lemma is built and reused at the call site.
#[derive(Clone, Debug, Default)]
struct StmtShape {
    /// `a..=b`: the invariants are stated at `b + 1` over `Int` (see
    /// [`PostStmt::lifted`]).
    lifted: bool,
    /// Generated conjuncts left out because they could not be proven at the
    /// exit (indices: the invariants in source order, then the `while`
    /// condition); see [`PostStmt::optional`].
    dropped: Vec<usize>,
}

/// The post-state statement of a loop, elaborated once in a context (the
/// lemma's telescope, or the call site after the loop).
#[derive(Clone)]
struct PostStmt {
    /// Depth of the context it was elaborated in.
    base: u32,
    /// `for` loops: the bound `b` (at `base`) and the width of the loop
    /// variable; `None` for `while`.
    bound: Option<(Tm, Width)>,
    /// The helper's result type (at `base`).
    rt: Tm,
    /// The body: at depth `base + 3` under `z : W`, `ret : RT`, `hz : Eq(W,
    /// z, b)` (`for`), at `base + 1` under `ret : RT` (`while`). It is the
    /// `let`s of the mutated locals (the components of `ret`), for `a..=b`
    /// with invariants over the loop variable (unless `lifted`) the guard
    /// `Π(hm : z < MAX)` and `let i = z + 1`, then the conjunction `Σ(h₁ :
    /// Inv₁). … Invₙ` (`∧ c = false` for `while`).
    body: Tm,
    /// Number of `let`/`Π` nodes before the conjunction.
    prefix: usize,
    /// Span of every conjunct (the conjunction has `spans.len()` of them).
    spans: Vec<Span>,
    /// Whether the body mentions `z` or `hz` (otherwise the statement at any
    /// index is the statement at `b`, and no transport is needed).
    uses_index: bool,
    /// `a..=b` with invariants over the loop variable, which occurs in them
    /// only as `i as Int` and without obligations: they are stated exactly
    /// at `b + 1` (`i as Int := (b as Int) + 1`, also for `b = MAX`) instead
    /// of under the guard `b < MAX`.
    lifted: bool,
    /// Per conjunct: its index (the invariants in source order, then the
    /// `while` condition).
    conj_idx: Vec<usize>,
    /// Per conjunct: the number of disjunctions of the invariant stated in
    /// implication form (`p ∨ q` as `¬p → q`, [`Elab::propify`]); such a
    /// conjunct is proven as the disjunction and converted
    /// ([`Elab::or_to_impl`]).
    weak: Vec<u32>,
    /// Per conjunct: generated rather than written — the `while` condition
    /// `¬c`, or the implication form `¬p → q` of a disjunctive invariant `p
    /// ∨ q`. A generated conjunct that cannot be proven at the exit is left
    /// out of the statement (with a warning) instead of failing the build.
    optional: Vec<bool>,
    /// The binder names of the index and of the result (the loop variable
    /// and a single mutated local print under their own names).
    zname: String,
    rname: String,
    /// Exit conjuncts the prover failed on: (conjunct index, obligation id).
    failed: Rc<std::cell::RefCell<Vec<(usize, u32)>>>,
}

/// How [`Elab::prove_post`] instantiates the statement's binders.
enum At {
    /// As in the statement: `z := b`, `hz := refl(W, b)` (`let`s).
    Stmt,
    /// `z := t`, with `hz : Eq(W, t, b)` as a hypothesis (a `λ`): the
    /// statement at another index, moved to `b` by [`Elab::post_moved`].
    Index(Tm),
}

/// The loop forms, with the helper binders the lemma walk needs.
#[derive(Clone, Copy)]
enum Shape {
    /// `a..b`: the binder and width of the loop variable.
    Excl { i_pos: u32, w: Width },
    /// `a..=b`: the binders of the loop variable and of `done`.
    Incl { i_pos: u32, done_pos: u32 },
    While,
}

/// The walk of the helper body that proves `f::loop#k::ensures`.
struct LoopGoal {
    ps: PostStmt,
    helper: GlobalId,
    /// Arity of the helper (the lemma has one more binder for `a..=b`).
    n: u32,
    shape: Shape,
    /// The helper's result type and the binders of the mutated locals.
    rt: Ty,
    m_pos: Vec<u32>,
    span: Span,
    /// `a..b`: the invariant proofs of the recursive call.
    rec_hints: Option<Hints>,
}

/// Proofs of the invariants already built at a sibling position of the
/// same depth (the other arm of a boolean match), tried for the conjuncts
/// of a post-state statement before the prover runs: the exit after an
/// iteration reuses the preservation proofs of the recursive call (both
/// state the invariants at `i + 1` for `M'`), the empty range at the call
/// site the entry proofs of the helper call (both at `a` for `M`). A
/// candidate is used only if the kernel accepts it for the conjunct in the
/// current context (a proof that uses the other arm's path equation does
/// not check there); otherwise the prover proves the conjunct.
#[derive(Clone)]
struct Hints {
    /// The depth the proofs are valid at.
    depth: u32,
    /// One proof per invariant (source order).
    proofs: Vec<Tm>,
}

impl<'a> WalkGoal<'a> for LoopGoal {
    fn goal(&mut self, el: &mut Elab<'a>, v: &Tm) -> R<Tm> {
        Ok(el.squash(&el.post_at(&self.ps, v)))
    }

    fn leaf(&mut self, el: &mut Elab<'a>, v: &Tm) -> R<Tm> {
        el.loop_leaf(self, v)
    }
}

/// An application spine with the relevance of each argument.
fn spine_rels(t: &Tm) -> (Tm, Vec<(Rel, Tm)>) {
    let mut args = Vec::new();
    let mut h = t.clone();
    while let Term::App { rel, fun, arg } = &*h.clone() {
        args.push((*rel, arg.clone()));
        h = fun.clone();
    }
    args.reverse();
    (h, args)
}

/// The parts of an `if` in the dependent-match idiom (§7.2): the condition,
/// the match, and the bodies of the `false` and `true` arms (under their
/// path equation).
fn split_if(t: &Tm, bool_: sandblaster_kernel::term::IndId) -> Option<(Tm, Tm, Tm, Tm)> {
    let Term::App { rel: Rel::Irr, fun, .. } = &**t else { return None };
    let Term::Match { ind, scrut, arms, .. } = &**fun else { return None };
    if *ind != bool_ || arms.len() != 2 {
        return None;
    }
    let body = |a: &sandblaster_kernel::term::Arm| match &*a.body {
        Term::Lam { body, .. } => Some(body.clone()),
        _ => None,
    };
    Some((scrut.clone(), fun.clone(), body(&arms[0])?, body(&arms[1])?))
}

/// [`Elab::lifted_invariants`]: the conjuncts elaborated at the index `j`
/// (conjunct `k` at depth `j + 1 + k`), with `j as Int` replaced by `(z as
/// Int) + 1` (`z` at level `z_lvl`) and `j` removed (conjunct `k` then at
/// depth `j + k`); `None` if `j` occurs otherwise.
fn lift_conjuncts(raw: Vec<(Tm, Span)>, j: u32, z_lvl: u32, w: Width) -> Option<Vec<(Tm, Span)>> {
    let from_int = PrimOp::Cast { from: w, to: Width::Int };
    let mut out = Vec::new();
    for (k, (p, span)) in raw.into_iter().enumerate() {
        let k = k as u32;
        // under `b` binders of the conjunct: `j` is `Var(b + k)`, `z` is
        // `Var(b + k + j - z_lvl)`
        let lifted = super::tm::map_post(&p, 0, &mut |n, b| {
            if let Term::Prim { op, args, proofs } = &*n
                && *op == from_int
                && proofs.is_empty()
                && let [a] = args.as_slice()
                && matches!(&**a, Term::Var(sandblaster_kernel::term::Idx(i)) if *i == b + k)
            {
                let z = mk::var(b + k + (j - z_lvl));
                return Some(mk::prim(PrimOp::IAdd, vec![mk::prim(from_int, vec![z], vec![]), mk::lit(Width::Int, 1u8)], vec![]));
            }
            Some(n)
        })?;
        if sandblaster_kernel::util::occurs(&lifted, k) {
            return None;
        }
        out.push((super::tm::subst_idx(&lifted, k, &mk::var(0)), span));
    }
    Some(out)
}

impl<'a> Elab<'a> {
    /// Builds and adds `f::loop#k::ensures` (see the module docs). `None`
    /// when the loop states nothing after it (a `for` loop without
    /// invariants), or when the helper or the lemma did
    /// not check (their failed obligations fail the build, and no fact is
    /// bound at the call site).
    fn post_lemma(&mut self, l: &'a Loop, helper: GlobalId, hi: &HelperInfo, mutated: &[LocalId], read: &[LocalId], jt: &Ty) -> Option<PostLemma> {
        let needs = match &l.kind {
            LoopKind::ForRange { .. } => !l.info.invariants.is_empty(),
            LoopKind::While { .. } => true,
        };
        if !needs {
            return None;
        }
        let incl = matches!(&l.kind, LoopKind::ForRange { inclusive: true, .. });
        let name = format!("{}::ensures", hi.name);
        let span = l.span;
        if !hi.checked {
            return None;
        }
        let mut dropped: Vec<usize> = Vec::new();
        let (res, lemma_state) = loop {
            let (nobl, ndiag) = (self.obligations.len(), self.diags.list.len());
            let mut st = FnState::new(name.clone(), self.f.item, self.f.locals, span);
            st.ngen = self.f.ngen;
            st.mode = Mode::Exec;
            st.fdef = self.f.fdef;
            let parent = std::mem::replace(&mut self.f, st);
            let res = self.post_lemma_inner(l, helper, hi, mutated, read, jt, &dropped);
            let lemma_state = std::mem::replace(&mut self.f, parent);
            // a generated conjunct (the `while` condition, the implication
            // form of a disjunctive invariant) that the prover cannot prove
            // at the exit is left out, and the lemma built again: it is
            // never a reason for the build to fail
            if let Ok(Some((.., ps))) = &res
                && lemma_state.failed
                && dropped.is_empty()
            {
                let failed_conj = ps.failed.borrow().clone();
                let failed_obls: Vec<u32> = self.obligations[nobl..].iter().filter(|o| !o.proven()).map(|o| o.id).collect();
                let optional = |c: usize| ps.conj_idx.iter().position(|x| *x == c).is_some_and(|j| ps.optional[j]);
                let drop: BTreeSet<usize> = failed_conj.iter().map(|(c, _)| *c).collect();
                if !failed_obls.is_empty() && failed_obls.iter().all(|id| failed_conj.iter().any(|(c, o)| o == id && optional(*c))) {
                    self.obligations.truncate(nobl);
                    self.diags.list.truncate(ndiag);
                    for c in &drop {
                        let msg = if *c == l.info.invariants.len() {
                            "after this loop, its condition being false is not available as a fact: the prover could not state it at the loop's exit".to_string()
                        } else {
                            "this disjunctive invariant is not available after the loop: its implication form `!p → q` could not be proven at the loop's exit".to_string()
                        };
                        let at = l.info.invariants.get(*c).map(|e| e.span).unwrap_or(span);
                        self.diag(crate::diag::Diagnostic::warning(crate::diag::DiagKind::Elab, at, msg).note("state what you need after the loop with `proof! { assert(..); }` (DESIGN.md §7.4)"));
                    }
                    dropped = drop.into_iter().collect();
                    continue;
                }
            }
            break (res, lemma_state);
        };
        match res {
            Ok(None) => None,
            Ok(Some((ty, body, arity, measure, ps))) => {
                let g = self.add_definition(&name, DefKind::Ensures, self.f.item, ty, body, Recursion::Measure { measure }, arity, false, lemma_state.failed, span).ok()?;
                let checked = self.defs.last().is_some_and(|d| d.global == Some(g) && d.status == super::DefStatus::Checked);
                checked.then_some(PostLemma { global: g, helper, incl, shape: StmtShape { lifted: ps.lifted, dropped } })
            }
            Err(e) => {
                let at = if e.span.is_dummy() { span } else { e.span };
                self.diag(crate::diag::Diagnostic::error(crate::diag::DiagKind::Elab, at, format!("the post-loop lemma `{name}` could not be built: {}", e.msg)));
                self.defs.push(super::DefRecord { name, kind: DefKind::Ensures, item: self.f.item, global: None, status: super::DefStatus::Unsupported(e.msg), span });
                None
            }
        }
    }

    /// The lemma's type, body, arity and measure, and its statement (in a
    /// fresh `FnState`), leaving out the conjuncts `dropped`.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn post_lemma_inner(&mut self, l: &'a Loop, helper: GlobalId, hi: &HelperInfo, mutated: &[LocalId], read: &[LocalId], jt: &Ty, dropped: &[usize]) -> R<Option<(Tm, Tm, u32, Tm, PostStmt)>> {
        let span = l.span;
        let n = hi.arity;
        let no_def = |what: &str| super::ElabError { span, msg: format!("loop helper without {what}"), kind: super::ErrKind::Internal };
        // the helper's telescope, binder for binder (its `requires` stay
        // irrelevant: the recursive calls of the body pass its proofs)
        let mut t = self.env.global_type(helper).ok_or_else(|| no_def("type"))?;
        let mut binders: Vec<TBinder> = Vec::new();
        let mut rels = Vec::new();
        for _ in 0..n {
            let Term::Pi { name, rel, dom, cod } = &*t.clone() else { return internal(span, "loop helper type") };
            let lvl = self.push(name, *rel, dom, None)?;
            if *rel == Rel::Irr {
                self.f.scope.facts.push(FactRef { lvl: Lvl(lvl), origin: FactOrigin::Invariant, span });
                self.f.scope.fact_tys.insert(lvl, dom.clone());
            }
            binders.push(TBinder { name: name.to_string(), rel: *rel, ty: dom.clone() });
            rels.push(*rel);
            t = cod.clone();
        }
        // HIR locals ↦ binders (the helper's layout: type parameters, `i`,
        // `done`, the mutated locals, the read locals)
        let mut pos = self.f.ngen;
        let mut shape = Shape::While;
        let mut done_lvl = None;
        if let LoopKind::ForRange { var, lo, inclusive, .. } = &l.kind {
            let w = self.width_of(&lo.ty, lo.span)?;
            if let Some(v) = var {
                self.f.scope.locals.insert(*v, pos);
            }
            if *inclusive {
                done_lvl = Some(pos + 1);
                shape = Shape::Incl { i_pos: pos, done_pos: pos + 1 };
                pos += 2;
            } else {
                shape = Shape::Excl { i_pos: pos, w };
                pos += 1;
            }
        }
        let mut m_pos = Vec::new();
        for x in mutated {
            self.f.scope.locals.insert(*x, pos);
            m_pos.push(pos);
            pos += 1;
        }
        for x in read {
            self.f.scope.locals.insert(*x, pos);
            pos += 1;
        }
        // `a..=b`: the lemma is about runs that start with `done = false`
        if let Some(dl) = done_lvl {
            let hd = mk::eq(mk::bool_ty(self.p.bool_), self.f.scope.var(dl), self.bool_lit(false));
            self.push_fact_rel("hd", Rel::Irr, &hd, None, FactOrigin::Invariant, span)?;
            binders.push(TBinder { name: "hd".into(), rel: Rel::Irr, ty: hd });
        }
        let arity = self.depth();
        let Some(ps) = self.post_stmt(l, mutated, jt, None, dropped)? else { return Ok(None) };
        let app = mk::apps(mk::global(helper), rels.iter().enumerate().map(|(j, r)| (*r, self.f.scope.var(j as u32))));
        let ty = pi_tele(&binders, self.squash(&self.post_at(&ps, &app)));
        // measure recursion with the helper's measure: the recursive calls
        // of the helper get their facts from recursive calls of the lemma
        let measure = shift(&hi.measure, (arity - n) as i64);
        self.f.rec = Some(RecInfo { item: None, ty: ty.clone(), arity, measure: Some((measure.clone(), hi.width)) });
        let rt_h = shift(&t, (arity - n) as i64);
        let body = self.env.global_body(helper).ok_or_else(|| no_def("body"))?;
        let inner = shift(&strip_lams(&body, n), (arity - n) as i64);
        // `a..b`: the invariant proofs of the (single) recursive call, for
        // the exit after the same iteration (`Hints`)
        let rec_hints = match shape {
            Shape::Excl { .. } => self.rec_call_hints(&inner, helper, n, arity, l.info.invariants.len()),
            _ => None,
        };
        let mut goal = LoopGoal { ps: ps.clone(), helper, n, shape, rt: jt.clone(), m_pos, span, rec_hints };
        let walked = self.walk_body(&inner, &mut goal)?;
        // `H x h` is opaque: it unfolds to the walked body by `delta`,
        // transport(RT, body, H x h, sym(delta(H; x h)), w. Post(w), walked)
        let args: Vec<Tm> = (0..n).map(|j| self.f.scope.var(j)).collect();
        let delta = Rc::new(Term::Delta { def: helper, args });
        let sym = mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, rt_h.clone()), (Rel::Rel, app.clone()), (Rel::Rel, inner.clone()), (Rel::Rel, delta)]);
        let motive = self.post_motive_value(&ps, &rt_h, true)?;
        let proof = Rc::new(Term::Transport { ty: rt_h, lhs: inner, rhs: app, eq: sym, motive, val: walked });
        Ok(Some((ty, lam_tele(&binders, proof), arity, measure, ps)))
    }

    /// `Squash(p) = Σ(_ : Unit) ×Irr p` (a term at the current depth): the
    /// statement of the post-loop lemma. Its proof carries `p`'s proof in an
    /// irrelevant position, so every conjunct is proven irrelevantly from
    /// the helper's (irrelevant) hypotheses — equations and disjunctions,
    /// existentials or opaque predicates alike.
    fn squash(&self, p: &Tm) -> Tm {
        mk::sigma("_", Rel::Irr, mk::ind(self.p.unit, vec![]), shift(p, 1))
    }

    /// `(tt, proof) : Squash(p)`.
    fn squash_intro(&self, p: &Tm, proof: Tm) -> Tm {
        mk::pair(self.squash(p), self.unit_val(), proof)
    }

    /// The invariant proofs of the recursive call of an `a..b` helper body
    /// (`inner`, at depth `base`), as [`Hints`] for the exit conjuncts: the
    /// exit after an iteration states the invariants at `i + 1` for the
    /// state `M'`, exactly what the recursive call `rec(i + 1, M'..)` in the
    /// other branch of `i + 1 < b` proves for preservation. `None` unless
    /// the body has exactly one recursive call.
    fn rec_call_hints(&self, inner: &Tm, helper: GlobalId, n: u32, base: u32, ninv: usize) -> Option<Hints> {
        fn go(t: &Tm, k: u32, helper: GlobalId, n: u32, out: &mut Vec<(u32, Vec<(Rel, Tm)>)>, seen: &mut std::collections::HashSet<(*const Term, u32)>) {
            if !seen.insert((Rc::as_ptr(t), k)) {
                return;
            }
            if let Term::App { .. } = &**t {
                let (head, args) = spine_rels(t);
                if matches!(&*head, Term::Global(h) if *h == helper) && args.len() == n as usize {
                    out.push((k, args));
                }
            }
            super::tm::children_depth(t, &mut |c, j| go(c, k + j, helper, n, out, seen));
        }
        let mut calls: Vec<(u32, Vec<(Rel, Tm)>)> = Vec::new();
        go(inner, 0, helper, n, &mut calls, &mut std::collections::HashSet::new());
        let [(k, args)] = calls.as_slice() else { return None };
        let proofs = self.invariant_args(helper, args, ninv)?;
        Some(Hints { depth: base + k, proofs })
    }

    /// The arguments of a helper application `H args` that prove the user
    /// invariants (the helper's `h_inv` binders, in source order).
    fn invariant_args(&self, helper: GlobalId, args: &[(Rel, Tm)], ninv: usize) -> Option<Vec<Tm>> {
        let kinds = self.helper_kinds.get(&helper)?;
        let mut t = self.env.global_type(helper)?;
        let mut irr = 0usize;
        let mut out = Vec::new();
        for (_, a) in args {
            let Term::Pi { rel, cod, .. } = &*t.clone() else { return None };
            if *rel == Rel::Irr {
                if kinds.get(irr) == Some(&ObligationKind::InvariantPreserve) {
                    out.push(a.clone());
                }
                irr += 1;
            }
            t = cod.clone();
        }
        (out.len() == ninv).then_some(out)
    }

    /// Elaborates the post-state statement of `l` in the current context
    /// (see [`PostStmt`]); `None` when there is nothing to state (no
    /// invariant is a proposition, and a `while` condition cannot be stated
    /// at the exit states). `lift`: the index form of `a..=b`
    /// ([`PostStmt::lifted`]), `None` to decide it (the lemma; the call site
    /// uses the lemma's decision). The conjuncts `dropped` are left out.
    fn post_stmt(&mut self, l: &'a Loop, mutated: &[LocalId], jt: &Ty, lift: Option<bool>, dropped: &[usize]) -> R<Option<PostStmt>> {
        let saved = self.f.scope.clone();
        let r = self.post_stmt_inner(l, mutated, jt, lift, dropped);
        self.f.scope = saved;
        r
    }

    fn post_stmt_inner(&mut self, l: &'a Loop, mutated: &[LocalId], jt: &Ty, lift: Option<bool>, dropped: &[usize]) -> R<Option<PostStmt>> {
        enum Node {
            Let(String, Tm, Tm),
            Pi(String, Tm),
        }
        let span = l.span;
        let base = self.depth();
        let rt = self.ty(jt, span)?;
        let mut prefix: Vec<Node> = Vec::new();
        // binder names: the loop variable of `a..b` is the index itself; a
        // single mutated local is the result itself
        let zname = match &l.kind {
            LoopKind::ForRange { var: Some(v), inclusive: false, .. } => format!("{}_exit", self.local_decl(*v).name),
            LoopKind::ForRange { var: Some(v), inclusive: true, .. } => format!("{}_last", self.local_decl(*v).name),
            _ => "z".to_string(),
        };
        let rname = match mutated {
            [x] => self.local_decl(*x).name.clone(),
            _ => "ret".to_string(),
        };
        // the binders: `z : W`, `ret : RT`, `hz : Eq(W, z, b)` / `ret : RT`
        let (bound, nb) = match &l.kind {
            LoopKind::ForRange { lo, hi, .. } => {
                let w = self.width_of(&lo.ty, lo.span)?;
                let b = self.pure_loop_value(hi)?;
                let wt = mk::int_ty(w);
                self.push(&zname, Rel::Rel, &wt, None)?;
                self.push(&rname, Rel::Rel, &shift(&rt, 1), None)?;
                let hz = mk::eq(wt, mk::var(1), shift(&b, 2));
                self.push_fact_rel("hz", Rel::Rel, &hz, None, FactOrigin::Invariant, span)?;
                (Some((b, w)), 3)
            }
            LoopKind::While { .. } => {
                self.push(&rname, Rel::Rel, &rt, None)?;
                (None, 1)
            }
        };
        let ret_lvl = if nb == 3 { base + 1 } else { base };
        // the mutated locals: the components of `ret`
        match mutated {
            [] => {}
            [x] => {
                self.f.scope.locals.insert(*x, ret_lvl);
            }
            _ => {
                let Ty::Tuple(comps) = jt else { return internal(span, "loop join type") };
                for (j, x) in mutated.iter().enumerate() {
                    let (ind, params) = self.ind_of(jt, span)?;
                    let fty = self.ty(&comps[j], span)?;
                    let val = self.proj(ind, params, self.f.scope.var(ret_lvl), j, comps.len(), fty.clone());
                    let name = self.local_decl(*x).name.clone();
                    let lvl = self.push(&name, Rel::Rel, &fty, Some(&val))?;
                    self.f.scope.locals.insert(*x, lvl);
                    prefix.push(Node::Let(name, fty, val));
                }
            }
        }
        // the loop variable: `b` for `a..b`; for `a..=b` (only if an
        // invariant mentions it) `b + 1`, exactly over `Int` when possible,
        // else when `b < MAX`
        let mut lifted = false;
        // (conjunct, span, index, disjunctions in implication form)
        let mut conj: Vec<(Tm, Span, usize, u32)> = Vec::new();
        if let LoopKind::ForRange { var: Some(v), lo, inclusive, .. } = &l.kind {
            let uses_var = l.info.invariants.iter().any(|e| free_locals(e).contains(v));
            if *inclusive && uses_var && lift != Some(false) {
                let w = self.width_of(&lo.ty, lo.span)?;
                match self.lifted_invariants(l, *v, w, base, dropped)? {
                    Some(c) => {
                        conj = c.into_iter().enumerate().map(|(k, (p, sp))| (p, sp, k, 0)).collect();
                        lifted = true;
                    }
                    None if lift == Some(true) => return internal(span, "the lemma's lifted post-loop statement does not elaborate at the call site"),
                    None => {}
                }
            }
            if !*inclusive {
                self.f.scope.locals.insert(*v, base);
            } else if uses_var && !lifted {
                let w = self.width_of(&lo.ty, lo.span)?;
                let wt = mk::int_ty(w);
                let max = mk::lit(w, sandblaster_kernel::prim::max_of(w));
                let hm = self.holds(mk::prim(PrimOp::Lt(w), vec![self.f.scope.var(base), max], vec![]));
                self.push_fact_rel("hm", Rel::Rel, &hm, None, FactOrigin::Invariant, span)?;
                prefix.push(Node::Pi("hm".into(), hm));
                let next = self.checked_prim(PrimOp::Add(w), vec![self.f.scope.var(base), mk::lit(w, 1u8)], ObligationKind::WellFormed, span)?;
                let name = self.local_decl(*v).name.clone();
                let lvl = self.push(&name, Rel::Rel, &wt, Some(&next))?;
                self.f.scope.locals.insert(*v, lvl);
                prefix.push(Node::Let(name, wt, next));
            }
        }
        // the conjunction: the invariants that are propositions (each a
        // fact for the next ones; a disjunction in its implication form),
        // then `¬c` for `while`
        if !lifted {
            // the earlier conjuncts are facts for an invariant's own
            // operations only when they are needed (a first attempt hides
            // them): proofs that use them embed their statements, which
            // makes each later statement larger
            let mut conj_lvls: Vec<u32> = Vec::new();
            for (k, inv) in l.info.invariants.iter().enumerate() {
                if dropped.contains(&k) {
                    continue;
                }
                let (nobl, ndiag, failed) = (self.obligations.len(), self.diags.list.len(), self.f.failed);
                let saved = self.f.scope.clone();
                let first = self.prop(inv);
                let p = match first {
                    Ok(p) if conj_lvls.is_empty() || self.obligations[nobl..].iter().all(|o| o.proven()) => p,
                    _ => {
                        self.obligations.truncate(nobl);
                        self.diags.list.truncate(ndiag);
                        self.f.failed = failed;
                        self.f.scope = saved;
                        for lv in &conj_lvls {
                            self.f.scope.hidden.remove(lv);
                        }
                        let p = self.prop(inv)?;
                        conj_lvls.iter().for_each(|lv| {
                            self.f.scope.hidden.insert(*lv);
                        });
                        p
                    }
                };
                self.retag_exit_failures(nobl, ndiag, inv.span);
                let Some((q, weakened)) = self.propify(&p, 8) else { continue };
                let lv = self.push_fact_rel("h_inv", Rel::Rel, &q, None, FactOrigin::Invariant, inv.span)?;
                self.f.scope.hidden.insert(lv);
                conj_lvls.push(lv);
                conj.push((q, inv.span, k, weakened));
            }
            // all of them are facts for the loop condition
            for lv in &conj_lvls {
                self.f.scope.hidden.remove(lv);
            }
        }
        let ci = l.info.invariants.len();
        if let LoopKind::While { cond } = &l.kind
            && !dropped.contains(&ci)
            && let Some(c) = self.exit_condition(cond)
        {
            conj.push((c, l.span, ci, 0));
        }
        let Some((last, ..)) = conj.last() else { return Ok(None) };
        let mut body = last.clone();
        for (p, ..) in conj[..conj.len() - 1].iter().rev() {
            body = mk::sigma("h_inv", Rel::Rel, p.clone(), body);
        }
        for node in prefix.iter().rev() {
            body = match node {
                Node::Let(name, ty, val) => mk::let_(name, Rel::Rel, ty.clone(), val.clone(), body),
                Node::Pi(name, dom) => mk::pi(name, Rel::Rel, dom.clone(), body),
            };
        }
        let uses_index = nb == 3 && (sandblaster_kernel::util::occurs(&body, 2) || sandblaster_kernel::util::occurs(&body, 0));
        Ok(Some(PostStmt {
            base,
            bound,
            rt,
            body,
            prefix: prefix.len(),
            spans: conj.iter().map(|c| c.1).collect(),
            uses_index,
            lifted,
            conj_idx: conj.iter().map(|c| c.2).collect(),
            weak: conj.iter().map(|c| c.3).collect(),
            optional: conj.iter().map(|c| c.3 > 0 || c.2 == ci).collect(),
            zname,
            rname,
            failed: Rc::new(std::cell::RefCell::new(Vec::new())),
        }))
    }

    /// A proposition the post-state statement can carry for the invariant
    /// `p` (a term at the current depth), and whether it is weaker than `p`:
    /// `p` itself when it is a proposition in the kernel's sense (its proofs
    /// carry no information: equations, `Π`, `Σ` of propositions, `Unit`,
    /// `Empty`, after `let`s and the unfolding of transparent definitions
    /// such as `Not`, `And`, `Iff` and spec predicates), since the lemma's
    /// statement is a squash of the conjunction; for a disjunction `p ∨ q`
    /// the implication `¬p → q'` (`q'` for `q`), which follows from it and
    /// is what a proof after the loop uses; `None` otherwise (`exists`, an
    /// opaque predicate): that invariant is not stated after the loop.
    fn propify(&self, p: &Tm, fuel: u32) -> Option<(Tm, u32)> {
        if self.is_prop_tm(p, 16) {
            return Some((p.clone(), 0));
        }
        if fuel == 0 {
            return None;
        }
        if let Term::Let { name, rel, ty, val, body } = &**p {
            let (b, w) = self.propify(body, fuel - 1)?;
            return Some((mk::let_(name, *rel, ty.clone(), val.clone(), b), w));
        }
        let (a, b) = self.or_parts(p)?;
        let (q, w) = self.propify(&b, fuel - 1)?;
        Some((mk::pi("h_not", Rel::Rel, self.premise_of(&a), shift(&q, 1)), w + 1))
    }

    /// The premise of the implication form of `a ∨ q`: `t = !c` when `a` is
    /// the boolean equation `t = c` (what a proof after the loop has, e.g.
    /// `found == true` for `found == false || ..`), else `Not(a)`.
    fn premise_of(&self, a: &Tm) -> Tm {
        match self.bool_eq(a) {
            Some((t, c)) => mk::eq(mk::bool_ty(self.p.bool_), t, self.bool_lit(!c)),
            None => mk::app(mk::global(self.p.g("Not")), a.clone()),
        }
    }

    /// `(t, c)` for the proposition `Eq(Bool, t, c)` with `c` a literal.
    fn bool_eq(&self, a: &Tm) -> Option<(Tm, bool)> {
        let Term::Eq { ty, lhs, rhs } = &**a else { return None };
        let bool_ = self.p.bool_;
        match (&**ty, &**rhs) {
            (Term::Ind { ind, .. }, Term::Ctor { ind: i2, ctor, .. }) if *ind == bool_ && *i2 == bool_ => Some((lhs.clone(), *ctor == 1)),
            _ => None,
        }
    }

    /// `(p, q)` for the proposition `Or(p, q)`.
    fn or_parts(&self, t: &Tm) -> Option<(Tm, Tm)> {
        let (head, args) = spine_rels(t);
        match (&*head, args.as_slice()) {
            (Term::Global(g), [(Rel::Rel, a), (Rel::Rel, b)]) if *g == self.p.g("Or") => Some((a.clone(), b.clone())),
            _ => None,
        }
    }

    /// The disjunction a conjunct in implication form stands for (`n` of its
    /// disjunctions converted, [`Elab::propify`]): `Π(h : Not(p)). q ↦
    /// Or(p, q)`, under its `let`s.
    fn unweaken(&self, t: &Tm, n: u32) -> Option<Tm> {
        if n == 0 {
            return Some(t.clone());
        }
        match &**t {
            Term::Let { name, rel, ty, val, body } => Some(mk::let_(name, *rel, ty.clone(), val.clone(), self.unweaken(body, n)?)),
            Term::Pi { rel: Rel::Rel, dom, cod, .. } => {
                let (head, args) = spine_rels(dom);
                let a = match (self.bool_eq(dom), args.as_slice()) {
                    (Some((t, c)), _) => mk::eq(mk::bool_ty(self.p.bool_), t, self.bool_lit(!c)),
                    (None, [(Rel::Rel, a)]) if matches!(&*head, Term::Global(g) if *g == self.p.g("Not")) => a.clone(),
                    _ => return None,
                };
                let rest = self.unweaken(cod, n - 1)?;
                if sandblaster_kernel::util::occurs(&rest, 0) {
                    return None;
                }
                Some(mk::apps(mk::global(self.p.g("Or")), [(Rel::Rel, a.clone()), (Rel::Rel, shift(&rest, -1))]))
            }
            _ => None,
        }
    }

    /// From a proof `o` of a proposition `p` (terms at the same depth), a
    /// proof of [`Elab::propify`]`(p)`: `p` itself, or for `Or(a, b)` the
    /// implication `λ(h : Not(a)). match o with | Left(x) => absurd(h x) |
    /// Right(y) => <y converted>` (an irrelevant proof: the match
    /// eliminates an irrelevant disjunction into a proposition).
    fn or_to_impl(&self, o: &Tm, p: &Tm) -> Option<Tm> {
        if self.is_prop_tm(p, 16) {
            return Some(o.clone());
        }
        if let Term::Let { name, rel, ty, val, body } = &**p {
            return Some(mk::let_(name, *rel, ty.clone(), val.clone(), self.or_to_impl(&shift(o, 1), body)?));
        }
        let (a, b) = self.or_parts(p)?;
        let (qb, _) = self.propify(&b, 8)?;
        let prem = self.premise_of(&a);
        // under `h` and a field: depth + 2
        let q2 = shift(&qb, 2);
        let empty = match self.bool_eq(&a) {
            // `x : t = c`, `h : t = !c`: `c = !c` by `trans(sym(x), h)`
            Some((t, c)) => {
                let bt = mk::bool_ty(self.p.bool_);
                let (t2, cl, ncl) = (shift(&t, 2), self.bool_lit(c), self.bool_lit(!c));
                let sym_x = mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, bt.clone()), (Rel::Rel, t2.clone()), (Rel::Rel, cl.clone()), (Rel::Rel, mk::var(0))]);
                let e = mk::apps(mk::global(self.p.g("eq::trans")), [(Rel::Rel, bt.clone()), (Rel::Rel, cl.clone()), (Rel::Rel, t2), (Rel::Rel, ncl.clone()), (Rel::Rel, sym_x), (Rel::Rel, mk::var(1))]);
                // `false = true`
                let ft = if c { mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, bt), (Rel::Rel, cl), (Rel::Rel, ncl), (Rel::Rel, e)]) } else { e };
                mk::app(mk::global(self.p.g("bool::false_ne_true")), ft)
            }
            None => mk::app(mk::var(1), mk::var(0)),
        };
        let left = Rc::new(Term::Absurd { ty: q2.clone(), proof: empty });
        let right = self.or_to_impl(&mk::var(0), &shift(&b, 2))?;
        let m = Rc::new(Term::Match {
            ind: self.p.either,
            params: vec![shift(&a, 1), shift(&b, 1)],
            scrut: shift(o, 1),
            motive: q2,
            arms: vec![mk::arm(&["x"], left), mk::arm(&["y"], right)],
        });
        Some(mk::lam("h_not", Rel::Rel, prem, m))
    }

    /// Whether the proposition `ty` (a term at the current depth) is one the
    /// kernel accepts as the irrelevant component of a `Σ` (a conservative
    /// syntactic check, see [`Elab::propify`]).
    fn is_prop_tm(&self, ty: &Tm, fuel: u32) -> bool {
        if fuel == 0 {
            return false;
        }
        match &**ty {
            Term::Eq { .. } => true,
            Term::Let { body, .. } => self.is_prop_tm(body, fuel),
            Term::Pi { cod, .. } => self.is_prop_tm(cod, fuel - 1),
            Term::Sigma { fst, snd, .. } => self.is_prop_tm(fst, fuel - 1) && self.is_prop_tm(snd, fuel - 1),
            Term::Ind { ind, .. } => *ind == self.p.unit || *ind == self.env.empty_ind(),
            _ => match super::tm::head_unfold(&self.env, ty, &|t| matches!(t, Term::Eq { .. } | Term::Pi { .. } | Term::Sigma { .. } | Term::Ind { .. })) {
                Some(t2) => self.is_prop_tm(&t2, fuel - 1),
                None => false,
            },
        }
    }

    /// Obligations of an invariant's own operations (an index, an overflow,
    /// …) that failed while it was stated at the exit (records from `nobl`,
    /// diagnostics from `ndiag`): reported as `invariant-exit` with a note,
    /// since the invariant must be defined after the last iteration.
    fn retag_exit_failures(&mut self, nobl: usize, ndiag: usize, span: Span) {
        let mut any = false;
        for o in &mut self.obligations[nobl..] {
            if !o.proven() && o.kind != ObligationKind::InvariantExit {
                o.kind = ObligationKind::InvariantExit;
                any = true;
            }
        }
        if !any {
            return;
        }
        for d in &mut self.diags.list[ndiag..] {
            if d.kind == crate::diag::DiagKind::Obligation
                && let Some(rest) = d.msg.strip_prefix("unproven obligation [")
                && let Some(i) = rest.find(']')
            {
                let what = rest[..i].to_string();
                d.msg = format!("unproven obligation [invariant-exit] in{}", rest[i + 1..].strip_prefix(" in").unwrap_or(&rest[i + 1..]));
                d.notes.insert(0, (Some(span), format!("the invariant's operations must be defined when the loop exits ({what}), not only inside the loop body")));
                d.notes.push((None, super::obl::INVARIANT_EXIT_NOTE.to_string()));
            }
        }
    }

    /// The invariants of `a..=b` stated exactly at `b + 1` over `Int`
    /// ([`PostStmt::lifted`]): elaborated at a fresh index `j`, then every
    /// `j as Int` replaced by `(z as Int) + 1` (`z` the statement's binder at
    /// level `z_lvl`, the last index) and `j` removed. `None`, with nothing
    /// recorded, when an invariant needs an obligation (its proof could
    /// depend on `j`), uses the loop variable other than as `i as Int`, is
    /// not a proposition ([`Elab::propify`]), or is `dropped`. The
    /// conjuncts are pushed as facts, like the unlifted ones.
    fn lifted_invariants(&mut self, l: &'a Loop, v: LocalId, w: Width, z_lvl: u32, dropped: &[usize]) -> R<Option<Vec<(Tm, Span)>>> {
        if !dropped.is_empty() {
            return Ok(None);
        }
        let saved = self.f.scope.clone();
        let (nobl, ndiag, failed) = (self.obligations.len(), self.diags.list.len(), self.f.failed);
        let j = self.push("i", Rel::Rel, &mk::int_ty(w), None)?;
        self.f.scope.locals.insert(v, j);
        let mut raw: Vec<(Tm, Span)> = Vec::new();
        let mut ok = true;
        for inv in &l.info.invariants {
            match self.prop(inv) {
                Ok(p) if self.is_prop_tm(&p, 16) && self.push("h_inv", Rel::Rel, &p, None).is_ok() => raw.push((p, inv.span)),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        ok = ok && self.obligations.len() == nobl && self.f.failed == failed;
        self.f.scope = saved;
        let lifted = if ok { lift_conjuncts(raw, j, z_lvl, w) } else { None };
        let Some(out) = lifted else {
            self.obligations.truncate(nobl);
            self.diags.list.truncate(ndiag);
            self.f.failed = failed;
            return Ok(None);
        };
        for (p, span) in &out {
            self.push_fact_rel("h_inv", Rel::Rel, p, None, FactOrigin::Invariant, *span)?;
        }
        Ok(Some(out))
    }

    /// `¬c` for the `while` condition `c` at the exit state, as a
    /// proposition in the current context (the invariants are facts):
    /// `c = false` for a simple condition; for `a && b` (where `b` runs
    /// only when `a` holds) `a = true → ¬b`, for `a || b` `a = false ∧ ¬b`,
    /// for `!x` `x = true`. `None` when the condition has another branching
    /// form or one of its partial operations is not provably defined there
    /// (then the post-state has no `¬c`; nothing is recorded).
    fn exit_condition(&mut self, cond: &'a Expr) -> Option<Tm> {
        let saved = self.f.scope.clone();
        let (nobl, ndiag, failed) = (self.obligations.len(), self.diags.list.len(), self.f.failed);
        let c = self.neg_cond(cond, 8);
        self.f.scope = saved;
        if c.is_some() && self.obligations[nobl..].iter().all(|o| o.proven()) {
            return c;
        }
        self.obligations.truncate(nobl);
        self.diags.list.truncate(ndiag);
        self.f.failed = failed;
        None
    }

    fn neg_cond(&mut self, e: &'a Expr, fuel: u32) -> Option<Tm> {
        let e = Elab::peel(e);
        let bool_ty = mk::bool_ty(self.p.bool_);
        let lit = |s: &Self, b: bool| s.bool_lit(b);
        match &e.kind {
            ExprKind::Binary(op @ (BinOp::And | BinOp::Or), a, b) if fuel > 0 => {
                let and = *op == BinOp::And;
                let va = self.pure_loop_value(a).ok()?;
                // `b` runs when `a` is `and`
                let guard = mk::eq(bool_ty, va, lit(self, and));
                self.push_fact_rel("h_c", Rel::Rel, &guard, None, FactOrigin::PathCond, e.span).ok()?;
                let nb = self.neg_cond(b, fuel - 1)?;
                Some(if and { mk::pi("h_c", Rel::Rel, guard, nb) } else { mk::sigma("h_c", Rel::Rel, guard, nb) })
            }
            ExprKind::Unary(UnOp::Not, x) if matches!(x.ty, Ty::Bool) => {
                let v = self.pure_loop_value(x).ok()?;
                Some(mk::eq(bool_ty, v, lit(self, true)))
            }
            _ => {
                let v = self.pure_loop_value(e).ok()?;
                Some(mk::eq(bool_ty, v, lit(self, false)))
            }
        }
    }

    /// The statement at the value `v` (a term at the current depth `d`):
    /// `let z : W = b; let ret : RT = v; let hz : Eq(W, z, b) = refl(W, b);
    /// body` (`for`), `let ret : RT = v; body` (`while`).
    fn post_at(&self, ps: &PostStmt, v: &Tm) -> Tm {
        let k = (self.depth() - ps.base) as i64;
        match &ps.bound {
            Some((b, w)) => {
                let wt = mk::int_ty(*w);
                let b2 = shift(b, k + 2);
                let hz = mk::let_("hz", Rel::Rel, mk::eq(wt.clone(), mk::var(1), b2.clone()), mk::refl(wt.clone(), b2), shift_from(&ps.body, k, 3));
                mk::let_(&ps.zname, Rel::Rel, wt, shift(b, k), mk::let_(&ps.rname, Rel::Rel, shift(&ps.rt, k + 1), shift(v, 1), hz))
            }
            None => mk::let_(&ps.rname, Rel::Rel, shift(&ps.rt, k), v.clone(), shift_from(&ps.body, k, 1)),
        }
    }

    /// `w. Post(w)` (`w. Squash(Post(w))` when `squashed`): the statement
    /// as a motive over the value (a term at depth `d + 1`; `rt` is the
    /// value's type at the current depth `d`).
    fn post_motive_value(&mut self, ps: &PostStmt, rt: &Tm, squashed: bool) -> R<Tm> {
        let saved = self.f.scope.clone();
        let r = self.push("w", Rel::Rel, rt, None).map(|_| {
            let p = self.post_at(ps, &mk::var(0));
            if squashed { self.squash(&p) } else { p }
        });
        self.f.scope = saved;
        r
    }

    /// `z. let ret : RT = v; Π(hz : Eq(W, z, b)). body`: the statement as a
    /// motive over the index (a term at depth `d + 1`, `v` at `d`).
    fn post_motive_index(&self, ps: &PostStmt, v: &Tm) -> R<Tm> {
        let Some((b, w)) = &ps.bound else { return internal(Span::DUMMY, "index motive of a `while` statement") };
        let k = (self.depth() - ps.base) as i64;
        let wt = mk::int_ty(*w);
        let hz = mk::pi("hz", Rel::Rel, mk::eq(wt, mk::var(1), shift(b, k + 2)), shift_from(&ps.body, k, 3));
        Ok(mk::let_(&ps.rname, Rel::Rel, shift(&ps.rt, k + 1), shift(v, 1), hz))
    }

    /// The statement at `v`, proven at the index `t` (with `hz : t = b` as
    /// a fact) and moved to `b`: `transport(W, t, b, t = b, z. …, proof)`
    /// applied to `refl(W, b)`. Proving at `t` keeps the goals in the shape
    /// of the loop's own obligations (`i + 1` like preservation, `a` like
    /// entry).
    fn post_moved(&mut self, ps: &PostStmt, v: &Tm, t: Tm, hints: Option<&Hints>, span: Span) -> R<Tm> {
        let Some((b, w)) = &ps.bound else { return internal(span, "index of a `while` statement") };
        let wt = mk::int_ty(*w);
        let b = shift(b, (self.depth() - ps.base) as i64);
        let at = self.prove_post(ps, v, At::Index(t.clone()), ObligationKind::InvariantExit, hints)?;
        let eq = self.prove(ObligationKind::WellFormed, span, &mk::eq(wt.clone(), t.clone(), b.clone()), false)?;
        let motive = self.post_motive_index(ps, v)?;
        let tr = Rc::new(Term::Transport { ty: wt.clone(), lhs: t, rhs: b.clone(), eq, motive, val: at });
        Ok(Rc::new(Term::App { rel: Rel::Rel, fun: tr, arg: mk::refl(wt, b) }))
    }

    /// A proof of the statement at `v` (a term at the current depth), its
    /// binders instantiated per `at`; every conjunct is an obligation of
    /// `kind` at its span, proven irrelevantly (the proof is used in the
    /// squash of the lemma, or as the call site's irrelevant fact), first
    /// from the `hints`.
    fn prove_post(&mut self, ps: &PostStmt, v: &Tm, at: At, kind: ObligationKind, hints: Option<&Hints>) -> R<Tm> {
        let saved = self.f.scope.clone();
        let r = self.prove_post_inner(ps, v, at, kind, hints);
        self.f.scope = saved;
        r
    }

    fn prove_post_inner(&mut self, ps: &PostStmt, v: &Tm, at: At, kind: ObligationKind, hints: Option<&Hints>) -> R<Tm> {
        enum Wrap {
            Let(String, Tm, Tm),
            Lam(String, Rel, Tm),
        }
        let span = ps.spans.first().copied().unwrap_or(Span::DUMMY);
        let k = (self.depth() - ps.base) as i64;
        let mut wraps = Vec::new();
        let nb = match &ps.bound {
            Some((b, w)) => {
                let wt = mk::int_ty(*w);
                let (zv, stmt) = match &at {
                    At::Stmt => (shift(b, k), true),
                    At::Index(t) => (t.clone(), false),
                };
                self.push(&ps.zname, Rel::Rel, &wt, Some(&zv))?;
                wraps.push(Wrap::Let(ps.zname.clone(), wt.clone(), zv));
                let (rt1, v1) = (shift(&ps.rt, k + 1), shift(v, 1));
                self.push(&ps.rname, Rel::Rel, &rt1, Some(&v1))?;
                wraps.push(Wrap::Let(ps.rname.clone(), rt1, v1));
                let b2 = shift(b, k + 2);
                let hz = mk::eq(wt.clone(), mk::var(1), b2.clone());
                if stmt {
                    let r = mk::refl(wt, b2);
                    self.push_fact_rel("hz", Rel::Rel, &hz, Some(&r), FactOrigin::Invariant, span)?;
                    wraps.push(Wrap::Let("hz".into(), hz, r));
                } else {
                    self.push_fact_rel("hz", Rel::Rel, &hz, None, FactOrigin::Invariant, span)?;
                    wraps.push(Wrap::Lam("hz".into(), Rel::Rel, hz));
                }
                3
            }
            None => {
                let rt0 = shift(&ps.rt, k);
                self.push(&ps.rname, Rel::Rel, &rt0, Some(v))?;
                wraps.push(Wrap::Let(ps.rname.clone(), rt0, v.clone()));
                1
            }
        };
        let mut cur = shift_from(&ps.body, k, nb);
        for _ in 0..ps.prefix {
            let next = match &*cur {
                Term::Let { name, ty, val, body, .. } => {
                    self.push(name, Rel::Rel, ty, Some(val))?;
                    wraps.push(Wrap::Let(name.to_string(), ty.clone(), val.clone()));
                    body.clone()
                }
                Term::Pi { name, rel, dom, cod } => {
                    self.push_fact_rel(name, *rel, dom, None, FactOrigin::Invariant, span)?;
                    wraps.push(Wrap::Lam(name.to_string(), *rel, dom.clone()));
                    cod.clone()
                }
                _ => return internal(span, "post-loop statement prefix"),
            };
            cur = next;
        }
        let mut p = self.prove_chain(&cur, ps, 0, &kind, hints)?;
        for w in wraps.into_iter().rev() {
            p = match w {
                Wrap::Let(name, ty, val) => mk::let_(&name, Rel::Rel, ty, val, p),
                Wrap::Lam(name, rel, dom) => mk::lam(&name, rel, dom, p),
            };
        }
        Ok(p)
    }

    /// Proves the conjunction `t` from its `j`-th conjunct on: `pair(Σ, p,
    /// rest)`. Conjuncts are proven independently (an already proven
    /// conjunct is not a fact for the next ones, which keeps the linear
    /// search of each one as small as for the loop's own obligations); a
    /// conjunct whose statement depends on an earlier one (a partial
    /// operation whose definedness proof uses it) gets it bound, hidden
    /// from the provers.
    fn prove_chain(&mut self, t: &Tm, ps: &PostStmt, j: usize, kind: &ObligationKind, hints: Option<&Hints>) -> R<Tm> {
        if j + 1 >= ps.spans.len() {
            return self.prove_conj(t, ps, j, kind, hints);
        }
        let Term::Sigma { name, snd_rel: Rel::Rel, fst, snd } = &**t else { return internal(ps.spans[j], "post-loop conjunction") };
        let p = self.prove_conj(fst, ps, j, kind, hints)?;
        if !sandblaster_kernel::util::occurs(snd, 0) {
            let rest = self.prove_chain(&shift(snd, -1), ps, j + 1, kind, hints)?;
            return Ok(mk::pair(t.clone(), p, rest));
        }
        let saved = self.f.scope.clone();
        let rest = self.push(name, Rel::Rel, fst, Some(&p)).and_then(|lvl| {
            self.f.scope.hidden.insert(lvl);
            self.prove_chain(snd, ps, j + 1, kind, hints)
        });
        self.f.scope = saved;
        Ok(mk::pair(t.clone(), p.clone(), mk::let_(name, Rel::Rel, fst.clone(), p, rest?)))
    }

    /// The `j`-th conjunct, as an irrelevant proof: the hint of its
    /// invariant (a proof valid at the hints' depth, shifted here) when the
    /// kernel accepts it, else the prover's (a failure is recorded in
    /// [`PostStmt::failed`]).
    fn prove_conj(&mut self, target: &Tm, ps: &PostStmt, j: usize, kind: &ObligationKind, hints: Option<&Hints>) -> R<Tm> {
        // a disjunction in implication form: the disjunction, converted
        if ps.weak[j] > 0
            && let Some(orig) = self.unweaken(target, ps.weak[j])
        {
            let o = self.prove_conj_as(&orig, ps, j, kind, hints)?;
            return match self.or_to_impl(&o, &orig) {
                Some(p) => Ok(p),
                None => internal(ps.spans[j], "post-loop disjunction"),
            };
        }
        self.prove_conj_as(target, ps, j, kind, hints)
    }

    fn prove_conj_as(&mut self, target: &Tm, ps: &PostStmt, j: usize, kind: &ObligationKind, hints: Option<&Hints>) -> R<Tm> {
        let (span, ci) = (ps.spans[j], ps.conj_idx[j]);
        if let Some(h) = hints
            && let Some(hp) = h.proofs.get(ci)
            && h.depth <= self.depth()
        {
            let cand = shift(hp, (self.depth() - h.depth) as i64);
            let tv = self.eval(target)?;
            if self.check_proof_in(&self.f.scope.ctx, &cand, target, &tv, false).is_ok() {
                let id = self.obligations.len() as u32;
                self.record(id, kind.clone(), span, super::OblStatus::Proven { by: "reuse".into() }, false, String::new());
                return Ok(cand);
            }
        }
        let id = self.obligations.len() as u32;
        let p = self.prove(kind.clone(), span, target, false)?;
        if self.obligations.get(id as usize).is_some_and(|o| !o.proven()) {
            ps.failed.borrow_mut().push((ci, id));
        }
        Ok(p)
    }

    /// A tail of the helper body in the lemma walk: a recursive call (the
    /// induction hypothesis; for `a..=b`, the final call with `done = true`
    /// unfolds to the exit), an exit (`InvariantExit`), or `unreachable!()`.
    fn loop_leaf(&mut self, g: &LoopGoal, v: &Tm) -> R<Tm> {
        let span = g.span;
        if let Term::Absurd { proof, .. } = &**v {
            // the same proof of `Empty`
            let goal = self.squash(&self.post_at(&g.ps, v));
            return Ok(Rc::new(Term::Absurd { ty: goal, proof: proof.clone() }));
        }
        let (head, args) = spine_rels(v);
        if matches!(&*head, Term::Global(h) if *h == g.helper) && args.len() == g.n as usize {
            if let Shape::Incl { done_pos, .. } = g.shape {
                let bool_ = self.p.bool_;
                let lit = |t: &Tm| match &**t {
                    Term::Ctor { ind, ctor, .. } if *ind == bool_ => Some(*ctor == 1),
                    _ => None,
                };
                match lit(&args[done_pos as usize].1) {
                    Some(true) => return self.incl_final(g, v, &args),
                    Some(false) => {}
                    None => return internal(span, "inclusive loop helper called with a non-literal `done`"),
                }
            }
            // the induction hypothesis
            let mut all: Vec<Tm> = args.into_iter().map(|a| a.1).collect();
            if matches!(g.shape, Shape::Incl { .. }) {
                all.push(mk::refl(mk::bool_ty(self.p.bool_), self.bool_lit(false)));
            }
            let r = self.f.rec.clone().ok_or_else(|| super::ElabError { span, msg: "post-loop lemma without recursion".into(), kind: super::ErrKind::Internal })?;
            let (m, w) = r.measure.clone().ok_or_else(|| super::ElabError { span, msg: "post-loop lemma without measure".into(), kind: super::ErrKind::Internal })?;
            let proof = self.measure_proof(&m, w, r.arity, &all, span)?;
            return Ok(Rc::new(Term::Rec { args: all, proof: Some(proof) }));
        }
        // the exit (a proof of the statement, in the squash)
        let hints = g.rec_hints.as_ref().filter(|h| h.depth == self.depth());
        let exit = match g.shape {
            // the exit of `a..b` after `i`: proven at `i + 1` (the shape of
            // preservation, whose proofs are the hints) and moved to `b`
            Shape::Excl { i_pos, w } if g.ps.uses_index => {
                let i = self.f.scope.var(i_pos);
                let one = mk::lit(w, 1u8);
                let mut proofs = Vec::new();
                for o in sandblaster_kernel::prim::prim_obligations(PrimOp::Add(w), &[i.clone(), one.clone()], self.p.bool_) {
                    proofs.push(self.prove(ObligationKind::WellFormed, span, &o, false)?);
                }
                let next = mk::prim(PrimOp::Add(w), vec![i, one], proofs);
                self.post_moved(&g.ps, v, next, hints, span)?
            }
            Shape::Excl { .. } => self.prove_post(&g.ps, v, At::Stmt, ObligationKind::InvariantExit, hints)?,
            // `while` (the invariants are the hypotheses, `c = false` the path
            // condition) and the `done` branch of `a..=b` (unreachable under
            // `hd`)
            _ => self.prove_post(&g.ps, v, At::Stmt, ObligationKind::InvariantExit, None)?,
        };
        Ok(self.squash_intro(&self.post_at(&g.ps, v), exit))
    }

    /// The final call `H(i, true, M')` of `a..=b` (after the iteration with
    /// `i = b`): the statement for `M'` (proven at `i`, moved to `b`), then
    /// `H(i, true, M') = M'` by `delta`.
    fn incl_final(&mut self, g: &LoopGoal, v: &Tm, args: &[(Rel, Tm)]) -> R<Tm> {
        let span = g.span;
        let Shape::Incl { i_pos, .. } = g.shape else { return internal(span, "inclusive exit") };
        let comps: Vec<Tm> = g.m_pos.iter().map(|p| args[*p as usize].1.clone()).collect();
        let mt = match comps.len() {
            0 => self.unit_val(),
            1 => comps[0].clone(),
            _ => {
                let (ind, params) = self.ind_of(&g.rt, span)?;
                mk::ctor(ind, 0, params, comps)
            }
        };
        let exit = if g.ps.uses_index { self.post_moved(&g.ps, &mt, args[i_pos as usize].1.clone(), None, span)? } else { self.prove_post(&g.ps, &mt, At::Stmt, ObligationKind::InvariantExit, None)? };
        let exit = self.squash_intro(&self.post_at(&g.ps, &mt), exit);
        let rt = shift(&g.ps.rt, (self.depth() - g.ps.base) as i64);
        let delta = Rc::new(Term::Delta { def: g.helper, args: args.iter().map(|a| a.1.clone()).collect() });
        let eq = mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, rt.clone()), (Rel::Rel, v.clone()), (Rel::Rel, mt.clone()), (Rel::Rel, delta)]);
        let motive = self.post_motive_value(&g.ps, &rt, true)?;
        Ok(Rc::new(Term::Transport { ty: rt, lhs: mt, rhs: v.clone(), eq, motive, val: exit }))
    }

    /// The post-loop fact at the call site (after the loop's join, the
    /// mutated locals destructured): `h_loop :Irr [a ≤ b →] Post(J)`, then
    /// `k`. `J` (`jv`) is the call: `if a < b { H(a, ..) } else { M }`
    /// (`for`), `H(..)` (`while`); its proof opens a squash built from the
    /// lemma (`snd(E ..)` for `while`, `snd` of the mirrored call for
    /// `for`, [`Elab::post_mirror`]). The premise `a ≤ b` is left out when
    /// `a` is the literal `0` or it holds by evaluation.
    ///
    /// The committed `let` states the fact about `J` (so the fact's proof
    /// stays valid where the join variable is abstracted). The elaboration
    /// context sees the same fact stated about the destructured locals,
    /// `Post((x₁, …, xₙ))`, which is convertible to it (the locals are
    /// projections of the join variable, which is `J` by definition) and
    /// much smaller: goals after the loop read back the locals, not `J`,
    /// and the fact is carried into the requires of a later loop that reads
    /// the locals (§7.4: facts over the helper's parameters). The binder is
    /// abstract there (its proof is never unfolded by the provers).
    fn post_fact(&mut self, l: &'a Loop, lemma: &PostLemma, jv: &Val, mutated: &[LocalId], jt: &Ty, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let span = l.span;
        let saved = self.f.scope.clone();
        let res = (|| -> R<Option<(Tm, Tm, Tm)>> {
            let Some(ps) = self.post_stmt(l, mutated, jt, Some(lemma.shape.lifted), &lemma.shape.dropped)? else { return Ok(None) };
            let (hab, proof) = match &l.kind {
                LoopKind::While { .. } => {
                    let (_, args) = spine_rels(&jv.at(self.depth()));
                    (None, mk::snd(self.post_lemma_app(lemma, args)))
                }
                LoopKind::ForRange { lo, hi, .. } => {
                    let Some((test, jmatch, jfalse, jtrue)) = split_if(&jv.tm, self.p.bool_) else { return internal(span, "loop call shape") };
                    // the premise `a <= b`, unless `a` is the literal `0` or
                    // it holds by evaluation (literal bounds)
                    let hab = if matches!(&Elab::peel(lo).kind, ExprKind::Lit(Lit::Int(0))) {
                        None
                    } else {
                        let w = self.width_of(&lo.ty, lo.span)?;
                        let (a, b) = (self.pure_loop_value(lo)?, self.pure_loop_value(hi)?);
                        let le = mk::prim(PrimOp::Le(w), vec![a, b], vec![]);
                        let bool_ = self.p.bool_;
                        if matches!(&*self.eval(&le)?, sandblaster_kernel::value::Value::Ctor { ind, ctor: 1, .. } if *ind == bool_) { None } else { Some(self.holds(le)) }
                    };
                    let proof = self.post_mirror(l, &ps, lemma, jv.depth, (&test, &jmatch, &jfalse, &jtrue), hab.as_ref())?;
                    (hab, proof)
                }
            };
            let committed = self.stmt_under(&ps, &jv.at(self.depth()), hab.as_ref())?;
            let locals = self.locals_tuple(mutated, span)?;
            let view = self.stmt_under(&ps, &locals, hab.as_ref())?;
            Ok(Some((view, committed, proof)))
        })();
        self.f.scope = saved;
        match res? {
            Some((view, committed, proof)) => {
                let rel = self.fact_rel();
                let saved = self.f.scope.clone();
                self.push_fact("h_loop", &view, None, FactOrigin::Invariant, span)?;
                let body = k(self);
                self.f.scope = saved;
                Ok(mk::let_("h_loop", rel, committed, proof, body?))
            }
            None => k(self),
        }
    }

    /// `[Π(hab : a ≤ b).] Post(v)` (`v` and `hab` at the current depth).
    fn stmt_under(&mut self, ps: &PostStmt, v: &Tm, hab: Option<&Tm>) -> R<Tm> {
        let Some(h) = hab else { return Ok(self.post_at(ps, v)) };
        let saved = self.f.scope.clone();
        let r = self.push("hab", Rel::Rel, h, None).map(|_| self.post_at(ps, &shift(v, 1)));
        self.f.scope = saved;
        Ok(mk::pi("hab", Rel::Rel, h.clone(), r?))
    }

    /// `E args` (with `refl(Bool, false)` for `hd` of `a..=b`).
    fn post_lemma_app(&self, lemma: &PostLemma, args: Vec<(Rel, Tm)>) -> Tm {
        let mut args = args;
        if lemma.incl {
            args.push((Rel::Irr, mk::refl(mk::bool_ty(self.p.bool_), self.bool_lit(false))));
        }
        mk::apps(mk::global(lemma.global), args)
    }

    /// The (irrelevant) proof of the post-loop fact `[Π(hab : a ≤ b).]
    /// Post(J)` of a `for` loop: the call `J` = `if a < b { H(a, ..) } else
    /// { M }` mirrored (as in the `ensures` walk) into a squash, then
    /// opened: `snd((match a < b as y return Π(e). Squash([Π(hab).]
    /// Post((match y … J's arms) e)) with | false => λe. (tt, [λhab.] <M:
    /// the statement at `a` (like entry, whose proofs are the hints), moved
    /// to `b`>) | true => λe. E(a, ..) (or `(tt, λhab. snd(E(a, ..)))`))
    /// refl)`. The squash is opened outside the match (and inside the
    /// premise's `λ`): the kernel opens a squash in an irrelevant position
    /// only if it mentions no variable bound inside that position. `J`'s
    /// parts are at depth `d0` (arm bodies under their equation), `hab` at
    /// the current depth.
    fn post_mirror(&mut self, l: &'a Loop, ps: &PostStmt, lemma: &PostLemma, d0: u32, j: (&Tm, &Tm, &Tm, &Tm), hab: Option<&Tm>) -> R<Tm> {
        let (test, jmatch, jfalse, jtrue) = j;
        let span = l.span;
        let LoopKind::ForRange { lo, .. } = &l.kind else { return internal(span, "for loop") };
        let dp = self.depth();
        let kj = (dp - d0) as i64;
        let test = shift(test, kj);
        let bool_ty = mk::bool_ty(self.p.bool_);
        // the motive: Squash([Π(hab).] Post(J's match on `y`, applied to `e`))
        let saved = self.f.scope.clone();
        let mbody = (|| -> R<Tm> {
            self.push("y", Rel::Rel, &bool_ty, None)?;
            self.push("e", Rel::Irr, &mk::eq(bool_ty.clone(), shift(&test, 1), mk::var(0)), None)?;
            let Term::Match { ind, params, motive, arms, .. } = &*shift(jmatch, kj + 2) else { return internal(span, "loop call match") };
            let arms = arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: a.body.clone() }).collect();
            let inner = Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: mk::var(1), motive: motive.clone(), arms });
            let jm = Rc::new(Term::App { rel: Rel::Irr, fun: inner, arg: mk::var(0) });
            let st = self.stmt_under(ps, &jm, hab.map(|h| shift(h, 2)).as_ref())?;
            Ok(self.squash(&st))
        })();
        self.f.scope = saved;
        let motive = mk::pi("e", Rel::Irr, mk::eq(bool_ty.clone(), shift(&test, 1), mk::var(0)), mbody?);
        // `a..b`: the entry proofs of the helper call (in the `true` arm,
        // under its equation) are the hints for the empty range
        let hints = if lemma.incl {
            None
        } else {
            let (_, args) = spine_rels(&shift_from(jtrue, kj, 1));
            self.invariant_args(lemma.helper, &args, l.info.invariants.len()).map(|proofs| Hints { depth: dp + 1, proofs })
        };
        // the arms
        let mut arms = Vec::new();
        for (b, body) in [(false, jfalse), (true, jtrue)] {
            let saved = self.f.scope.clone();
            let ety = mk::eq(bool_ty.clone(), test.clone(), self.bool_lit(b));
            let r = (|| -> R<Tm> {
                self.push_fact_rel("e", Rel::Irr, &ety, None, FactOrigin::PathCond, span)?;
                let body = shift_from(body, kj, 1);
                let hab1 = hab.map(|h| shift(h, 1));
                if b && hab1.is_none() {
                    let (_, args) = spine_rels(&body);
                    return Ok(self.post_lemma_app(lemma, args));
                }
                // under the premise
                let saved = self.f.scope.clone();
                let inner = (|| -> R<Tm> {
                    if let Some(h) = &hab1 {
                        self.push_fact_rel("hab", Rel::Rel, h, None, FactOrigin::Invariant, span)?;
                    }
                    let nh = hab1.is_some() as i64;
                    let body = shift(&body, nh);
                    if b {
                        let (_, args) = spine_rels(&body);
                        return Ok(mk::snd(self.post_lemma_app(lemma, args)));
                    }
                    // the empty range: `M` at `a` (with `a = b`), moved to `b`
                    if ps.uses_index {
                        let a = self.pure_loop_value(lo)?;
                        self.post_moved(ps, &body, a, hints.as_ref(), span)
                    } else {
                        self.prove_post(ps, &body, At::Stmt, ObligationKind::InvariantExit, hints.as_ref())
                    }
                })();
                self.f.scope = saved;
                let p = match &hab1 {
                    Some(h) => mk::lam("hab", Rel::Rel, h.clone(), inner?),
                    None => inner?,
                };
                let st = self.stmt_under(ps, &body, hab1.as_ref())?;
                Ok(self.squash_intro(&st, p))
            })();
            self.f.scope = saved;
            arms.push(sandblaster_kernel::term::Arm { names: vec![], body: mk::lam("e", Rel::Irr, ety, r?) });
        }
        let m = Rc::new(Term::Match { ind: self.p.bool_, params: vec![], scrut: test.clone(), motive, arms });
        Ok(mk::snd(Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::refl(bool_ty, test) })))
    }
}
