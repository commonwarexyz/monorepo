//! Closing statements that name their reasoning (DESIGN.md §4.4,
//! docs/PROOF-GUIDE.md). Mounted by [`super`] (`elab::script`).
//!
//! A closing statement says *why* the remaining goal holds, and the
//! elaborator checks that claim, not merely the goal:
//!
//! * `by_contradiction()` — [`Elab::by_contradiction`]: the prover must
//!   derive `Empty` from the facts in scope; the goal is not used. The goal's
//!   proof is then `absurd(goal, p)`.
//! * `by_arithmetic()` / `by_unfolding(f, ..)` — [`Elab::by_reasoning`]: the
//!   prover chain runs **restricted** ([`Hint::Only`]: no case analysis on
//!   program values — linear integer arithmetic still splits internally on
//!   arithmetic atoms (integer cuts, disequalities), DESIGN.md §4.4 — no
//!   instantiation of ∀-facts or of the crate's lemmas, no `Delta` of a
//!   global beyond the named prelude definitions; the rules of the built-in
//!   theory — the library rewrite lemmas about the ghost `Seq`, slice and
//!   array operations, `auto::lemmas::LEMMA_ROLES` — and evaluation of the
//!   built-in functions (`pow2` on a literal) stay available, as DESIGN.md
//!   §4.4 lists them; `crate::auto::Mode`, `basic` without splits) on a
//!   **view** of the goal in which the crate's functions cannot be unfolded
//!   by evaluation either:
//!
//!   1. every function of the crate (an exec or spec `fn`, with or without
//!      parameters; `const` items stay: they are values) that occurs in the
//!      goal, a fact or a `let` value — plus the functions their types
//!      mention and the functions the named definitions call — becomes a
//!      variable `F_g : type of g`. A named definition `f` refers to these
//!      variables, so unfolding it exposes the variables of its callees,
//!      never their definitions: a non-recursive transparent `f` is a `let`
//!      `F_f := body` (its callees generalized), evaluated with the goal; a
//!      recursive or opaque one is a variable with its defining equation
//!      `Π(x..). F_f x.. == body[x..]` (a hidden fact, [`Hint::ViewFunction`]),
//!      which the prover uses like `Delta`;
//!   2. every relevant `let` the goal or a fact mentions (transitively)
//!      loses its value; an equation `x == value` (with the functions as
//!      variables) states it instead. When the goal does not follow in that
//!      view, the step is tried once more in the *derived* view, where each
//!      such `let` is bound again after the variables with its value in
//!      terms of them (a definition: the prover sees through it), and which
//!      adds derived facts: the facts with the named definitions unfolded
//!      once, the comparisons their bodies test when arithmetic decides
//!      them, the Nat ranges of spec results, and the field equations of a
//!      view link `s == v(e)` (`Elab::view_link_fields`: all of them when
//!      `v` is a type's `#[view]`, otherwise only the fields `v`'s body
//!      copies from its arguments, a projection or cast of an argument's
//!      fields; a computed field stays hidden with `v`);
//!   3. every fact that mentions a function of the crate or such a `let` is
//!      replaced by its copy in terms of the variables (the original is
//!      hidden from the provers, [`super::super::set_hidden_facts`]), and so
//!      is the goal. Context entries that are not recorded facts (with a
//!      statement term) are hidden as well.
//!
//!   The view's context is the goal's, extended by the variables, the
//!   definitions, the equations and the copied facts. The prover's proof
//!   `p` of the copied goal is kernel-checked in the view: **that** is the
//!   check of the claim (`p` cannot use what a variable stands for). The
//!   proof of the goal is `let F_g := g; ..; let e := refl; ..; let h' :=
//!   h; ..; p` (the equations of the named definitions are `λx.. delta(f;
//!   x..)`); should the kernel reject it, the unrestricted chain proves the
//!   goal — the claim has already been checked.
//!
//! Failures say what the step needs beyond its claim: the functions that
//! were treated as unknown (candidates for `by_unfolding(..)`), and
//! `follows()` for splits and lemmas.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry};
use sandblaster_kernel::term::{GlobalId, Idx, Lvl, Name, Rel, Term, Tm};
use sandblaster_kernel::util::{mk, shift};
use sandblaster_kernel::value::{Arg, Budget, V};

use super::super::{ElabError, ErrKind, ItemGlobal, Mode, OblStatus, Val, R};
use super::super::Elab;
use crate::diag::{DiagKind, Diagnostic};
use crate::hir::*;
use crate::prover::{AutoFailure, FactRef, Goal, Hint, ObligationId, ObligationKind, Reasoning};
use crate::span::Span;

/// A binder of the view and its value in the lifted proof (a `let`).
struct Abs {
    name: Name,
    rel: Rel,
    /// Its type, a term at the binder's depth.
    dom: Tm,
    /// Its value in the lifted proof, a term at the binder's depth (the
    /// goal's context extended by the earlier binders).
    val: Tm,
}

/// The restricted view of a goal (see the module docs).
struct View {
    ctx: Ctx,
    facts: Vec<FactRef>,
    hidden: Vec<u32>,
    /// The goal in the view (a term at the view's depth).
    target: Tm,
    /// Fact level ↦ statement term (at the depth of the level), for the
    /// basic prover.
    terms: Vec<(u32, Tm)>,
    abs: Vec<Abs>,
    /// The functions of the crate that became variables without a
    /// definition (unknown).
    unknown: Vec<GlobalId>,
    /// [`Hint::ViewFunction`] for every variable of the view (with the
    /// defining equation for the named recursive/opaque definitions).
    defined: Vec<Hint>,
    /// Named definitions of the crate that occur neither in the goal, the
    /// facts, nor the bodies of the other named definitions that do.
    unused: Vec<GlobalId>,
    /// Whether the view has derived facts or definitional `let`s (it
    /// differs from the plain view).
    derived: bool,
}

/// The free variables (levels below `d`) of the value of `t` (a term at
/// depth `d + b`), split by position for `bv()`: the variables of a shift's
/// amount and of a `pow2` exponent go to `amounts`, every other variable of
/// a computationally relevant position goes to `others`. Irrelevant
/// positions (the proofs of a primitive, irrelevant `let`s and arguments, λ
/// domains, match motives) do not decide the value and are skipped.
fn amount_split(t: &Tm, d: u32, b: u32, pow2: Option<GlobalId>, amounts: &mut BTreeSet<u32>, others: &mut BTreeSet<u32>, seen: &mut HashSet<(*const Term, u32)>) {
    use sandblaster_kernel::term::PrimOp;
    if !seen.insert((Rc::as_ptr(t), b)) {
        return;
    }
    let amount = |a: &Tm, amounts: &mut BTreeSet<u32>| {
        let mut ls = BTreeSet::new();
        free_levels(a, d + b, &mut ls);
        amounts.extend(ls.into_iter().filter(|l| *l < d));
    };
    match &**t {
        Term::Var(Idx(i)) => {
            if let Some(l) = (d + b).checked_sub(1 + *i)
                && l < d
            {
                others.insert(l);
            }
        }
        Term::Prim { op: PrimOp::Shr(_) | PrimOp::WShr(_) | PrimOp::Shl(_) | PrimOp::WShl(_), args, .. } if args.len() == 2 => {
            amount_split(&args[0], d, b, pow2, amounts, others, seen);
            amount(&args[1], amounts);
        }
        Term::Prim { args, .. } => args.iter().for_each(|a| amount_split(a, d, b, pow2, amounts, others, seen)),
        Term::App { fun, arg, .. } if pow2.is_some_and(|p| matches!(&**fun, Term::Global(x) if *x == p)) => amount(arg, amounts),
        Term::App { rel, fun, arg } => {
            amount_split(fun, d, b, pow2, amounts, others, seen);
            if *rel == Rel::Rel {
                amount_split(arg, d, b, pow2, amounts, others, seen);
            }
        }
        Term::Let { rel, val, body, .. } => {
            if *rel == Rel::Rel {
                amount_split(val, d, b, pow2, amounts, others, seen);
            }
            amount_split(body, d, b + 1, pow2, amounts, others, seen);
        }
        Term::Lam { body, .. } => amount_split(body, d, b + 1, pow2, amounts, others, seen),
        Term::Match { scrut, arms, .. } => {
            amount_split(scrut, d, b, pow2, amounts, others, seen);
            for a in arms {
                amount_split(&a.body, d, b + a.names.len() as u32, pow2, amounts, others, seen);
            }
        }
        _ => super::super::tm::children_depth(t, &mut |c, k| amount_split(c, d, b + k, pow2, amounts, others, seen)),
    }
}

/// The free variables (levels) of `t`, a term at depth `d`.
fn free_levels(t: &Tm, d: u32, out: &mut BTreeSet<u32>) {
    super::super::tm::any_node_depth(t, &mut |n, b| {
        if let Term::Var(Idx(i)) = n
            && *i >= b
            && let Some(l) = d.checked_sub(1 + (*i - b))
        {
            out.insert(l);
        }
        false
    });
}

/// The globals of `set` that occur in `t`.
fn globals_in(t: &Tm, set: &HashSet<GlobalId>, out: &mut BTreeSet<GlobalId>) {
    super::super::tm::any_node(t, &mut |n| {
        if let Term::Global(g) = n
            && set.contains(g)
        {
            out.insert(*g);
        }
        false
    });
}

/// `t` (a term at depth `from`, `from <= to`) at depth `to`, with every
/// global of `funs` replaced by the variable at its level.
fn generalize(t: &Tm, from: u32, to: u32, funs: &HashMap<GlobalId, u32>) -> Tm {
    generalize_remap(t, from, to, funs, &HashMap::new())
}

/// [`generalize`], also redirecting every free variable whose level (below
/// `from`) is a key of `remap` to the level it maps to (below `to`): a
/// copied fact's statement that embeds the proof of another copied fact
/// (a Nat subtraction's bound, a callee's requirement) refers to that
/// fact's copy, whose type mentions the variables, not to the hidden
/// original, whose type mentions the globals.
fn generalize_remap(t: &Tm, from: u32, to: u32, funs: &HashMap<GlobalId, u32>, remap: &HashMap<u32, u32>) -> Tm {
    let k = to - from;
    super::super::tm::map_post(t, 0, &mut |n, b| match &*n {
        Term::Var(Idx(i)) if *i >= b && !remap.is_empty() && let Some(nl) = from.checked_sub(1 + (*i - b)).and_then(|l| remap.get(&l)) => Some(Rc::new(Term::Var(Idx(to + b - 1 - nl)))),
        Term::Var(Idx(i)) if *i >= b && k > 0 => Some(Rc::new(Term::Var(Idx(*i + k)))),
        Term::Global(g) => match funs.get(g) {
            Some(l) => Some(Rc::new(Term::Var(Idx(to + b - 1 - l)))),
            None => Some(n),
        },
        _ => Some(n),
    })
    .expect("generalize")
}

impl<'a> Elab<'a> {
    /// The kernel globals of the crate's functions: the exec and spec
    /// `fn`s, with or without parameters (`const` items are values).
    fn user_functions(&self) -> HashSet<GlobalId> {
        let mut all = HashSet::new();
        for it in &self.krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            if !matches!(f.kind, FnKind::Exec | FnKind::Spec) {
                continue;
            }
            let Some(ItemGlobal::Def(g)) = self.globals.get(&it.id) else { continue };
            all.insert(*g);
        }
        all
    }

    /// Whether a definition unfolds by evaluation (transparent and not
    /// recursive).
    pub(in crate::elab) fn unfolds_by_evaluation(&self, g: GlobalId) -> bool {
        self.env.global_opaque(g) == Some(false) && self.env.global_body(g).is_some_and(|b| !super::super::tm::any_node(&b, &mut |n| matches!(n, Term::Global(x) if *x == g)))
    }

    /// The defining equation of a (recursive or opaque) definition `f` of
    /// arity `n`: `Π(x..). Eq(R, f x.., body[x..])` and its proof `λ(x..).
    /// delta(f; x..)`, both closed. `None` for a proposition-valued `f`
    /// (`delta` needs a result type `R : Type`).
    pub(in crate::elab) fn defining_equation(&self, f: GlobalId) -> Option<(Tm, Tm)> {
        let n = self.env.global_arity(f)? as usize;
        let mut ty = self.env.global_type(f)?;
        let mut body = self.env.global_body(f)?;
        let mut binders: Vec<(Name, Rel, Tm)> = Vec::new();
        for _ in 0..n {
            let Term::Pi { name, rel, dom, cod } = &*ty.clone() else { return None };
            let Term::Lam { body: b, .. } = &*body.clone() else { return None };
            binders.push((name.clone(), *rel, dom.clone()));
            ty = cod.clone();
            body = b.clone();
        }
        if matches!(&*ty, Term::Sort(_)) {
            return None;
        }
        let lhs = mk::apps(mk::global(f), binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))));
        let mut stmt = mk::eq(ty, lhs, body);
        let mut proof: Tm = Rc::new(Term::Delta { def: f, args: (0..n).map(|i| mk::var((n - 1 - i) as u32)).collect() });
        for (name, rel, dom) in binders.into_iter().rev() {
            stmt = Rc::new(Term::Pi { name: name.clone(), rel, dom: dom.clone(), cod: stmt });
            proof = Rc::new(Term::Lam { name, rel, dom, body: proof });
        }
        Some((stmt, proof))
    }

    /// How a global is named in messages (its source path).
    fn global_text(&self, g: GlobalId) -> String {
        let n = self.env.global_name(g).map(|n| n.to_string()).unwrap_or_else(|| format!("#{}", g.0));
        n.strip_prefix("crate::").map(str::to_string).unwrap_or(n)
    }

    /// The kernel global a `by_unfolding` name stands for.
    fn unfolding_global(&self, t: &UnfoldTarget, sp: Span) -> R<GlobalId> {
        match t {
            UnfoldTarget::Item(id) => self.item_global(*id, sp),
            UnfoldTarget::Builtin(b) => {
                let n = match b {
                    crate::builtins::Builtin::Int(m, w) => format!("{}::{}", w.name(), m.name()),
                    _ => return super::super::unsupported(sp, "`by_unfolding` of this builtin"),
                };
                self.env.lookup_global(&n).ok_or_else(|| ElabError { span: sp, msg: format!("no prelude definition `{n}`"), kind: ErrKind::Unsupported })
            }
            UnfoldTarget::Ghost(g) => {
                let n = g.nat_def().unwrap_or_default();
                self.env.lookup_global(n).ok_or_else(|| ElabError { span: sp, msg: format!("no ghost-library definition `{n}`"), kind: ErrKind::Unsupported })
            }
        }
    }

    /// Evaluates `t` in the context `entries` (a view under construction).
    fn eval_in_entries(&self, entries: &[CtxEntry], t: &Tm, sp: Span) -> R<V> {
        let ctx = Ctx { entries: Rc::new(entries.to_vec()) };
        let venv = self.env.ctx_venv(&ctx);
        let mut b = Budget { steps: self.opts.def_budget };
        self.env
            .eval(&venv, Lvl(entries.len() as u32), t, &mut b)
            .map_err(|e| ElabError { span: sp, msg: format!("evaluation failed while building the view of a closing statement: {e:?}"), kind: ErrKind::Internal })
    }

    /// The restricted view of `target` (a term at the current depth) with
    /// the definitions `keep` unfoldable (see the module docs).
    fn restricted_view(&self, target: &Tm, keep: &[GlobalId], unfold_facts: bool, sp: Span) -> R<View> {
        let sc = &self.f.scope;
        let dd = sc.depth();
        let user = self.user_functions();
        let named: BTreeSet<GlobalId> = keep.iter().copied().filter(|g| user.contains(g)).collect();
        // the visible facts, with their statements at the goal's depth
        let mut seen = HashSet::new();
        let mut vis: Vec<(FactRef, Tm)> = Vec::new();
        for fr in &sc.facts {
            let l = fr.lvl.0;
            if sc.hidden.contains(&l) || !seen.insert(l) {
                continue;
            }
            let Some(t) = sc.fact_tys.get(&l) else { continue };
            vis.push((fr.clone(), shift(t, (dd - l) as i64)));
        }
        let fact_lvls: HashSet<u32> = sc.facts.iter().map(|f| f.lvl.0).collect();
        // the relevant `let`s mentioned by the goal and the facts
        // (transitively through `let` values): level ↦ (type, value) at `dd`
        let mut refs = BTreeSet::new();
        free_levels(target, dd, &mut refs);
        for (_, t) in &vis {
            free_levels(t, dd, &mut refs);
        }
        let mut lets: std::collections::BTreeMap<u32, (Tm, Tm)> = std::collections::BTreeMap::new();
        let mut work: Vec<u32> = refs.iter().copied().collect();
        while let Some(l) = work.pop() {
            if lets.contains_key(&l) || fact_lvls.contains(&l) {
                continue;
            }
            let Some(e) = sc.ctx.entries.get(l as usize) else { continue };
            let (Some(Arg::Rel(v)), Some((ty, val, v0))) = (&e.def, sc.let_tms.get(&l)) else { continue };
            // the recorded value belongs to this binder (not to an earlier
            // one at the same level)
            if !Rc::ptr_eq(v, v0) {
                continue;
            }
            let mut inner = BTreeSet::new();
            free_levels(val, l, &mut inner);
            free_levels(ty, l, &mut inner);
            work.extend(inner);
            lets.insert(l, (shift(ty, (dd - l) as i64), shift(val, (dd - l) as i64)));
        }
        // the functions that become variables: those the goal, the facts
        // and the `let`s mention, the functions their types mention and the
        // functions the named definitions call — in definition order (a
        // type or body mentions earlier globals only)
        let mut occ = BTreeSet::new();
        globals_in(target, &user, &mut occ);
        for (_, t) in &vis {
            globals_in(t, &user, &mut occ);
        }
        for (ty, val) in lets.values() {
            globals_in(ty, &user, &mut occ);
            globals_in(val, &user, &mut occ);
        }
        let mut work: Vec<GlobalId> = occ.iter().copied().collect();
        while let Some(g) = work.pop() {
            let mut more = BTreeSet::new();
            if let Some(ty) = self.env.global_type(g) {
                globals_in(&ty, &user, &mut more);
            }
            if named.contains(&g)
                && let Some(body) = self.env.global_body(g)
            {
                globals_in(&body, &user, &mut more);
            }
            for h in more {
                if occ.insert(h) {
                    work.push(h);
                }
            }
        }
        let regen = |t: &Tm| -> bool {
            let mut gs = BTreeSet::new();
            globals_in(t, &user, &mut gs);
            if !gs.is_empty() {
                return true;
            }
            let mut ls = BTreeSet::new();
            free_levels(t, dd, &mut ls);
            ls.iter().any(|l| lets.contains_key(l))
        };
        // the view
        let mut entries: Vec<CtxEntry> = (*sc.ctx.entries).clone();
        for l in lets.keys() {
            entries[*l as usize].def = None;
        }
        let mut hidden: BTreeSet<u32> = (0..dd).collect();
        let mut facts = Vec::new();
        let mut terms = Vec::new();
        let mut copies = Vec::new();
        for (fr, t) in &vis {
            if regen(t) {
                copies.push((fr.clone(), t.clone()));
            } else {
                hidden.remove(&fr.lvl.0);
                facts.push(fr.clone());
                terms.push((fr.lvl.0, sc.fact_tys[&fr.lvl.0].clone()));
            }
        }
        let mut funs: HashMap<GlobalId, u32> = HashMap::new();
        let mut abs = Vec::new();
        let mut with_equation: Vec<(GlobalId, u32)> = Vec::new();
        let mut unknown_vars: Vec<Hint> = Vec::new();
        for g in &occ {
            let p = entries.len() as u32;
            let Some(ty) = self.env.global_type(*g) else { continue };
            let dom = generalize(&ty, 0, p, &funs);
            let tv = self.eval_in_entries(&entries, &dom, sp)?;
            let name: Name = Rc::from(self.global_text(*g).as_str());
            if named.contains(g) && self.unfolds_by_evaluation(*g) {
                // a named non-recursive transparent definition: its body,
                // calling the variables
                let Some(body) = self.env.global_body(*g) else { continue };
                let val = generalize(&body, 0, p, &funs);
                let vv = self.eval_in_entries(&entries, &val, sp)?;
                entries.push(CtxEntry { name: name.clone(), rel: Rel::Rel, ty: tv, def: Some(Arg::Rel(vv)) });
                abs.push(Abs { name, rel: Rel::Rel, dom, val });
            } else {
                entries.push(CtxEntry { name: name.clone(), rel: Rel::Rel, ty: tv, def: None });
                abs.push(Abs { name, rel: Rel::Rel, dom, val: mk::global(*g) });
                if named.contains(g) {
                    with_equation.push((*g, p));
                } else {
                    unknown_vars.push(Hint::ViewFunction { def: *g, var: Lvl(p), eq: None, arity: self.env.global_arity(*g).unwrap_or(0) });
                }
            }
            funs.insert(*g, p);
        }
        // the proofs about the generalized functions that the goal, the
        // facts or the `let`s mention (a lemma application, a callee's
        // `ensures`, a Nat range, embedded in a statement): variables of
        // their generalized types, bound to them in the lifted proof — the
        // statements that embed them stay well typed in terms of the
        // variables
        {
            let occset: HashSet<GlobalId> = occ.iter().copied().collect();
            let mut proofs: BTreeSet<GlobalId> = BTreeSet::new();
            let mut scan = |t: &Tm| {
                super::super::tm::any_node(t, &mut |n| {
                    if let Term::Global(h) = n
                        && !occset.contains(h)
                        && matches!(self.env.global_kind(*h), Some(sandblaster_kernel::term::DefKind::Lemma | sandblaster_kernel::term::DefKind::Law | sandblaster_kernel::term::DefKind::Ensures))
                    {
                        proofs.insert(*h);
                    }
                    false
                });
            };
            scan(target);
            for (_, t) in &vis {
                scan(t);
            }
            for (ty, val) in lets.values() {
                scan(ty);
                scan(val);
            }
            for h in proofs {
                let Some(ty) = self.env.global_type(h) else { continue };
                let mut gs = BTreeSet::new();
                globals_in(&ty, &occset, &mut gs);
                if gs.is_empty() {
                    continue;
                }
                let p = entries.len() as u32;
                let dom = generalize(&ty, 0, p, &funs);
                let tv = self.eval_in_entries(&entries, &dom, sp)?;
                let name: Name = Rc::from(self.global_text(h).as_str());
                entries.push(CtxEntry { name: name.clone(), rel: Rel::Rel, ty: tv, def: None });
                hidden.insert(p);
                abs.push(Abs { name, rel: Rel::Rel, dom, val: mk::global(h) });
                funs.insert(h, p);
            }
        }
        let frel = self.fact_rel();
        // the defining equations of the named recursive/opaque definitions
        let mut defined = unknown_vars;
        let mut equations: Vec<(GlobalId, u32, u32)> = Vec::new();
        for (g, var) in with_equation {
            let p = entries.len() as u32;
            let Some((stmt, proof)) = self.defining_equation(g) else {
                return super::super::unsupported(sp, format!("`by_unfolding({})`: a recursive or opaque proposition cannot be unfolded here; `unfold({})` it first", self.global_text(g), self.global_text(g)));
            };
            let dom = generalize(&stmt, 0, p, &funs);
            let tv = self.eval_in_entries(&entries, &dom, sp)?;
            let name: Name = Rc::from(format!("{}_def", self.global_text(g)).as_str());
            entries.push(CtxEntry { name: name.clone(), rel: frel, ty: tv, def: None });
            // used through the hint only (never as a ∀-fact)
            hidden.insert(p);
            abs.push(Abs { name, rel: frel, dom, val: proof });
            defined.push(Hint::ViewFunction { def: g, var: Lvl(var), eq: Some(Lvl(p)), arity: self.env.global_arity(g).unwrap_or(0) });
            equations.push((g, var, p));
        }
        // the `let` equations and the copied facts, in the order of their
        // original levels: a statement that mentions (the proof of) a copied
        // fact refers to the copy (`remap`, original level ↦ copy level)
        let mut remap: HashMap<u32, u32> = HashMap::new();
        let mut copied: Vec<(u32, Tm, FactRef)> = Vec::new();
        // whether the view differs from the plain one (`unfold_facts`)
        let mut derived = false;
        let mut order: Vec<(u32, Option<FactRef>, Tm)> = lets.keys().map(|l| (*l, None, Rc::new(Term::Erased))).collect();
        order.extend(copies.into_iter().map(|(fr, t)| (fr.lvl.0, Some(fr), t)));
        order.sort_by_key(|(l, fr, _)| (*l, fr.is_some()));
        for (l, fr, t) in order {
            let p = entries.len() as u32;
            let Some(fr) = fr else {
                let (ty, val) = &lets[&l];
                if !unfold_facts {
                    // the plain view: the `let` is a variable and an
                    // equation `x == value` states its value
                    let x = mk::var(dd - 1 - l);
                    let eq = mk::eq(ty.clone(), x.clone(), val.clone());
                    let dom = generalize_remap(&eq, dd, p, &funs, &remap);
                    let tv = self.eval_in_entries(&entries, &dom, sp)?;
                    let name: Name = Rc::from(format!("{}_value", sc.ctx.entries[l as usize].name).as_str());
                    entries.push(CtxEntry { name: name.clone(), rel: frel, ty: tv, def: None });
                    facts.push(FactRef { lvl: Lvl(p), origin: crate::prover::FactOrigin::LetDef, span: sp });
                    terms.push((p, dom.clone()));
                    abs.push(Abs { name, rel: frel, dom, val: shift(&mk::refl(ty.clone(), x), (p - dd) as i64) });
                    continue;
                }
                // a `let` keeps its value (a definition in terms of the
                // variables): the prover sees through it, as it does outside
                // the view (`let z = x + 1` makes `r(z)` and `r(x + 1)` the
                // same atom)
                derived = true;
                let dom = generalize_remap(ty, dd, p, &funs, &remap);
                let tv = self.eval_in_entries(&entries, &dom, sp)?;
                let gval = generalize_remap(val, dd, p, &funs, &remap);
                let vv = self.eval_in_entries(&entries, &gval, sp)?;
                let name = sc.ctx.entries[l as usize].name.clone();
                entries.push(CtxEntry { name: name.clone(), rel: Rel::Rel, ty: tv, def: Some(Arg::Rel(vv)) });
                abs.push(Abs { name, rel: Rel::Rel, dom, val: mk::var(p - 1 - l) });
                remap.insert(l, p);
                continue;
            };
            let dom = generalize_remap(&t, dd, p, &funs, &remap);
            let tv = self.eval_in_entries(&entries, &dom, sp)?;
            let orig = &sc.ctx.entries[fr.lvl.0 as usize];
            entries.push(CtxEntry { name: orig.name.clone(), rel: orig.rel, ty: tv, def: None });
            facts.push(FactRef { lvl: Lvl(p), origin: fr.origin.clone(), span: fr.span });
            terms.push((p, dom.clone()));
            abs.push(Abs { name: orig.name.clone(), rel: orig.rel, dom: dom.clone(), val: mk::var(p - 1 - fr.lvl.0) });
            remap.insert(fr.lvl.0, p);
            copied.push((p, dom, fr));
        }
        // `by_unfolding(f)` of a recursive or opaque `f` unfolds it in the
        // facts too: a fact that applies `f` gains a copy with those
        // applications unfolded once (`transport` along the defining
        // equation; the body's own calls of `f` stay folded)
        if unfold_facts && !equations.is_empty() {
            // the applications the goal makes, and the recursive calls their
            // one-step unfoldings make: a fact about those is what the goal
            // becomes after unfolding it, so it stays folded
            let q_e = entries.len() as u32;
            let tq = generalize_remap(target, dd, q_e, &funs, &remap);
            let mut exclude: Vec<Tm> = Vec::new();
            for (g, var, _) in &equations {
                let goal_apps = self.var_apps(&tq, q_e, *var, self.env.global_arity(*g).unwrap_or(0) as usize);
                for o in &goal_apps {
                    if let Some(body_t) = self.one_step_body(*g, o, q_e, &funs) {
                        exclude.extend(self.var_apps(&body_t, q_e, *var, self.env.global_arity(*g).unwrap_or(0) as usize));
                    }
                }
                exclude.extend(goal_apps);
            }
            for (q0, dom, fr) in copied {
                let q = entries.len() as u32;
                let excl: Vec<Tm> = exclude.iter().map(|t| shift(t, (q - q_e) as i64)).collect();
                let Some((stmt, pf)) = self.unfold_in_fact(&entries, q0, &dom, &equations, &funs, &excl, sp) else { continue };
                let p = entries.len() as u32;
                let tv = self.eval_in_entries(&entries, &stmt, sp)?;
                let orig = &sc.ctx.entries[fr.lvl.0 as usize];
                derived = true;
                let name: Name = Rc::from(format!("{}_unfolded", orig.name).as_str());
                entries.push(CtxEntry { name: name.clone(), rel: orig.rel, ty: tv, def: None });
                facts.push(FactRef { lvl: Lvl(p), origin: fr.origin.clone(), span: fr.span });
                terms.push((p, stmt.clone()));
                abs.push(Abs { name, rel: orig.rel, dom: stmt.clone(), val: pf });
                // the comparisons the unfolded body branches on, decided by
                // linear arithmetic over the facts: facts of their own, so
                // the prover takes the branches
                let guards = self.decide_guards(&entries, &terms, &shift(&stmt, 1));
                for (i, (c, lin)) in guards.into_iter().enumerate() {
                    let (c, lin) = (shift(&c, i as i64), shift(&lin, i as i64));
                    let p = entries.len() as u32;
                    let tv = self.eval_in_entries(&entries, &c, sp)?;
                    let name: Name = Rc::from("h_guard");
                    entries.push(CtxEntry { name: name.clone(), rel: frel, ty: tv, def: None });
                    facts.push(FactRef { lvl: Lvl(p), origin: crate::prover::FactOrigin::PathCond, span: fr.span });
                    terms.push((p, c.clone()));
                    abs.push(Abs { name, rel: frel, dom: c, val: lin });
                }
            }
        }
        // the field equations of a view link: a fact `s == v(e)` whose `v`
        // is a function of the crate that builds a record (`S { a: e.a as
        // Nat, .. }`) gives `s.a == e.a as Nat` for each field — what the
        // record is made of, which the view hides once `v` is unknown
        if unfold_facts {
            let mut links: Vec<(Tm, Tm)> = Vec::new();
            for (fr, t) in &vis {
                links.extend(self.view_link_fields(t, &user, mk::var(dd - 1 - fr.lvl.0)));
            }
            for (stmt, pf) in links.into_iter().take(16) {
                let p = entries.len() as u32;
                let dom = generalize_remap(&stmt, dd, p, &funs, &remap);
                let Ok(tv) = self.eval_in_entries(&entries, &dom, sp) else { continue };
                derived = true;
                let name: Name = Rc::from("h_field");
                entries.push(CtxEntry { name: name.clone(), rel: frel, ty: tv, def: None });
                facts.push(FactRef { lvl: Lvl(p), origin: crate::prover::FactOrigin::Assert, span: sp });
                terms.push((p, dom.clone()));
                abs.push(Abs { name, rel: frel, dom, val: shift(&pf, (p - dd) as i64) });
            }
        }
        // the Nat range facts of the spec applications in the goal and the
        // facts (`0 <= f(x)` for a `Nat`-valued `f`: a property of its
        // type, which the view keeps although `f` is unknown)
        if unfold_facts && !self.nat_ranges.is_empty() && (self.arithmetic_goal(target) || self.ranged_guard_goal(target) || !equations.is_empty()) {
            let mut ts: Vec<Tm> = vec![target.clone()];
            ts.extend(vis.iter().map(|(_, t)| t.clone()));
            for (stmt, pf) in self.nat_range_instances(&ts, 12) {
                let p = entries.len() as u32;
                let dom = generalize_remap(&stmt, dd, p, &funs, &remap);
                let tv = self.eval_in_entries(&entries, &dom, sp)?;
                derived = true;
                let name: Name = Rc::from("h_range");
                entries.push(CtxEntry { name: name.clone(), rel: frel, ty: tv, def: None });
                facts.push(FactRef { lvl: Lvl(p), origin: crate::prover::FactOrigin::TypeBound, span: sp });
                terms.push((p, dom.clone()));
                abs.push(Abs { name, rel: frel, dom, val: shift(&pf, (p - dd) as i64) });
            }
        }
        let target_v = generalize_remap(target, dd, entries.len() as u32, &funs, &remap);
        let unknown = occ.iter().copied().filter(|g| !named.contains(g)).collect();
        let unused = keep.iter().copied().filter(|g| named.contains(g) && !occ.contains(g)).collect();
        Ok(View { ctx: Ctx { entries: Rc::new(entries) }, facts, hidden: hidden.into_iter().collect(), target: target_v, terms, abs, unknown, defined, unused, derived })
    }

    /// The field equations of a view-link fact `t` (a term at the current
    /// depth, proven by `h`): for `Eq(D, s, v(a..))` (either side) whose `v`
    /// is a transparent non-recursive function of the crate (`user`) whose
    /// body at `a..` is a record constructor `C(f₀, ..)`, the statements
    /// `proj_j(s) == f_j` with their proofs `eq::cong D F_j proj_j s v(a..)
    /// h` (the projection of `v(a..)` computes to `f_j`).
    fn view_link_fields(&self, t: &Tm, user: &HashSet<GlobalId>, h: Tm) -> Vec<(Tm, Tm)> {
        let mut t = t.clone();
        while let Term::Let { body, val, .. } = &*t.clone() {
            t = super::super::tm::subst0(body, val);
        }
        let Term::Eq { ty: d_ty, lhs, rhs } = &*t else { return vec![] };
        let Some(cong) = self.env.lookup_global("eq::cong") else { return vec![] };
        let mut out = Vec::new();
        for (app, other, app_is_rhs) in [(rhs, lhs, true), (lhs, rhs, false)] {
            let (hd, args) = super::super::items::spine(app);
            let Term::Global(v) = &*hd else { continue };
            if !user.contains(v) || !self.unfolds_by_evaluation(*v) || self.env.global_arity(*v) != Some(args.len() as u32) {
                continue;
            }
            let Some(mut body) = self.env.global_body(*v) else { continue };
            for _ in 0..args.len() {
                let Term::Lam { body: b, .. } = &*body.clone() else { break };
                body = b.clone();
            }
            let mut inst = super::super::tm::simp_redexes(&super::super::tm::subst_closed(&body, &args));
            while let Term::Let { body, val, .. } = &*inst.clone() {
                inst = super::super::tm::simp_redexes(&super::super::tm::subst0(body, val));
            }
            let Term::Ctor { ind, ctor, params, args: fields } = &*inst else { continue };
            let Some(decl) = self.env.inductive_decl(*ind) else { continue };
            if decl.ctors.len() != 1 {
                continue;
            }
            // which fields come with the code: all of them for a type's
            // `#[view]` (`T::view`); for any other function only the fields
            // its body copies from its arguments (a projection or cast of an
            // argument's fields). A computed field (`a: x + 7`) is what the
            // function computes: that needs `by_unfolding(v)`.
            let is_view = self.is_view_global(*v);
            let copied = if is_view { vec![] } else { copied_fields(&body, args.len() as u32) };
            let c = &decl.ctors[*ctor as usize];
            let n = c.fields.len() as u32;
            for (j, (_, rel, fty)) in c.fields.iter().enumerate() {
                if *rel != Rel::Rel || (0..j as u32).any(|i| sandblaster_kernel::util::occurs(fty, i)) {
                    continue;
                }
                if !is_view && !copied.get(j).copied().unwrap_or(false) {
                    continue;
                }
                // the field type over the parameters (fields before it do not occur)
                let fj = super::super::tm::subst_closed(&shift(fty, -(j as i64)), params);
                let proj = |x: &Tm| -> Tm {
                    Rc::new(Term::Match {
                        ind: *ind,
                        params: params.clone(),
                        scrut: x.clone(),
                        motive: shift(&fj, 1),
                        arms: vec![sandblaster_kernel::term::Arm { names: c.fields.iter().map(|f| f.0.clone()).collect(), body: mk::var(n - 1 - j as u32) }],
                    })
                };
                let Some(fv) = fields.get(j) else { continue };
                let stmt = mk::eq(fj.clone(), proj(other), fv.clone());
                // `other == app` from `h`
                let h2 = if app_is_rhs { h.clone() } else { mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, d_ty.clone()), (Rel::Rel, app.clone()), (Rel::Rel, other.clone()), (Rel::Rel, h.clone())]) };
                let fun = mk::lam("z", Rel::Rel, d_ty.clone(), Rc::new(Term::Match {
                    ind: *ind,
                    params: params.iter().map(|q| shift(q, 1)).collect(),
                    scrut: mk::var(0),
                    motive: shift(&fj, 2),
                    arms: vec![sandblaster_kernel::term::Arm { names: c.fields.iter().map(|f| f.0.clone()).collect(), body: mk::var(n - 1 - j as u32) }],
                }));
                let pf = mk::apps(mk::global(cong), [(Rel::Rel, d_ty.clone()), (Rel::Rel, fj.clone()), (Rel::Rel, fun), (Rel::Rel, other.clone()), (Rel::Rel, app.clone()), (Rel::Rel, h2)]);
                // checked here: a malformed statement only loses the fact
                let mut b = Budget { steps: self.opts.def_budget };
                let Ok(sv) = self.eval(&stmt) else { continue };
                if self.env.check(&self.f.scope.ctx, &pf, &sv, &mut b).is_err() {
                    continue;
                }
                out.push((stmt, pf));
            }
        }
        out
    }

    /// Whether `g` is a type's `#[view]` (`T::view`, DESIGN.md §15.3).
    fn is_view_global(&self, g: GlobalId) -> bool {
        if self.s1.views.values().any(|v| v.global == g) {
            return true;
        }
        // the optimizer's resumed and generated modes run without the S1
        // state: a `#[view]` item's definition by name
        let Some(name) = self.env.global_name(g) else { return false };
        let Some(ty_path) = name.strip_suffix("::view") else { return false };
        self.krate.items.iter().any(|it| {
            it.path.to_string() == ty_path
                && match &it.kind {
                    crate::hir::ItemKind::Struct(s) => s.view.is_some(),
                    crate::hir::ItemKind::Enum(e) => e.view.is_some(),
                    _ => false,
                }
        })
    }

    /// A copied fact `dom` (a term at depth `q0`, in the view `entries`)
    /// with the applications of the named recursive/opaque definitions
    /// (`equations`: global, its variable's level, its defining equation's
    /// level) unfolded once, as a statement and its proof at depth
    /// `entries.len()`. `None` if the fact applies none of them (or no
    /// motive generalizing an application is well-typed).
    #[allow(clippy::too_many_arguments)]
    fn unfold_in_fact(&self, entries: &[CtxEntry], q0: u32, dom: &Tm, equations: &[(GlobalId, u32, u32)], funs: &HashMap<GlobalId, u32>, exclude: &[Tm], sp: Span) -> Option<(Tm, Tm)> {
        let q = entries.len() as u32;
        let mut stmt = shift(dom, (q - q0) as i64);
        let mut proof = mk::var(q - 1 - q0);
        let mut changed = false;
        for (g, var, eql) in equations {
            let n = self.env.global_arity(*g)? as usize;
            // the applications `F_g a..` of the original fact (at most a
            // few; the calls the unfolded bodies expose stay folded), but
            // not those of the goal or its one-step unfolding (`exclude`)
            let occs: Vec<Tm> = self.var_apps(&stmt, q, *var, n).into_iter().filter(|o| !exclude.iter().any(|x| self.env.alpha_eq_relevant(x, o, &|a, c| a == c))).take(4).collect();
            if occs.is_empty() {
                continue;
            }
            // the defining equation, closed: `Π(x..). Eq(R, g x.., body)`
            let (eq_stmt, _) = self.defining_equation(*g)?;
            let mut inner = eq_stmt;
            let mut rels = Vec::new();
            for _ in 0..n {
                let Term::Pi { rel, cod, .. } = &*inner.clone() else { return None };
                rels.push(*rel);
                inner = cod.clone();
            }
            let Term::Eq { ty: r_c, rhs: body_c, .. } = &*inner else { return None };
            for occ in occs {
                let (_, args) = super::super::items::spine(&occ);
                let r_t = generalize(&super::super::tm::subst_closed(r_c, &args), q, q, funs);
                let body_t = super::super::tm::simp_redexes(&generalize(&super::super::tm::subst_closed(body_c, &args), q, q, funs));
                let Some(m) = super::super::tm::abstract_syntactic(&self.env, &stmt, &occ) else { continue };
                // the motive must be a proposition over the generalized
                // application
                let Ok(rv) = self.eval_in_entries(entries, &r_t, sp) else { continue };
                let mut ext = entries.to_vec();
                ext.push(CtxEntry { name: Rc::from("y"), rel: Rel::Rel, ty: rv, def: None });
                let mut b = Budget { steps: self.opts.def_budget };
                if !matches!(self.env.infer(&Ctx { entries: Rc::new(ext) }, &m, &mut b), Ok(t) if matches!(&*t, sandblaster_kernel::value::Value::Sort(_))) {
                    continue;
                }
                let eq = mk::apps(mk::var(q - 1 - eql), rels.iter().copied().zip(args.iter().cloned()));
                proof = Rc::new(Term::Transport { ty: r_t, lhs: occ, rhs: body_t.clone(), eq, motive: m.clone(), val: proof });
                stmt = super::super::tm::simp_redexes(&super::super::tm::subst0(&m, &body_t));
                changed = true;
            }
        }
        changed.then_some((stmt, proof))
    }

    /// The distinct applications `V a..` (`n` arguments) of the variable of
    /// level `var` in `t` (a term at depth `q`) that mention no binder of
    /// `t`, as terms at depth `q`.
    fn var_apps(&self, t: &Tm, q: u32, var: u32, n: usize) -> Vec<Tm> {
        let mut occs: Vec<Tm> = Vec::new();
        let mut seen: HashSet<(*const Term, u32)> = HashSet::new();
        let mut stack: Vec<(Tm, u32)> = vec![(t.clone(), 0)];
        while let Some((t, b)) = stack.pop() {
            if occs.len() >= 16 || !seen.insert((Rc::as_ptr(&t), b)) {
                continue;
            }
            let (h, args) = super::super::items::spine(&t);
            if args.len() == n && matches!(&*h, Term::Var(Idx(i)) if *i >= b && q + b == var + 1 + *i) {
                let mut fl = BTreeSet::new();
                free_levels(&t, q + b, &mut fl);
                if fl.iter().all(|l| *l < q) {
                    let o = shift(&t, -(b as i64));
                    if !occs.iter().any(|x| self.env.alpha_eq_relevant(x, &o, &|a, c| a == c)) {
                        occs.push(o);
                    }
                }
            }
            super::super::tm::children_depth(&t, &mut |c, k| stack.push((c.clone(), b + k)));
        }
        occs
    }

    /// The body of the named definition `g` instantiated with the
    /// arguments of its application `occ` (a term at depth `q` in the view),
    /// its calls generalized to the view's variables.
    fn one_step_body(&self, g: GlobalId, occ: &Tm, q: u32, funs: &HashMap<GlobalId, u32>) -> Option<Tm> {
        let n = self.env.global_arity(g)? as usize;
        let (eq_stmt, _) = self.defining_equation(g)?;
        let mut inner = eq_stmt;
        for _ in 0..n {
            let Term::Pi { cod, .. } = &*inner.clone() else { return None };
            inner = cod.clone();
        }
        let Term::Eq { rhs: body_c, .. } = &*inner else { return None };
        let (_, args) = super::super::items::spine(occ);
        Some(generalize(&super::super::tm::subst_closed(body_c, &args), q, q, funs))
    }

    /// The boolean comparisons an unfolded fact `stmt` (a term at depth
    /// `entries.len()`) branches on that linear arithmetic over the view's
    /// facts (`terms`: level ↦ statement at that level) decides: `(Eq(Bool,
    /// c, b), its Linarith proof)` each (at most 8). The guards of a body —
    /// `n == 0`, a Nat parameter's `0 <= n` — are what separates the
    /// unfolded fact from the branch the proof is about; with them as facts
    /// the prover takes the branch.
    fn decide_guards(&self, entries: &[CtxEntry], terms: &[(u32, Tm)], stmt: &Tm) -> Vec<(Tm, Tm)> {
        use sandblaster_kernel::term::PrimOp;
        let q = entries.len() as u32;
        let ctx = Ctx { entries: Rc::new(entries.to_vec()) };
        let bool_ = self.env.bool_ind();
        let is_cmp = |op: &PrimOp| matches!(op, PrimOp::Eq(_) | PrimOp::Ne(_) | PrimOp::Lt(_) | PrimOp::Le(_) | PrimOp::Gt(_) | PrimOp::Ge(_));
        // the arithmetic facts, conjunctions split (`(proof, stated)`)
        let mut hyps: Vec<(Tm, Tm)> = Vec::new();
        let mut work: Vec<(Tm, Tm, u32)> = terms.iter().map(|(l, t)| (mk::var(q - 1 - l), shift(t, (q - l) as i64), 0)).collect();
        while let Some((h, t, n)) = work.pop() {
            let t = match &*t {
                Term::Let { val, body, .. } => super::super::tm::subst0(body, val),
                _ => t,
            };
            match &*t {
                Term::Sigma { fst, snd, .. } if n < 8 => {
                    work.push((mk::fst(h.clone()), fst.clone(), n + 1));
                    work.push((mk::snd(h.clone()), super::super::tm::subst0(snd, &mk::fst(h)), n + 1));
                }
                Term::Eq { ty, lhs, rhs } => {
                    let ok = match (&**ty, &**lhs, &**rhs) {
                        (Term::IntTy(_), _, _) => true,
                        (Term::Ind { ind, .. }, Term::Prim { op, .. }, Term::Ctor { ind: i2, ctor, .. }) if *ind == bool_ && *i2 == bool_ => is_cmp(op) && !(matches!(op, PrimOp::Ne(_)) && *ctor == 1) && !(matches!(op, PrimOp::Eq(_)) && *ctor == 0),
                        _ => false,
                    };
                    if ok {
                        hyps.push((h, t.clone()));
                    }
                }
                _ => {}
            }
        }
        // the matches on comparisons that do not mention the binders around
        // them
        let mut cands: Vec<Tm> = Vec::new();
        let mut seen: HashSet<(*const Term, u32)> = HashSet::new();
        let mut stack: Vec<(Tm, u32)> = vec![(stmt.clone(), 0)];
        while let Some((t, b)) = stack.pop() {
            if cands.len() >= 8 || !seen.insert((Rc::as_ptr(&t), b)) {
                continue;
            }
            if let Term::Match { ind, scrut, .. } = &*t
                && *ind == bool_
                && matches!(&**scrut, Term::Prim { op, .. } if is_cmp(op))
            {
                let mut fl = BTreeSet::new();
                free_levels(scrut, q + b, &mut fl);
                let c = shift(scrut, -(b as i64));
                if fl.iter().all(|l| *l < q) && !cands.iter().any(|x| self.env.alpha_eq_relevant(x, &c, &|a, d| a == d)) {
                    cands.push(c);
                }
            }
            super::super::tm::children_depth(&t, &mut |c, k| stack.push((c.clone(), b + k)));
        }
        let bool_ty = mk::ind(bool_, vec![]);
        let mut out = Vec::new();
        for c in cands {
            for v in [true, false] {
                let goal = mk::eq(bool_ty.clone(), c.clone(), mk::ctor(bool_, v as u32, vec![], vec![]));
                let mut hs = hyps.clone();
                super::super::recert::harvest(&self.env, &goal, &mut hs);
                if let Ok(p) = super::super::basic::linarith_term(&self.env, &ctx, hs, goal.clone()) {
                    out.push((goal, p));
                    break;
                }
            }
        }
        out
    }

    /// `by_arithmetic()` (`names` empty) / `by_unfolding(names..)`: the goal
    /// follows from the facts by arithmetic and equality reasoning, after
    /// unfolding exactly `names` (see the module docs).
    pub(super) fn by_reasoning(&mut self, goal: Val, kind: ObligationKind, sp: Span, names: &[UnfoldTarget]) -> R<Tm> {
        self.by_reasoning_as(goal, kind, sp, names, false)
    }

    /// `bv()` on a goal outside word algebra (a shift by a variable amount,
    /// `/`, `%`): linear arithmetic with the built-in shift and `pow2`
    /// rules, as `by_arithmetic()` does, but with only the facts that bound
    /// the goal's shift amounts and `pow2` exponents (`s < 8`: the side
    /// conditions of the shift rule) and the ranges that come with a type
    /// (`0 <= x` of a `Nat`). A shift amount is a variable that occurs only
    /// in amount positions ([`amount_split`], `let`s read as their values),
    /// so a kept fact says nothing about the shifted or divided values. So
    /// `bv()` still claims a machine-word identity: a goal that needs other
    /// facts (`x == 10` for `x / 2 == 5`, a type invariant) fails and says to
    /// write `by_arithmetic()`.
    pub(super) fn by_bv_arithmetic(&mut self, goal: Val, kind: ObligationKind, sp: Span) -> R<Tm> {
        use sandblaster_kernel::term::PrimOp;
        let d = self.depth();
        let g = goal.at(d);
        let pow2 = self.env.lookup_global("ghost::pow2");
        // the shift amounts: the variables that occur in amount positions
        // (a shift's amount, a `pow2` exponent) and nowhere else in the
        // goal's value, a `let` read as the variables of its value. A
        // variable that is also shifted, divided or compared is not an
        // amount: a fact about it is a fact about the value (`let s = x;`
        // with `s == 4` fixes `x`, which `x >> s == 0` needs)
        let (mut in_amount, mut elsewhere) = (BTreeSet::new(), BTreeSet::new());
        amount_split(&g, d, 0, pow2, &mut in_amount, &mut elsewhere, &mut HashSet::new());
        let mut opaque_lets = BTreeSet::new();
        let in_amount = self.let_expanded(in_amount, &mut opaque_lets);
        let elsewhere = self.let_expanded(elsewhere, &mut opaque_lets);
        let amounts: BTreeSet<u32> = in_amount.into_iter().filter(|l| !elsewhere.contains(l) && !opaque_lets.contains(l)).collect();
        // hide every other fact for this step. A range that comes with a
        // type is kept: `0 <= x` of a `Nat` (or of a `Nat` component, or a
        // spec result's Nat range), `len(s) <= ISIZE_MAX` of a slice — it is
        // the value's type, not a hypothesis. A type *invariant* (also a
        // `TypeBound` fact) is a hypothesis about the value, so it is hidden
        // like any other fact unless it only bounds shift amounts.
        let saved = self.f.scope.hidden.clone();
        let facts = self.f.scope.facts.clone();
        let isize_max = self.env.lookup_global("ISIZE_MAX");
        let type_range = |t: &Tm| -> bool {
            let Term::Eq { lhs, rhs, .. } = &**t else { return false };
            if !matches!(&**rhs, Term::Ctor { ctor: 1, .. }) {
                return false;
            }
            match &**lhs {
                Term::Prim { op: PrimOp::Le(sandblaster_kernel::term::Width::Int), args, .. } if args.len() == 2 => {
                    matches!(&*args[0], Term::Lit { n, .. } if *n == 0u8.into()) || isize_max.is_some_and(|g| matches!(&*args[1], Term::Global(x) if *x == g))
                }
                _ => false,
            }
        };
        for fr in &facts {
            let l = fr.lvl.0;
            // (an invariant `0 <= self.x` of an `Int` field has a range's
            // shape but is a hypothesis: invariant facts are the `h_inv`
            // binders of `elab::invariant`)
            let invariant = self.f.scope.ctx.entries.get(l as usize).is_some_and(|e| e.name.starts_with("h_inv"));
            if matches!(fr.origin, crate::prover::FactOrigin::TypeBound) && !invariant && self.f.scope.fact_tys.get(&l).is_some_and(|t| type_range(t)) {
                continue;
            }
            let bounds_amounts = self.f.scope.fact_tys.get(&l).is_some_and(|t| {
                let mut ls = BTreeSet::new();
                free_levels(t, l, &mut ls);
                let mut opaque = BTreeSet::new();
                let ls = self.let_expanded(ls, &mut opaque);
                opaque.is_empty() && !ls.is_empty() && ls.iter().all(|x| amounts.contains(x))
            });
            if !bounds_amounts {
                self.f.scope.hidden.insert(l);
            }
        }
        let r = self.by_reasoning_as(goal, kind, sp, &[], true);
        self.f.scope.hidden = saved;
        r
    }

    /// `levels` with every `let` of the context replaced by the variables
    /// of its value (transitively): what a statement about them is about. A
    /// `let` whose value is not recorded goes to `opaque` (it may stand for
    /// anything).
    fn let_expanded(&self, levels: BTreeSet<u32>, opaque: &mut BTreeSet<u32>) -> BTreeSet<u32> {
        let sc = &self.f.scope;
        let mut out = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut work: Vec<u32> = levels.into_iter().collect();
        while let Some(l) = work.pop() {
            if !seen.insert(l) {
                continue;
            }
            let Some(e) = sc.ctx.entries.get(l as usize) else { continue };
            match (&e.def, sc.let_tms.get(&l)) {
                (None, _) => {
                    out.insert(l);
                }
                (Some(Arg::Rel(v)), Some((_, val, v0))) if Rc::ptr_eq(v, v0) => {
                    let mut inner = BTreeSet::new();
                    free_levels(val, l, &mut inner);
                    work.extend(inner);
                }
                _ => {
                    out.insert(l);
                    opaque.insert(l);
                }
            }
        }
        out
    }

    fn by_reasoning_as(&mut self, goal: Val, kind: ObligationKind, sp: Span, names: &[UnfoldTarget], bv: bool) -> R<Tm> {
        let relevant = self.f.mode == Mode::Proof;
        let d = self.depth();
        let target = goal.at(d);
        let target = super::super::recert::recertify(&self.env, &self.f.scope.ctx, &target);
        let mut keep = Vec::new();
        for t in names {
            keep.push(self.unfolding_global(t, sp)?);
        }
        let stmt = if bv {
            "bv()".to_string()
        } else if keep.is_empty() {
            "by_arithmetic()".to_string()
        } else {
            format!("by_unfolding({})", keep.iter().map(|g| self.global_text(*g)).collect::<Vec<_>>().join(", "))
        };
        // first the facts in scope; then, if the goal does not follow from
        // them, with the derived facts too (the facts with the named
        // definitions unfolded, the comparisons their bodies test, the Nat
        // ranges of the spec results): a step that needs none keeps its
        // search
        let view0 = self.restricted_view(&target, &keep, false, sp)?;
        self.unused_unfoldings(&view0, &keep, sp);
        let id = self.obligations.len() as u32;
        let reasoning = if keep.is_empty() { Reasoning::Arithmetic } else { Reasoning::Unfolding(keep.clone()) };
        let mut view = view0;
        let mut phase = 0;
        let failure = loop {
            // no `Unfold` hints: they unfold every application; the
            // restricted search unfolds a named definition where that
            // unblocks the goal
            let mut hints = vec![Hint::Only(reasoning.clone())];
            hints.extend(view.defined.iter().cloned());
            let tv = self.eval_in_entries(&view.ctx.entries, &view.target, sp)?;
            let g = Goal { id: ObligationId(id), kind: kind.clone(), span: sp, ctx: view.ctx.clone(), facts: view.facts.clone(), target: tv.clone(), hints };
            let terms = super::super::basic::GoalTerms { id, target: view.target.clone(), facts: view.terms.clone() };
            let res = self.run_chain(&g, view.hidden.clone(), terms);
            let failure = match res {
                Ok(p) => {
                    // the claim: `p` proves the goal in the view
                    let p = super::super::recert::recertify(&self.env, &view.ctx, &p);
                    let checked = if !self.opts.check_proofs || super::super::tm::has_erased(&view.target) { Ok(()) } else { self.check_proof_in(&view.ctx, &p, &view.target, &tv, relevant) };
                    match checked {
                        // the report groups obligations by this label (like
                        // `script(by_computation)`)
                        Ok(()) => return self.lift_restricted(&view, p, &target, kind, sp, relevant, &stmt, if bv { "bv" } else if keep.is_empty() { "by_arithmetic" } else { "by_unfolding" }),
                        Err(msg) => AutoFailure { tried: vec![format!("the prover returned a proof the kernel rejects: {msg}")], ..Default::default() },
                    }
                }
                Err(f) => f,
            };
            if phase > 0 {
                break failure;
            }
            phase += 1;
            let derived = self.restricted_view(&target, &keep, true, sp)?;
            if !derived.derived {
                break failure;
            }
            view = derived;
        };
        self.fail_obligation(id, kind, sp, &target, failure, true);
        if bv {
            let notes = [
                "`bv()`: the goal is not a machine-word identity: word algebra does not decide it, and linear arithmetic with the built-in shift and `pow2` rules does not either, using only the facts that bound its shift amounts and `pow2` exponents (such as `s < 8`)".to_string(),
                "`bv()` uses no other facts: if the goal follows from the facts in scope, write `by_arithmetic()`".to_string(),
            ];
            if let Some(dg) = self.diags.list.last_mut() {
                for n in notes {
                    dg.notes.push((None, n));
                }
            }
            return Ok(Rc::new(Term::Erased));
        }
        let mut notes = vec![if keep.is_empty() {
            "`by_arithmetic()`: the goal does not follow from the facts in scope by arithmetic and equality reasoning alone (the crate's functions are unknown, no case analysis on program values)".to_string()
        } else {
            format!("`{stmt}`: the goal does not follow from the facts in scope by arithmetic after unfolding only the named definitions (every other function, including the ones they call, is unknown; no case analysis on program values)")
        }];
        if !view.unknown.is_empty() {
            let us: Vec<String> = view.unknown.iter().map(|g| format!("`{}`", self.global_text(*g))).collect();
            let mut all: Vec<String> = keep.iter().filter(|g| !view.unused.contains(g)).map(|g| self.global_text(*g)).collect();
            all.extend(view.unknown.iter().map(|g| self.global_text(*g)));
            notes.push(format!("treated as unknown functions: {} — if the step depends on what they compute, name them: `by_unfolding({})`", us.join(", "), all.join(", ")));
        }
        notes.push("if the step needs a case split on a program value, split with `by_cases(..)` or write `follows()`; if a quantified fact or a lemma is needed, apply it first; `by_computation()` if the goal holds by evaluation alone".into());
        if let Some(dg) = self.diags.list.last_mut() {
            for n in notes {
                dg.notes.push((None, n));
            }
        }
        Ok(Rc::new(Term::Erased))
    }

    /// The proof of the goal from the view's proof `p` (see the module
    /// docs); records the obligation as proven by `script(label)`.
    #[allow(clippy::too_many_arguments)]
    fn lift_restricted(&mut self, view: &View, p: Tm, target: &Tm, kind: ObligationKind, sp: Span, relevant: bool, stmt: &str, label: &str) -> R<Tm> {
        // `let F_g := g; ..; let h' := h; p`: the view's binders bound to
        // what they stand for
        let mut lifted = p;
        for a in view.abs.iter().rev() {
            lifted = Rc::new(Term::Let { name: a.name.clone(), rel: a.rel, ty: a.dom.clone(), val: a.val.clone(), body: lifted });
        }
        let by = format!("script({label})");
        // checked even when obligations are not checked on the spot: an
        // ill-formed view statement must fall back here, not fail the
        // definition in the kernel
        let checked = if view.abs.is_empty() || super::super::tm::has_erased(target) {
            Ok(())
        } else {
            match self.eval(target) {
                Ok(tv) => self.check_proof_in(&self.f.scope.ctx, &lifted, target, &tv, relevant),
                Err(e) => Err(e.msg),
            }
        };
        if std::env::var_os("SANDBLASTER_TRACE_OBL").is_some() {
            eprintln!("closer {stmt} in {}: {} unknown function(s), {} view binder(s), lifted proof: {:?}", self.f.name, view.unknown.len(), view.abs.len(), checked);
        }
        if checked.is_ok() {
            let id = self.obligations.len() as u32;
            self.record(id, kind, sp, OblStatus::Proven { by }, true, String::new());
            return Ok(lifted);
        }
        // the lifted proof is rejected (not expected: the view's binders
        // are bound to their values): the claim is checked, the
        // unrestricted chain proves the goal
        let n = self.obligations.len();
        let pf = self.prove(kind, sp, target, relevant)?;
        if let Some(o) = self.obligations.get_mut(n)
            && o.proven()
        {
            o.status = OblStatus::Proven { by };
        }
        Ok(pf)
    }

    /// Warns about named definitions the view does not need: a function of
    /// the crate that occurs neither in the goal, the facts in scope, nor
    /// the bodies of the named definitions that do; a prelude definition
    /// that occurs nowhere in the view.
    fn unused_unfoldings(&mut self, view: &View, keep: &[GlobalId], sp: Span) {
        let user = self.user_functions();
        let prelude: HashSet<GlobalId> = keep.iter().copied().filter(|g| !user.contains(g)).collect();
        let mut found = BTreeSet::new();
        if !prelude.is_empty() {
            globals_in(&view.target, &prelude, &mut found);
            for (_, t) in &view.terms {
                globals_in(t, &prelude, &mut found);
            }
            for a in &view.abs {
                globals_in(&a.dom, &prelude, &mut found);
                globals_in(&a.val, &prelude, &mut found);
            }
        }
        for g in keep {
            if view.unused.contains(g) || (prelude.contains(g) && !found.contains(g)) {
                let name = self.global_text(*g);
                self.diags.push(Diagnostic::warning(DiagKind::Script, sp, format!("`by_unfolding`: `{name}` does not occur in the goal or the facts in scope")).note("the step does not depend on it: remove it from the list"));
            }
        }
    }

    /// `by_contradiction()`: the facts in scope are contradictory; the goal
    /// is not used.
    pub(super) fn by_contradiction(&mut self, goal: Val, kind: ObligationKind, sp: Span) -> R<Tm> {
        let d = self.depth();
        let g = goal.at(d);
        let empty = mk::ind(self.env.empty_ind(), vec![]);
        let n = self.obligations.len();
        let nd = self.diags.list.len();
        let p = self.prove(kind, sp, &empty, false)?;
        let proven = self.obligations.get(n).is_some_and(|o| o.proven());
        if !proven {
            let goal_text = self.show_tm(&g);
            if self.diags.list.len() > nd
                && let Some(dg) = self.diags.list.last_mut()
            {
                dg.notes.push((None, "`by_contradiction()`: the facts in scope must contradict each other on their own; the goal is not used".into()));
                dg.notes.push((None, format!("the goal (not used): {}", trunc(goal_text))));
                dg.notes.push((None, "if the case is possible, the goal needs a proof of its own: `by_arithmetic()`, `follows()` or more steps".into()));
            }
            return Ok(Rc::new(Term::Erased));
        }
        if let Some(o) = self.obligations.get_mut(n) {
            o.status = OblStatus::Proven { by: "script(by_contradiction)".into() };
        }
        Ok(Rc::new(Term::Absurd { ty: g, proof: p }))
    }
}

impl<'a> Elab<'a> {
    /// The echo check of a law (DESIGN.md §15.1 LR6 (a)): whether `target`
    /// (a term at the current depth; the facts in scope are the law's
    /// hypotheses) follows in the restricted view of a closing statement
    /// (see the module docs) where exactly `keep` unfold — each a named
    /// definition, unfolded once — by `prover` within `budget` steps. The
    /// view makes every other function of the crate an unknown variable, so
    /// nothing else unfolds by evaluation; the caller restricts the prover
    /// (no induction, no lemma, no arithmetic beyond evaluation). A proof
    /// counts only if the kernel checks it in the view. Nothing is
    /// recorded: this is a diagnostic, not an obligation.
    pub(in crate::elab) fn echo_attempt(&mut self, target: &Tm, keep: &[GlobalId], prover: &mut dyn crate::prover::Prover, budget: u64, sp: Span) -> R<super::super::law_rules::EchoOutcome> {
        let target = super::super::recert::recertify(&self.env, &self.f.scope.ctx, target);
        // a recursive or opaque proposition has no defining equation to
        // unfold by: it stays an unknown function of the view (the echo is
        // still attempted with every other definition unfolded — never
        // skipped)
        let keep: Vec<GlobalId> = keep.iter().copied().filter(|g| self.unfolds_by_evaluation(*g) || self.defining_equation(*g).is_some()).collect();
        let keep = &keep[..];
        let view = self.restricted_view(&target, keep, false, sp)?;
        let tv = self.eval_in_entries(&view.ctx.entries, &view.target, sp)?;
        let unfolded: Vec<String> = keep.iter().filter(|g| !view.unused.contains(g)).map(|g| self.global_text(*g)).collect();
        let unknown: Vec<String> = view.unknown.iter().map(|g| self.global_text(*g)).collect();
        let g = Goal { id: ObligationId(u32::MAX - 1), kind: ObligationKind::LawGoal, span: sp, ctx: view.ctx.clone(), facts: view.facts.clone(), target: tv.clone(), hints: view.defined.clone() };
        let mut b = Budget { steps: budget };
        super::super::set_hidden_facts(view.hidden.clone());
        let res = prover.prove(&self.env, &g, &mut b);
        super::super::set_hidden_facts(Vec::new());
        let proven = match res {
            Ok(p) => {
                let p = super::super::recert::recertify(&self.env, &view.ctx, &p);
                !super::super::tm::has_erased(&view.target) && self.check_proof_in(&view.ctx, &p, &view.target, &tv, false).is_ok()
            }
            Err(_) => false,
        };
        Ok(super::super::law_rules::EchoOutcome { proven, unfolded, unknown, reads: String::new(), undecided: None })
    }
}

fn trunc(s: String) -> String {
    if s.len() <= 300 {
        return s;
    }
    let mut cut = 300;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &s[..cut])
}

/// For the body of a function of arity `n` (the term under its `n` λs)
/// that is, after its `let`s, a record constructor: per field, whether the
/// field is copied from the arguments — an argument, or a projection
/// (`π_k`, `fst`, `snd`, a one-arm `match` returning a field) or cast of
/// one, repeatedly. Such a field equation says only what the record is
/// made of (DESIGN.md §4.4, the view-link rule of `by_arithmetic()`); a
/// computed field is part of what the function computes. Empty when the
/// body is not a constructor.
fn copied_fields(body: &Tm, n: u32) -> Vec<bool> {
    fn copied(t: &Tm, n: u32) -> bool {
        match &**t {
            Term::Var(i) => i.0 < n,
            Term::Fst(x) | Term::Snd(x) => copied(x, n),
            Term::Prim { op: sandblaster_kernel::term::PrimOp::Cast { .. }, args, .. } if args.len() == 1 => copied(&args[0], n),
            Term::Match { scrut, arms, .. } if arms.len() == 1 => {
                let k = arms[0].names.len() as u32;
                matches!(&*arms[0].body, Term::Var(j) if j.0 < k) && copied(scrut, n)
            }
            _ => false,
        }
    }
    // `let`s are substituted: their uses are judged as written
    let mut b = super::super::tm::simp_redexes(body);
    while let Term::Let { body: inner, val, .. } = &*b.clone() {
        b = super::super::tm::simp_redexes(&super::super::tm::subst0(inner, val));
    }
    let Term::Ctor { args, .. } = &*b else { return vec![] };
    args.iter().map(|a| copied(a, n)).collect()
}
