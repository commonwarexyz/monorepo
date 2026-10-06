//! Types that carry invariants (DESIGN.md §15.3; stage **S2**).
//!
//! # The kernel encoding
//!
//! `#[invariant(p)]` on `struct S<T..> { f̄ }` (several attributes are
//! conjoined) makes the invariant part of the kernel type:
//!
//! ```text
//! inductive S(T..) := S(f̄, inv₀ :Irr P₀(f̄), …, invₘ :Irr Pₘ(f̄))
//! ```
//!
//! with one trailing `Irr` constructor field per conjunct. A conjunct is a
//! top-level `&&`-part of an attribute. A part that needs the earlier ones
//! (`self.a != 0 && self.b / self.a < 5`: the division needs the first part)
//! takes them as `Irr` hypotheses — `S::invariant#k : Π(T..)(f̄)(h₀ :Irr
//! P₀)…` and the field `invₖ :Irr Pₖ(f̄, inv₀, …)` — so every part keeps its
//! own simple fact (`Elab::invariant_bodies`):
//!
//! * a **`bool` invariant** (anything the front end can read as a `bool`
//!   expression: comparisons, `==` on scalars, `&&`, `||`, `!`, `implies`,
//!   `iff`, `if`, `match` and `if let` with `bool` arms) is the spec
//!   definition `S::invariant#k : Π(T..)(f̄). Bool` and the field `Eq(Bool,
//!   S::invariant#k T.. f̄, true)`;
//! * a **proposition** (`forall`, a `-> Prop` spec function, equality of
//!   structured values) is `S::invariant#k : Π(T..)(f̄). Type` and the field
//!   `S::invariant#k T.. f̄`, which must pass the kernel's `is_prop`. The
//!   front end checks this first (a readable `error[invariant]`: `||`
//!   between propositions, a proposition-valued `if`/`match`, a stuck
//!   predicate), and `exists(..)` is encoded as `¬¬∃` (reported: its
//!   consequences are usable for decidable goals only).
//!
//! `self.f` is the field binder (the typechecker rewrote it); the free
//! variables of an invariant are the fields, the type parameters, constants
//! and spec-closed globals (§15.3 evidence rule, [`Elab::invariant_closure`]).
//! An invariant cannot mention `S` itself (not even through a spec function
//! taking an `S`): the type is declared before any of its values exists.
//!
//! **`Nat` fields** (spec structs) are not conjuncts: their bounds are the
//! guards and hypotheses of S1's `Nat` parameters, extended to the `Nat`
//! components of parameters (`Elab::nat_components`). A proof inside a spec
//! value would block the case analysis and rewriting refinement proofs rely
//! on (the provers generalize a value without its proofs).
//!
//! # Construction (`ObligationKind::TypeInvariant`)
//!
//! Every constructor application supplies the `Irr` fields
//! ([`Elab::ctor_irr_proofs`]): struct literals and tuple-struct calls,
//! `..base` updates, SSA field assignments (`x.f = v` rebuilds `x`, so the
//! invariant can be broken only in unpacked locals), the structural view
//! of a type onto a spec struct, and `sandblaster eval` inputs (checked by
//! evaluation). The obligation's target is the field type instantiated by
//! substitution from the kernel declaration — never from the HIR. Pattern rebuilds
//! (script refinements, the body walk) reuse the matched `Irr` fields.
//!
//! # Free facts (`FactOrigin::TypeBound`)
//!
//! `S::inv#k : Π(T..)(s : S T..). Pₖ(π₀ s, …)` is proven once per conjunct
//! (a match on `s` promoting the `Irr` field, `eq::promote`). Its instance
//! is a fact wherever a value of `S` appears: parameters, `let`s and
//! pattern bindings, call results, projections and projected patterns
//! ([`Elab::with_inv_facts`]; one fact per value term), bound as `let`s.
//! In a pure context (a proposition elaborated as a type, a place index, a
//! loop bound or measure: `FnState::pure_facts`) a binder would change the
//! type or value being built, so there the facts are hints of the proof
//! slots ([`Elab::add_inv_hints`]); the paths such an expression projects
//! are bound before its statement ([`Elab::prebind_inv_facts`]), and a loop
//! helper's parameters have theirs as hints.
//!
//! # Views, `Abstract(T)`, determinacy
//!
//! A closure view's injectivity (`T::view_inj`) is attempted automatically
//! ([`Elab::view_injectivity`]) or proven by a `#[proof(view_inj = T)]`
//! item ([`Elab::view_inj_proof_item`]); `Abstract(T)` is
//! [`crate::validate::abstract_reasons`]; [`Elab::s2_post_pass`] gives the
//! simulation-form refinements of an `Abstract` represents type their
//! verdict.
//!
//! # Ghost parameters
//!
//! The `#[ghost]` parameters of an exec function (the last ones) and the
//! `requires` that mention them are one `Irr` binder, the ghost bundle
//! ([`Elab::ghost_bundle`]); callers pass `ghost!(e)` ([`Elab::ghost_bundle_arg`]),
//! the printer omits both, and the boundary rule rejects a `pub` function
//! with one (§3.1). Facts over ghost values are given to the prover inside
//! each proof slot (`Scope::hint_facts`).

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::term::{Arm, DefKind, GlobalId, IndId, Recursion, Rel, Term, Tm};
use sandblaster_kernel::util::{mk, shift};
use sandblaster_kernel::value::{Budget, Value, V};

use super::items::{lam_tele, pi_tele, TBinder};
use super::{Elab, ElabError, ErrKind, FnState, Mode, Val, R};
use crate::diag::{DiagKind, Diagnostic};
use crate::hir::*;
use crate::prover::{FactOrigin, ObligationKind};
use crate::span::Span;

/// One conjunct of a struct's invariant: one `Irr` constructor field.
#[derive(Clone, Debug)]
pub struct InvPart {
    /// `S::invariant#k` (absent for the bound of a `Nat` field).
    pub def: Option<GlobalId>,
    /// `Eq(Bool, p̂(f̄), true)` (else a proposition).
    pub boolean: bool,
    /// The `#[invariant]` attribute it comes from (the struct for a `Nat`
    /// bound).
    pub span: Span,
    /// What it is, for diagnostics.
    pub what: String,
    /// An `exists` in it is encoded as `¬¬∃`.
    pub double_negated: bool,
}

/// The §15 S2 state of an elaboration (inside [`super::views::S1State`]).
#[derive(Clone, Debug, Default)]
pub struct S2State {
    /// The invariant conjuncts of every struct that has any, in `Irr`
    /// field order.
    pub invariants: HashMap<ItemId, Vec<InvPart>>,
    /// `T::view_inj` (DESIGN.md §15.2), by type: the checked lemma, or why
    /// the view is not known to be injective.
    pub view_inj: HashMap<ItemId, Result<GlobalId, String>>,
}

/// The elaborated body of one conjunct (before it is defined).
struct InvBody {
    binders: Vec<TBinder>,
    body: Tm,
    boolean: bool,
    double_negated: bool,
    span: Span,
    failed: bool,
    /// The earlier conjuncts of the same attribute it takes as `Irr`
    /// hypotheses (the last binders): `0`, or its position in the
    /// attribute (all of the earlier ones).
    hyps: u32,
}

impl InvBody {
    /// The proposition the conjunct states, at the depth of its own body
    /// (`generics + fields + hyps`): the hypothesis a later dependent
    /// conjunct takes.
    fn stated(&self, holds: impl Fn(Tm) -> Tm) -> Tm {
        if self.boolean { holds(self.body.clone()) } else { self.body.clone() }
    }
}

/// Whether a struct's kernel type has `Irr` fields: an invariant. (The
/// bounds of `Nat` fields are guards and hypotheses at parameters, like
/// S1's `Nat` parameters: `Elab::nat_components`.)
pub fn has_irr_fields(s: &StructDef) -> bool {
    s.invariant.is_some()
}

/// The top-level `&&`-parts of a proposition.
fn split_conjuncts(e: &Expr) -> Vec<&Expr> {
    match &e.kind {
        ExprKind::PropAnd(a, b) => {
            let mut v = split_conjuncts(a);
            v.extend(split_conjuncts(b));
            v
        }
        ExprKind::Block(b) if b.stmts.is_empty() && b.tail.is_some() => split_conjuncts(b.tail.as_ref().unwrap()),
        _ => vec![e],
    }
}

/// Whether `==` on values of this type is a `bool` operation of the
/// elaborator.
fn bool_comparable(t: &Ty) -> bool {
    matches!(t.peel_refs(), Ty::Bool | Ty::Uint(_) | Ty::Int | Ty::Nat)
}

/// The `bool` reading of a proposition, when it has one (see the module
/// docs): `BoolToProp(b)` is `b`, `==`/`!=` on scalars are the `bool`
/// comparisons, `&&`/`||` short-circuit, `implies(p, q)` is `!p || q`,
/// `iff(p, q)` is `p == q`, and an `if`, `match` or `if let` is read arm by
/// arm.
pub fn boolify(e: &Expr) -> Option<Expr> {
    let span = e.span;
    let b = |k: ExprKind| Expr::new(k, Ty::Bool, span);
    Some(match &e.kind {
        ExprKind::Coerce(Coercion::BoolToProp, x) => (**x).clone(),
        ExprKind::PropEq(x, y) | ExprKind::PropNe(x, y) if bool_comparable(&x.ty) && bool_comparable(&y.ty) => {
            let op = if matches!(e.kind, ExprKind::PropEq(..)) { BinOp::Eq } else { BinOp::Ne };
            b(ExprKind::Binary(op, x.clone(), y.clone()))
        }
        ExprKind::PropAnd(p, q) => b(ExprKind::Binary(BinOp::And, Box::new(boolify(p)?), Box::new(boolify(q)?))),
        ExprKind::PropOr(p, q) => b(ExprKind::Binary(BinOp::Or, Box::new(boolify(p)?), Box::new(boolify(q)?))),
        ExprKind::PropNot(p) => b(ExprKind::Unary(UnOp::Not, Box::new(boolify(p)?))),
        ExprKind::Implies(p, q) => {
            let np = b(ExprKind::Unary(UnOp::Not, Box::new(boolify(p)?)));
            b(ExprKind::Binary(BinOp::Or, Box::new(np), Box::new(boolify(q)?)))
        }
        ExprKind::Iff(p, q) => b(ExprKind::Binary(BinOp::Eq, Box::new(boolify(p)?), Box::new(boolify(q)?))),
        ExprKind::If { cond, then, els: Some(x) } => b(ExprKind::If { cond: cond.clone(), then: Box::new(boolify(then)?), els: Some(Box::new(boolify(x)?)) }),
        // a `match` (or `if let`) whose arms are all `bool` readings
        ExprKind::Match { scrut, arms, source } => {
            let arms = arms.iter().map(|a| Some(crate::hir::Arm { pat: a.pat.clone(), guard: a.guard.clone(), body: boolify(&a.body)?, span: a.span })).collect::<Option<Vec<_>>>()?;
            b(ExprKind::Match { scrut: scrut.clone(), arms, source: *source })
        }
        ExprKind::Block(bl) if bl.stmts.is_empty() && bl.tail.is_some() => return boolify(bl.tail.as_ref().unwrap()),
        _ => return None,
    })
}

/// `exists(..)` wrapped as `!!exists(..)` wherever it is not already
/// negated (§15.3); whether any was wrapped.
fn double_negate_exists(e: &Expr) -> (Expr, bool) {
    let mut changed = false;
    let out = dne(e, false, &mut changed);
    (out, changed)
}

fn dne(e: &Expr, under_not: bool, changed: &mut bool) -> Expr {
    let span = e.span;
    let re = |k: ExprKind| Expr::new(k, e.ty.clone(), span);
    match &e.kind {
        ExprKind::Quant { quant: Quant::Exists, .. } if !under_not => {
            *changed = true;
            let inner = Expr::new(ExprKind::PropNot(Box::new(e.clone())), Ty::Prop, span);
            Expr::new(ExprKind::PropNot(Box::new(inner)), Ty::Prop, span)
        }
        ExprKind::Quant { quant, binders, body } => re(ExprKind::Quant { quant: *quant, binders: binders.clone(), body: Box::new(dne(body, false, changed)) }),
        ExprKind::PropNot(p) => re(ExprKind::PropNot(Box::new(dne(p, true, changed)))),
        ExprKind::PropAnd(p, q) => re(ExprKind::PropAnd(Box::new(dne(p, false, changed)), Box::new(dne(q, false, changed)))),
        ExprKind::Implies(p, q) => re(ExprKind::Implies(Box::new(dne(p, false, changed)), Box::new(dne(q, false, changed)))),
        ExprKind::Iff(p, q) => re(ExprKind::Iff(Box::new(dne(p, false, changed)), Box::new(dne(q, false, changed)))),
        _ => e.clone(),
    }
}

impl<'a> Elab<'a> {
    // ------------------------------------------------------------------
    // the kernel type
    // ------------------------------------------------------------------

    /// The `Irr` constructor fields of struct `id` (see the module docs):
    /// `(name, type)`, field k's type a term at depth `generics + fields +
    /// k` (the earlier `Irr` fields in scope).
    /// Defines `S::invariant#k` for every conjunct; an invariant that is
    /// not a proposition, mentions `S` or has unproven obligations fails
    /// the type (dependents are blocked).
    pub fn invariant_fields(&mut self, id: ItemId, s: &'a StructDef) -> R<Vec<(String, Tm)>> {
        if !has_irr_fields(s) {
            return Ok(vec![]);
        }
        let it = self.krate.item(id);
        let path = it.path.to_string();
        let ngen = s.generics.len() as u32;
        let nf = s.fields.len() as u32;
        let depth = ngen + nf;
        let mut out = Vec::new();
        let mut parts = Vec::new();
        if let Some(inv) = &s.invariant {
            self.invariant_cycle_check(id, inv)?;
            for (p, pspan) in &inv.props {
                let conj = split_conjuncts(p);
                // the index of the attribute's first conjunct
                let k0 = parts.len() as u32;
                for b in self.invariant_bodies(id, s, inv, p, &conj, *pspan)? {
                    let k = parts.len();
                    let name = format!("{path}::invariant#{k}");
                    let rty = if b.boolean { mk::bool_ty(self.p.bool_) } else { mk::ty() };
                    let arity = b.binders.len() as u32;
                    let ty = pi_tele(&b.binders, rty);
                    let lam = lam_tele(&b.binders, b.body);
                    let r = self.add_definition(&name, DefKind::Spec, Some(id), ty, lam, Recursion::None, arity, false, b.failed, b.span);
                    if b.failed {
                        return Err(ElabError { span: b.span, msg: format!("the invariant of `{path}` has unproven obligations (see above)"), kind: ErrKind::Blocked });
                    }
                    let g = r?;
                    if b.double_negated {
                        self.diag(
                            Diagnostic::warning(DiagKind::Invariant, b.span, format!("the `exists` in the invariant of `{path}` is encoded as `¬¬∃`"))
                                .note("an existential proof carries its witness, so it is not a proposition the kernel can erase; `¬¬∃` is (DESIGN.md §15.3), and it gives `∃` only for goals that are decidable — store the witness in a field to keep it"),
                        );
                    }
                    self.invariant_closure(id, g, b.span);
                    // the field's type, at depth `generics + fields + k` (the
                    // earlier `Irr` fields in scope): `S::invariant#k` at the
                    // type parameters and fields, and — for a conjunct that
                    // needs the earlier ones of its attribute — at their
                    // `Irr` fields
                    let d = depth + k as u32;
                    let mut args: Vec<(Rel, Tm)> = (0..depth).map(|i| (Rel::Rel, mk::var(d - 1 - i))).collect();
                    args.extend((0..b.hyps).map(|m| (Rel::Irr, mk::var(d - 1 - (depth + k0 + m)))));
                    let app = mk::apps(mk::global(g), args);
                    out.push((format!("inv{k}"), if b.boolean { self.holds(app) } else { app }));
                    parts.push(InvPart { def: Some(g), boolean: b.boolean, span: b.span, what: format!("the `#[invariant]` of `{path}`"), double_negated: b.double_negated });
                }
            }
        }
        self.s1.s2.invariants.insert(id, parts);
        Ok(out)
    }

    /// The bodies of one attribute: its `&&`-parts, each on its own (every
    /// obligation proven) or, when it needs them (`self.hi - self.lo` after
    /// `self.lo <= self.hi`), with the earlier parts as `Irr` hypotheses —
    /// so every part is its own conjunct with its own simple fact. Only if
    /// a part fails even so is the whole attribute one conjunct.
    fn invariant_bodies(&mut self, id: ItemId, s: &'a StructDef, inv: &'a TypeInvariant, whole: &'a Expr, conj: &[&'a Expr], span: Span) -> R<Vec<InvBody>> {
        if conj.len() > 1 {
            let (no, nd) = (self.obligations.len(), self.diags.list.len());
            let mut v: Vec<InvBody> = Vec::new();
            let mut ok = true;
            for (j, c) in conj.iter().enumerate() {
                let (no1, nd1) = (self.obligations.len(), self.diags.list.len());
                match self.invariant_body(id, s, inv, c, span, &[]) {
                    Ok(b) if !b.failed => {
                        v.push(b);
                        continue;
                    }
                    _ => {
                        self.obligations.truncate(no1);
                        self.diags.list.truncate(nd1);
                    }
                }
                // the earlier parts as hypotheses, each at its position of
                // the telescope (an independent part's body is weakened)
                let hyps: Vec<Tm> = v.iter().enumerate().map(|(m, b)| shift(&b.stated(|t| self.holds(t)), m as i64 - b.hyps as i64)).collect();
                match (j > 0).then(|| self.invariant_body(id, s, inv, c, span, &hyps)) {
                    Some(Ok(b)) if !b.failed => v.push(b),
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                return Ok(v);
            }
            self.obligations.truncate(no);
            self.diags.list.truncate(nd);
            let b = self.invariant_body(id, s, inv, whole, span, &[])?;
            if !b.failed {
                let path = self.krate.item(id).path.to_string();
                self.diag(
                    Diagnostic::warning(DiagKind::Invariant, span, format!("this invariant of `{path}` is one conjunct: its `&&`-parts could not be stated one by one"))
                        .note("a conjunct's fact is used as a whole, so proofs that need one part must take the conjunct apart (slower, and less readable goals)")
                        .note("state each part so it is well-defined on its own, e.g. `self.w as Int + self.lo as Int == self.hi as Int` instead of `self.w == self.hi - self.lo`"),
                );
            }
            return Ok(vec![b]);
        }
        Ok(vec![self.invariant_body(id, s, inv, whole, span, &[])?])
    }

    /// Elaborates one conjunct over the field binders (see the module
    /// docs); the result's `failed` tells whether an obligation of its own
    /// (a division, an index) is unproven.
    fn invariant_body(&mut self, id: ItemId, s: &'a StructDef, inv: &'a TypeInvariant, e: &'a Expr, span: Span, hyps: &[Tm]) -> R<InvBody> {
        let it = self.krate.item(id);
        self.f = FnState::new(format!("{}::invariant", it.path), Some(id), &inv.locals, span);
        let mut binders = Vec::new();
        for g in &s.generics {
            self.push(&g.name, Rel::Rel, &mk::ty(), None)?;
            binders.push(TBinder { name: g.name.clone(), rel: Rel::Rel, ty: mk::ty() });
        }
        self.f.ngen = s.generics.len() as u32;
        for (j, f) in s.fields.iter().enumerate() {
            let ty = self.ty(&f.ty, span)?;
            let local = inv.fields[j];
            let name = inv.locals.get(local.0 as usize).map(|d| d.name.clone()).unwrap_or_else(|| format!("self.{j}"));
            let lvl = self.push(&name, Rel::Rel, &ty, None)?;
            self.f.scope.locals.insert(local, lvl);
            binders.push(TBinder { name, rel: Rel::Rel, ty });
        }
        // the earlier parts of the attribute, as facts (a dependent part)
        for (m, h) in hyps.iter().enumerate() {
            let name = format!("h_inv{m}");
            self.push_fact_rel(&name, Rel::Irr, h, None, FactOrigin::TypeBound, span)?;
            binders.push(TBinder { name, rel: Rel::Irr, ty: h.clone() });
        }
        let (body, boolean, double_negated) = match boolify(e) {
            Some(b) => {
                let b: &'a Expr = Box::leak(Box::new(b));
                self.f.answer = Ty::Bool;
                self.f.ret = Ty::Bool;
                (self.expr(b, &mut |s, v| Ok(v.at(s.depth())))?, true, false)
            }
            None => {
                self.invariant_prop_precheck(id, e)?;
                let (e2, nn) = double_negate_exists(e);
                let e2: &'a Expr = Box::leak(Box::new(e2));
                self.f.answer = Ty::Prop;
                self.f.ret = Ty::Prop;
                let p = self.prop(e2)?;
                // the kernel's `is_prop` on the elaborated proposition (a
                // `-> Prop` spec function must unfold to one)
                if !self.f.failed {
                    let v = self.eval(&p)?;
                    if !self.value_is_prop(&v, 32) {
                        let path = self.krate.item(id).path.to_string();
                        self.diag(
                            Diagnostic::error(DiagKind::Invariant, e.span, format!("the invariant of `{path}` is not a proposition the kernel accepts as an `Irr` field"))
                                .note("an invariant is erased, so it must be proof-irrelevant (`is_prop`: equations, `!`, `forall`, `implies`, `&&` of those); a disjunction, a recursive `-> Prop` predicate or a proposition-valued `if`/`match` is not")
                                .note("write the invariant as a `bool` expression (a `bool` `||` is fine), or as a `bool`-valued spec function (DESIGN.md §15.3)"),
                        );
                        return Err(ElabError { span: e.span, msg: format!("the invariant of `{path}` is not a proposition"), kind: ErrKind::Blocked });
                    }
                }
                (p, false, nn)
            }
        };
        Ok(InvBody { binders, body, boolean, double_negated, span, failed: self.f.failed, hyps: hyps.len() as u32 })
    }

    /// The readable `is_prop` pre-check of a proposition invariant (§15.3):
    /// reports the construct the kernel would reject, before any kernel
    /// error.
    fn invariant_prop_precheck(&mut self, id: ItemId, e: &Expr) -> R<()> {
        fn bad(e: &Expr) -> Option<(Span, &'static str, &'static str)> {
            match &e.kind {
                ExprKind::PropOr(..) => Some((e.span, "`||` between propositions is not a proposition (a proof of it says which side holds)", "write the invariant as a `bool` expression, where `||` is fine (e.g. `self.a < 10 || self.b < 10`), or split it into cases with `implies`")),
                ExprKind::If { .. } | ExprKind::Match { .. } => Some((
                    e.span,
                    "a proposition-valued `if`/`match` over the fields is stuck on the field values, so the kernel cannot see a proposition (an arm is not a `bool` expression: a `forall`, an equality of structured values, ..)",
                    "make every arm a `bool` expression; or move the case split into a `bool`-valued spec function over the fields (`#[spec] fn ok(p: Option<u64>, i: u64) -> bool { match p { .. } }`); or state each case with `implies`: `implies(c, p) && implies(!c, q)`, and for an `Option` field `forall(|x| implies(self.f == Some(x), p(x)))`",
                )),
                ExprKind::PropAnd(p, q) | ExprKind::Implies(p, q) | ExprKind::Iff(p, q) => bad(p).or_else(|| bad(q)),
                ExprKind::Quant { quant: Quant::Forall, body, .. } => bad(body),
                ExprKind::Block(b) if b.stmts.is_empty() => b.tail.as_ref().and_then(|t| bad(t)),
                // `!p` is `p → Empty`, a proposition for any `p`; an `exists`
                // is encoded as `¬¬∃`
                _ => None,
            }
        }
        if let Some((span, what, fix)) = bad(e) {
            let path = self.krate.item(id).path.to_string();
            self.diag(Diagnostic::error(DiagKind::Invariant, span, format!("the invariant of `{path}` is not a proposition: {what}")).note(fix).note("an invariant is an `Irr` constructor field, erased by codegen, so it must be proof-irrelevant (the kernel's `is_prop`, DESIGN.md §15.3)"));
            return Err(ElabError { span, msg: format!("the invariant of `{path}` is not a proposition"), kind: ErrKind::Blocked });
        }
        Ok(())
    }

    /// The kernel's conservative `is_prop` on a type value (a front-end
    /// mirror of `Checker::is_prop`, for the readable error; the kernel
    /// decides when the type is declared).
    pub fn value_is_prop(&self, v: &V, fuel: u32) -> bool {
        self.value_is_prop_at(v, sandblaster_kernel::term::Lvl(self.depth()), fuel)
    }

    fn value_is_prop_at(&self, v: &V, depth: sandblaster_kernel::term::Lvl, fuel: u32) -> bool {
        use sandblaster_kernel::value::{EnvEntry, VEnv};
        if fuel == 0 {
            return false;
        }
        let next = sandblaster_kernel::term::Lvl(depth.0 + 1);
        let mut b = Budget { steps: self.opts.goal_budget };
        let inst = |c: &sandblaster_kernel::value::Closure, rel: Rel, dom: &V, b: &mut Budget| -> Option<V> {
            let x = self.env.fresh_var(depth, rel, dom);
            let mut e = (*c.env.0).clone();
            e.push(x);
            self.env.eval(&VEnv(Rc::new(e)), next, &c.body, b).ok()
        };
        match &**v {
            Value::Eq { .. } => true,
            Value::Pi { rel, dom, cod, .. } => inst(cod, *rel, dom, &mut b).is_some_and(|c| self.value_is_prop_at(&c, next, fuel - 1)),
            Value::Sigma { fst, snd, .. } => self.value_is_prop_at(fst, depth, fuel - 1) && inst(snd, Rel::Rel, fst, &mut b).is_some_and(|c| self.value_is_prop_at(&c, next, fuel - 1)),
            Value::Ind { ind, params } => {
                let Some(decl) = self.env.inductive_decl(*ind) else { return false };
                if self.env.inductive_is_recursive(*ind) != Some(false) || decl.ctors.len() > 1 {
                    return false;
                }
                let Some(c) = decl.ctors.first() else { return true };
                let mut fenv: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
                let mut d = depth;
                for (_, frel, fty) in &c.fields {
                    let Ok(ftv) = self.env.eval(&VEnv(Rc::new(fenv.clone())), d, fty, &mut b) else { return false };
                    if !self.value_is_prop_at(&ftv, d, fuel - 1) {
                        return false;
                    }
                    fenv.push(self.env.fresh_var(d, *frel, &ftv));
                    d = sandblaster_kernel::term::Lvl(d.0 + 1);
                }
                true
            }
            _ => false,
        }
    }

    /// An invariant may not mention its own type: `declare_adt` runs before
    /// any value exists (§15.3). Reports a spec function (or anything
    /// else the invariant reaches) whose signature mentions the struct.
    fn invariant_cycle_check(&mut self, id: ItemId, inv: &TypeInvariant) -> R<()> {
        struct Calls(Vec<ItemId>);
        impl crate::visit::Visitor for Calls {
            fn expr(&mut self, e: &Expr) {
                match &e.kind {
                    ExprKind::Call { callee: Callee::Item(c, _), .. } => self.0.push(*c),
                    ExprKind::Const(c) => self.0.push(*c),
                    _ => {}
                }
                crate::visit::walk_expr(self, e);
            }
        }
        let mut c = Calls(vec![]);
        for (p, _) in &inv.props {
            crate::visit::Visitor::expr(&mut c, p);
        }
        let mut seen = std::collections::HashSet::new();
        let mut work: Vec<(ItemId, ItemId)> = c.0.iter().map(|x| (*x, *x)).collect();
        while let Some((x, root)) = work.pop() {
            if !seen.insert(x) {
                continue;
            }
            let refs = super::order::refs(self.krate, x);
            if x == id || refs.contains(&id) {
                let path = self.krate.item(id).path.to_string();
                let via = self.krate.item(root).path.to_string();
                let span = inv.props.first().map(|p| p.1).unwrap_or(self.krate.item(id).span);
                self.diag(
                    Diagnostic::error(DiagKind::Invariant, span, format!("the invariant of `{path}` uses `{via}`, which mentions `{path}` itself"))
                        .note("an invariant is part of the type's definition and is stated over the field values; a function of the type (or one that reaches it) would be circular — the type does not exist yet when its invariant is declared")
                        .note("state the invariant over the fields, with spec functions that take the fields' types (DESIGN.md §15.3)"),
                );
                return Err(ElabError { span, msg: format!("the invariant of `{path}` is circular"), kind: ErrKind::Blocked });
            }
            for r in refs {
                if !matches!(self.krate.item(r).kind, ItemKind::Struct(_) | ItemKind::Enum(_) | ItemKind::TypeAlias(_)) {
                    work.push((r, root));
                }
            }
        }
        Ok(())
    }

    /// The free-variable rule of invariants and evidence types (§15.3):
    /// besides the fields and type parameters, an invariant may mention
    /// constants and spec-closed pure globals — spec functions, spec
    /// constants and established exec functions (§15.1) — never any other
    /// exec function (`error[spec-depends-on-impl]`).
    pub fn invariant_closure(&mut self, id: ItemId, g: GlobalId, span: Span) {
        if !self.s1.on {
            return;
        }
        let consts: Vec<GlobalId> = self
            .globals
            .iter()
            .filter_map(|(k, v)| match (v, &self.krate.item(*k).kind) {
                (super::ItemGlobal::Def(g), ItemKind::Const(_)) => Some(*g),
                _ => None,
            })
            .collect();
        self.spec_closure_check(id, "the invariant of", &[mk::global(g)], &consts, true, span);
    }

    /// For every `Irr` field `k` of struct `id` (see the module docs): the
    /// predicate `S::holds#k : Π(T..)(s : S T..). Bool` (a `bool`
    /// conjunct; `Type` for a proposition) — the conjunct at the value's
    /// projections — and the lemma `S::inv#k : Π(T..)(s : S T..).
    /// Eq(Bool, S::holds#k T.. s, true)` (or `S::holds#k T.. s`). Facts are
    /// stated with the predicate, so their types contain no `match`.
    pub fn invariant_lemmas(&mut self, id: ItemId, ind: IndId) -> R<()> {
        let it = self.krate.item(id);
        let span = it.span;
        let path = it.path.to_string();
        let ItemKind::Struct(s) = &it.kind else { return Ok(()) };
        let decl = self.env.inductive_decl(ind).ok_or_else(|| ElabError { span, msg: "unknown inductive".into(), kind: ErrKind::Internal })?;
        let c = decl.ctors[0].clone();
        let ngen = s.generics.len() as u32;
        let nfields = c.fields.len() as u32;
        let self_ty = Ty::Adt(id, s.generics.iter().enumerate().map(|(i, g)| Ty::Param(i as u32, g.name.clone())).collect());
        let bool_ind = self.p.bool_;
        let mut k = 0usize;
        // the `S::inv#m` lemmas defined so far (the proofs of the earlier
        // `Irr` fields at a value, for a conjunct that depends on them)
        let mut inv_gs: Vec<GlobalId> = Vec::new();
        for (fi, (_, frel, fty)) in c.fields.iter().enumerate() {
            if *frel != Rel::Irr {
                continue;
            }
            let kk = k;
            k += 1;
            // the field type at the projections of `sv` (a term at depth `at`)
            let stmt_at = |me: &Self, sv: Tm, at: u32| -> Tm {
                let params: Vec<Tm> = (0..ngen).map(|i| mk::var(at - 1 - i)).collect();
                let mut args = params.clone();
                let mut m = 0usize;
                for (j, (_, r, jt)) in c.fields.iter().enumerate().take(fi) {
                    if *r == Rel::Rel {
                        let jty = super::tm::subst_closed(jt, &args);
                        args.push(me.proj(ind, params.clone(), sv.clone(), j, nfields as usize, jty));
                    } else {
                        let mut a: Vec<(Rel, Tm)> = params.iter().map(|p| (Rel::Rel, p.clone())).collect();
                        a.push((Rel::Rel, sv.clone()));
                        args.push(inv_gs.get(m).map(|g| mk::apps(mk::global(*g), a)).unwrap_or_else(|| Rc::new(Term::Erased)));
                        m += 1;
                    }
                }
                super::tm::subst_closed(fty, &args)
            };
            // `S::holds#k`
            let hname = format!("{path}::holds#{kk}");
            self.f = FnState::new(hname.clone(), Some(id), &[], span);
            let mut binders = Vec::new();
            for g in &s.generics {
                self.push(&g.name, Rel::Rel, &mk::ty(), None)?;
                binders.push(TBinder { name: g.name.clone(), rel: Rel::Rel, ty: mk::ty() });
            }
            self.f.ngen = ngen;
            let st = self.ty(&self_ty, span)?;
            self.push("s", Rel::Rel, &st, None)?;
            binders.push(TBinder { name: "s".into(), rel: Rel::Rel, ty: st.clone() });
            let d = self.depth();
            let at_s = stmt_at(self, mk::var(0), d);
            let (hbody, hty, boolean) = match &*at_s {
                Term::Eq { ty, lhs, rhs } if matches!(&**ty, Term::Ind { ind, .. } if *ind == bool_ind) && matches!(&**rhs, Term::Ctor { ind, ctor: 1, .. } if *ind == bool_ind) => (lhs.clone(), mk::bool_ty(bool_ind), true),
                _ => (at_s.clone(), mk::ty(), false),
            };
            let hg = self.add_definition(&hname, DefKind::Spec, Some(id), pi_tele(&binders, hty), lam_tele(&binders, hbody), Recursion::None, ngen + 1, false, false, span)?;
            // `S::inv#k`
            let name = format!("{path}::inv#{kk}");
            self.f = FnState::new(name.clone(), Some(id), &[], span);
            self.f.mode = Mode::Proof;
            for g in &s.generics {
                self.push(&g.name, Rel::Rel, &mk::ty(), None)?;
            }
            self.f.ngen = ngen;
            self.push("s", Rel::Rel, &st, None)?;
            // the fact's type at `sv` (depth `at`): no projection in it
            let fact_at = |sv: Tm, at: u32| -> Tm {
                let mut args: Vec<(Rel, Tm)> = (0..ngen).map(|i| (Rel::Rel, mk::var(at - 1 - i))).collect();
                args.push((Rel::Rel, sv));
                let app = mk::apps(mk::global(hg), args);
                if boolean { mk::eq_bool(bool_ind, app, true) } else { app }
            };
            let target = fact_at(mk::var(0), d);
            let motive = fact_at(mk::var(0), d + 1);
            // the arm: the promoted `Irr` field
            let ad = d + nfields;
            let mut args: Vec<Tm> = (0..ngen).map(|i| mk::var(ad - 1 - i)).collect();
            for j in 0..fi as u32 {
                args.push(mk::var(nfields - 1 - j));
            }
            let fty_arm = super::tm::subst_closed(fty, &args);
            let proof = self.promote_irr(&fty_arm, &mk::var(nfields - 1 - fi as u32), 16).ok_or_else(|| ElabError { span, msg: format!("the invariant of `{path}` cannot be used as a fact (not built from equations, `forall`, `!` and `&&`)"), kind: ErrKind::Unsupported })?;
            let params: Vec<Tm> = (0..ngen).map(|i| mk::var(d - 1 - i)).collect();
            let m = Rc::new(Term::Match { ind, params, scrut: mk::var(0), motive, arms: vec![Arm { names: c.fields.iter().map(|f| f.0.clone()).collect(), body: proof }] });
            let ty = pi_tele(&binders, target);
            let lam = lam_tele(&binders, m);
            inv_gs.push(self.add_definition(&name, DefKind::Lemma, Some(id), ty, lam, Recursion::None, ngen + 1, false, false, span)?);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // facts
    // ------------------------------------------------------------------

    /// The `S::inv#k` lemmas of a struct (empty for types without `Irr`
    /// fields; looked up by name).
    pub fn inv_lemmas(&self, id: ItemId) -> Vec<GlobalId> {
        let it = self.krate.item(id);
        let ItemKind::Struct(s) = &it.kind else { return vec![] };
        if !has_irr_fields(s) {
            return vec![];
        }
        let path = it.path.to_string();
        (0..).map_while(|k| self.env.lookup_global(&format!("{path}::inv#{k}"))).collect()
    }

    /// Runs `k` with the invariant facts of the value `v : ty` in scope
    /// (`FactOrigin::TypeBound`, `S::inv#k T.. v`), unless `ty` has no
    /// invariant or the same value already has them. The facts are `let`
    /// binders around the rest of the computation — except in a pure
    /// context (`FnState::pure_facts`: a proposition elaborated as a type, a
    /// place index, a loop bound or a measure), where a binder would change
    /// the type or value being built: there they are hints of the proof
    /// slots ([`Elab::add_inv_hints`]).
    pub fn with_inv_facts(&mut self, v: &Val, ty: &Ty, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        if self.f.pure_facts > 0 {
            let saved = self.f.scope.clone();
            let r = self.add_inv_hints(v, ty, span).and_then(|_| k(self));
            self.f.scope = saved;
            return r;
        }
        let Some((d, t, facts)) = self.inv_facts_of(v, ty, span)? else { return k(self) };
        let saved = self.f.scope.clone();
        self.f.scope.inv_seen.push((d, t));
        let r = self.push_inv_facts(&facts, 0, d, span, k);
        self.f.scope = saved;
        r
    }

    /// The invariant facts of the value `v : ty` (`(type, proof)` at depth
    /// `d`, with the value term): `None` when `ty` has no invariant or the
    /// value already has its facts in scope (`Scope::inv_seen`).
    #[allow(clippy::type_complexity)]
    fn inv_facts_of(&mut self, v: &Val, ty: &Ty, span: Span) -> R<Option<(u32, Tm, Vec<(Tm, Tm)>)>> {
        let Ty::Adt(id, args) = ty.peel_refs() else { return Ok(None) };
        let lemmas = self.inv_lemmas(*id);
        if lemmas.is_empty() {
            return Ok(None);
        }
        let d = self.depth();
        let t = v.at(d);
        let fp = super::tm::fingerprint(&t);
        if self.f.scope.inv_seen.iter().any(|(dd, tt)| *dd <= d && super::tm::fingerprint(&shift(tt, (d - dd) as i64)) == fp) {
            return Ok(None);
        }
        let mut params = Vec::new();
        for a in args {
            params.push(self.ty(a, span)?);
        }
        let mut facts = Vec::new();
        for g in lemmas {
            let Some(lty) = self.env.global_type(g) else { continue };
            let mut all = params.clone();
            all.push(t.clone());
            let stmt = super::ensures::strip_pis(&lty, all.len() as u32);
            facts.push((super::tm::subst_closed(&stmt, &all), mk::apps(mk::global(g), all.into_iter().map(|a| (Rel::Rel, a)))));
        }
        Ok(Some((d, t, facts)))
    }

    /// Adds the invariant facts of the value `v : ty` as hints of every
    /// later proof slot (`Scope::hint_facts`, no binder) and marks the value
    /// seen; the caller restores the scope. Used in pure contexts and for
    /// the parameters of loop helpers (whose types and measures are built
    /// before any body binder).
    pub fn add_inv_hints(&mut self, v: &Val, ty: &Ty, span: Span) -> R<()> {
        let Some((d, t, facts)) = self.inv_facts_of(v, ty, span)? else { return Ok(()) };
        self.f.scope.inv_seen.push((d, t));
        for (fty, pf) in facts {
            self.f.scope.hint_facts.push(super::scope::HintFact { ty: Val::new(fty, d), proof: Val::new(pf, d), name: "h_inv", origin: FactOrigin::TypeBound });
        }
        Ok(())
    }

    /// Runs `f` in a pure context (see `FnState::pure_facts`).
    pub fn in_pure<T>(&mut self, f: impl FnOnce(&mut Self) -> R<T>) -> R<T> {
        self.f.pure_facts += 1;
        let r = f(self);
        self.f.pure_facts = self.f.pure_facts.saturating_sub(1);
        r
    }

    /// Binds the invariant facts (§15.3) of the invariant-typed values
    /// projected in `es` — expressions that are elaborated later in a pure
    /// context (place indices, loop bounds, invariants and measures, proof
    /// steps), where no fact can be bound — as `let`s before `k`, so the
    /// obligations that use those expressions (an index bound, a loop
    /// entry, an assertion) see them. Only projections of paths (`x.f`,
    /// `x.f.g`) over locals in scope are bound.
    pub fn prebind_inv_facts(&mut self, es: &[&Expr], steps: &[ScriptStmt], span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        if self.f.pure_facts > 0 {
            return k(self);
        }
        let bases = collect_inv_bases(self.krate, es, steps);
        let mut vals = Vec::new();
        for b in &bases {
            if let Some(t) = self.path_value(b, span) {
                vals.push((Val::new(t, self.depth()), b.ty.clone()));
            }
        }
        self.prebind_from(&vals, 0, span, k)
    }

    fn prebind_from(&mut self, vals: &[(Val, Ty)], i: usize, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some((v, ty)) = vals.get(i) else { return k(self) };
        self.with_inv_facts(v, ty, span, &mut |s| s.prebind_from(vals, i + 1, span, k))
    }

    /// The value of a path expression (`x`, `x.f`, through references) at
    /// the current depth; `None` when a local is not in scope.
    fn path_value(&mut self, e: &Expr, span: Span) -> Option<Tm> {
        match &e.kind {
            ExprKind::Local(l) => self.f.scope.local(*l).map(|lvl| self.f.scope.var(lvl)),
            ExprKind::Field { base, index, .. } => {
                let b = self.path_value(base, span)?;
                self.field(&base.ty, b, *index as usize, span).ok()
            }
            ExprKind::Ref(x) | ExprKind::Deref(x) | ExprKind::Coerce(Coercion::AutoRef | Coercion::AutoDeref, x) => self.path_value(x, span),
            _ => None,
        }
    }

    fn push_inv_facts(&mut self, facts: &[(Tm, Tm)], i: usize, d0: u32, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some((ty, pf)) = facts.get(i) else { return k(self) };
        let sh = (self.depth() - d0) as i64;
        self.fact_in("h_inv", shift(ty, sh), shift(pf, sh), FactOrigin::TypeBound, span, &mut |s| s.push_inv_facts(facts, i + 1, d0, span, k))
    }

    /// The invariant facts of the parameters of `f` (levels `ngen + i`).
    pub fn param_inv_facts(&mut self, f: &'a FnDef, i: usize, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some(p) = f.params.get(i) else { return k(self) };
        if p.ghost {
            return self.param_inv_facts(f, i + 1, span, k);
        }
        let v = Val::new(self.f.scope.var(f.generics.len() as u32 + i as u32), self.depth());
        let ty = p.ty.clone();
        self.with_inv_facts(&v, &ty, span, &mut |s| s.param_inv_facts(f, i + 1, span, k))
    }

    // ------------------------------------------------------------------
    // construction
    // ------------------------------------------------------------------

    /// The proofs of the `Irr` fields of constructor `ctor` of `ind` applied
    /// to `params` and the relevant arguments `rel_args` (terms at the
    /// current depth): one `TypeInvariant` obligation per field, its
    /// target the field type instantiated from the kernel declaration.
    /// Empty when the constructor has no `Irr` field.
    pub fn ctor_irr_proofs(&mut self, ind: IndId, ctor: u32, params: &[Tm], rel_args: &[Tm], owner: Option<ItemId>, span: Span) -> R<Vec<Tm>> {
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(vec![]) };
        let Some(c) = decl.ctors.get(ctor as usize) else { return Ok(vec![]) };
        if c.fields.iter().all(|f| f.1 == Rel::Rel) {
            return Ok(vec![]);
        }
        let mut all: Vec<Tm> = params.to_vec();
        let mut rel = rel_args.iter();
        let mut proofs = Vec::new();
        for (_, r, fty) in &c.fields {
            match r {
                Rel::Rel => {
                    let a = rel.next().ok_or_else(|| ElabError { span, msg: "constructor arity".into(), kind: ErrKind::Internal })?;
                    all.push(a.clone());
                }
                Rel::Irr => {
                    let target = super::tm::subst_closed(fty, &all);
                    let pf = self.prove_type_invariant(owner, proofs.len(), &target, span)?;
                    all.push(pf.clone());
                    proofs.push(pf);
                }
            }
        }
        Ok(proofs)
    }

    /// `mk::ctor` with the `Irr` fields proven ([`Elab::ctor_irr_proofs`]).
    pub fn ctor_with_invariants(&mut self, ind: IndId, ctor: u32, params: Vec<Tm>, mut args: Vec<Tm>, owner: Option<ItemId>, span: Span) -> R<Tm> {
        let proofs = self.ctor_irr_proofs(ind, ctor, &params, &args, owner, span)?;
        args.extend(proofs);
        Ok(mk::ctor(ind, ctor, params, args))
    }

    /// `X` when `t` unfolds to `¬¬X` (`Π(h : Π(x : X). Empty). Empty`): the
    /// `¬¬∃` encoding of an existential invariant (§15.3).
    fn double_negated(&self, t: &Tm) -> Option<Tm> {
        let empty = self.env.empty_ind();
        let is_empty = |c: &Tm| matches!(&**c, Term::Ind { ind, .. } if *ind == empty);
        let t = super::tm::head_unfold(&self.env, t, &|x| matches!(x, Term::Pi { .. }))?;
        let Term::Pi { dom, cod, .. } = &*t else { return None };
        if !is_empty(cod) {
            return None;
        }
        let d = super::tm::head_unfold(&self.env, dom, &|x| matches!(x, Term::Pi { .. }))?;
        let Term::Pi { dom: x, cod: c2, .. } = &*d else { return None };
        if !is_empty(c2) {
            return None;
        }
        Some(x.clone())
    }

    /// One `TypeInvariant` obligation; a failure says which invariant. A
    /// `¬¬∃` conjunct is proven through its existential (the prover finds
    /// witnesses for `∃`, not under a double negation): `λh. h p`.
    fn prove_type_invariant(&mut self, owner: Option<ItemId>, k: usize, target: &Tm, span: Span) -> R<Tm> {
        if let Some(x) = self.double_negated(target) {
            let (no, nd, failed0) = (self.obligations.len(), self.diags.list.len(), self.f.failed);
            let p = self.prove(ObligationKind::TypeInvariant, span, &x, false)?;
            if self.obligations[no..].iter().all(|o| o.proven()) {
                // `λ(h : ¬X). h p` (in the irrelevant slot)
                let not_x = mk::pi("x", Rel::Rel, x.clone(), mk::ind(self.env.empty_ind(), vec![]));
                return Ok(mk::lam("h", Rel::Rel, not_x, mk::app(mk::var(0), shift(&p, 1))));
            }
            self.obligations.truncate(no);
            self.diags.list.truncate(nd);
            self.f.failed = failed0;
        }
        let (no, nd) = (self.obligations.len(), self.diags.list.len());
        let p = self.prove(ObligationKind::TypeInvariant, span, target, false)?;
        let failed = self.obligations[no..].iter().any(|o| !o.proven());
        // the goal in the invariant's own terms (the definition unfolded)
        let shown = failed.then(|| {
            let mut t = target.clone();
            if let Some(part) = owner.and_then(|o| self.s1.s2.invariants.get(&o)).and_then(|ps| ps.get(k))
                && let Some(g) = part.def
                && let Some(u) = super::tm::unfold_syntactic(&self.env, &t, g)
            {
                t = u;
            }
            self.show_tm(&super::tm::simp_redexes(&t))
        });
        if failed && let Some(d) = self.diags.list.get_mut(nd) {
            if let (Some(sh), Some(goal)) = (shown, d.goal.as_mut()) {
                let rest: String = goal.lines().skip(1).map(|l| format!("\n{l}")).collect();
                *goal = format!("goal: {sh}{rest}");
            }
            let part = owner.and_then(|o| self.s1.s2.invariants.get(&o)).and_then(|ps| ps.get(k)).cloned();
            let tname = owner.map(|o| self.krate.item(o).name.clone()).unwrap_or_else(|| "the type".into());
            match part {
                Some(p) if p.def.is_some() => {
                    d.notes.push((Some(p.span), format!("a value of `{tname}` can only be built where its invariant holds (the invariant is part of the type, DESIGN.md §15.3)")));
                    d.notes.push((None, format!("check the value first (e.g. a constructor `{tname}::new(..) -> Option<{tname}>` that tests it), or keep the parts in separate locals while the invariant is broken")));
                }
                Some(p) => d.notes.push((Some(p.span), format!("{}: the value must be provably non-negative here", p.what))),
                None => d.notes.push((None, format!("a value of `{tname}` can only be built where its invariant holds (DESIGN.md §15.3)"))),
            }
        }
        Ok(p)
    }

    // ------------------------------------------------------------------
    // view injectivity and Abstract(T) (§15.2, §15.3)
    // ------------------------------------------------------------------

    /// `T::view_inj : Π(T..)(a b : T)(h : Eq(V, T::view a, T::view b)).
    /// Eq(T, a, b)` (`ObligationKind::ViewInjective`) for the `#[view(|s|
    /// e)]` of type `id` (a structural view is injective by construction).
    /// Proven: the view counts as injective (refinements through it
    /// determine and establish their functions, DESIGN.md §15.2). Not
    /// proven: for a public type (reachable from the root) that is not
    /// `Abstract(T)` it is an error — host code could observe what the view
    /// hides ("a lossy view on a public type without `view_inj`"); for any
    /// other type the view is lossy (refinements through it are "up to
    /// view", or determine through `Abstract(T)`) and the failed attempt
    /// leaves no trace.
    pub fn view_injectivity(&mut self, id: ItemId) {
        if !self.s1.on {
            return;
        }
        let Some(info) = self.s1.views.get(&id).cloned() else { return };
        if info.injective {
            return;
        }
        let krate = self.krate;
        // a `#[proof(view_inj = T)]` item proves it when it is reached
        // ([`Elab::view_inj_proof_item`])
        if view_inj_proof_of(krate, id).is_some() {
            return;
        }
        let it = krate.item(id);
        let span = match &it.kind {
            ItemKind::Struct(s) => s.view.as_ref().map(|v| v.span()),
            ItemKind::Enum(e) => e.view.as_ref().map(|v| v.span()),
            _ => None,
        }
        .unwrap_or(it.span);
        let reasons = crate::validate::abstract_reasons(krate, id, false);
        let strict = krate.reachable.contains(&id) && !reasons.is_empty();
        let r = self.view_inj_lemma(id, &info, strict, span);
        match &r {
            Ok(_) => {
                if let Some(v) = self.s1.views.get_mut(&id) {
                    v.injective = true;
                }
            }
            Err(why) if strict => {
                let mut d = Diagnostic::error(DiagKind::ViewInjective, span, format!("the view of the public type `{}` is not proven injective, and `{}` is not `Abstract`", it.path, it.name))
                    .note(format!("`{}::view_inj : Π a b. view(a) == view(b) → a == b` did not prove: {why}", it.path))
                    .note("host code sees this type's values, so a view that forgets part of the value would let two implementations that agree on the view differ observably (DESIGN.md §15.2, §15.8: a lossy view hiding wrong output)");
                for x in &reasons {
                    d = d.note(format!("not `Abstract({})`: {x}", it.name));
                }
                d = d.note(format!("make the view injective (map every field), prove it with a `#[proof(view_inj = {})] fn ..(a: {n}, b: {n}) {{ .. }}` item in `PROOF.rs` (its steps show that the view determines every field), or make the type `Abstract`: private fields, no derived `Debug`/`PartialEq`, and `#[refines]` through the view on every boundary function that takes or returns it (DESIGN.md §15.3)", it.name, n = it.name));
                self.diag(d);
            }
            Err(_) => {}
        }
        self.s1.s2.view_inj.insert(id, r);
    }

    /// Builds and proves `T::view_inj` (see [`Elab::view_injectivity`]): a
    /// match on `a` and on `b`; different constructors contradict `h`, equal
    /// ones rebuild `a = b` from the field equations the prover derives from
    /// `h` ([`Elab::ctor_congruence`]). With `strict` unset a failure is
    /// rolled back (no obligation or diagnostic remains).
    fn view_inj_lemma(&mut self, id: ItemId, info: &super::views::ViewInfo, strict: bool, span: Span) -> Result<GlobalId, String> {
        let (no, nd, ndefs) = (self.obligations.len(), self.diags.list.len(), self.defs.len());
        let r = self.view_inj_build(id, info, None, span);
        let failed = r.is_err() || self.obligations[no..].iter().any(|o| !o.proven());
        if failed {
            if !strict {
                self.obligations.truncate(no);
                self.diags.list.truncate(nd);
                self.defs.truncate(ndefs);
            }
            return Err(match r {
                Err(e) => e.msg,
                Ok(_) => "a field is not determined by the view (see the unproven obligations)".into(),
            });
        }
        r.map_err(|e| e.msg)
    }

    /// With `fields_lemma` (`T::view_inj_fields`, from a `#[proof(view_inj
    /// = T)]` item; structs only) the field equations are its projections
    /// instead of prover obligations.
    fn view_inj_build(&mut self, id: ItemId, info: &super::views::ViewInfo, fields_lemma: Option<GlobalId>, span: Span) -> R<GlobalId> {
        let krate = self.krate;
        let it = krate.item(id);
        let name = format!("{}::view_inj", it.path);
        // the fields the view does not determine / pairs of variants it
        // does not distinguish (for the diagnostic)
        let mut undetermined: Vec<String> = Vec::new();
        let generics: Vec<TyParam> = match &it.kind {
            ItemKind::Struct(s) => s.generics.clone(),
            ItemKind::Enum(e) => e.generics.clone(),
            _ => return super::internal(span, "a view on a non-type"),
        };
        let ind = self.adt(id, span)?;
        self.f = FnState::new(name.clone(), Some(id), &[], span);
        self.f.mode = Mode::Proof;
        let mut binders = Vec::new();
        for g in &generics {
            self.push(&g.name, Rel::Rel, &mk::ty(), None)?;
            binders.push(TBinder { name: g.name.clone(), rel: Rel::Rel, ty: mk::ty() });
        }
        let ngen = generics.len() as u32;
        self.f.ngen = ngen;
        let self_ty = Ty::Adt(id, generics.iter().enumerate().map(|(i, g)| Ty::Param(i as u32, g.name.clone())).collect());
        // `T` and the view type at the current depth
        let sty = |me: &Self| me.ty(&self_ty, span);
        let vty = |me: &Self| me.ty(&info.target, span);
        // the type parameters at the current depth
        let pv = |me: &Self| -> Vec<Tm> { (0..ngen).map(|i| me.f.scope.var(i)).collect() };
        // `T::view T.. x` (x at the current depth)
        let view_app = |me: &Self, x: Tm| -> Tm {
            let mut args: Vec<(Rel, Tm)> = pv(me).into_iter().map(|p| (Rel::Rel, p)).collect();
            args.push((Rel::Rel, x));
            mk::apps(mk::global(info.global), args)
        };
        let st_a = sty(self)?;
        let la = self.push("a", Rel::Rel, &st_a, None)?;
        let st_b = sty(self)?;
        let lb = self.push("b", Rel::Rel, &st_b, None)?;
        let hty = mk::eq(vty(self)?, view_app(self, self.f.scope.var(la)), view_app(self, self.f.scope.var(lb)));
        binders.push(TBinder { name: "a".into(), rel: Rel::Rel, ty: st_a });
        binders.push(TBinder { name: "b".into(), rel: Rel::Rel, ty: st_b });
        binders.push(TBinder { name: "h".into(), rel: Rel::Rel, ty: hty.clone() });
        let lh = self.push_fact_rel("h", Rel::Rel, &hty, None, FactOrigin::LemmaHyp, span)?;
        let goal = mk::eq(sty(self)?, self.f.scope.var(la), self.f.scope.var(lb));
        let decl = self.env.inductive_decl(ind).ok_or_else(|| ElabError { span, msg: "unknown inductive".into(), kind: ErrKind::Internal })?;
        // outer match on `a` (at the depth after `h`): arms `λh. inner h`
        let mut outer_arms = Vec::new();
        for (ci, c) in decl.ctors.iter().enumerate() {
            let saved = self.f.scope.clone();
            let r = (|| -> R<Tm> {
                let ps = pv(self);
                let xs = self.push_ctor_fields(ind, ci, &ps, Some((id, "a")))?;
                self.irr_field_hints(&xs);
                let d = self.depth();
                let ca = mk::ctor(ind, ci as u32, pv(self), xs.iter().map(|l| self.f.scope.var(*l)).collect());
                let mut inner_arms = Vec::new();
                for (cj, c2) in decl.ctors.iter().enumerate() {
                    let saved2 = self.f.scope.clone();
                    let r2 = (|| -> R<Tm> {
                        let ps2 = pv(self);
                        let ys = self.push_ctor_fields(ind, cj, &ps2, Some((id, "b")))?;
                        self.irr_field_hints(&ys);
                        let ca2 = mk::ctor(ind, ci as u32, pv(self), xs.iter().map(|l| self.f.scope.var(*l)).collect());
                        let cb = mk::ctor(ind, cj as u32, pv(self), ys.iter().map(|l| self.f.scope.var(*l)).collect());
                        let h2ty = mk::eq(vty(self)?, view_app(self, ca2.clone()), view_app(self, cb.clone()));
                        let lh2 = self.push_fact_rel("h", Rel::Rel, &h2ty, None, FactOrigin::LemmaHyp, span)?;
                        let target = mk::eq(sty(self)?, shift(&ca2, 1), shift(&cb, 1));
                        let body = if ci != cj {
                            let empty = mk::ind(self.p.empty, vec![]);
                            let no = self.obligations.len();
                            let pf = self.prove(ObligationKind::ViewInjective, span, &empty, true)?;
                            if self.obligations[no..].iter().any(|o| !o.proven()) {
                                let vn = |k: usize| variant_name(krate, id, k);
                                undetermined.push(format!("the variants `{}` and `{}`", vn(ci), vn(cj)));
                            }
                            Rc::new(Term::Absurd { ty: target, proof: pf })
                        } else {
                            let nrel = c.fields.iter().filter(|f| f.1 == Rel::Rel).count();
                            let args_now: Vec<Tm> = pv(self);
                            let mut eqs = Vec::new();
                            // the proof item's lemma, applied to the two values
                            // (its field equations reduce to the arm's)
                            let lemma_app = fields_lemma.map(|l| {
                                let mut a: Vec<(Rel, Tm)> = args_now.iter().map(|p| (Rel::Rel, p.clone())).collect();
                                a.extend([(Rel::Rel, shift(&ca2, 1)), (Rel::Rel, shift(&cb, 1)), (Rel::Rel, self.f.scope.var(lh2))]);
                                mk::apps(mk::global(l), a)
                            });
                            for k in 0..nrel {
                                if let Some(app) = &lemma_app {
                                    let mut x = app.clone();
                                    for _ in 0..k {
                                        x = mk::snd(x);
                                    }
                                    eqs.push(mk::fst(x));
                                    continue;
                                }
                                let mut targs = args_now.clone();
                                targs.extend(xs[..k].iter().map(|l| self.f.scope.var(*l)));
                                let fty = super::tm::subst_closed(&c.fields[k].2, &targs);
                                let g = mk::eq(fty, self.f.scope.var(xs[k]), self.f.scope.var(ys[k]));
                                let no = self.obligations.len();
                                eqs.push(self.prove(ObligationKind::ViewInjective, span, &g, true)?);
                                if self.obligations[no..].iter().any(|o| !o.proven()) {
                                    let fname = self.f.scope.names().get(xs[k] as usize).map(|n| n.trim_start_matches("a.").to_string()).unwrap_or_else(|| k.to_string());
                                    undetermined.push(format!("the field `{fname}`"));
                                }
                            }
                            let v = |ls: &[u32], me: &Self| -> Vec<Tm> { ls.iter().map(|l| me.f.scope.var(*l)).collect() };
                            let (xv, yv, pvx, pvy) = (v(&xs[..nrel], self), v(&ys[..nrel], self), v(&xs[nrel..], self), v(&ys[nrel..], self));
                            self.ctor_congruence(ind, ci as u32, &args_now, &xv, &yv, &pvx, &pvy, &eqs, span)?
                        };
                        Ok(mk::lam("h", Rel::Rel, h2ty, body))
                    })();
                    self.f.scope = saved2;
                    inner_arms.push(Arm { names: c2.fields.iter().map(|f| f.0.clone()).collect(), body: r2? });
                }
                // the inner motive at depth d + 1 (`b'` = Var(0)):
                // `Π(h : view (C x̄) = view b'). C x̄ = b'`
                let (vt_d, st_d, ps_d) = (vty(self)?, sty(self)?, pv(self));
                let view_of = |x: Tm, sh: i64| -> Tm {
                    let mut args: Vec<(Rel, Tm)> = ps_d.iter().map(|p| (Rel::Rel, shift(p, sh))).collect();
                    args.push((Rel::Rel, x));
                    mk::apps(mk::global(info.global), args)
                };
                let inner_motive = mk::pi("h", Rel::Rel, mk::eq(shift(&vt_d, 1), view_of(shift(&ca, 1), 1), view_of(mk::var(0), 1)), mk::eq(shift(&st_d, 2), shift(&ca, 2), mk::var(1)));
                let inner = Rc::new(Term::Match { ind, params: ps_d.clone(), scrut: self.f.scope.var(lb), motive: inner_motive, arms: inner_arms });
                let _ = d;
                let h1 = mk::eq(vt_d.clone(), view_app(self, ca.clone()), view_app(self, self.f.scope.var(lb)));
                Ok(mk::lam("h", Rel::Rel, h1, mk::app(shift(&inner, 1), mk::var(0))))
            })();
            self.f.scope = saved;
            outer_arms.push(Arm { names: c.fields.iter().map(|f| f.0.clone()).collect(), body: r? });
        }
        // the outer motive at depth d + 1 (`a'` = Var(0)):
        // `Π(h : view a' = view b). a' = b`, applied to `h`
        let (vt_d, st_d, ps_d) = (vty(self)?, sty(self)?, pv(self));
        let d = self.depth();
        let view_of = |x: Tm, sh: i64| -> Tm {
            let mut args: Vec<(Rel, Tm)> = ps_d.iter().map(|p| (Rel::Rel, shift(p, sh))).collect();
            args.push((Rel::Rel, x));
            mk::apps(mk::global(info.global), args)
        };
        let b_at = |depth: u32| mk::var(depth - 1 - lb);
        let outer_motive = mk::pi("h", Rel::Rel, mk::eq(shift(&vt_d, 1), view_of(mk::var(0), 1), view_of(b_at(d + 1), 1)), mk::eq(shift(&st_d, 2), mk::var(1), b_at(d + 2)));
        let outer = Rc::new(Term::Match { ind, params: ps_d.clone(), scrut: self.f.scope.var(la), motive: outer_motive, arms: outer_arms });
        let proof = mk::app(outer, self.f.scope.var(lh));
        let ty = pi_tele(&binders, goal);
        let lam = lam_tele(&binders, proof);
        let arity = binders.len() as u32;
        if self.f.failed {
            let msg = if undetermined.is_empty() { "a field is not determined by the view".to_string() } else { format!("the view does not determine {}", undetermined.join(", ")) };
            return Err(ElabError { span, msg, kind: ErrKind::Blocked });
        }
        self.add_definition(&name, DefKind::Lemma, Some(id), ty, lam, Recursion::None, arity, false, false, span)
    }

    /// The `Irr` fields among the arm binders `ls` (an invariant's proofs):
    /// promoted, they are hints of the proof slots (`Scope::hint_facts`),
    /// so `view_inj` may use the invariant (e.g. a field determined by
    /// another through it).
    fn irr_field_hints(&mut self, ls: &[u32]) {
        let d = self.depth();
        for &l in ls {
            let e = &self.f.scope.ctx.entries[l as usize];
            if e.rel != Rel::Irr {
                continue;
            }
            // the entry's type lives in the context before it (depth `l`)
            let ty = shift(&self.env.quote(sandblaster_kernel::term::Lvl(l), &e.ty, true), (d - l) as i64);
            let v = self.f.scope.var(l);
            if let Some(pf) = self.promote_irr(&ty, &v, 16) {
                self.f.scope.hint_facts.push(super::scope::HintFact { ty: Val::new(ty, d), proof: Val::new(pf, d), name: "h_inv", origin: FactOrigin::TypeBound });
            }
        }
    }

    /// Pushes the fields of constructor `ci` of `ind` (arm binders, types by
    /// substitution with `params`, terms at the depth before the push);
    /// returns their levels. With `named = (T, v)` the binders are named
    /// after `T`'s fields, `v.x` (so goals over two values read clearly).
    fn push_ctor_fields(&mut self, ind: IndId, ci: usize, params: &[Tm], named: Option<(ItemId, &str)>) -> R<Vec<u32>> {
        let span = self.f.span;
        let decl = self.env.inductive_decl(ind).ok_or_else(|| ElabError { span, msg: "unknown inductive".into(), kind: ErrKind::Internal })?;
        let d0 = self.depth();
        let hir_names: Vec<String> = match named.map(|(id, _)| &self.krate.item(id).kind) {
            Some(ItemKind::Struct(s)) => s.fields.iter().enumerate().map(|(j, f)| f.name.clone().unwrap_or_else(|| j.to_string())).collect(),
            Some(ItemKind::Enum(e)) => e.variants.get(ci).map(|v| v.fields.iter().enumerate().map(|(j, f)| f.name.clone().unwrap_or_else(|| j.to_string())).collect()).unwrap_or_default(),
            _ => vec![],
        };
        let mut out: Vec<u32> = Vec::new();
        for (j, (fname, r, fty)) in decl.ctors[ci].fields.iter().enumerate() {
            let sh = (self.depth() - d0) as i64;
            let mut args: Vec<Tm> = params.iter().map(|p| shift(p, sh)).collect();
            args.extend(out.iter().map(|l| self.f.scope.var(*l)));
            let t = super::tm::subst_closed(fty, &args);
            let name = match (named, hir_names.get(j)) {
                (Some((_, v)), Some(n)) => format!("{v}.{n}"),
                (Some((_, v)), None) => format!("{v}.{fname}"),
                _ => fname.to_string(),
            };
            out.push(self.push(&name, *r, &t, None)?);
        }
        Ok(out)
    }

    /// `T::view_inj` from the `#[proof(view_inj = T)]` item `pid` (DESIGN.md
    /// §15.2, S2): its steps prove the lemma
    ///
    /// ```text
    /// T::view_inj_fields : Π(T..)(a b : T)(h : Eq(V, T::view a, T::view b)).
    ///                      Σ(_ : Eq(F₀, π₀ a, π₀ b)) … Unit
    /// ```
    ///
    /// (one equation per field; the invariants of `a` and `b` are facts),
    /// and `T::view_inj` rebuilds `a = b` from it. A failure is an error
    /// (the item claims the view is injective).
    pub fn view_inj_proof_item(&mut self, pid: ItemId, pf: &'a FnDef, target: ItemId) {
        let krate = self.krate;
        let span = krate.item(pid).span;
        let tpath = krate.item(target).path.to_string();
        let Some(info) = self.s1.views.get(&target).cloned() else {
            self.diag(Diagnostic::error(DiagKind::ViewInjective, span, format!("`#[proof(view_inj = ..)]` names `{tpath}`, whose view did not elaborate")));
            return;
        };
        let no = self.obligations.len();
        let r = self.view_inj_fields_lemma(pid, pf, target, &info, span).and_then(|l| self.view_inj_build(target, &info, Some(l), span));
        let failed = r.is_err() || self.obligations[no..].iter().any(|o| !o.proven());
        match r {
            Ok(g) if !failed => {
                if let Some(v) = self.s1.views.get_mut(&target) {
                    v.injective = true;
                }
                self.s1.s2.view_inj.insert(target, Ok(g));
            }
            r => {
                let why = match &r {
                    Err(e) => e.msg.clone(),
                    Ok(_) => "a step is unproven (see above)".into(),
                };
                self.diag(
                    Diagnostic::error(DiagKind::ViewInjective, span, format!("`{}` does not prove the view of `{tpath}` injective: {why}", krate.item(pid).path))
                        .note("its steps must show that the view determines every field: each `a.f == b.f` follows from `view(a) == view(b)` (and the invariants of `a` and `b`) (DESIGN.md §15.2)"),
                );
                self.s1.s2.view_inj.insert(target, Err(why));
            }
        }
    }

    fn view_inj_fields_lemma(&mut self, pid: ItemId, pf: &'a FnDef, target: ItemId, info: &super::views::ViewInfo, span: Span) -> R<GlobalId> {
        let krate = self.krate;
        let it = krate.item(target);
        let ItemKind::Struct(s) = &it.kind else { return super::unsupported(span, "`#[proof(view_inj = ..)]` is for structs (an enum's view is proven automatically)") };
        let crate::hir::FnBody::Script(steps) = &pf.body else { return super::internal(span, "a proof item without steps") };
        let name = format!("{}::view_inj_fields", it.path);
        let ind = self.adt(target, span)?;
        self.f = FnState::new(name.clone(), Some(pid), &pf.locals, span);
        self.f.fdef = Some(pf);
        self.f.mode = Mode::Proof;
        let mut binders = Vec::new();
        for g in &s.generics {
            self.push(&g.name, Rel::Rel, &mk::ty(), None)?;
            binders.push(TBinder { name: g.name.clone(), rel: Rel::Rel, ty: mk::ty() });
        }
        let ngen = s.generics.len() as u32;
        self.f.ngen = ngen;
        let self_ty = Ty::Adt(target, s.generics.iter().enumerate().map(|(i, g)| Ty::Param(i as u32, g.name.clone())).collect());
        let pv = |me: &Self| -> Vec<Tm> { (0..ngen).map(|i| me.f.scope.var(i)).collect() };
        let view_app = |me: &Self, x: Tm| -> Tm {
            let mut args: Vec<(Rel, Tm)> = pv(me).into_iter().map(|p| (Rel::Rel, p)).collect();
            args.push((Rel::Rel, x));
            mk::apps(mk::global(info.global), args)
        };
        let mut lv = Vec::new();
        for (i, p) in pf.params.iter().enumerate() {
            let st = self.ty(&self_ty, span)?;
            let n = match &p.pat.kind {
                PatKind::Binding { local, .. } => pf.locals.get(local.0 as usize).map(|d| d.name.clone()).unwrap_or_else(|| ["a", "b"][i.min(1)].into()),
                _ => ["a", "b"][i.min(1)].into(),
            };
            let l = self.push(&n, Rel::Rel, &st, None)?;
            if let PatKind::Binding { local, .. } = &p.pat.kind {
                self.f.scope.locals.insert(*local, l);
            }
            binders.push(TBinder { name: n, rel: Rel::Rel, ty: st });
            lv.push(l);
        }
        let (la, lb) = match lv.as_slice() {
            [a, b] => (*a, *b),
            _ => return super::unsupported(span, "a `#[proof(view_inj = T)]` item has two parameters `(a: T, b: T)`"),
        };
        let vty = self.ty(&info.target, span)?;
        let hty = mk::eq(vty, view_app(self, self.f.scope.var(la)), view_app(self, self.f.scope.var(lb)));
        self.push_fact_rel("h", Rel::Rel, &hty, None, FactOrigin::LemmaHyp, span)?;
        binders.push(TBinder { name: "h".into(), rel: Rel::Rel, ty: hty });
        // the goal: one equation per (relevant) field
        let decl = self.env.inductive_decl(ind).ok_or_else(|| ElabError { span, msg: "unknown inductive".into(), kind: ErrKind::Internal })?;
        let c = decl.ctors[0].clone();
        let nfields = c.fields.len();
        let params = pv(self);
        let mut eqs = Vec::new();
        for (k, (_, r, fty)) in c.fields.iter().enumerate() {
            if *r != Rel::Rel {
                continue;
            }
            let fty = super::tm::subst_closed(fty, &params);
            let pa = self.proj(ind, params.clone(), self.f.scope.var(la), k, nfields, fty.clone());
            let pb = self.proj(ind, params.clone(), self.f.scope.var(lb), k, nfields, fty.clone());
            eqs.push(mk::eq(fty, pa, pb));
        }
        let mut goal = mk::ind(self.p.unit, vec![]);
        for (k, e) in eqs.iter().enumerate().rev() {
            goal = mk::sigma(&format!("e{k}"), Rel::Rel, e.clone(), shift(&goal, 1));
        }
        let arity = self.depth();
        let gv = Val::new(goal.clone(), arity);
        // the invariants of `a` and `b` are facts (laws and lemmas over an
        // invariant type gain it, §15.3)
        let body = self.param_inv_facts(pf, 0, span, &mut |s| s.script(steps, gv.clone(), ObligationKind::ViewInjective, span))?;
        let ty = pi_tele(&binders, goal);
        let lam = lam_tele(&binders, body);
        let failed = self.f.failed;
        let g = self.add_definition(&name, DefKind::Lemma, Some(target), ty, lam, Recursion::None, arity, false, failed, span)?;
        if failed {
            return Err(ElabError { span, msg: "a step is unproven (see above)".into(), kind: ErrKind::Blocked });
        }
        Ok(g)
    }

    /// The determinacy verdict of simulation-form refinements (§15.3, run
    /// once after every item): a method of a `#[represents]` struct `S`
    /// determines its function when `S` is `Abstract(S)` and some
    /// constructor-like method of `S` establishes the relation (a checked
    /// refinement); otherwise the record keeps its "up to" reason. A struct
    /// with a representation relation that is not `Abstract` is an error
    /// ("`S` must be `Abstract`", DESIGN.md §15.3).
    pub fn s2_post_pass(&mut self) {
        if !self.s1.on {
            return;
        }
        let krate = self.krate;
        for it in &krate.items {
            let ItemKind::Struct(s) = &it.kind else { continue };
            let Some(rep) = &s.represents else { continue };
            let reasons = crate::validate::abstract_reasons(krate, it.id, false);
            if !reasons.is_empty() {
                let mut d = Diagnostic::error(DiagKind::Invariant, rep.span, format!("`{}` has a representation relation, so it must be `Abstract({})`", it.path, it.name))
                    .note("its abstract state is not computable from the representation, so only an abstract type keeps host code from observing the difference between two representations of one state (DESIGN.md §15.3)");
                for x in reasons {
                    d = d.note(format!("not `Abstract({})`: {x}", it.name));
                }
                self.diag(d);
                continue;
            }
            let owner_of = |r: &super::refines::RefinesRecord| krate.fn_def(r.item).and_then(|f| f.owner);
            let Some(ctor) = self.s1.refinements.iter().find(|r| owner_of(r) == Some(it.id) && r.form == super::refines::RefinesForm::RepConstructor && r.status == super::DefStatus::Checked).map(|r| krate.item(r.item).path.to_string()) else {
                continue;
            };
            for r in self.s1.refinements.iter_mut() {
                if owner_of(r) == Some(it.id) && r.form != super::refines::RefinesForm::Plain && !r.domain && r.up_to.as_deref().is_some_and(|u| u.contains("representation relation")) {
                    r.up_to = None;
                    r.determined_by = Some(format!("`Abstract({})` and its representation relation, established by `{ctor}`: determined up to the relation; not established", it.name));
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // ghost parameters (§15.3)
    // ------------------------------------------------------------------

    /// The ghost bundle of exec function `f` (after its other parameters,
    /// DESIGN.md §15.3): one binder
    ///
    /// ```text
    /// ghost : Σ(g₁ : T₁) … (gₙ : Tₙ). R₁ × … × Rₘ × Unit
    /// ```
    ///
    /// holding its `#[ghost]` parameters and the `requires` `Rⱼ` that
    /// mention them — `Irr` in the function (a ghost value never reaches the
    /// compiled code; every type position being relevant, the requires over
    /// it cannot be separate binders, §5.3), relevant in the function's
    /// lemmas (proof mode). The ghost locals are the projections; the
    /// requires are facts of the prover (`Scope::hint_facts`).
    pub fn ghost_bundle(&mut self, f: &'a FnDef, binders: &mut Vec<TBinder>, span: Span) -> R<()> {
        let ghosts: Vec<&'a Param> = f.params.iter().filter(|p| p.ghost).collect();
        let greq = ghost_requires(f);
        let base = self.depth();
        let saved = self.f.scope.clone();
        let mut comps: Vec<(String, Tm)> = Vec::new();
        let mut ghost_ids = Vec::new();
        let elab = (|| -> R<()> {
            for (i, p) in ghosts.iter().enumerate() {
                let PatKind::Binding { local, sub: None, .. } = &p.pat.kind else {
                    return Err(ElabError { span: p.span, msg: "a `#[ghost]` parameter is a plain name".into(), kind: ErrKind::Unsupported });
                };
                let ty = self.ty(&p.ty, span)?;
                let name = f.locals.get(local.0 as usize).map(|d| d.name.clone()).unwrap_or_else(|| format!("ghost{i}"));
                let lvl = self.push(&name, Rel::Rel, &ty, None)?;
                self.f.scope.locals.insert(*local, lvl);
                ghost_ids.push(*local);
                comps.push((name, ty));
            }
            for &j in &greq {
                let pr = self.prop(&f.requires[j])?;
                self.push("h_req", Rel::Rel, &pr, None)?;
                comps.push((format!("h_req{j}"), pr));
            }
            Ok(())
        })();
        self.f.scope = saved;
        elab?;
        let mut t = mk::ind(self.p.unit, vec![]);
        for (name, ty) in comps.iter().rev() {
            t = mk::sigma(name, Rel::Rel, ty.clone(), t);
        }
        let rel = if self.f.mode == Mode::Exec { Rel::Irr } else { Rel::Rel };
        self.push("ghost", rel, &t, None)?;
        binders.push(TBinder { name: "ghost".into(), rel, ty: t });
        let d = self.depth();
        let proj = |k: usize| -> Tm {
            let mut x = mk::var(0);
            for _ in 0..k {
                x = mk::snd(x);
            }
            mk::fst(x)
        };
        for (i, l) in ghost_ids.iter().enumerate() {
            self.f.scope.ghost_locals.insert(*l, Val::new(proj(i), d));
        }
        for (m, _) in greq.iter().enumerate() {
            let k = ghosts.len() + m;
            let ty = replace_levels(&comps[k].1, base + k as u32, base, &proj, d);
            self.f.scope.hint_facts.push(super::scope::HintFact { ty: Val::new(ty, d), proof: Val::new(proj(k), d), name: "h_ghost", origin: FactOrigin::Requires });
        }
        Ok(())
    }

    /// The ghost bundle argument of a call (see [`Elab::ghost_bundle`]):
    /// nested pairs of the ghost values `vals` (terms at the current depth)
    /// and proofs of the callee's ghost `requires` (obligations, `kind`),
    /// for the bundle type `ty` (instantiated at the call).
    pub fn ghost_bundle_arg(&mut self, ty: &Tm, vals: &[Tm], kind: ObligationKind, span: Span) -> R<Tm> {
        match &**ty {
            Term::Sigma { fst, snd, .. } => {
                let (v, rest) = match vals.split_first() {
                    Some((v, rest)) => (v.clone(), rest),
                    None => (self.prove(kind.clone(), span, fst, false)?, vals),
                };
                let inner_ty = super::tm::subst0(snd, &v);
                let inner = self.ghost_bundle_arg(&inner_ty, rest, kind, span)?;
                Ok(mk::pair(ty.clone(), v, inner))
            }
            _ => Ok(self.unit_val()),
        }
    }

    // ------------------------------------------------------------------
    // §15 hooks
    // ------------------------------------------------------------------

    /// `#[invariant(..)]` on struct `id` (after every item): the invariant
    /// is already part of the kernel type (`declare_adt`); nothing is left
    /// to do here.
    pub fn invariant_hook(&mut self, _id: ItemId, _inv: &TypeInvariant) {}

    /// `#[ghost]` parameters of exec function `id` (after every item): they
    /// are `Irr` Π binders of the function (`items::fn_params`); nothing is
    /// left to do here.
    pub fn ghost_params_hook(&mut self, _id: ItemId) {}
}


/// The `requires` of `f` (indices) that mention one of its `#[ghost]`
/// parameters: they belong to the ghost bundle ([`Elab::ghost_bundle`]).
pub fn ghost_requires(f: &FnDef) -> Vec<usize> {
    let ghosts: Vec<LocalId> = f.params.iter().filter(|p| p.ghost).flat_map(|p| p.pat.bindings()).collect();
    if ghosts.is_empty() {
        return vec![];
    }
    struct V<'g>(&'g [LocalId], bool);
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Local(l) = &e.kind
                && self.0.contains(l)
            {
                self.1 = true;
            }
            crate::visit::walk_expr(self, e);
        }
    }
    f.requires
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            let mut v = V(&ghosts, false);
            crate::visit::Visitor::expr(&mut v, r);
            v.1
        })
        .map(|(i, _)| i)
        .collect()
}

/// `t` (a term at depth `from_depth`) with the levels `base..from_depth`
/// replaced by `repl(level - base)` (terms at depth `to_depth`) and the
/// levels below `base` kept, moved to depth `to_depth`.
fn replace_levels(t: &Tm, from_depth: u32, base: u32, repl: &dyn Fn(usize) -> Tm, to_depth: u32) -> Tm {
    use sandblaster_kernel::term::Idx;
    super::tm::map_post(t, 0, &mut |n, b| match &*n {
        Term::Var(Idx(i)) if *i >= b => {
            let lvl = from_depth - 1 - (*i - b);
            if lvl >= base { Some(shift(&repl((lvl - base) as usize), b as i64)) } else { Some(mk::var(to_depth - 1 - lvl + b)) }
        }
        _ => Some(n),
    })
    .expect("replace_levels")
}

/// The bases of the projections in `e` whose type has an invariant and
/// which are paths (`x`, `x.f`, through references), for
/// [`Elab::prebind_inv_facts`]; quantifier bodies are skipped (their locals
/// are not in scope).
fn collect_inv_bases(krate: &Crate, es: &[&Expr], steps: &[ScriptStmt]) -> Vec<Expr> {
    fn is_path(e: &Expr) -> bool {
        match &e.kind {
            ExprKind::Local(_) => true,
            ExprKind::Field { base, .. } | ExprKind::Ref(base) | ExprKind::Deref(base) => is_path(base),
            ExprKind::Coerce(Coercion::AutoRef | Coercion::AutoDeref, x) => is_path(x),
            _ => false,
        }
    }
    struct V<'k, 'o>(&'k Crate, &'o mut Vec<Expr>);
    impl crate::visit::Visitor for V<'_, '_> {
        fn expr(&mut self, e: &Expr) {
            match &e.kind {
                ExprKind::Quant { .. } => return,
                ExprKind::Field { base, .. } => {
                    if let Ty::Adt(id, _) = base.ty.peel_refs()
                        && matches!(&self.0.item(*id).kind, ItemKind::Struct(s) if has_irr_fields(s))
                        && is_path(base)
                    {
                        self.1.push((**base).clone());
                    }
                }
                _ => {}
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut out = Vec::new();
    let mut v = V(krate, &mut out);
    for e in es {
        crate::visit::Visitor::expr(&mut v, e);
    }
    for st in steps {
        crate::visit::Visitor::script(&mut v, st);
    }
    out
}

/// The `#[proof(view_inj = T)]` item of type `id`, if any.
pub fn view_inj_proof_of(krate: &Crate, id: ItemId) -> Option<ItemId> {
    krate.items.iter().find_map(|it| match &it.kind {
        ItemKind::Fn(f) if f.kind == FnKind::Proof && f.spec.proof_of.is_some_and(|p| p.kind == ProofKind::ViewInj && p.target == id) => Some(it.id),
        _ => None,
    })
}

/// The name of variant `k` of enum `id` (the type's name for a struct).
fn variant_name(krate: &Crate, id: ItemId, k: usize) -> String {
    match &krate.item(id).kind {
        ItemKind::Enum(e) => e.variants.get(k).map(|v| v.name.clone()).unwrap_or_else(|| k.to_string()),
        _ => krate.item(id).name.clone(),
    }
}
