//! Repair of quoted proofs (kernel `INTERFACE_CHANGES.md`: typed quoting
//! substitutes values into irrelevant proof closures, "automation must
//! re-prove such proof slots").
//!
//! A `linarith` certificate is positional (DESIGN.md §5.8: one multiplier
//! per constraint in canonical order). When a proof closure of a prelude
//! function is quoted after instantiation (e.g. the bound proof of
//! `slice::index` with `i := 3`, or `i := fst s`), atoms can disappear or
//! merge, and the stored certificate no longer matches the (smaller)
//! system, although the specialized system is still infeasible (a
//! refutation stays one under substitution). [`repair`] walks a term with its
//! local typing context and re-derives every `linarith` certificate that
//! does not match its system ([`super::simplex`]); everything else is
//! unchanged. It is applied to a motive that fails to type-check and to a
//! final proof that the kernel rejects, before giving up.
//!
//! [`repair_validated`] additionally re-proves **ill-typed proof slots**:
//! a proof *value* read back into a term is `refl(A, c)` whatever equation
//! it proved (the evaluator's canonical proof), so a proof of `c == true`
//! that was bound as a value (a relevant hypothesis binder, a path equation
//! instantiated out of its branch) reads back as `refl(Bool, c)`. Every
//! `refl` in a proof slot (an irrelevant argument, a relevant argument of
//! proposition type, a primitive's proof slot, a `linarith` hypothesis) is
//! checked against the slot's type; an ill-typed one is replaced by a proof
//! of the slot's proposition from the context (a fact by conversion, or
//! linarith over the context's arithmetic facts). The kernel checks the
//! result like any other term.

use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{Arm, Rel, Term, Tm};
use sandblaster_kernel::value::{Arg, Budget, EnvEntry, V, VEnv, Value};

use super::simplex;

struct Repair<'e, 'b> {
    env: &'e Env,
    b: &'b mut Budget,
    changed: usize,
    /// Whether a subterm (by `Rc` identity) contains anything to repair
    /// (`linarith` or `Erased`); subterms without are returned unchanged.
    needs: std::collections::HashMap<*const Term, bool>,
    /// Repaired subterms by (term, context) identity: shared subterms are
    /// repaired once per context (terms are DAGs; as trees they can be
    /// exponentially larger).
    memo: std::collections::HashMap<(*const Term, *const Vec<CtxEntry>), Tm>,
    /// Keeps the contexts used as memo keys alive (no address reuse).
    keep: Vec<Ctx>,
    /// Also check `refl` proof slots and `linarith` hypotheses against
    /// their types ([`repair_validated`]).
    validate: bool,
}

impl Repair<'_, '_> {
    fn needs(&mut self, t: &Tm) -> bool {
        let key = Rc::as_ptr(t);
        if let Some(r) = self.needs.get(&key) {
            return *r;
        }
        let r = match &**t {
            Term::Linarith { .. } | Term::Erased => true,
            Term::Refl { .. } if self.validate => true,
            _ => {
                let mut any = false;
                crate::elab::tm::children(t, &mut |c| {
                    if !any && self.needs(c) {
                        any = true;
                    }
                });
                any
            }
        };
        self.needs.insert(key, r);
        r
    }

    fn eval(&mut self, ctx: &Ctx, t: &Tm) -> Option<V> {
        self.env.eval(&self.env.ctx_venv(ctx), ctx.depth(), t, self.b).ok()
    }

    fn push(&mut self, ctx: &Ctx, name: &Rc<str>, rel: Rel, ty: Option<V>, def: Option<Arg>) -> Ctx {
        let ty = ty.unwrap_or_else(|| Rc::new(Value::Sort(sandblaster_kernel::term::Sort::Type)));
        ctx.push(CtxEntry { name: name.clone(), rel, ty, def })
    }

    /// Re-prove a proof slot's proposition: by reflexivity, or by linarith
    /// over the arithmetic facts (irrelevant binders) of `ctx`.
    fn reprove(&mut self, ctx: &Ctx, prop: &V) -> Option<Tm> {
        let depth = ctx.depth();
        if let Value::Eq { ty, lhs, rhs } = &**prop
            && self.env.conv(depth, lhs, rhs, self.b).unwrap_or(false)
        {
            let a = super::util::kernel_friendly(self.env, &self.env.quote_typed(ctx, ty, None, false));
            let x = super::util::kernel_friendly(self.env, &self.env.quote_typed(ctx, lhs, Some(ty), false));
            return (!has_erased(&a) && !has_erased(&x)).then(|| Rc::new(Term::Refl { ty: a, val: x }));
        }
        // the context's facts, with the conjuncts of conjunctions (`fst`/`snd`
        // projections): `(proof, type)`; an irrelevant position may use every
        // binder of the context when validating
        let mut facts: Vec<(Tm, V)> = Vec::new();
        for (l, e) in ctx.entries.iter().enumerate() {
            if e.rel == Rel::Irr || self.validate {
                self.conjuncts(ctx, super::util::var_at(depth.0, l as u32), e.ty.clone(), 0, &mut facts);
            }
        }
        if self.validate {
            // a context fact (or conjunct) of that type
            for (p, ty) in facts.iter().rev() {
                if matches!(&**ty, Value::Eq { .. }) && self.env.conv(depth, ty, prop, self.b).unwrap_or(false) {
                    return Some(p.clone());
                }
            }
        }
        let goal = super::util::kernel_friendly(self.env, &self.env.quote_typed(ctx, prop, None, false));
        if has_erased(&goal) {
            return None;
        }
        let bool_ind = self.env.bool_ind();
        let mut hyps = Vec::new();
        for (p, ty) in &facts {
            if lin_hyp_form(bool_ind, ty) {
                let stated = super::util::kernel_friendly(self.env, &self.env.quote_typed(ctx, ty, None, false));
                if !has_erased(&stated) {
                    hyps.push((p.clone(), stated));
                }
            }
        }
        let sys = self.env.linearize(ctx, &hyps, &goal, self.b).ok()?;
        let cert = simplex::certificate(&sys)?;
        Some(Rc::new(Term::Linarith { hyps, goal, cert }))
    }

    /// `p : ty` and, for a conjunction `Σ(h : A). B` of propositions, the
    /// conjuncts `fst(p) : A` and `snd(p) : B[fst(p)]`, recursively (at most
    /// 12 levels deep).
    fn conjuncts(&mut self, ctx: &Ctx, p: Tm, ty: V, depth: u32, out: &mut Vec<(Tm, V)>) {
        if let Value::Sigma { fst, snd, .. } = &*ty
            && depth < 12
            && matches!(&**fst, Value::Eq { .. } | Value::Sigma { .. })
        {
            let f = Rc::new(Term::Fst(p.clone()));
            let sd = Rc::new(Term::Snd(p.clone()));
            let fst_ty = fst.clone();
            let snd_ty = self.eval(ctx, &f).and_then(|fv| {
                let mut env = (*snd.env.0).clone();
                env.push(EnvEntry::Rel(fv));
                self.env.eval(&VEnv(Rc::new(env)), ctx.depth(), &snd.body, self.b).ok()
            });
            self.conjuncts(ctx, f, fst_ty, depth + 1, out);
            if let Some(t) = snd_ty {
                self.conjuncts(ctx, sd, t, depth + 1, out);
            }
            return;
        }
        out.push((p, ty));
    }

    fn go(&mut self, ctx: &Ctx, t: &Tm) -> Tm {
        if !self.needs(t) {
            return t.clone();
        }
        let key = (Rc::as_ptr(t), Rc::as_ptr(&ctx.entries));
        if let Some(r) = self.memo.get(&key) {
            return r.clone();
        }
        let r = self.go_node(ctx, t);
        self.keep.push(ctx.clone());
        self.memo.insert(key, r.clone());
        r
    }

    fn go_node(&mut self, ctx: &Ctx, t: &Tm) -> Tm {
        let node = match &**t {
            Term::Var(_) | Term::Global(_) | Term::Sort(_) | Term::IntTy(_) | Term::Lit { .. } | Term::Erased => return t.clone(),
            Term::Linarith { hyps, goal, cert } => {
                let mut hyps: Vec<(Tm, Tm)> = hyps.iter().map(|(p, s)| (self.go(ctx, p), self.go(ctx, s))).collect();
                let goal = self.go(ctx, goal);
                if self.validate {
                    // hypotheses whose proofs lost their stated type are
                    // dropped; the context's arithmetic facts replace them
                    let before = hyps.len();
                    hyps.retain(|(p, s)| self.slot_ok(ctx, p, s));
                    if hyps.len() < before {
                        self.changed += 1;
                        self.add_ctx_hyps(ctx, &mut hyps);
                    }
                }
                let cert = match self.env.linearize(ctx, &hyps, &goal, self.b) {
                    Ok(sys) => {
                        let total: usize = sys.problems.iter().map(|p| p.len()).sum();
                        let ok = total == cert.len() && {
                            let mut off = 0;
                            sys.problems.iter().all(|p| {
                                let c: Vec<super::rat::Q> =
                                    cert[off..off + p.len()].iter().map(|r| super::rat::Q::new(r.num.clone(), r.den.clone())).collect();
                                off += p.len();
                                simplex::verify(p, &c)
                            })
                        };
                        if ok {
                            cert.clone()
                        } else if let Some(c) = simplex::certificate(&sys) {
                            self.changed += 1;
                            c
                        } else {
                            cert.clone()
                        }
                    }
                    Err(_) => cert.clone(),
                };
                Term::Linarith { hyps, goal, cert }
            }
            Term::Pi { name, rel, dom, cod } => {
                let dom2 = self.go(ctx, dom);
                let ty = self.eval(ctx, &dom2);
                let c2 = self.push(ctx, name, *rel, ty, None);
                Term::Pi { name: name.clone(), rel: *rel, dom: dom2, cod: self.go(&c2, cod) }
            }
            Term::Lam { name, rel, dom, body } => {
                let dom2 = self.go(ctx, dom);
                let ty = self.eval(ctx, &dom2);
                let c2 = self.push(ctx, name, *rel, ty, None);
                Term::Lam { name: name.clone(), rel: *rel, dom: dom2, body: self.go(&c2, body) }
            }
            Term::Sigma { name, snd_rel, fst, snd } => {
                let fst2 = self.go(ctx, fst);
                let ty = self.eval(ctx, &fst2);
                let c2 = self.push(ctx, name, Rel::Rel, ty, None);
                Term::Sigma { name: name.clone(), snd_rel: *snd_rel, fst: fst2, snd: self.go(&c2, snd) }
            }
            Term::Let { name, rel, ty, val, body } => {
                let ty2 = self.go(ctx, ty);
                let val2 = self.go(ctx, val);
                let tyv = self.eval(ctx, &ty2);
                let def = if *rel == Rel::Rel { self.eval(ctx, &val2).map(Arg::Rel) } else { None };
                let c2 = self.push(ctx, name, *rel, tyv, def);
                Term::Let { name: name.clone(), rel: *rel, ty: ty2, val: val2, body: self.go(&c2, body) }
            }
            Term::Match { ind, params, scrut, motive, arms } => {
                let params2: Vec<Tm> = params.iter().map(|p| self.go(ctx, p)).collect();
                let scrut2 = self.go(ctx, scrut);
                let pvals: Option<Vec<V>> = params2.iter().map(|p| self.eval(ctx, p)).collect();
                let ind_ty = pvals.as_ref().map(|ps| Rc::new(Value::Ind { ind: *ind, params: ps.clone() }) as V);
                let cy = self.push(ctx, &Rc::from("y"), Rel::Rel, ind_ty, None);
                let motive2 = self.go(&cy, motive);
                let decl = self.env.inductive_decl(*ind);
                let mut arms2 = Vec::with_capacity(arms.len());
                for (k, a) in arms.iter().enumerate() {
                    let mut ca = ctx.clone();
                    let mut fenv: Vec<EnvEntry> = pvals.clone().unwrap_or_default().into_iter().map(EnvEntry::Rel).collect();
                    if let Some(c) = decl.as_ref().and_then(|d| d.ctors.get(k)) {
                        for (fname, frel, fty) in &c.fields {
                            let ftv = self.env.eval(&VEnv(Rc::new(fenv.clone())), ca.depth(), fty, self.b).ok();
                            let e = match &ftv {
                                Some(t) => self.env.fresh_var(ca.depth(), *frel, t),
                                None => EnvEntry::Rel(Rc::new(Value::Sort(sandblaster_kernel::term::Sort::Type))),
                            };
                            ca = self.push(&ca, fname, *frel, ftv, None);
                            fenv.push(e);
                        }
                    }
                    arms2.push(Arm { names: a.names.clone(), body: self.go(&ca, &a.body) });
                }
                Term::Match { ind: *ind, params: params2, scrut: scrut2, motive: motive2, arms: arms2 }
            }
            Term::Transport { ty, lhs, rhs, eq, motive, val } => {
                let ty2 = self.go(ctx, ty);
                let tyv = self.eval(ctx, &ty2);
                let cy = self.push(ctx, &Rc::from("y"), Rel::Rel, tyv.clone(), None);
                let (lhs2, rhs2) = (self.go(ctx, lhs), self.go(ctx, rhs));
                // the equation of a transport read back from a stuck value is
                // not stored (`Erased`, DESIGN.md §5.9): re-prove `Eq(ty,
                // lhs, rhs)` in its (irrelevant) slot — a context fact by
                // conversion, or linarith over every arithmetic binder
                let eq2 = if matches!(&**eq, Term::Erased) {
                    let prop = match (tyv, self.eval(ctx, &lhs2), self.eval(ctx, &rhs2)) {
                        (Some(ty), Some(lhs), Some(rhs)) => Some(Rc::new(Value::Eq { ty, lhs, rhs })),
                        _ => None,
                    };
                    let saved = std::mem::replace(&mut self.validate, true);
                    let has_prop = prop.is_some();
                    let q = prop.and_then(|p| self.reprove(ctx, &p));
                    self.validate = saved;
                    if q.is_none() && std::env::var_os("SANDBLASTER_TRACE_REPAIR").is_some() {
                        let names: Vec<sandblaster_kernel::term::Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
                        eprintln!("[repair] transport equation not re-proved (prop {has_prop}, depth {}): {} == {}", ctx.depth().0, sandblaster_kernel::syntax::printer::print_term_bounded(self.env, &names, &lhs2, 400), sandblaster_kernel::syntax::printer::print_term_bounded(self.env, &names, &rhs2, 200));
                    }
                    match q {
                        Some(q) => {
                            self.changed += 1;
                            q
                        }
                        None => eq.clone(),
                    }
                } else {
                    self.go(ctx, eq)
                };
                Term::Transport { ty: ty2, lhs: lhs2, rhs: rhs2, eq: eq2, motive: self.go(&cy, motive), val: self.go(ctx, val) }
            }
            Term::App { rel: Rel::Irr, fun, arg } if has_erased(arg) => {
                // A proof slot quoted with an `Erased` placeholder: re-prove
                // the slot's proposition (the function's Π domain).
                let fun2 = self.go(ctx, fun);
                let slot = self.env.infer(ctx, &fun2, self.b).ok();
                let proof = match slot.as_deref() {
                    Some(Value::Pi { rel: Rel::Irr, dom, .. }) => self.reprove(ctx, dom),
                    _ => None,
                };
                match proof {
                    Some(p) => {
                        self.changed += 1;
                        Term::App { rel: Rel::Irr, fun: fun2, arg: p }
                    }
                    None => Term::App { rel: Rel::Irr, fun: fun2, arg: self.go(ctx, arg) },
                }
            }
            Term::App { rel, fun, arg } if self.validate && matches!(&**arg, Term::Refl { .. }) => {
                // a `refl` proof slot: re-proved when it is ill-typed
                let fun2 = self.go(ctx, fun);
                let slot = self.env.infer(ctx, &fun2, self.b).ok();
                let fixed = match slot.as_deref() {
                    Some(Value::Pi { rel: prel, dom, .. })
                        if *prel == *rel && matches!(&**dom, Value::Eq { .. }) && !self.env.check(ctx, arg, dom, self.b).is_ok() =>
                    {
                        self.reprove(ctx, dom)
                    }
                    _ => None,
                };
                match fixed {
                    Some(p) => {
                        self.changed += 1;
                        Term::App { rel: *rel, fun: fun2, arg: p }
                    }
                    None => Term::App { rel: *rel, fun: fun2, arg: self.go(ctx, arg) },
                }
            }
            Term::App { rel, fun, arg } => Term::App { rel: *rel, fun: self.go(ctx, fun), arg: self.go(ctx, arg) },
            Term::Pair { ty, fst, snd } => Term::Pair { ty: self.go(ctx, ty), fst: self.go(ctx, fst), snd: self.go(ctx, snd) },
            Term::Fst(p) => Term::Fst(self.go(ctx, p)),
            Term::Snd(p) => Term::Snd(self.go(ctx, p)),
            Term::Eq { ty, lhs, rhs } => Term::Eq { ty: self.go(ctx, ty), lhs: self.go(ctx, lhs), rhs: self.go(ctx, rhs) },
            Term::Refl { ty, val } => Term::Refl { ty: self.go(ctx, ty), val: self.go(ctx, val) },
            Term::Ind { ind, params } => Term::Ind { ind: *ind, params: params.iter().map(|p| self.go(ctx, p)).collect() },
            Term::Ctor { ind, ctor, params, args } => Term::Ctor {
                ind: *ind,
                ctor: *ctor,
                params: params.iter().map(|p| self.go(ctx, p)).collect(),
                args: args.iter().map(|p| self.go(ctx, p)).collect(),
            },
            Term::Prim { op, args, proofs } => {
                let args2: Vec<Tm> = args.iter().map(|p| self.go(ctx, p)).collect();
                let obligations = sandblaster_kernel::prim::prim_obligations(*op, &args2, self.env.bool_ind());
                let mut proofs2 = Vec::with_capacity(proofs.len());
                for (i, p) in proofs.iter().enumerate() {
                    // Proof slots with `Erased` placeholders are re-proved,
                    // and (validating) ill-typed `refl` slots.
                    let re = if has_erased(p) {
                        obligations.get(i).and_then(|o| self.eval(ctx, o)).and_then(|o| self.reprove(ctx, &o))
                    } else if self.validate && matches!(&**p, Term::Refl { .. }) {
                        match obligations.get(i).and_then(|o| self.eval(ctx, o)) {
                            Some(o) if !self.env.check(ctx, p, &o, self.b).is_ok() => self.reprove(ctx, &o),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    match re {
                        Some(q) => {
                            self.changed += 1;
                            proofs2.push(q);
                        }
                        None => proofs2.push(self.go(ctx, p)),
                    }
                }
                Term::Prim { op: *op, args: args2, proofs: proofs2 }
            }
            Term::Rec { args, proof } => {
                Term::Rec { args: args.iter().map(|p| self.go(ctx, p)).collect(), proof: proof.as_ref().map(|p| self.go(ctx, p)) }
            }
            Term::Delta { def, args } => Term::Delta { def: *def, args: args.iter().map(|p| self.go(ctx, p)).collect() },
            Term::Unfold { def, args, to_body, val } => {
                Term::Unfold { def: *def, args: args.iter().map(|p| self.go(ctx, p)).collect(), to_body: *to_body, val: self.go(ctx, val) }
            }
            Term::BvRefl { ty, lhs, rhs } => Term::BvRefl { ty: self.go(ctx, ty), lhs: self.go(ctx, lhs), rhs: self.go(ctx, rhs) },
            Term::Absurd { ty, proof } => Term::Absurd { ty: self.go(ctx, ty), proof: self.go(ctx, proof) },
            Term::Axiom { ax, args } => Term::Axiom { ax: *ax, args: args.iter().map(|p| self.go(ctx, p)).collect() },
        };
        Rc::new(node)
    }
}

impl Repair<'_, '_> {
    /// Adds the arithmetic facts of `ctx` (every binder of a linarith
    /// hypothesis form; an irrelevant position may use all of them) to
    /// `hyps`.
    fn add_ctx_hyps(&mut self, ctx: &Ctx, hyps: &mut Vec<(Tm, Tm)>) {
        let bool_ind = self.env.bool_ind();
        let depth = ctx.depth();
        for (l, e) in ctx.entries.iter().enumerate() {
            if lin_hyp_form(bool_ind, &e.ty) {
                let idx = depth.0 - 1 - l as u32;
                if hyps.iter().any(|(p, _)| matches!(&**p, Term::Var(i) if i.0 == idx)) {
                    continue;
                }
                let v = super::util::var_at(depth.0, l as u32);
                let stated = super::util::kernel_friendly(self.env, &self.env.quote_typed(ctx, &e.ty, None, false));
                if !has_erased(&stated) {
                    hyps.push((v, stated));
                }
            }
        }
    }

    /// Whether the proof `p` has the stated type `s` (terms in `ctx`).
    fn slot_ok(&mut self, ctx: &Ctx, p: &Tm, s: &Tm) -> bool {
        match self.eval(ctx, s) {
            Some(sv) => self.env.check(ctx, p, &sv, self.b).is_ok(),
            None => false,
        }
    }
}

/// Re-derive the `linarith` certificates of `t` (a term in `ctx`) that do not
/// match their systems, charging `b`. Returns the repaired term and the
/// number of certificates changed.
pub fn repair(env: &Env, ctx: &Ctx, t: &Tm, b: &mut Budget) -> (Tm, usize) {
    let mut r = Repair { env, b, changed: 0, needs: Default::default(), memo: Default::default(), keep: Vec::new(), validate: false };
    let t2 = r.go(ctx, t);
    (t2, r.changed)
}

/// [`repair`], and re-prove the ill-typed proof slots of `t` (see the module
/// docs): for a proof the kernel rejected. Returns the repaired term and the
/// number of changes.
pub fn repair_validated(env: &Env, ctx: &Ctx, t: &Tm, b: &mut Budget) -> (Tm, usize) {
    let mut r = Repair { env, b, changed: 0, needs: Default::default(), memo: Default::default(), keep: Vec::new(), validate: true };
    let t2 = r.go(ctx, t);
    (t2, r.changed)
}

/// Does `t` contain a `linarith` term (anything [`repair`] could change)?
pub fn has_linarith(t: &Tm) -> bool {
    crate::elab::tm::any_node(t, &mut |x| matches!(x, Term::Linarith { .. }))
}

/// Does `t` contain an `Erased` placeholder?
pub fn has_erased(t: &Tm) -> bool {
    crate::elab::tm::any_node(t, &mut |x| matches!(x, Term::Erased))
}

/// Is `t` a (non-disjunctive) linarith hypothesis form (DESIGN.md §5.8)?
fn lin_hyp_form(bool_ind: sandblaster_kernel::term::IndId, t: &V) -> bool {
    use sandblaster_kernel::term::PrimOp;
    let Value::Eq { ty, lhs, rhs } = &**t else { return false };
    match &**ty {
        Value::IntTy(_) => true,
        Value::Ind { ind, .. } if *ind == bool_ind => {
            let Some(b) = super::util::bool_lit(bool_ind, rhs) else { return false };
            match super::util::as_prim(lhs) {
                Some((PrimOp::Eq(_), _)) => b,
                Some((PrimOp::Ne(_), _)) => !b,
                Some((op, _)) => super::util::cmp_width(op).is_some(),
                None => false,
            }
        }
        _ => false,
    }
}
