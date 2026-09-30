//! Re-certification of linear-arithmetic proofs (untrusted).
//!
//! Terms obtained by quoting values contain the *instantiated* irrelevant
//! proofs of unfolded definitions (e.g. the bound proofs inside
//! `slice::index` after `i := 0`). A `linarith` certificate is tied to the
//! linear structure of its hypotheses and goal *after evaluation*;
//! substituting a literal for a variable removes atoms and changes the
//! constraint system, so the old certificate no longer fits even though the
//! statement is still true. The kernel re-checks every irrelevant subterm,
//! so such terms would be rejected.
//!
//! [`recertify`] walks a term with its typing context and recomputes the
//! certificate of every `Linarith` node (via `Env::linearize` and the
//! Fourier–Motzkin search), keeping the original when no new one is found.
//! The kernel still checks the result.
//!
//! Inside a prover call, every step (evaluation, linearization, type checks
//! of hypotheses, certificate search, the traversal itself) is charged to
//! the goal ([`crate::auto::meter`]); an exhausted goal gets the remaining
//! nodes unchanged.

use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{Arm, Lvl, Name, Rel, Term, Tm};
use sandblaster_kernel::value::{Arg, Budget, Closure, EnvEntry, VEnv, V};

use crate::auto::meter;

/// Runs `f` with a budget of `cap` steps, capped by what remains of the
/// current goal (inside a prover call), and charges the steps used.
fn metered<T>(cap: u64, f: impl FnOnce(&mut Budget) -> T) -> T {
    let start = cap.min(meter::available());
    let mut b = Budget { steps: start };
    let r = f(&mut b);
    meter::spend(start - b.steps);
    r
}

/// Recomputes the certificates of the `Linarith` nodes of `t` (a term in
/// `ctx`).
pub fn recertify(env: &Env, ctx: &Ctx, t: &Tm) -> Tm {
    recertify_with(env, ctx, t, false)
}

/// [`recertify`] for terms **quoted from values** (prover atoms and
/// facts): additionally checks every hypothesis proof against its stated
/// type, since quoting can instantiate a branch's path equation with the
/// `refl` it was applied to (`refl(Bool, c) : Eq(Bool, c, false)` is only
/// valid inside the branch); ill-typed hypotheses are replaced by the
/// context's equational facts.
pub fn recertify_quoted(env: &Env, ctx: &Ctx, t: &Tm) -> Tm {
    recertify_with(env, ctx, t, true)
}

fn recertify_with(env: &Env, ctx: &Ctx, t: &Tm, validate: bool) -> Tm {
    if !super::tm::has_linarith(t) {
        return t.clone();
    }
    let mut r = Recert { env, ctx: ctx.clone(), venv: env.ctx_venv(ctx), lin: std::collections::HashMap::new(), done: std::collections::HashMap::new(), validate, scope: 0, next_scope: 1 };
    r.go(t)
}

struct Recert<'e> {
    env: &'e Env,
    ctx: Ctx,
    venv: VEnv,
    /// Memo of "contains a `Linarith` node", by subterm identity (the
    /// subterm is kept alive so its address is not reused).
    lin: std::collections::HashMap<*const Term, (Tm, bool)>,
    /// Results by (subterm identity, scope): shared subterms (from
    /// substitution) are re-certified once per scope and stay shared.
    done: std::collections::HashMap<(*const Term, u64), (Tm, Tm)>,
    /// Identity of the current binder scope (fresh for every pushed
    /// binder, so memoized results never cross contexts).
    scope: u64,
    next_scope: u64,
    /// Check hypothesis proofs against their statements (quoted terms).
    validate: bool,
}

impl Recert<'_> {
    /// Whether a hypothesis proof has its stated type in the current
    /// context.
    fn hyp_ok(&self, p: &Tm, st: &Tm) -> bool {
        let Some(sv) = self.eval(st) else { return false };
        metered(5_000_000, |b| self.env.check(&self.ctx, p, &sv, b).is_ok())
    }

    /// The equational facts of the context (binders of type `Eq(..)`), as
    /// `(Var, statement)` linarith hypotheses.
    fn ctx_facts(&self) -> Vec<(Tm, Tm)> {
        let d = self.depth();
        let mut out = Vec::new();
        let bool_ = self.env.bool_ind();
        for (i, e) in self.ctx.entries.iter().enumerate() {
            if !matches!(&*e.ty, sandblaster_kernel::value::Value::Eq { .. }) {
                continue;
            }
            if !meter::charge_quote(self.env, &self.ctx, &e.ty, None, false) {
                break;
            }
            let st = self.env.quote(Lvl(d), &e.ty, false);
            // §5.8 forms only: an `Int`/machine equation, or a comparison
            // equated to a literal that is not a disjunction
            let ok = match &*st {
                Term::Eq { ty, lhs, rhs } => match (&**ty, &**lhs, &**rhs) {
                    (Term::IntTy(_), _, _) => true,
                    (Term::Ind { ind, .. }, Term::Prim { op, .. }, Term::Ctor { ind: bi, ctor, .. }) if *ind == bool_ && *bi == bool_ => {
                        use sandblaster_kernel::term::PrimOp::*;
                        match op {
                            Eq(_) => *ctor == 1,
                            Ne(_) => *ctor == 0,
                            Lt(_) | Le(_) | Gt(_) | Ge(_) => true,
                            _ => false,
                        }
                    }
                    _ => false,
                },
                _ => false,
            };
            if ok {
                out.push((sandblaster_kernel::util::mk::var(d - 1 - i as u32), st));
            }
        }
        out
    }

    /// Whether `t` contains a `Linarith` node (memoized; linear in the
    /// term graph over a whole traversal).
    fn has_lin(&mut self, t: &Tm) -> bool {
        let key = Rc::as_ptr(t);
        if let Some((_, b)) = self.lin.get(&key) {
            return *b;
        }
        meter::spend(1);
        let mut found = matches!(&**t, Term::Linarith { .. });
        if !found {
            let mut kids = Vec::new();
            super::tm::children(t, &mut |c| kids.push(c.clone()));
            for c in &kids {
                if self.has_lin(c) {
                    found = true;
                    break;
                }
            }
        }
        self.lin.insert(key, (t.clone(), found));
        found
    }
}

impl Recert<'_> {
    fn depth(&self) -> u32 {
        self.ctx.entries.len() as u32
    }

    fn eval(&self, t: &Tm) -> Option<V> {
        metered(50_000_000, |b| self.env.eval(&self.venv, Lvl(self.depth()), t, b).ok())
    }

    fn eval_in(&self, env: &VEnv, t: &Tm) -> Option<V> {
        metered(50_000_000, |b| self.env.eval(env, Lvl(self.depth()), t, b).ok())
    }

    /// Pushes a binder (a fresh variable, or a `let` value).
    fn push(&mut self, name: &Name, rel: Rel, ty: V, def: Option<&Tm>) -> Option<()> {
        let (entry, d) = match def {
            None => (self.env.fresh_var(Lvl(self.depth()), rel, &ty), None),
            Some(v) => match rel {
                Rel::Rel => {
                    let vv = self.eval(v)?;
                    (EnvEntry::Rel(vv.clone()), Some(Arg::Rel(vv)))
                }
                Rel::Irr => {
                    let c = Closure { env: self.venv.clone(), body: v.clone() };
                    (EnvEntry::Irr(c.clone()), Some(Arg::Irr(c)))
                }
            },
        };
        self.scope = self.next_scope;
        self.next_scope += 1;
        let mut es = (*self.ctx.entries).clone();
        es.push(CtxEntry { name: name.clone(), rel, ty, def: d });
        self.ctx = Ctx { entries: Rc::new(es) };
        let mut ve = (*self.venv.0).clone();
        ve.push(entry);
        self.venv = VEnv(Rc::new(ve));
        Some(())
    }

    fn with<T>(&mut self, f: impl FnOnce(&mut Self) -> T) -> T {
        let saved = (self.ctx.clone(), self.venv.clone(), self.scope);
        let r = f(self);
        self.ctx = saved.0;
        self.venv = saved.1;
        self.scope = saved.2;
        r
    }

    fn go(&mut self, t: &Tm) -> Tm {
        if !self.has_lin(t) {
            return t.clone();
        }
        let key = (Rc::as_ptr(t), self.scope);
        if let Some((_, r)) = self.done.get(&key) {
            return r.clone();
        }
        if !meter::spend(1) {
            return t.clone();
        }
        let r = self.go_inner(t).unwrap_or_else(|| t.clone());
        self.done.insert(key, (t.clone(), r.clone()));
        r
    }

    fn go_inner(&mut self, t: &Tm) -> Option<Tm> {
        use Term::*;
        Some(match &**t {
            Linarith { hyps, goal, cert } => {
                let mut hyps2: Vec<(Tm, Tm)> = hyps.iter().map(|(p, s)| (self.go(p), self.go(s))).collect();
                let goal2 = self.go(goal);
                let mut dropped = false;
                if self.validate {
                    let before = hyps2.len();
                    hyps2.retain(|(p, st)| self.hyp_ok(p, st));
                    if hyps2.len() < before {
                        dropped = true;
                        hyps2.extend(self.ctx_facts());
                    }
                }
                // first with the node's own hypotheses (keeps proofs from
                // growing on repeated re-certification)
                if let Ok(sys) = metered(50_000_000, |b| self.env.linearize(&self.ctx, &hyps2, &goal2, b))
                    && let Some(c) = super::fm::certificate(&sys)
                {
                    let unchanged = !dropped && c == *cert && hyps2.iter().zip(hyps).all(|((p2, s2), (p, s))| Rc::ptr_eq(p2, p) && Rc::ptr_eq(s2, s)) && Rc::ptr_eq(&goal2, goal);
                    return Some(if unchanged { t.clone() } else { Rc::new(Linarith { hyps: hyps2, goal: goal2, cert: c }) });
                }
                // hypotheses whose proofs no longer have their stated type
                // (an instantiated path equation quoted out of its branch,
                // e.g. `refl(Bool, c) : Eq(Bool, c, false)`) are dropped;
                // the context's own linear facts replace them
                if !self.validate {
                    let before = hyps2.len();
                    hyps2.retain(|(p, st)| self.hyp_ok(p, st));
                    if hyps2.len() < before {
                        hyps2.extend(self.ctx_facts());
                    }
                }
                // facts carried by the proof slots of checked primitives in
                // the statements (substitution may have made them necessary)
                let mut extra = Vec::new();
                harvest(self.env, &goal2, &mut extra);
                for (_, st) in &hyps2 {
                    harvest(self.env, st, &mut extra);
                }
                hyps2.extend(extra);
                let cert2 = match metered(50_000_000, |b| self.env.linearize(&self.ctx, &hyps2, &goal2, b)) {
                    Ok(sys) => match super::fm::certificate(&sys) {
                        Some(c) => c,
                        None => {
                            if std::env::var("SANDBLASTER_DEBUG_RECERT").is_ok() {
                                let names: Vec<_> = self.ctx.entries.iter().map(|e| e.name.clone()).collect();
                                eprintln!("recert: no certificate for {}\n  system: {:?}", self.env.print_term(&names, &goal2), sys.problems);
                                for (p, st) in &hyps2 {
                                    eprintln!("  hyp {} : {}", self.env.print_term(&names, p), self.env.print_term(&names, st));
                                }
                            }
                            cert.clone()
                        }
                    },
                    Err(e) => {
                        if std::env::var("SANDBLASTER_DEBUG_RECERT").is_ok() {
                            eprintln!("recert: linearize failed: {e}");
                        }
                        cert.clone()
                    }
                };
                Rc::new(Linarith { hyps: hyps2, goal: goal2, cert: cert2 })
            }
            Pi { name, rel, dom, cod } | Lam { name, rel, dom, body: cod } => {
                let dom2 = self.go(dom);
                let dv = self.eval(&dom2)?;
                let cod2 = self.with(|s| {
                    s.push(name, *rel, dv, None)?;
                    Some(s.go(cod))
                })?;
                match &**t {
                    Pi { .. } => Rc::new(Pi { name: name.clone(), rel: *rel, dom: dom2, cod: cod2 }),
                    _ => Rc::new(Lam { name: name.clone(), rel: *rel, dom: dom2, body: cod2 }),
                }
            }
            Let { name, rel, ty, val, body } => {
                let ty2 = self.go(ty);
                let val2 = self.go(val);
                let tv = self.eval(&ty2)?;
                let body2 = self.with(|s| {
                    s.push(name, *rel, tv, Some(&val2))?;
                    Some(s.go(body))
                })?;
                Rc::new(Let { name: name.clone(), rel: *rel, ty: ty2, val: val2, body: body2 })
            }
            Sigma { name, snd_rel, fst, snd } => {
                let fst2 = self.go(fst);
                let fv = self.eval(&fst2)?;
                let snd2 = self.with(|s| {
                    s.push(name, Rel::Rel, fv, None)?;
                    Some(s.go(snd))
                })?;
                Rc::new(Sigma { name: name.clone(), snd_rel: *snd_rel, fst: fst2, snd: snd2 })
            }
            Match { ind, params, scrut, motive, arms } => {
                let params2: Vec<Tm> = params.iter().map(|p| self.go(p)).collect();
                let scrut2 = self.go(scrut);
                let dty = self.eval(&Rc::new(Ind { ind: *ind, params: params2.clone() }))?;
                let motive2 = self.with(|s| {
                    s.push(&Rc::from("y"), Rel::Rel, dty, None)?;
                    Some(s.go(motive))
                })?;
                let decl = self.env.inductive_decl(*ind)?;
                let pvals: Vec<V> = params2.iter().map(|p| self.eval(p)).collect::<Option<_>>()?;
                let mut arms2 = Vec::new();
                for (a, c) in arms.iter().zip(&decl.ctors) {
                    let body2 = self.with(|s| {
                        let mut fenv: Vec<EnvEntry> = pvals.iter().map(|v| EnvEntry::Rel(v.clone())).collect();
                        for (fname, frel, fty) in &c.fields {
                            let ftv = s.eval_in(&VEnv(Rc::new(fenv.clone())), fty)?;
                            s.push(fname, *frel, ftv, None)?;
                            fenv.push(s.venv.0.last().cloned()?);
                        }
                        Some(s.go(&a.body))
                    })?;
                    arms2.push(Arm { names: a.names.clone(), body: body2 });
                }
                Rc::new(Match { ind: *ind, params: params2, scrut: scrut2, motive: motive2, arms: arms2 })
            }
            Transport { ty, lhs, rhs, eq, motive, val } => {
                let ty2 = self.go(ty);
                let tv = self.eval(&ty2)?;
                let motive2 = self.with(|s| {
                    s.push(&Rc::from("y"), Rel::Rel, tv, None)?;
                    Some(s.go(motive))
                })?;
                Rc::new(Transport { ty: ty2, lhs: self.go(lhs), rhs: self.go(rhs), eq: self.go(eq), motive: motive2, val: self.go(val) })
            }
            // binder-free nodes: recurse structurally
            _ => self.children(t),
        })
    }

    /// Rebuilds a binder-free node with its children recertified.
    fn children(&mut self, t: &Tm) -> Tm {
        use Term::*;
        let g = |s: &mut Self, x: &Tm| s.go(x);
        match &**t {
            App { rel, fun, arg } => Rc::new(App { rel: *rel, fun: g(self, fun), arg: g(self, arg) }),
            Pair { ty, fst, snd } => Rc::new(Pair { ty: g(self, ty), fst: g(self, fst), snd: g(self, snd) }),
            Fst(p) => Rc::new(Fst(g(self, p))),
            Snd(p) => Rc::new(Snd(g(self, p))),
            Eq { ty, lhs, rhs } => Rc::new(Eq { ty: g(self, ty), lhs: g(self, lhs), rhs: g(self, rhs) }),
            Refl { ty, val } => Rc::new(Refl { ty: g(self, ty), val: g(self, val) }),
            Ind { ind, params } => Rc::new(Ind { ind: *ind, params: params.iter().map(|p| g(self, p)).collect() }),
            Ctor { ind, ctor, params, args } => Rc::new(Ctor { ind: *ind, ctor: *ctor, params: params.iter().map(|p| g(self, p)).collect(), args: args.iter().map(|p| g(self, p)).collect() }),
            Prim { op, args, proofs } => Rc::new(Prim { op: *op, args: args.iter().map(|p| g(self, p)).collect(), proofs: proofs.iter().map(|p| g(self, p)).collect() }),
            Rec { args, proof } => Rc::new(Rec { args: args.iter().map(|p| g(self, p)).collect(), proof: proof.as_ref().map(|p| g(self, p)) }),
            Delta { def, args } => Rc::new(Delta { def: *def, args: args.iter().map(|p| g(self, p)).collect() }),
            Unfold { def, args, to_body, val } => Rc::new(Unfold { def: *def, args: args.iter().map(|p| g(self, p)).collect(), to_body: *to_body, val: g(self, val) }),
            BvRefl { ty, lhs, rhs } => Rc::new(BvRefl { ty: g(self, ty), lhs: g(self, lhs), rhs: g(self, rhs) }),
            Absurd { ty, proof } => Rc::new(Absurd { ty: g(self, ty), proof: g(self, proof) }),
            Axiom { ax, args } => Rc::new(Axiom { ax: *ax, args: args.iter().map(|p| g(self, p)).collect() }),
            _ => t.clone(),
        }
    }
}

/// The proof slots of checked primitives occurring (outside binders) in
/// `t`, as linarith hypotheses `(eq::promote .. .p, obligation)`; only the
/// §5.8 hypothesis forms (no `ne … true`).
pub fn harvest(env: &Env, t: &Tm, out: &mut Vec<(Tm, Tm)>) {
    use sandblaster_kernel::term::PrimOp;
    let bool_ = env.bool_ind();
    let promote = env.lookup_global("eq::promote");
    // DAG-aware (quoted terms share subterms heavily); `t` is borrowed for
    // the whole walk, so the recorded addresses stay valid
    fn walk(env: &Env, t: &Tm, bool_: sandblaster_kernel::term::IndId, promote: Option<sandblaster_kernel::term::GlobalId>, out: &mut Vec<(Tm, Tm)>, seen: &mut std::collections::HashSet<*const Term>) {
        use Term::*;
        if out.len() > 64 || !seen.insert(Rc::as_ptr(t)) || !crate::auto::meter::spend(1) {
            return;
        }
        match &**t {
            Prim { op, args, proofs } => {
                if !proofs.is_empty() && !matches!(op, PrimOp::Div(_) | PrimOp::Rem(_)) {
                    let obls = sandblaster_kernel::prim::prim_obligations(*op, args, bool_);
                    for (p, o) in proofs.iter().zip(obls) {
                        if matches!(&**p, Erased) || out.len() > 64 {
                            continue;
                        }
                        let Eq { ty, lhs, rhs } = &*o else { continue };
                        let pf = match promote {
                            Some(g) => sandblaster_kernel::util::mk::apps(sandblaster_kernel::util::mk::global(g), [(Rel::Rel, ty.clone()), (Rel::Rel, lhs.clone()), (Rel::Rel, rhs.clone()), (Rel::Irr, p.clone())]),
                            None => continue,
                        };
                        // duplicates by statement (α-equivalence up to
                        // proofs, memoized on shared nodes; either proof of
                        // a duplicate would do)
                        if !out.iter().any(|(_, s)| Rc::ptr_eq(s, &o) || env.alpha_eq_relevant(s, &o, &|a, b| a == b)) {
                            out.push((pf, o.clone()));
                        }
                    }
                }
                for a in args {
                    walk(env, a, bool_, promote, out, seen);
                }
            }
            App { fun, arg, rel } => {
                walk(env, fun, bool_, promote, out, seen);
                if *rel == Rel::Rel {
                    walk(env, arg, bool_, promote, out, seen);
                }
            }
            Eq { lhs, rhs, .. } => {
                walk(env, lhs, bool_, promote, out, seen);
                walk(env, rhs, bool_, promote, out, seen);
            }
            Fst(x) | Snd(x) => walk(env, x, bool_, promote, out, seen),
            Ctor { args, .. } => args.iter().for_each(|a| walk(env, a, bool_, promote, out, seen)),
            Match { scrut, .. } => walk(env, scrut, bool_, promote, out, seen),
            Pair { fst, .. } => walk(env, fst, bool_, promote, out, seen),
            _ => {}
        }
    }
    walk(env, t, bool_, promote, out, &mut std::collections::HashSet::new());
}
