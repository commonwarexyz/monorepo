//! Kernel-checked equality of multiversioned clones (DESIGN.md §9.3).
//!
//! A clone `c = f__<set>` is `f` with every call of a cloned function
//! redirected to its clone and every call of a portable function to its
//! variant; its kernel body is α-equivalent in all relevant positions to
//! `f`'s modulo that renaming (`multiversion`). This module turns the
//! renaming into a **proof**, checked by the kernel like any lemma:
//!
//! ```text
//! c::clone_equiv : Π x̄ h̄. Eq(R, c x̄ h̄, f x̄ h̄)
//!   := λ x̄ h̄. trans(delta(c; x̄ h̄), trans(P, sym(delta(f; x̄ h̄))))
//! ```
//!
//! where `P : Eq(R, B_c, B_f)` relates the two bodies. `P` **mirrors** the
//! bodies' binder structure (the same `let`s and match arms with their
//! path equations, in the same order), so every term of a body is valid
//! verbatim in the proof's context, and is built bottom-up:
//!
//! * identical subterms (up to irrelevant positions): `refl`;
//! * a renamed call `g' ā` vs `g ā`: the lemma of `g'` (a clone's
//!   `clone_equiv`, a variant's `variant_equiv`) instantiated at `ā`; for
//!   a recursive clone, the recursive call is the **induction hypothesis**
//!   `rec(ā; p)`, with the measure proof `p` of the clone's own (pre-commit)
//!   body at that position — the lemma recurses with the clone's measure;
//! * differing arguments of the same head: `cong` one argument at a time;
//! * `let y = v; b`: mirrored when the values agree, otherwise `(λy. P_b)
//!   v_c` followed by `cong` on the value;
//! * a match (plain, or the dependent-match idiom applied to `refl`) on the
//!   same scrutinee: a match with motive `Eq(R, match_c, match_f)` whose arms
//!   are the arm proofs.
//!
//! Anything else (differing scrutinees, differing values under irrelevant
//! proofs that depend on them, …) makes the builder give up; the kernel
//! checks every lemma it produces. A clone without its lemma is not
//! admitted (plan O4): its variant set falls back to the portable code.

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{Arm, DefDecl, DefKind, GlobalId, Lvl, Recursion, Rel, Term, Tm};
use sandblaster_kernel::util::{mk, shift};
use sandblaster_kernel::value::{Arg, Budget, Closure};

type MR<T> = Result<T, String>;

/// A proof of `Eq(ty, lhs, rhs)` in the current context.
struct Pf {
    tm: Tm,
    ty: Tm,
    lhs: Tm,
    rhs: Tm,
}

/// Global ids of the prelude's equality lemmas.
#[derive(Clone, Copy)]
pub struct EqIds {
    pub sym: GlobalId,
    pub trans: GlobalId,
    pub cong: GlobalId,
}

impl EqIds {
    pub fn new(env: &Env) -> Option<EqIds> {
        Some(EqIds { sym: env.lookup_global("eq::sym")?, trans: env.lookup_global("eq::trans")?, cong: env.lookup_global("eq::cong")? })
    }
}

struct Mirror<'e> {
    env: &'e Env,
    ctx: Ctx,
    /// clone → (original, lemma `Π x̄. Eq(R, clone x̄, original x̄)`).
    lemmas: &'e HashMap<GlobalId, (GlobalId, GlobalId)>,
    this: GlobalId,
    orig: GlobalId,
    eq: EqIds,
    budget: u64,
    /// Remaining `prove` steps (the builder gives up when exhausted).
    fuel: u64,
    /// [`Mirror::type_of`] by (term, context) address, both kept alive: the
    /// proof asks the type of the same argument at every `cong` level.
    types: std::cell::RefCell<crate::auto::util::FxMap<(usize, usize), (Tm, Ctx, Tm)>>,
}

fn app_spine(t: &Tm) -> (Tm, Vec<(Rel, Tm)>) {
    let mut args = Vec::new();
    let mut h = t.clone();
    while let Term::App { rel, fun, arg } = &*h.clone() {
        args.push((*rel, arg.clone()));
        h = fun.clone();
    }
    args.reverse();
    (h, args)
}

impl Mirror<'_> {
    fn same(&self, a: &Tm, b: &Tm) -> bool {
        self.env.alpha_eq_relevant(a, b, &|x, y| x == y)
    }

    /// [`Mirror::same`] modulo the renaming (this clone and the clones with
    /// a lemma stand for their originals), for the types of facts: a fact
    /// may mention renamed calls, e.g. a post-loop fact about the loop's
    /// result (DESIGN.md §7.4). The proof keeps the clone's fact; the
    /// kernel checks it.
    fn same_renamed(&self, a: &Tm, b: &Tm) -> bool {
        let (this, orig, lemmas) = (self.this, self.orig, self.lemmas);
        self.env.alpha_eq_relevant(a, b, &|x, y| x == y || (x == this && y == orig) || lemmas.get(&x).is_some_and(|l| l.0 == y))
    }

    fn b(&self) -> Budget {
        Budget { steps: self.budget }
    }

    /// The type of `t` in the current context, as a term.
    fn type_of(&self, t: &Tm) -> MR<Tm> {
        let key = (Rc::as_ptr(t) as *const () as usize, Rc::as_ptr(&self.ctx.entries) as *const () as usize);
        if let Some((_, _, ty)) = self.types.borrow().get(&key) {
            return Ok(ty.clone());
        }
        let mut b = self.b();
        let v = self.env.infer(&self.ctx, t, &mut b).map_err(|e| format!("type of a body term: {}", e.to_string().chars().take(200).collect::<String>()))?;
        let ty = self.env.quote_typed(&self.ctx, &v, None, false);
        self.types.borrow_mut().insert(key, (t.clone(), self.ctx.clone(), ty.clone()));
        Ok(ty)
    }

    fn refl(&self, ty: Tm, a: &Tm, b: &Tm) -> Pf {
        Pf { tm: mk::refl(ty.clone(), a.clone()), ty, lhs: a.clone(), rhs: b.clone() }
    }

    fn trans(&self, p: Pf, q: Pf) -> Pf {
        let tm = mk::apps(mk::global(self.eq.trans), [(Rel::Rel, p.ty.clone()), (Rel::Rel, p.lhs.clone()), (Rel::Rel, p.rhs.clone()), (Rel::Rel, q.rhs.clone()), (Rel::Rel, p.tm), (Rel::Rel, q.tm)]);
        Pf { tm, ty: p.ty, lhs: p.lhs, rhs: q.rhs }
    }

    fn sym(&self, p: Pf) -> Pf {
        let tm = mk::apps(mk::global(self.eq.sym), [(Rel::Rel, p.ty.clone()), (Rel::Rel, p.lhs.clone()), (Rel::Rel, p.rhs.clone()), (Rel::Rel, p.tm)]);
        Pf { tm, ty: p.ty, lhs: p.rhs, rhs: p.lhs }
    }

    /// `cong(λy. f[y], e)` for `e : Eq(A, x, x')`: `Eq(B, f[x], f[x'])`;
    /// `body` is `f[y]` with `y` the innermost variable.
    fn cong(&self, a_ty: &Tm, b_ty: &Tm, body: Tm, e: Pf) -> Pf {
        let f = mk::lam("y", Rel::Rel, a_ty.clone(), body.clone());
        let lhs = mk::app(f.clone(), e.lhs.clone());
        let rhs = mk::app(f.clone(), e.rhs.clone());
        let tm = mk::apps(mk::global(self.eq.cong), [(Rel::Rel, a_ty.clone()), (Rel::Rel, b_ty.clone()), (Rel::Rel, f), (Rel::Rel, e.lhs), (Rel::Rel, e.rhs), (Rel::Rel, e.tm)]);
        Pf { tm, ty: b_ty.clone(), lhs, rhs }
    }

    fn push(&mut self, name: &str, rel: Rel, ty: &Tm, def: Option<&Tm>) -> MR<()> {
        let venv = self.env.ctx_venv(&self.ctx);
        let depth = self.ctx.depth();
        let mut b = self.b();
        let tyv = self.env.eval(&venv, depth, ty, &mut b).map_err(|e| format!("{e:?}"))?;
        let def = match def {
            Some(d) => Some(match rel {
                Rel::Rel => Arg::Rel(self.env.eval(&venv, depth, d, &mut b).map_err(|e| format!("{e:?}"))?),
                Rel::Irr => Arg::Irr(Closure { env: venv.clone(), body: d.clone() }),
            }),
            None => None,
        };
        self.ctx = self.ctx.push(CtxEntry { name: Rc::from(name), rel, ty: tyv, def });
        Ok(())
    }

    fn pop(&mut self) {
        let mut es = (*self.ctx.entries).clone();
        es.pop();
        self.ctx = Ctx { entries: Rc::new(es) };
    }

    /// `P : Eq(T, a, b)` (see the module docs); `p` is the clone's
    /// pre-commit term at the same position as `a` (for measure proofs).
    fn prove(&mut self, a: &Tm, p: &Tm, b: &Tm) -> MR<Pf> {
        if self.fuel == 0 {
            return Err("the proof builder's step budget is exhausted".into());
        }
        self.fuel -= 1;
        if self.same(a, b) {
            let ty = self.type_of(a)?;
            return Ok(self.refl(ty, a, b));
        }
        match (&**a, &**b) {
            (Term::Let { name, rel: Rel::Rel, ty, val: va, body: ba }, Term::Let { rel: Rel::Rel, ty: tb, val: vb, body: bb, .. }) => {
                let Term::Let { val: vp, body: bp, .. } = &**p else { return Err("pre-commit shape".into()) };
                if !self.same(ty, tb) {
                    return Err("let types differ".into());
                }
                let t = self.type_of(a)?;
                if self.same(va, vb) {
                    self.push(name, Rel::Rel, ty, Some(va))?;
                    let pb = self.prove(ba, bp, bb);
                    self.pop();
                    let pb = pb?;
                    return Ok(Pf { tm: mk::let_(name, Rel::Rel, ty.clone(), va.clone(), pb.tm), ty: t, lhs: a.clone(), rhs: b.clone() });
                }
                // differing values: substitute them (`let y = v; b` is
                // `b[v/y]` by ζ); the value proofs appear where `y` did
                let (ba2, bp2, bb2) = (crate::elab::tm::subst0(ba, va), crate::elab::tm::subst0(bp, vp), crate::elab::tm::subst0(bb, vb));
                if let Ok(pb) = self.prove(&ba2, &bp2, &bb2) {
                    return Ok(Pf { lhs: a.clone(), rhs: b.clone(), ..pb });
                }
                // otherwise (e.g. the variable is a scrutinee): `(λy. P_b) v_c`
                // followed by `cong` on the value
                let pv = self.prove(va, vp, vb)?;
                self.push(name, Rel::Rel, ty, None)?;
                let pb = self.prove(ba, bp, bb);
                self.pop();
                let pb = pb?;
                let lam = mk::lam(name, Rel::Rel, ty.clone(), pb.tm);
                let step1 = Pf { tm: mk::app(lam, va.clone()), ty: t.clone(), lhs: a.clone(), rhs: mk::let_(name, Rel::Rel, ty.clone(), va.clone(), bb.clone()) };
                let step2 = self.cong(ty, &t, mk::let_(name, Rel::Rel, shift(ty, 1), mk::var(0), shift_under(bb, 1)), pv);
                let step2 = Pf { lhs: step1.rhs.clone(), rhs: b.clone(), ..step2 };
                Ok(self.trans(step1, step2))
            }
            (Term::Let { name, rel: Rel::Irr, ty, val, body: ba }, Term::Let { rel: Rel::Irr, ty: tb, body: bb, .. }) => {
                let Term::Let { body: bp, .. } = &**p else { return Err("pre-commit shape".into()) };
                if !self.same_renamed(ty, tb) {
                    return Err("fact types differ".into());
                }
                let t = self.type_of(a)?;
                self.push(name, Rel::Irr, ty, Some(val))?;
                let pb = self.prove(ba, bp, bb);
                self.pop();
                let pb = pb?;
                Ok(Pf { tm: mk::let_(name, Rel::Irr, ty.clone(), val.clone(), pb.tm), ty: t, lhs: a.clone(), rhs: b.clone() })
            }
            (Term::Match { .. }, Term::Match { .. }) => self.plain_match(a, p, b, None),
            // an array literal `pair(Array T N, xs, len_xs)` with differing
            // lists (plan O10: a lane site returns an array of calls): the
            // lists' proof, transported under a Π over the irrelevant length
            // fact (the fact depends on the list), applied to the clone's
            // fact; `pair(_, xs, q) ≡ pair(_, xs, q')` by Σ-η.
            (Term::Pair { ty, fst: fa, snd: sa }, Term::Pair { ty: tb, fst: fb, snd: sb }) if self.same(ty, tb) => {
                let Term::Pair { fst: fp, .. } = &**p else { return Err("pre-commit shape".into()) };
                let (h, targs) = app_spine(ty);
                let (Some(array), Some(len)) = (self.env.lookup_global("Array"), self.env.lookup_global("seq::len")) else { return Err("prelude `Array`/`seq::len` missing".into()) };
                if !matches!(&*h, Term::Global(g) if *g == array) || targs.len() != 2 {
                    return Err("a pair that is not an array literal".into());
                }
                let (el, n) = (targs[0].1.clone(), targs[1].1.clone());
                let e = self.prove(fa, fp, fb)?;
                let t = self.type_of(a)?;
                let lty = self.type_of(fa)?;
                let int = mk::int_ty(sandblaster_kernel::term::Width::Int);
                let cast = |x: Tm| mk::prim(sandblaster_kernel::term::PrimOp::Cast { from: sandblaster_kernel::term::Width::Usize, to: sandblaster_kernel::term::Width::Int }, vec![x], vec![]);
                let len_fact = |el: Tm, z: Tm, n: Tm| mk::eq(int.clone(), mk::apps(mk::global(len), [(Rel::Rel, el), (Rel::Rel, z)]), cast(n));
                // motive z. Π (.q : len z = N). Eq(t, pair(ty, fa, sa), pair(ty, z, q))
                let motive = mk::pi(
                    "q",
                    Rel::Irr,
                    len_fact(shift(&el, 1), mk::var(0), shift(&n, 1)),
                    mk::eq(shift(&t, 2), mk::pair(shift(ty, 2), shift(fa, 2), shift(sa, 2)), mk::pair(shift(ty, 2), mk::var(1), mk::var(0))),
                );
                let val = mk::lam("q", Rel::Irr, len_fact(el.clone(), fa.clone(), n.clone()), mk::refl(shift(&t, 1), mk::pair(shift(ty, 1), shift(fa, 1), shift(sa, 1))));
                let tr = Rc::new(Term::Transport { ty: lty, lhs: fa.clone(), rhs: fb.clone(), eq: e.tm, motive, val });
                return Ok(Pf { tm: mk::app_irr(tr, sb.clone()), ty: t, lhs: a.clone(), rhs: b.clone() });
            }
            _ => {
                let (ha, aa) = app_spine(a);
                let (hb, ab) = app_spine(b);
                let (hp, ap) = app_spine(p);
                // the dependent-match idiom: `(match ..) .e`
                if let (Term::Match { .. }, Term::Match { .. }) = (&*ha, &*hb)
                    && aa.len() == 1
                    && ab.len() == 1
                    && aa[0].0 == Rel::Irr
                {
                    return self.plain_match(&ha, &hp, &hb, Some(aa[0].1.clone()));
                }
                if let (Term::Global(ga), Term::Global(gb)) = (&*ha, &*hb) {
                    if aa.len() != ab.len() {
                        return Err("spines of different lengths".into());
                    }
                    // the pre-commit arguments (a recursive call is one `rec` node)
                    let ap: Vec<(Rel, Tm)> = match &*hp {
                        Term::Rec { args, .. } => aa.iter().zip(args).map(|((r, _), x)| (*r, x.clone())).collect(),
                        _ => ap,
                    };
                    if ga == gb {
                        return self.cong_args(&ha, &aa, &ap, &ab);
                    }
                    // a renamed call: the callee's lemma (or the induction
                    // hypothesis), then the arguments
                    let t = self.type_of(a)?;
                    let first = if *ga == self.this && *gb == self.orig {
                        let Term::Rec { args, proof } = &*p.clone() else { return Err("recursive call without its pre-commit `rec`".into()) };
                        Pf { tm: Rc::new(Term::Rec { args: args.clone(), proof: proof.clone() }), ty: t.clone(), lhs: a.clone(), rhs: mk::apps(hb.clone(), aa.iter().cloned()) }
                    } else {
                        let Some((o, lemma)) = self.lemmas.get(ga).copied() else { return Err(format!("no lemma for `{}`", self.env.global_name(*ga).unwrap_or_default())) };
                        if o != *gb {
                            return Err("renamed call to an unexpected original".into());
                        }
                        Pf { tm: mk::apps(mk::global(lemma), aa.iter().map(|(r, x)| (*r, x.clone()))), ty: t.clone(), lhs: a.clone(), rhs: mk::apps(hb.clone(), aa.iter().cloned()) }
                    };
                    let rest = self.cong_args(&hb, &aa, &ap, &ab)?;
                    let rest = Pf { lhs: first.rhs.clone(), ..rest };
                    return Ok(self.trans(first, rest));
                }
                if let (Term::Ctor { ind, ctor, params, args: xa }, Term::Ctor { ind: ib, ctor: cb, args: xb, .. }) = (&**a, &**b) {
                    let Term::Ctor { args: xp, .. } = &**p else { return Err("pre-commit shape".into()) };
                    if ind != ib || ctor != cb || xa.len() != xb.len() {
                        return Err("different constructors".into());
                    }
                    let t = self.type_of(a)?;
                    let mut acc: Option<Pf> = None;
                    let mut cur: Vec<Tm> = xa.clone();
                    for i in 0..xa.len() {
                        if self.same(&xa[i], &xb[i]) {
                            continue;
                        }
                        let e = self.prove(&xa[i], &xp[i], &xb[i])?;
                        let ai = self.type_of(&xa[i])?;
                        let mut body_args: Vec<Tm> = cur.iter().map(|x| shift(x, 1)).collect();
                        body_args[i] = mk::var(0);
                        let body = mk::ctor(*ind, *ctor, params.iter().map(|x| shift(x, 1)).collect(), body_args);
                        let step = self.cong(&ai, &t, body, e);
                        let step = Pf { lhs: mk::ctor(*ind, *ctor, params.clone(), cur.clone()), ..step };
                        cur[i] = xb[i].clone();
                        let step = Pf { rhs: mk::ctor(*ind, *ctor, params.clone(), cur.clone()), ..step };
                        acc = Some(match acc {
                            None => step,
                            Some(prev) => self.trans(prev, step),
                        });
                    }
                    return acc.map(|p| Pf { lhs: a.clone(), rhs: b.clone(), ..p }).ok_or_else(|| "constructors differ only irrelevantly".into());
                }
                Err(format!("unsupported difference at `{}`", self.env.print_term(&[], a).chars().take(80).collect::<String>()))
            }
        }
    }

    /// `h ā` vs `h b̄` (same head): `cong` on each differing relevant
    /// argument, left to right.
    fn cong_args(&mut self, h: &Tm, aa: &[(Rel, Tm)], ap: &[(Rel, Tm)], ab: &[(Rel, Tm)]) -> MR<Pf> {
        let full_a = mk::apps(h.clone(), aa.iter().cloned());
        let t = self.type_of(&full_a)?;
        let mut cur: Vec<(Rel, Tm)> = aa.to_vec();
        let mut acc: Option<Pf> = None;
        for i in 0..aa.len() {
            if aa[i].0 == Rel::Irr || self.same(&aa[i].1, &ab[i].1) {
                continue;
            }
            let pi = ap.get(i).map(|x| x.1.clone()).unwrap_or_else(|| aa[i].1.clone());
            let e = self.prove(&aa[i].1, &pi, &ab[i].1)?;
            let ai = self.type_of(&aa[i].1)?;
            let mut body_args: Vec<(Rel, Tm)> = cur.iter().map(|(r, x)| (*r, shift(x, 1))).collect();
            body_args[i].1 = mk::var(0);
            let body = mk::apps(shift(h, 1), body_args);
            let lhs = mk::apps(h.clone(), cur.iter().cloned());
            cur[i] = ab[i].clone();
            let rhs = mk::apps(h.clone(), cur.iter().cloned());
            let step = self.cong(&ai, &t, body, e);
            let step = Pf { lhs, rhs, ..step };
            acc = Some(match acc {
                None => step,
                Some(prev) => self.trans(prev, step),
            });
        }
        let full_b = mk::apps(h.clone(), ab.iter().cloned());
        Ok(match acc {
            Some(p) => Pf { lhs: full_a, rhs: full_b, ..p },
            None => self.refl(t, &full_a, &full_b),
        })
    }

    /// Two matches on the same scrutinee with the same motive (optionally
    /// applied to the path-equation argument `e` of the dependent-match
    /// idiom): a match whose motive is the equation of the two matches
    /// (applied to the arm's own path equation), with the arm proofs.
    fn plain_match(&mut self, a: &Tm, p: &Tm, b: &Tm, idiom_arg: Option<Tm>) -> MR<Pf> {
        let (Term::Match { ind, params, scrut: sa, motive: ma, arms: xa }, Term::Match { ind: ib, scrut: sb, motive: mb, arms: xb, .. }, Term::Match { arms: xp, .. }) = (&**a, &**b, &**p) else { return Err("pre-commit shape".into()) };
        if ind != ib || !self.same(sa, sb) || !self.same(ma, mb) || xa.len() != xb.len() || xa.len() != xp.len() {
            return Err("matches on different scrutinees or motives".into());
        }
        let whole_a = match &idiom_arg {
            Some(e) => mk::app_irr(a.clone(), e.clone()),
            None => a.clone(),
        };
        let whole_b = match &idiom_arg {
            Some(e) => mk::app_irr(b.clone(), e.clone()),
            None => b.clone(),
        };
        let t = self.type_of(&whole_a)?;
        // motive: y ⊢ [Π(e :Irr P[y]).] Eq(R, match y ..a [e], match y ..b [e])
        let ma_body = ma.clone();
        let rematch = |arms: &Vec<Arm>| -> Tm {
            // `match y as y' return M with arms` in the context extended with `y`
            let arms2: Vec<Arm> = arms.iter().map(|x| Arm { names: x.names.clone(), body: shift_under(&x.body, x.names.len() as u32) }).collect();
            Rc::new(Term::Match { ind: *ind, params: params.iter().map(|x| shift(x, 1)).collect(), scrut: mk::var(0), motive: shift_under(&ma_body, 1), arms: arms2 })
        };
        let (eq_ty, motive) = match &idiom_arg {
            None => {
                let r = shift(&t, 1);
                (r.clone(), mk::eq(r, rematch(xa), rematch(xb)))
            }
            Some(_) => {
                // the idiom's motive is `Π(e :Irr E[y]). R`: the equation of
                // the two matches applied to that `e`
                let Term::Pi { name, rel: Rel::Irr, dom, cod } = &**ma else { return Err("unexpected idiom motive".into()) };
                let r = cod.clone(); // R, in context (y, e)
                let lhs = mk::app_irr(shift(&rematch(xa), 1), mk::var(0));
                let rhs = mk::app_irr(shift(&rematch(xb), 1), mk::var(0));
                (t.clone(), mk::pi(name, Rel::Irr, dom.clone(), mk::eq(r, lhs, rhs)))
            }
        };
        let _ = eq_ty;
        // the constructors' field types, for the arm contexts
        let decl = self.env.inductive_decl(*ind).ok_or("unknown inductive")?;
        let mut arms_out = Vec::new();
        for (k, ((aa, ab), ap)) in xa.iter().zip(xb).zip(xp).enumerate() {
            let c = &decl.ctors[k];
            if aa.names.len() != c.fields.len() {
                return Err("arm arity".into());
            }
            // push the fields (types from the declaration, instantiated)
            let saved = self.ctx.clone();
            let np = params.len();
            for (j, (fname, rel, fty)) in c.fields.iter().enumerate() {
                // field type in context (params, previous fields)
                let mut ft = fty.clone();
                // substitute params: field types are over params + earlier fields
                let depth_here = self.ctx.depth().0;
                ft = subst_params(&ft, params, np, j, depth_here, saved.depth().0);
                self.push(fname, *rel, &ft, None)?;
            }
            let body_proof = match &idiom_arg {
                None => self.prove(&aa.body, &ap.body, &ab.body),
                Some(_) => {
                    // arm bodies are `λ(e :Irr ..). body`
                    let (Term::Lam { name, rel: Rel::Irr, dom, body: ba }, Term::Lam { body: bb, .. }, Term::Lam { body: bp, .. }) = (&*aa.body, &*ab.body, &*ap.body) else {
                        self.ctx = saved;
                        return Err("idiom arm without its path equation".into());
                    };
                    self.push(name, Rel::Irr, dom, None).and_then(|_| {
                        let r = self.prove(ba, bp, bb);
                        r.map(|pf| mk::lam(name, Rel::Irr, dom.clone(), pf.tm))
                    }).map(|tm| Pf { tm, ty: t.clone(), lhs: aa.body.clone(), rhs: ab.body.clone() })
                }
            };
            self.ctx = saved;
            arms_out.push(Arm { names: aa.names.clone(), body: body_proof?.tm });
        }
        let m = Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: sa.clone(), motive, arms: arms_out });
        let tm = match &idiom_arg {
            Some(e) => mk::app_irr(m, e.clone()),
            None => m,
        };
        Ok(Pf { tm, ty: t, lhs: whole_a, rhs: whole_b })
    }
}

/// Shifts the free variables of a term that sits under `k` binders (so its
/// own bound variables `< k` stay).
fn shift_under(t: &Tm, k: u32) -> Tm {
    sandblaster_kernel::util::shift_from(t, 1, k)
}

/// A constructor field type (in the context of the family parameters and
/// the previous `j` fields) instantiated with the match's parameters, as a
/// term at depth `depth` (the previous fields are the innermost `j`
/// variables; the parameters are terms at depth `base`).
fn subst_params(fty: &Tm, params: &[Tm], np: usize, j: usize, depth: u32, base: u32) -> Tm {
    // variables of fty: indices < j are earlier fields (keep), indices
    // j..j+np are parameters (replace by the params, shifted to `depth`)
    crate::elab::tm::map_post(fty, 0, &mut |n, b| match &*n {
        Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= b + j as u32 => {
            let k = (*i - b - j as u32) as usize; // 0 = last parameter
            if k < np {
                let pi = &params[np - 1 - k];
                Some(sandblaster_kernel::util::shift(pi, (depth - base) as i64 + b as i64))
            } else {
                Some(n)
            }
        }
        _ => Some(n),
    })
    .unwrap_or_else(|| fty.clone())
}

/// Builds and adds `name : Π x̄. Eq(R, clone x̄, orig x̄)` (see the module
/// docs). `pre` is the clone's pre-commit body (with `rec`) and
/// `recursion` its recursion mode (the lemma recurses the same way).
#[allow(clippy::too_many_arguments)]
pub fn prove_clone(env: &mut Env, clone: GlobalId, orig: GlobalId, pre: &Tm, recursion: &Recursion, lemmas: &HashMap<GlobalId, (GlobalId, GlobalId)>, eq: EqIds, name: &str, budget: u64) -> MR<GlobalId> {
    let tele = super::symex::telescope(env, clone).ok_or("no telescope")?;
    let n = tele.binders.len();
    let body_c = env.global_body(clone).ok_or("no body")?;
    let body_o = env.global_body(orig).ok_or("no body")?;
    let strip = |t: &Tm| -> MR<Tm> {
        let mut t = t.clone();
        for _ in 0..n {
            t = match &*t {
                Term::Lam { body, .. } => body.clone(),
                _ => return Err("body without its parameter λs".into()),
            };
        }
        Ok(t)
    };
    let (bc, bo, bp) = (strip(&body_c)?, strip(&body_o)?, strip(pre)?);
    let proof = {
        let envr: &Env = env;
        let mut m = Mirror { env: envr, ctx: Ctx::default(), lemmas, this: clone, orig, eq, budget, fuel: 20_000, types: Default::default() };
        for (nm, rel, dom) in &tele.binders {
            m.push(nm, *rel, dom, None)?;
        }
        let r = shift(&tele.ret, 0);
        let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
        let app_c = mk::apps(mk::global(clone), args.clone());
        let app_o = mk::apps(mk::global(orig), args.clone());
        let arg_tms: Vec<Tm> = args.iter().map(|(_, t)| t.clone()).collect();
        let pb = m.prove(&bc, &bp, &bo)?;
        let dc = Pf { tm: Rc::new(Term::Delta { def: clone, args: arg_tms.clone() }), ty: r.clone(), lhs: app_c.clone(), rhs: bc.clone() };
        let d_o = Pf { tm: Rc::new(Term::Delta { def: orig, args: arg_tms }), ty: r.clone(), lhs: app_o.clone(), rhs: bo.clone() };
        let pb = Pf { ty: r.clone(), lhs: bc.clone(), rhs: bo.clone(), ..pb };
        let tail = m.trans(pb, m.sym(d_o));
        m.trans(dc, tail).tm
    };
    let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
    let stmt = mk::eq(tele.ret.clone(), mk::apps(mk::global(clone), args.clone()), mk::apps(mk::global(orig), args));
    let mut ty = stmt;
    let mut body = proof;
    for (nm, rel, dom) in tele.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
        body = mk::lam(nm, *rel, dom.clone(), body);
    }
    // (hash-consed: the proof repeats the two bodies' common subterms, which
    // the kernel's checker then infers once, `check.rs` memo)
    let body = super::loopsum::lemmas::hashcons(&body);
    let d = DefDecl { name: Rc::from(name), kind: DefKind::Lemma, ty, body, recursion: recursion.clone(), arity: n as u32, opaque: true };
    let mut b = Budget { steps: budget };
    env.add_def(d, &mut b).map_err(|e| e.to_string().chars().take(600).collect())
}

#[allow(dead_code)]
fn lvl(l: u32) -> Lvl {
    Lvl(l)
}
