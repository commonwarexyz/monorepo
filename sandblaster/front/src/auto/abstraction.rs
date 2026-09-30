//! Term-level abstraction of occurrences for rewrite and case-split motives
//! (DESIGN.md §7.2 dependent match idiom, §7.6, §8.1 steps 6 and 11).
//!
//! `Env::abstract_occurrences` compares whole values only, so it cannot
//! abstract a stuck *scrutinee* — the prefix `c` of a neutral `match c { … }`
//! is not a value of its own — and it abstracts inside proofs, which breaks
//! their types. `auto` abstracts on terms instead: the proposition and the
//! abstracted value `c : A` are quoted (normal forms, so syntactic identity
//! is a good proxy for conversion) and occurrences of `c` are treated
//! according to their **position**:
//!
//! * in *computationally relevant* positions (match scrutinees, primitive
//!   and constructor arguments, relevant application arguments, pair
//!   components, the sides of an equation proposition) `c` becomes the motive
//!   variable `y`;
//! * *types inside terms* (match motives, λ domains — e.g. the path-equation
//!   types of the dependent-match idiom) are kept;
//! * a *proof* `p` in an irrelevant position whose own type `P[c]` mentions
//!   `c` is transported along the motive's equation binder
//!   `e : Eq(A, c, y)` (J / based path induction):
//!   `transport(A, c, y, e, z. Π(e' :Irr Eq(A, c, z)). P[z, e'], λe'. p) .e`,
//!   unless the position's expected type did not change: a proof argument
//!   of a global whose earlier arguments have no relevant occurrence of `c`
//!   ([`Abs::kept_side_condition`]), and likewise the irrelevant field of a
//!   constructor, the proof of a primitive and the second component of a
//!   pair whose earlier relevant parts did not change (its type is the
//!   field's, the primitive's side condition or the Σ's, at those parts) —
//!   such a proof is kept as it is (transported, it would prove `P[y]`
//!   where `P[c]` is expected);
//!   where `P[z, e']` is abstracted recursively; the dependent-match
//!   idiom's `refl(D, s[c])` is transported the same way, with the motive
//!   `Eq(D, s[c], s[z])`. Proof types are read syntactically (the goal of a
//!   `linarith`, the type of a fact or local binder, the instantiated type of
//!   a lemma application, a transport's motive); a proof of unknown type is
//!   kept, which may leave the motive ill-typed.
//!
//! The motive is `y. Π(e :Irr Eq(A, c, y)). T[y, e]` (the equation binder is
//! dropped when nothing uses it). Every motive is type-checked by the caller,
//! so an abstraction that still breaks typing only loses a rewrite.

use std::collections::BTreeMap;
use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{Arm, Idx, Lvl, Rel, Term, Tm};
use sandblaster_kernel::value::{Budget, EnvEntry, V, VEnv};

use super::util::shift;

/// A cheap shape key of a term (pre-filter before α-equivalence).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Key {
    Var(u32),
    Global(u32),
    Prim(sandblaster_kernel::term::PrimOp),
    Fst,
    Snd,
    Match(u32),
    App(u32),
    Other(u32),
}

fn key(t: &Term, k: u32) -> Key {
    match t {
        Term::Var(Idx(i)) => Key::Var(i.wrapping_sub(k)),
        Term::Global(g) => Key::Global(g.0),
        Term::Prim { op, .. } => Key::Prim(*op),
        Term::Fst(_) => Key::Fst,
        Term::Snd(_) => Key::Snd,
        Term::Match { ind, .. } => Key::Match(ind.0),
        Term::App { fun, .. } => {
            let mut h = fun;
            while let Term::App { fun, .. } = &**h {
                h = fun;
            }
            match &**h {
                Term::Global(g) => Key::App(g.0),
                Term::Var(Idx(i)) => Key::App(u32::MAX - i.wrapping_sub(k)),
                Term::Match { ind, .. } => Key::Match(ind.0 + (1 << 20)),
                _ => Key::Other(0),
            }
        }
        Term::Ctor { ind, ctor, .. } => Key::Other(16 + ind.0 * 64 + ctor),
        Term::Lit { .. } => Key::Other(1),
        _ => Key::Other(2),
    }
}

/// Position of a subterm.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Mode {
    /// A proposition (the abstracted statement, a connective component).
    Prop,
    /// A computationally relevant term.
    Val,
    /// A type inside a term, or a proof: only variables are remapped.
    Keep,
}

/// A memo key of [`Abs::go`]: node, local depth, mode, motive binders, dry.
type MemoKey = (*const Term, u32, Mode, Option<(u32, u32)>, bool);

struct Abs<'e> {
    env: &'e Env,
    target: Tm,
    tkey: Key,
    shifted: Vec<Tm>,
    /// Relevant occurrences replaced.
    count: usize,
    /// Uses of the equation binder.
    uses_e: usize,
    /// Irrelevant proofs kept without a readable type ([`Abs::own_type`]
    /// is `None`): the known way an abstraction leaves a motive ill-typed.
    blind: usize,
    /// Depth of the input term's context.
    depth: u32,
    /// The abstracted value's type (a term at `depth`).
    a_tm: Tm,
    /// Types (terms at `depth`) of the context facts that may be used.
    fact_types: BTreeMap<u32, Tm>,
    /// Types of local binders (input coordinates at their introduction
    /// depth), by local depth.
    locals: Vec<Option<Tm>>,
    /// Whether each local binder's type was changed by the abstraction (a
    /// `Π`/`Σ` domain of the proposition, or a binder this module adds):
    /// a proof referring to one no longer has its original type.
    changed: Vec<bool>,
    /// Local depths of the current motive variable and equation binder
    /// (`None`: the top-level ones, outside the term).
    ye: Option<(u32, u32)>,
    /// Counting only (no term is kept).
    dry: bool,
    /// Semantic matching: the context's evaluation environment, the
    /// abstracted value, entries for the local binders (neutral variables),
    /// and a budget for these evaluations.
    venv0: VEnv,
    tval: V,
    lvals: Vec<EnvEntry>,
    budget: Budget,
    /// Results by (node, local depth, mode, motive binders, dry): quoted
    /// terms are DAGs (shared subterms), so an unmemoized walk is
    /// exponential in the worst case. A memoized node replays its counts.
    memo: std::collections::HashMap<MemoKey, (Tm, usize, usize, usize)>,
    /// The memoized input nodes, kept alive so their addresses are never
    /// reused while the memo lives (inputs include temporary shifted terms).
    keep: Vec<Tm>,
    /// Compare every relevant subterm semantically, not only those with the
    /// target's head shape ([`abstract_prop_loose`]).
    loose: bool,
}

impl Abs<'_> {
    fn target_at(&mut self, k: u32) -> Tm {
        while self.shifted.len() <= k as usize {
            let n = self.shifted.len() as i64;
            self.shifted.push(shift(&self.target, n));
        }
        self.shifted[k as usize].clone()
    }

    fn is_target(&mut self, t: &Tm, k: u32) -> bool {
        if key(t, k) != self.tkey && !(self.loose && matches!(&**t, Term::App { .. } | Term::Match { .. } | Term::Prim { .. } | Term::Var(_) | Term::Fst(_) | Term::Snd(_))) {
            return false;
        }
        super::meter::spend(1);
        let tt = self.target_at(k);
        if self.env.alpha_eq_relevant(t, &tt, &|a, b| a == b) {
            return true;
        }
        // Terms quoted from proof closures are not normalized: compare by
        // evaluation in the local environment.
        let mut es: Vec<EnvEntry> = self.venv0.0.as_ref().clone();
        es.extend(self.lvals.iter().take(k as usize).cloned());
        if es.len() != (self.depth + k) as usize || self.budget.steps < 1000 {
            return false;
        }
        let d = Lvl(self.depth + k);
        match self.env.eval(&VEnv(Rc::new(es)), d, t, &mut self.budget) {
            Ok(v) => self.env.conv(d, &v, &self.tval, &mut self.budget).unwrap_or(false),
            Err(_) => false,
        }
    }

    /// The motive variable at local depth `k`.
    fn y(&self, k: u32) -> Tm {
        Rc::new(Term::Var(Idx(match self.ye {
            Some((ky, _)) => k - ky - 1,
            None => k + 1,
        })))
    }

    /// The equation binder at local depth `k`.
    fn e(&self, k: u32) -> Tm {
        Rc::new(Term::Var(Idx(match self.ye {
            Some((_, ke)) => k - ke - 1,
            None => k,
        })))
    }

    /// A context-level term (input depth `depth`) at output local depth `k`.
    fn outer(&self, t: &Tm, k: u32) -> Tm {
        shift(t, 2 + k as i64)
    }

    fn var(&self, i: u32, k: u32) -> Term {
        if i < k { Term::Var(Idx(i)) } else { Term::Var(Idx(i + 2)) }
    }

    fn push_local(&mut self, k: u32, ty: Option<Tm>) {
        self.push_local_changed(k, ty, false);
    }

    fn push_local_changed(&mut self, k: u32, ty: Option<Tm>, changed: bool) {
        self.changed.truncate(k as usize);
        self.changed.resize(k as usize, false);
        self.changed.push(changed);
        self.locals.truncate(k as usize);
        self.lvals.truncate(k as usize);
        while self.locals.len() < k as usize {
            self.locals.push(None);
            let l = self.depth + self.lvals.len() as u32;
            self.lvals.push(EnvEntry::Rel(super::util::neu_var(l)));
        }
        self.locals.push(ty);
        let l = self.depth + k;
        self.lvals.push(EnvEntry::Rel(super::util::neu_var(l)));
    }

    /// The type of a proof term (input coordinates at local depth `k`), if
    /// syntactically available.
    fn own_type(&self, p: &Tm, k: u32) -> Option<Tm> {
        match &**p {
            Term::Linarith { goal, .. } => Some(goal.clone()),
            Term::Var(Idx(i)) if *i < k => {
                let kb = k - 1 - i;
                let ty = self.locals.get(kb as usize).cloned().flatten()?;
                Some(shift(&ty, (k - kb) as i64))
            }
            Term::Var(Idx(i)) => {
                let l = self.depth as i64 - 1 - (i - k) as i64;
                let ty = self.fact_types.get(&(l as u32))?;
                Some(shift(ty, k as i64))
            }
            Term::Transport { motive, rhs, .. } => Some(super::util::subst0(motive, rhs)),
            Term::App { .. } => {
                let mut args = Vec::new();
                let mut h = p;
                while let Term::App { fun, arg, .. } = &**h {
                    args.push(arg.clone());
                    h = fun;
                }
                args.reverse();
                // the head's type: a global's, or (syntactically) that of a
                // transport or a variable — the rewrite and split idioms
                // apply a transport of a `Π(e :Irr ..)` motive to the path
                // equation
                let mut ty = match &**h {
                    Term::Global(g) => self.env.global_type(*g)?,
                    Term::Transport { .. } | Term::Var(_) => self.own_type(h, k)?,
                    _ => return None,
                };
                for a in &args {
                    let Term::Pi { cod, .. } = &*ty.clone() else { return None };
                    ty = super::util::subst0(cod, a);
                }
                Some(ty)
            }
            _ => None,
        }
    }

    /// Does `c` occur in a relevant position of `p` (input coordinates at
    /// local depth `k`), read in mode `m`?
    fn mentions(&mut self, p: &Tm, k: u32, m: Mode) -> bool {
        let saved = (self.count, self.uses_e, self.dry, self.locals.clone(), self.lvals.clone());
        let saved_changed = self.changed.clone();
        self.dry = true;
        self.go(p, k, m);
        let hit = self.count > saved.0 || (m == Mode::Prop && self.uses_e > saved.1);
        self.count = saved.0;
        self.uses_e = saved.1;
        self.dry = saved.2;
        self.locals = saved.3;
        self.lvals = saved.4;
        self.changed = saved_changed;
        hit
    }

    /// `transport(A, c, y, e, z. Π(e' :Irr Eq(A, c, z)). Q[z, e'], λe'. v) .e`
    /// where `q_abs` builds `Q` at local depth `k + 2` (with `z`, `e'` as the
    /// current motive variable and equation binder) and `v` is the kept proof
    /// (output coordinates at local depth `k`).
    fn transport_wrap(&mut self, k: u32, v: Tm, q_abs: &mut dyn FnMut(&mut Self) -> Tm) -> Tm {
        self.uses_e = self.uses_e.saturating_add(1);
        let saved_ye = self.ye;
        let saved_locals = (self.locals.clone(), self.lvals.clone());
        let saved_changed = self.changed.clone();
        self.push_local_changed(k, None, true);
        self.push_local_changed(k + 1, None, true);
        self.ye = Some((k, k + 1));
        let q = q_abs(self);
        self.ye = saved_ye;
        self.locals = saved_locals.0;
        self.lvals = saved_locals.1;
        self.changed = saved_changed;
        let a1 = self.outer(&self.a_tm.clone(), k + 1);
        let c1 = self.outer(&self.target.clone(), k + 1);
        let motive = Rc::new(Term::Pi {
            name: Rc::from("e"),
            rel: Rel::Irr,
            dom: Rc::new(Term::Eq { ty: a1, lhs: c1, rhs: Rc::new(Term::Var(Idx(0))) }),
            cod: q,
        });
        let a0 = self.outer(&self.a_tm.clone(), k);
        let c0 = self.outer(&self.target.clone(), k);
        let val = Rc::new(Term::Lam {
            name: Rc::from("e"),
            rel: Rel::Irr,
            dom: Rc::new(Term::Eq { ty: a0.clone(), lhs: c0.clone(), rhs: c0.clone() }),
            body: shift(&v, 1),
        });
        let tr = Rc::new(Term::Transport { ty: a0, lhs: c0, rhs: self.y(k), eq: self.e(k), motive, val });
        Rc::new(Term::App { rel: Rel::Irr, fun: tr, arg: self.e(k) })
    }

    /// Whether the irrelevant argument `arg` after the application prefix
    /// `fun` keeps the type it had, so it is kept as it is: the prefix is a
    /// global applied to arguments none of which has a relevant occurrence
    /// of `c` (the parameter type at this position is unchanged), and `arg`
    /// refers to no local binder whose type the abstraction changed (the
    /// types of context variables, globals and kept binders — λ domains,
    /// match fields — are unchanged; a proof over an abstracted `Π`/`Σ`
    /// domain is transported as before). Transporting a proof whose own type merely *mentions* `c`
    /// would give it a type the parameter does not have: a side condition
    /// `0 ≤ i` of `seq::index` — a context fact, or proven from a path
    /// equation — under a split on the scrutinee `0 ≤ i` of an enclosing
    /// match (the `Nat` guard of a spec function) must stay a proof of
    /// `0 ≤ i`, not become one of `y`.
    fn kept_side_condition(&mut self, fun: &Tm, arg: &Tm, k: u32) -> bool {
        let mut h = fun;
        while let Term::App { fun, .. } = &**h {
            h = fun;
        }
        if !matches!(&**h, Term::Global(_)) {
            return false;
        }
        !self.refers_changed(arg, k) && !self.mentions(fun, k, Mode::Val)
    }

    /// The path-equation argument `p` of the dependent-match idiom
    /// `match s as y return Π(e :Irr Eq(D, s, y)). T with .. end p`: the
    /// motive is kept, so `p` must prove `Eq(D, s, s')` with `s` as it was
    /// and `s'` the abstracted scrutinee. When the scrutinee changes, `p` —
    /// a `refl(D, s)`, or after a rewrite of the scrutinee a transported
    /// proof of `Eq(D, s, s₁)`, possibly with `s` folded where the quoted
    /// scrutinee is unfolded — is transported to exactly that type, built
    /// from the scrutinee itself (abstracting `p`'s own type instead would
    /// abstract its left side too, or miss a folded occurrence). When the
    /// scrutinee does not change, the kept motive needs `p`'s type as it
    /// was, so `p` is kept unless it refers to a binder whose type changed.
    fn idiom_arg(&mut self, scrut: &Tm, motive: &Tm, p: &Tm, k: u32) -> Tm {
        // the kept motive's equation `Eq(D, s₀, y₁)`: its type and left side
        // (terms at `k + 1`, not mentioning `y₁`), taken back to depth `k`
        let dom = match &**motive {
            Term::Pi { dom, .. } => match &**dom {
                Term::Eq { ty, lhs, rhs } if matches!(&**rhs, Term::Var(Idx(0))) => {
                    let mentions_y = |t: &Tm| crate::elab::tm::any_node_depth(t, &mut |n, b| matches!(n, Term::Var(Idx(i)) if *i == b));
                    (!mentions_y(ty) && !mentions_y(lhs)).then(|| {
                        let dummy: Tm = Rc::new(Term::Erased);
                        (crate::elab::tm::subst0(ty, &dummy), crate::elab::tm::subst0(lhs, &dummy))
                    })
                }
                _ => None,
            },
            _ => None,
        };
        if let Some((d_ty, lhs0)) = dom
            && self.mentions(scrut, k, Mode::Val)
        {
            if self.dry {
                self.uses_e = self.uses_e.saturating_add(1);
                return p.clone();
            }
            let kept = self.go(p, k, Mode::Keep);
            let scrut = scrut.clone();
            return self.transport_wrap(k, kept, &mut |s: &mut Self| {
                let d2 = s.go(&shift(&d_ty, 2), k + 2, Mode::Keep);
                let l2 = s.go(&shift(&lhs0, 2), k + 2, Mode::Keep);
                let r2 = s.go(&shift(&scrut, 2), k + 2, Mode::Val);
                Rc::new(Term::Eq { ty: d2, lhs: l2, rhs: r2 })
            });
        }
        if !self.refers_changed(p, k) && !self.mentions(scrut, k, Mode::Val) {
            return self.go(p, k, Mode::Keep);
        }
        self.irr_top(p, k)
    }

    /// Whether `t` refers to a local binder whose type the abstraction
    /// changed (see [`Abs::changed`]).
    fn refers_changed(&self, t: &Tm, k: u32) -> bool {
        let changed = &self.changed;
        // (the common case: no binder in scope was changed)
        if !changed.iter().take(k as usize).any(|c| *c) {
            return false;
        }
        crate::elab::tm::any_node_depth(t, &mut |n, b| match n {
            Term::Var(Idx(i)) if *i >= b && *i < b + k => changed.get((k - 1 - (i - b)) as usize).copied().unwrap_or(true),
            _ => false,
        })
    }

    /// A proof at the top of an irrelevant position.
    fn irr_top(&mut self, p: &Tm, k: u32) -> Tm {
        // a proof under `let`s (the facts a refined slice pattern binds for
        // an index's bound): its type is its body's, with the `let`s put in
        // (ζ), so a proof whose type mentions `c` is transported as a whole
        // instead of kept at its old type
        if matches!(&**p, Term::Let { .. }) {
            let mut z = p.clone();
            let mut n = 0;
            while let Term::Let { val, body, .. } = &*z.clone() {
                z = super::util::subst0(body, val);
                n += 1;
                if n > 16 {
                    break;
                }
            }
            if !matches!(&*z, Term::Let { .. }) && self.own_type(&z, k).is_some() {
                return self.irr_top(&z, k);
            }
        }
        if let Term::Refl { ty, val } = &**p
            && self.mentions(val, k, Mode::Val)
        {
            if self.dry {
                self.uses_e = self.uses_e.saturating_add(1);
                return p.clone();
            }
            // Expected: Eq(D, s[c], s[y]).
            let kept = self.go(p, k, Mode::Keep);
            let (ty, val) = (ty.clone(), val.clone());
            return self.transport_wrap(k, kept, &mut |s: &mut Self| {
                let d2 = s.go(&shift(&ty, 2), k + 2, Mode::Keep);
                let l2 = s.go(&shift(&val, 2), k + 2, Mode::Keep);
                let r2 = s.go(&shift(&val, 2), k + 2, Mode::Val);
                Rc::new(Term::Eq { ty: d2, lhs: l2, rhs: r2 })
            });
        }
        if let Some(pt) = self.own_type(p, k)
            && self.mentions(&pt, k, Mode::Prop)
        {
            if self.dry {
                self.uses_e = self.uses_e.saturating_add(1);
                return p.clone();
            }
            let kept = self.go(p, k, Mode::Keep);
            return self.transport_wrap(k, kept, &mut |s: &mut Self| s.go(&shift(&pt, 2), k + 2, Mode::Prop));
        }
        if !self.dry && self.own_type(p, k).is_none() && !matches!(&**p, Term::Erased | Term::Refl { .. }) {
            self.blind += 1;
        }
        self.go(p, k, Mode::Keep)
    }

    /// A proof in an irrelevant position whose expected type is built from
    /// earlier relevant parts of the same node (a constructor's earlier
    /// fields, a primitive's arguments, a pair's first component):
    /// `changed` says whether the abstraction changed one of them. When
    /// none changed and the proof refers to no binder whose type changed,
    /// its expected type is the one it had, and it is kept as it is.
    fn irr_after(&mut self, p: &Tm, k: u32, changed: bool) -> Tm {
        if !changed && !self.refers_changed(p, k) && !TRANSPORT_ALL.with(|c| c.get()) {
            return self.go(p, k, Mode::Keep);
        }
        self.irr_top(p, k)
    }

    fn go(&mut self, t: &Tm, k: u32, mode: Mode) -> Tm {
        let key = (Rc::as_ptr(t), k, mode, self.ye, self.dry);
        if let Some((r, c, u, bl)) = self.memo.get(&key) {
            // a memoized node replays its counts: on a DAG with exponential
            // sharing (an unrolled compression function) they saturate
            // instead of overflowing; only `> 0` and "changed" are read
            self.count = self.count.saturating_add(*c);
            self.uses_e = self.uses_e.saturating_add(*u);
            self.blind = self.blind.saturating_add(*bl);
            return r.clone();
        }
        // every node visited is charged to the goal (auto::meter); an
        // exhausted goal leaves the rest unchanged (the caller's kernel
        // check of the motive then fails on the zeroed budget)
        if !super::meter::spend(1) {
            return t.clone();
        }
        let (c0, u0, b0) = (self.count, self.uses_e, self.blind);
        let r = self.go_node(t, k, mode);
        self.memo.insert(key, (r.clone(), self.count - c0, self.uses_e - u0, self.blind - b0));
        self.keep.push(t.clone());
        r
    }

    fn go_node(&mut self, t: &Tm, k: u32, mode: Mode) -> Tm {
        use Mode::*;
        if matches!(mode, Val | Prop) && self.is_target(t, k) {
            self.count = self.count.saturating_add(1);
            return self.y(k);
        }
        let keep = mode == Keep;
        // Relevant sub-positions of a kept term stay kept.
        let val = if keep { Keep } else { Val };
        let prop_or = |m: Mode| if mode == Prop { Prop } else { m };
        let node = match &**t {
            Term::Var(Idx(i)) => self.var(*i, k),
            Term::Global(_) | Term::Sort(_) | Term::IntTy(_) | Term::Lit { .. } | Term::Erased => return t.clone(),
            Term::Pi { name, rel, dom, cod } => {
                let m = prop_or(Keep);
                let before = (self.count, self.uses_e);
                let dom2 = self.go(dom, k, m);
                let ch = (self.count, self.uses_e) != before;
                self.push_local_changed(k, Some(dom.clone()), ch);
                let cod2 = self.go(cod, k + 1, m);
                Term::Pi { name: name.clone(), rel: *rel, dom: dom2, cod: cod2 }
            }
            Term::Sigma { name, snd_rel, fst, snd } => {
                let m = prop_or(Keep);
                let before = (self.count, self.uses_e);
                let fst2 = self.go(fst, k, m);
                let ch = (self.count, self.uses_e) != before;
                self.push_local_changed(k, Some(fst.clone()), ch);
                let snd2 = self.go(snd, k + 1, m);
                Term::Sigma { name: name.clone(), snd_rel: *snd_rel, fst: fst2, snd: snd2 }
            }
            Term::Eq { ty, lhs, rhs } => {
                let m = if mode == Prop { Val } else { Keep };
                Term::Eq { ty: self.go(ty, k, Keep), lhs: self.go(lhs, k, m), rhs: self.go(rhs, k, m) }
            }
            Term::Ind { ind, params } => {
                let m = prop_or(Keep);
                Term::Ind { ind: *ind, params: params.iter().map(|p| self.go(p, k, m)).collect() }
            }
            Term::Lam { name, rel, dom, body } => {
                let dom2 = self.go(dom, k, Keep);
                self.push_local(k, Some(dom.clone()));
                Term::Lam { name: name.clone(), rel: *rel, dom: dom2, body: self.go(body, k + 1, val) }
            }
            Term::App { rel, fun, arg } => {
                let fm = if mode == Prop { Prop } else { val };
                let fun2 = self.go(fun, k, fm);
                // the path-equation argument of the dependent-match idiom is
                // a proof also when the match is a proposition elaborated
                // relevantly (a `Type`-valued match in a script statement
                // binds a relevant `e : Eq(D, s, y)`): its type follows the
                // kept motive, never the abstracted scrutinee
                let rel_idiom = *rel == Rel::Rel && !keep && matches!(&**fun, Term::Match { motive, .. } if idiom_eq_motive(motive));
                let arg2 = if (*rel == Rel::Irr || rel_idiom) && !keep {
                    if let Term::Match { scrut, motive, .. } = &**fun {
                        self.idiom_arg(scrut, motive, arg, k)
                    } else if self.kept_side_condition(fun, arg, k) {
                        self.go(arg, k, Keep)
                    } else {
                        self.irr_top(arg, k)
                    }
                } else {
                    self.go(arg, k, val)
                };
                Term::App { rel: *rel, fun: fun2, arg: arg2 }
            }
            Term::Let { name, rel, ty, val: v, body } => {
                let ty2 = self.go(ty, k, Keep);
                let v2 = if *rel == Rel::Irr && !keep { self.irr_top(v, k) } else { self.go(v, k, val) };
                self.push_local(k, Some(ty.clone()));
                let body2 = self.go(body, k + 1, if mode == Prop { Prop } else { val });
                Term::Let { name: name.clone(), rel: *rel, ty: ty2, val: v2, body: body2 }
            }
            Term::Pair { ty, fst, snd } => {
                let snd_irr = matches!(&**ty, Term::Sigma { snd_rel: Rel::Irr, .. });
                let ty2 = self.go(ty, k, Keep);
                let before = (self.count, self.uses_e);
                let fst2 = self.go(fst, k, val);
                let changed = (self.count, self.uses_e) != before;
                Term::Pair { ty: ty2, fst: fst2, snd: if snd_irr && !keep { self.irr_after(snd, k, changed) } else { self.go(snd, k, val) } }
            }
            Term::Fst(p) => Term::Fst(self.go(p, k, val)),
            Term::Snd(p) => Term::Snd(self.go(p, k, val)),
            Term::Refl { ty, val: v } => Term::Refl { ty: self.go(ty, k, Keep), val: self.go(v, k, val) },
            Term::Transport { ty, lhs, rhs, eq, motive, val: v } => {
                let ty2 = self.go(ty, k, Keep);
                let lhs2 = self.go(lhs, k, val);
                let rhs2 = self.go(rhs, k, val);
                let eq2 = if keep { self.go(eq, k, Keep) } else { self.irr_top(eq, k) };
                self.push_local(k, None);
                let motive2 = self.go(motive, k + 1, Keep);
                Term::Transport { ty: ty2, lhs: lhs2, rhs: rhs2, eq: eq2, motive: motive2, val: self.go(v, k, val) }
            }
            Term::Ctor { ind, ctor, params, args } => {
                let rels: Vec<Rel> = self
                    .env
                    .inductive_decl(*ind)
                    .and_then(|d| d.ctors.get(*ctor as usize).map(|c| c.fields.iter().map(|f| f.1).collect()))
                    .unwrap_or_default();
                // (the parameters are types inside a term: kept)
                let params2 = params.iter().map(|p| self.go(p, k, Keep)).collect();
                let mut args2 = Vec::with_capacity(args.len());
                // whether an earlier relevant field changed (an irrelevant
                // field's type is the declaration's at the earlier fields)
                let mut changed = false;
                for (i, a) in args.iter().enumerate() {
                    let irr = rels.get(i) == Some(&Rel::Irr);
                    if irr && !keep {
                        args2.push(self.irr_after(a, k, changed));
                    } else {
                        let before = (self.count, self.uses_e);
                        args2.push(self.go(a, k, val));
                        changed |= (self.count, self.uses_e) != before;
                    }
                }
                Term::Ctor { ind: *ind, ctor: *ctor, params: params2, args: args2 }
            }
            Term::Match { ind, params, scrut, motive, arms } => {
                let am = if mode == Prop { Prop } else { val };
                let params2 = params.iter().map(|p| self.go(p, k, Keep)).collect();
                let scrut2 = self.go(scrut, k, val);
                self.push_local(k, None);
                let motive2 = self.go(motive, k + 1, Keep);
                let mut arms2 = Vec::with_capacity(arms.len());
                for a in arms {
                    let n = a.names.len() as u32;
                    for j in 0..n {
                        self.push_local(k + j, None);
                    }
                    arms2.push(Arm { names: a.names.clone(), body: self.go(&a.body, k + n, am) });
                }
                Term::Match { ind: *ind, params: params2, scrut: scrut2, motive: motive2, arms: arms2 }
            }
            Term::Prim { op, args, proofs } => {
                let before = (self.count, self.uses_e);
                let args2 = args.iter().map(|p| self.go(p, k, val)).collect();
                // (a side condition's type is the primitive's at its arguments)
                let changed = (self.count, self.uses_e) != before;
                let proofs2 = proofs.iter().map(|p| if keep { self.go(p, k, Keep) } else { self.irr_after(p, k, changed) }).collect();
                Term::Prim { op: *op, args: args2, proofs: proofs2 }
            }
            Term::Rec { args, proof } => {
                Term::Rec { args: args.iter().map(|p| self.go(p, k, val)).collect(), proof: proof.as_ref().map(|p| self.go(p, k, Keep)) }
            }
            Term::Delta { def, args } => Term::Delta { def: *def, args: args.iter().map(|p| self.go(p, k, val)).collect() },
            Term::Unfold { def, args, to_body, val: v } => Term::Unfold {
                def: *def,
                args: args.iter().map(|p| self.go(p, k, val)).collect(),
                to_body: *to_body,
                val: self.go(v, k, val),
            },
            Term::Axiom { ax, args } => Term::Axiom { ax: *ax, args: args.iter().map(|p| self.go(p, k, Keep)).collect() },
            Term::Linarith { hyps, goal, cert } => Term::Linarith {
                hyps: hyps.iter().map(|(p, s)| (self.go(p, k, Keep), self.go(s, k, Keep))).collect(),
                goal: self.go(goal, k, Keep),
                cert: cert.clone(),
            },
            Term::BvRefl { ty, lhs, rhs } => {
                Term::BvRefl { ty: self.go(ty, k, Keep), lhs: self.go(lhs, k, Keep), rhs: self.go(rhs, k, Keep) }
            }
            Term::Absurd { ty, proof } => Term::Absurd { ty: self.go(ty, k, Keep), proof: self.go(proof, k, Keep) },
        };
        if self.dry {
            return t.clone();
        }
        Rc::new(node)
    }
}

thread_local! {
    static TRANSPORT_ALL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A simulated fault (must-reject R16, `opt::DriveFault::TransportKeptProof`)
/// while alive: [`Abs::irr_after`] transports the proofs it would keep (the
/// abstraction before that rule), so the proof builder builds an ill-typed
/// motive. Set only by the optimizer under that test hook.
pub struct TransportAll(bool);

impl TransportAll {
    pub fn new() -> TransportAll {
        TransportAll(TRANSPORT_ALL.with(|c| c.replace(true)))
    }
}

impl Default for TransportAll {
    fn default() -> Self {
        TransportAll::new()
    }
}

impl Drop for TransportAll {
    fn drop(&mut self) {
        let prev = self.0;
        TRANSPORT_ALL.with(|c| c.set(prev));
    }
}

/// Whether a match motive is the dependent-match idiom's
/// `Π(e : Eq(D, s, y)). T` (its argument is the path equation).
fn idiom_eq_motive(motive: &Tm) -> bool {
    matches!(&**motive, Term::Pi { dom, .. } if matches!(&**dom, Term::Eq { rhs, .. } if matches!(&**rhs, Term::Var(Idx(0)))))
}

/// The result of abstracting a proposition.
pub struct Abstracted {
    /// The body at depth `depth + 2`: the motive variable `y` is `Var(1)`,
    /// the equation binder `e : Eq(A, c, y)` is `Var(0)`.
    pub body: Tm,
    /// Relevant occurrences replaced by `y`.
    pub count: usize,
    /// Uses of the equation binder (transported proofs).
    pub uses_e: usize,
    /// Irrelevant proofs kept without a readable type: when this is zero, a
    /// motive the kernel finds ill-typed is a bug of the abstraction (or of
    /// the term given to it), not the documented incompleteness.
    pub blind: usize,
    /// Evaluation steps spent on semantic matching (charged by the caller).
    pub steps: u64,
}

/// Abstract `t : A` in the proposition `g` (terms at depth `depth`); the
/// types of the facts that proofs in `g` may refer to are given by level
/// (terms at `depth`); `venv0` is the context's evaluation environment and
/// `tval` the value of `t` (for semantic matching).
#[allow(clippy::too_many_arguments)]
pub fn abstract_prop(
    env: &Env,
    depth: u32,
    g: &Tm,
    t: &Tm,
    a_tm: &Tm,
    fact_types: BTreeMap<u32, Tm>,
    venv0: &VEnv,
    tval: &V,
) -> Abstracted {
    abstract_prop_opts(env, depth, g, t, a_tm, fact_types, venv0, tval, false)
}

/// [`abstract_prop`] comparing every relevant application, match,
/// primitive, variable and projection semantically (not only the subterms
/// with the target's head shape): for a target whose term and occurrences
/// have different shapes (a `let` variable and the value it stands for, a
/// builtin call and its unfolded body). Used by the optimizer's proof
/// builder.
#[allow(clippy::too_many_arguments)]
pub fn abstract_prop_loose(env: &Env, depth: u32, g: &Tm, t: &Tm, a_tm: &Tm, fact_types: BTreeMap<u32, Tm>, venv0: &VEnv, tval: &V) -> Abstracted {
    abstract_prop_opts(env, depth, g, t, a_tm, fact_types, venv0, tval, true)
}

#[allow(clippy::too_many_arguments)]
fn abstract_prop_opts(
    env: &Env,
    depth: u32,
    g: &Tm,
    t: &Tm,
    a_tm: &Tm,
    fact_types: BTreeMap<u32, Tm>,
    venv0: &VEnv,
    tval: &V,
    loose: bool,
) -> Abstracted {
    // semantic matching gets at most what remains of the goal (auto::meter)
    let start = ABS_STEPS.min(super::meter::available());
    let mut a = Abs {
        venv0: venv0.clone(),
        tval: tval.clone(),
        lvals: Vec::new(),
        budget: Budget { steps: start },
        env,
        target: t.clone(),
        tkey: key(t, 0),
        shifted: Vec::new(),
        count: 0,
        uses_e: 0,
        blind: 0,
        depth,
        a_tm: a_tm.clone(),
        fact_types,
        locals: Vec::new(),
        changed: Vec::new(),
        ye: None,
        dry: false,
        memo: std::collections::HashMap::new(),
        keep: Vec::new(),
        loose,
    };
    let body = a.go(g, 0, Mode::Prop);
    Abstracted { body, count: a.count, uses_e: a.uses_e, blind: a.blind, steps: start - a.budget.steps }
}

/// Evaluation steps available to one abstraction's semantic matching.
const ABS_STEPS: u64 = 2_000_000;

/// Levels of the free variables of `t` (a term at depth `depth`).
pub fn free_levels(t: &Tm, depth: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    fv(t, 0, depth, &mut out, &mut seen);
    out.sort();
    out.dedup();
    out
}

fn fv(t: &Tm, k: u32, depth: u32, out: &mut Vec<u32>, seen: &mut std::collections::HashSet<(*const Term, u32)>) {
    if !seen.insert((Rc::as_ptr(t), k)) {
        return;
    }
    if let Term::Var(Idx(i)) = &**t {
        if *i >= k {
            let l = depth as i64 - 1 - (*i - k) as i64;
            if l >= 0 {
                out.push(l as u32);
            }
        }
        return;
    }
    let mut kids: Vec<(Tm, u32)> = Vec::new();
    super::search::visit_children(t, &mut |c, b| kids.push((c.clone(), b)));
    for (c, b) in kids {
        fv(&c, k + b, depth, out, seen);
    }
}
