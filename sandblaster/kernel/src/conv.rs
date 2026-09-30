//! Definitional equality (DESIGN.md §5.3, §5.4, §5.9).
//!
//! Untyped NbE conversion on values with:
//! * η for functions (λ vs anything), Σ (pair vs anything; the `Irr` second
//!   component is skipped, so `(fst p, _) ≡ p` for an `Irr` Σ), and structs
//!   (a constructor of a non-recursive single-constructor inductive vs a
//!   neutral `s` compares each relevant field with `match s { c(xs) => xᵢ }`).
//!   Fixed-length array η is implemented by introducing array-typed variables
//!   in eta-expanded form (see [`crate::eval`]).
//! * Irrelevance skipping exactly per §5.3: irrelevant spine arguments,
//!   `Irr` pair components, prim proof slots, `Irr` constructor fields
//!   (the only irrelevant positions that survive in values; `Rec` proofs,
//!   `Transport.eq` and `Absurd.proof` are not stored in values at all).
//!   Irr-Σ *types* are compared fully (both components).
//! * Match eliminators are compared by scrutinee, parameters and arms; their
//!   motives are not compared (the value of a match does not depend on its
//!   motive in the set model, and both sides are well-typed at the same
//!   type). Transport neutrals are compared on every component including
//!   the motive.
//! * Checked `Shl/Shr` and `WShl/WShr` are the same function (the checked
//!   forms evaluate exactly like the wrapping ones).
//! * Memo (§5.9): scoped to one top-level [`Conv`] (one `conv` call), it
//!   records only completed positive results, keyed on the addresses of both
//!   values plus the comparison mode, and keeps `Rc` clones of both values so
//!   no address can be reused while the memo lives.
//! * Conversion never quotes values and never calls term-returning
//!   normalization. Every comparison step consumes budget.

use std::rc::Rc;

use crate::api::Env;
use crate::eval::Ev;
use crate::term::{Lvl, PrimOp, Rel, Sort, Term};
use crate::util::tick;
use crate::value::{Arg, Budget, Closure, Elim, EvalError, Head, Neutral, V, VEnv, Value};

type R<T> = Result<T, EvalError>;

/// Comparison mode stored in memo keys (only one mode exists in phase 1;
/// `BvRefl` normalization will add another, §9.8).
const MODE_DEFAULT: u8 = 0;

/// One top-level conversion problem with its memo.
///
/// `opaque`/`bv` select the evaluation mode used to instantiate closures
/// (see [`Ev`]): the default (checking) mode keeps opaque definitions
/// folded; the optimizer's transparent mode (`Env::eval_opaque`,
/// `check_residual_equal`) unfolds everything outside its opaque set.
pub(crate) struct Conv<'e> {
    env: &'e Env,
    memo: crate::util::FxSet<(usize, usize, u8)>,
    /// Keeps every memoized pair alive (no address reuse, §5.9).
    keep: Vec<(V, V)>,
    mode: u8,
    opaque: Option<&'e dyn Fn(crate::term::GlobalId) -> bool>,
    bv: bool,
    transparent: bool,
    /// Evaluation memo for closure instantiations (shared closure bodies
    /// are evaluated as DAGs; see `eval::EvalMemo`).
    ev_memo: Rc<std::cell::RefCell<crate::eval::EvalMemo>>,
}

fn addr(v: &V) -> usize {
    Rc::as_ptr(v) as *const () as usize
}

fn same_op(a: PrimOp, b: PrimOp) -> bool {
    use PrimOp::*;
    a == b || matches!((a, b), (Shl(x), WShl(y)) | (WShl(x), Shl(y)) | (Shr(x), WShr(y)) | (WShr(x), Shr(y)) if x == y)
}

impl<'e> Conv<'e> {
    pub fn new(env: &'e Env) -> Self {
        Conv {
            env,
            memo: Default::default(),
            keep: Vec::new(),
            mode: MODE_DEFAULT,
            opaque: None,
            bv: false,
            transparent: false,
            ev_memo: Default::default(),
        }
    }

    /// Conversion whose closure instantiations use the evaluation mode of `ev`.
    pub fn like(ev: &Ev<'e>) -> Self {
        Conv { opaque: ev.opaque, bv: ev.bv, transparent: ev.transparent, ..Conv::new(ev.env) }
    }

    /// Conversion in the optimizer's transparent mode with the given opaque
    /// set (see [`crate::api::Env::conv_opaque`]).
    pub fn with_opaque(env: &'e Env, opaque: &'e dyn Fn(crate::term::GlobalId) -> bool) -> Self {
        Conv { opaque: Some(opaque), ..Conv::new(env) }
    }

    /// Conversion in the fully transparent mode (see
    /// [`crate::api::Env::eval_transparent`]).
    pub fn transparent(env: &'e Env) -> Self {
        Conv::like(&Ev::transparent(env))
    }

    fn ev(&self) -> Ev<'e> {
        let mut ev = match self.opaque {
            Some(f) => Ev::with_opaque(self.env, f),
            None => Ev::new(self.env),
        };
        ev.bv = self.bv;
        ev.transparent = self.transparent;
        ev.sharing(self.ev_memo.clone())
    }

    /// Are `a` and `b` definitionally equal? Both live at `depth`.
    pub fn conv(&mut self, depth: Lvl, a: &V, b: &V, bud: &mut Budget) -> R<bool> {
        tick(bud)?;
        if Rc::ptr_eq(a, b) {
            return Ok(true);
        }
        let key = (addr(a), addr(b), self.mode);
        if self.memo.contains(&key) {
            return Ok(true);
        }
        let r = self.conv_inner(depth, a, b, bud)?;
        if r {
            self.memo.insert(key);
            self.keep.push((a.clone(), b.clone()));
        }
        Ok(r)
    }

    fn conv_arg(&mut self, depth: Lvl, a: &Arg, b: &Arg, bud: &mut Budget) -> R<bool> {
        match (a, b) {
            (Arg::Rel(x), Arg::Rel(y)) => self.conv(depth, x, y, bud),
            (Arg::Irr(_), Arg::Irr(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    fn conv_args(&mut self, depth: Lvl, a: &[Arg], b: &[Arg], bud: &mut Budget) -> R<bool> {
        if a.len() != b.len() {
            return Ok(false);
        }
        for (x, y) in a.iter().zip(b) {
            if !self.conv_arg(depth, x, y, bud)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn conv_vals(&mut self, depth: Lvl, a: &[V], b: &[V], bud: &mut Budget) -> R<bool> {
        if a.len() != b.len() {
            return Ok(false);
        }
        for (x, y) in a.iter().zip(b) {
            if !self.conv(depth, x, y, bud)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Compare two closures under one fresh variable of type `dom`.
    fn conv_closures(&mut self, depth: Lvl, rel: Rel, dom: &V, c1: &Closure, c2: &Closure, bud: &mut Budget) -> R<bool> {
        let mut ev = self.ev();
        let x = ev.fresh(depth, rel, dom);
        let v1 = ev.inst_root(c1, x.clone(), Lvl(depth.0 + 1), bud)?;
        let v2 = ev.inst_root(c2, x, Lvl(depth.0 + 1), bud)?;
        self.conv(Lvl(depth.0 + 1), &v1, &v2, bud)
    }

    /// η for functions: compare `body[x]` with `other x`.
    fn eta_lam(&mut self, depth: Lvl, rel: Rel, dom: &V, body: &Closure, other: &V, bud: &mut Budget) -> R<bool> {
        let mut ev = self.ev();
        let x = ev.fresh(depth, rel, dom);
        let arg = crate::util::entry_arg(&x);
        let d1 = Lvl(depth.0 + 1);
        let v1 = ev.inst_root(body, x, d1, bud)?;
        let v2 = ev.apply(other, arg, d1, bud)?;
        self.conv(d1, &v1, &v2, bud)
    }

    /// η for Σ: compare a pair with a (neutral) value through projections.
    fn eta_pair(&mut self, depth: Lvl, fst: &V, snd: &Arg, other: &V, bud: &mut Budget) -> R<bool> {
        let mut ev = self.ev();
        let of = ev.fst(other);
        if !self.conv(depth, fst, &of, bud)? {
            return Ok(false);
        }
        match snd {
            Arg::Irr(_) => Ok(true),
            Arg::Rel(s) => {
                let os = ev.snd(other, depth, bud)?;
                self.conv(depth, s, &os, bud)
            }
        }
    }

    /// η for structs: `c(ps; a₁..aₙ) ≡ n` iff every relevant `aᵢ ≡ πᵢ n`.
    fn eta_struct(&mut self, depth: Lvl, ctor_v: &V, n: &Neutral, bud: &mut Budget) -> R<bool> {
        let Value::Ctor { ind, params, args, .. } = &**ctor_v else { return Ok(false) };
        let nf = args.len();
        for (j, a) in args.iter().enumerate() {
            let Arg::Rel(a) = a else { continue };
            let proj = Elim::Match {
                ind: *ind,
                params: params.clone(),
                motive: Closure { env: VEnv::default(), body: Rc::new(Term::Sort(Sort::Type)) },
                arms: vec![Closure { env: VEnv::default(), body: Rc::new(Term::Var(crate::term::Idx((nf - 1 - j) as u32))) }],
            };
            let mut spine: Vec<Elim> = n.spine.iter().map(crate::eval::clone_elim).collect();
            spine.push(proj);
            let p = crate::eval::neu(crate::eval::clone_head(&n.head), spine);
            if !self.conv(depth, a, &p, bud)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn struct_like(&self, v: &V) -> bool {
        match &**v {
            Value::Ctor { ind, .. } => self.env.inds.get(ind.0 as usize).is_some_and(|i| i.struct_like()),
            _ => false,
        }
    }

    fn conv_inner(&mut self, depth: Lvl, a: &V, b: &V, bud: &mut Budget) -> R<bool> {
        use Value::*;
        match (&**a, &**b) {
            (Sort(x), Sort(y)) => Ok(x == y),
            (IntTy(x), IntTy(y)) => Ok(x == y),
            (Lit { w: w1, n: n1 }, Lit { w: w2, n: n2 }) => Ok(w1 == w2 && n1 == n2),
            (Pi { rel: r1, dom: d1, cod: c1, .. }, Pi { rel: r2, dom: d2, cod: c2, .. }) => {
                Ok(r1 == r2 && self.conv(depth, d1, d2, bud)? && self.conv_closures(depth, *r1, d1, c1, c2, bud)?)
            }
            (Sigma { snd_rel: r1, fst: f1, snd: s1, .. }, Sigma { snd_rel: r2, fst: f2, snd: s2, .. }) => {
                Ok(r1 == r2 && self.conv(depth, f1, f2, bud)? && self.conv_closures(depth, Rel::Rel, f1, s1, s2, bud)?)
            }
            (Lam { rel: r1, dom, body: b1, .. }, Lam { rel: r2, body: b2, .. }) => {
                Ok(r1 == r2 && self.conv_closures(depth, *r1, dom, b1, b2, bud)?)
            }
            (Lam { rel, dom, body, .. }, _) => self.eta_lam(depth, *rel, dom, body, b, bud),
            (_, Lam { rel, dom, body, .. }) => self.eta_lam(depth, *rel, dom, body, a, bud),
            (Pair { fst: f1, snd: s1 }, Pair { fst: f2, snd: s2 }) => {
                Ok(self.conv(depth, f1, f2, bud)? && self.conv_arg(depth, s1, s2, bud)?)
            }
            (Pair { fst, snd }, Neu(_)) => self.eta_pair(depth, fst, snd, b, bud),
            (Neu(_), Pair { fst, snd }) => self.eta_pair(depth, fst, snd, a, bud),
            (Eq { ty: t1, lhs: l1, rhs: r1 }, Eq { ty: t2, lhs: l2, rhs: r2 }) => {
                Ok(self.conv(depth, t1, t2, bud)? && self.conv(depth, l1, l2, bud)? && self.conv(depth, r1, r2, bud)?)
            }
            // Proofs of equalities in relevant positions: refl vs refl (UIP).
            (Refl { .. }, Refl { .. }) => Ok(true),
            (Ind { ind: i1, params: p1 }, Ind { ind: i2, params: p2 }) => Ok(i1 == i2 && self.conv_vals(depth, p1, p2, bud)?),
            (Ctor { ind: i1, ctor: c1, params: p1, args: a1 }, Ctor { ind: i2, ctor: c2, params: p2, args: a2 }) => {
                Ok(i1 == i2 && c1 == c2 && self.conv_vals(depth, p1, p2, bud)? && self.conv_args(depth, a1, a2, bud)?)
            }
            (Ctor { .. }, Neu(n)) if self.struct_like(a) => self.eta_struct(depth, a, n, bud),
            (Neu(n), Ctor { .. }) if self.struct_like(b) => self.eta_struct(depth, b, n, bud),
            (Neu(n1), Neu(n2)) => self.conv_neutral(depth, n1, n2, bud),
            _ => Ok(false),
        }
    }

    fn conv_neutral(&mut self, depth: Lvl, n1: &Neutral, n2: &Neutral, bud: &mut Budget) -> R<bool> {
        if n1.spine.len() != n2.spine.len() || !self.conv_head(depth, &n1.head, &n2.head, bud)? {
            return Ok(false);
        }
        for (e1, e2) in n1.spine.iter().zip(&n2.spine) {
            let ok = match (e1, e2) {
                (Elim::App(a1), Elim::App(a2)) => self.conv_arg(depth, a1, a2, bud)?,
                (Elim::Fst, Elim::Fst) | (Elim::Snd, Elim::Snd) => true,
                (Elim::Match { ind: i1, params: p1, arms: arms1, .. }, Elim::Match { ind: i2, params: p2, arms: arms2, .. }) => {
                    i1 == i2 && self.conv_vals(depth, p1, p2, bud)? && self.conv_arms(depth, *i1, p1, arms1, arms2, bud)?
                }
                _ => false,
            };
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Compare the arms of two match eliminators. Arm `k` is instantiated with
    /// fresh variables for the fields of constructor `k`, introduced exactly
    /// as the checker and the quoter introduce them ([`Ev::arm_fields`]): a
    /// field of fixed-length array type is eta-expanded (§5.9). (Plain
    /// variables here made a quoted-and-re-evaluated stuck match that binds
    /// an array field inconvertible with the original: phase-2 issue K1.)
    fn conv_arms(
        &mut self,
        depth: Lvl,
        ind: crate::term::IndId,
        params: &[V],
        a1: &[Closure],
        a2: &[Closure],
        bud: &mut Budget,
    ) -> R<bool> {
        if a1.len() != a2.len() {
            return Ok(false);
        }
        for (k, (c1, c2)) in a1.iter().zip(a2).enumerate() {
            let mut ev = self.ev();
            let es = ev.arm_fields(depth, ind, k as u32, params, bud)?;
            let d2 = Lvl(depth.0 + es.len() as u32);
            let v1 = ev.inst_n_root(c1, es.clone(), d2, bud)?;
            let v2 = ev.inst_n_root(c2, es, d2, bud)?;
            if !self.conv(d2, &v1, &v2, bud)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn conv_head(&mut self, depth: Lvl, h1: &Head, h2: &Head, bud: &mut Budget) -> R<bool> {
        match (h1, h2) {
            (Head::Var(l1), Head::Var(l2)) => Ok(l1 == l2),
            (Head::Global { def: d1, args: a1 }, Head::Global { def: d2, args: a2 }) => Ok(d1 == d2 && self.conv_args(depth, a1, a2, bud)?),
            (Head::Prim { op: o1, args: a1, .. }, Head::Prim { op: o2, args: a2, .. }) => {
                Ok(same_op(*o1, *o2) && self.conv_vals(depth, a1, a2, bud)?)
            }
            (Head::Absurd { ty: t1 }, Head::Absurd { ty: t2 }) => self.conv(depth, t1, t2, bud),
            (
                Head::Transport { ty: t1, lhs: l1, rhs: r1, motive: m1, val: v1 },
                Head::Transport { ty: t2, lhs: l2, rhs: r2, motive: m2, val: v2 },
            ) => Ok(self.conv(depth, t1, t2, bud)?
                && self.conv(depth, l1, l2, bud)?
                && self.conv(depth, r1, r2, bud)?
                && self.conv(depth, v1, v2, bud)?
                && self.conv_closures(depth, Rel::Rel, t1, m1, m2, bud)?),
            (Head::Axiom { ax: x1, args: a1 }, Head::Axiom { ax: x2, args: a2 }) => Ok(x1 == x2 && self.conv_args(depth, a1, a2, bud)?),
            _ => Ok(false),
        }
    }
}
