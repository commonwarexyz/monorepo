//! The facts of one path of the process graph (optimizer design §5
//! `FactSet`, §6.3 "fact normalization").
//!
//! * **Linear facts** are context binders of the path's `auto` state
//!   ([`St`]): the `requires` binders and the path equation of every
//!   enclosing split (`e : Eq(D, scrut, Cₖ(fields))`). Linear arithmetic
//!   ([`crate::auto`]) reads them in the forms `DESIGN.md` §5.8.2 accepts;
//!   the disjunctive forms `ne(a, b) == true` / `eq(a, b) == false` are
//!   never handed to the simplex as such: `auto` turns an unsigned `a ≠ 0`
//!   into `0 < a` and splits other disequalities on demand (`lt(a, b)`,
//!   then `lt(b, a)`; the remaining case contradicts the fact), which is
//!   exactly the normalization of design §6.3 — it makes
//!   `h < 2 ∧ h ≠ 0 ⊢ h = 1` provable.
//! * **The decision cache** maps a split scrutinee to the constructor its
//!   arm fixed, with the arm's field values and the level of its path
//!   equation: a later stuck match on a convertible scrutinee is decided by
//!   it (`Reuse`).

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId, Lvl};
use sandblaster_kernel::value::{Arg, Budget, V};

use crate::auto::state::{Origin, St};
use crate::prover::FactOrigin;

/// A scrutinee decided by an enclosing split.
#[derive(Clone, Debug)]
pub struct Decided {
    pub scrut: V,
    pub ind: IndId,
    pub ctor: u32,
    /// The arm's field values (fresh variables of the arm).
    pub fields: Vec<Arg>,
    /// Level of the arm's path equation.
    pub eq_lvl: u32,
}

/// The facts of one path.
#[derive(Clone, Default)]
pub struct Facts {
    pub decided: Vec<Decided>,
}

impl Facts {
    /// The decision for `scrut`, if an enclosing split fixed a convertible
    /// scrutinee (compared in the driver's evaluation mode).
    pub fn lookup(&self, env: &Env, depth: u32, scrut: &V, ind: IndId, opaque: &dyn Fn(GlobalId) -> bool, b: &mut Budget) -> Option<Decided> {
        for d in self.decided.iter().rev() {
            if d.ind != ind {
                continue;
            }
            if std::rc::Rc::ptr_eq(&d.scrut, scrut) || env.conv_opaque(Lvl(depth), &d.scrut, scrut, opaque, b).unwrap_or(false) {
                return Some(d.clone());
            }
        }
        None
    }
}

/// Registers the `requires` binders of a function's telescope (the
/// irrelevant binders after the parameters) as facts of the root state.
pub fn register_requires(st: &mut St, from: u32) {
    let n = st.ctx.entries.len() as u32;
    for lvl in from..n {
        let e = &st.ctx.entries[lvl as usize];
        if e.rel == sandblaster_kernel::term::Rel::Irr {
            let ty = e.ty.clone();
            st.add_ctx_fact(lvl, ty, Origin::Goal(Some(FactOrigin::Requires)));
        }
    }
}

// ---------------------------------------------------------------------------
// Which decisions are worth a linear-arithmetic query (untrusted filter).
// ---------------------------------------------------------------------------

use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};
use sandblaster_kernel::term::{PrimOp, Width};
use sandblaster_kernel::value::{Head, Value};

/// What the interval pre-check says about a boolean scrutinee (optimizer
/// design §6.3: a decision is attempted where the facts can decide it).
/// Untrusted: it only chooses which conditions are handed to linear
/// arithmetic (whose certificate the kernel checks); a wrong verdict costs
/// a failed query or a missed prune, never soundness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decidable {
    /// Interval bounds from the path's literal-bound facts and the
    /// operations' ranges decide it.
    ByIntervals,
    /// It shares an atom with a fact relating several atoms (`acc + n·B ≤
    /// MAX`): only linear arithmetic can tell.
    Relational,
    /// Neither: bounds do not decide it and no relational fact touches it
    /// (a split without a query: the query would fail).
    No,
}

/// A closed integer interval (`None`: unbounded on that side).
#[derive(Clone, Debug)]
struct Iv {
    lo: Option<BigInt>,
    hi: Option<BigInt>,
}

impl Iv {
    fn exact(n: BigInt) -> Iv {
        Iv { lo: Some(n.clone()), hi: Some(n) }
    }
    fn width(w: Width) -> Iv {
        match w.bits() {
            Some(_) => Iv { lo: Some(BigInt::zero()), hi: Some(sandblaster_kernel::prim::max_of(w)) },
            None => Iv { lo: None, hi: None },
        }
    }
    fn meet(&self, o: &Iv) -> Iv {
        let lo = match (&self.lo, &o.lo) {
            (Some(a), Some(b)) => Some(a.max(b).clone()),
            (a, b) => a.clone().or(b.clone()),
        };
        let hi = match (&self.hi, &o.hi) {
            (Some(a), Some(b)) => Some(a.min(b).clone()),
            (a, b) => a.clone().or(b.clone()),
        };
        Iv { lo, hi }
    }
}

/// A structural key of a value (literals, heads, relevant arguments;
/// irrelevant proofs ignored), for matching atoms between facts and a
/// condition.
fn vkey(v: &V, depth: u32) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    fn go(v: &V, depth: u32, h: &mut std::collections::hash_map::DefaultHasher) {
        use std::hash::Hash;
        if depth == 0 {
            (std::rc::Rc::as_ptr(v) as usize).hash(h);
            return;
        }
        match &**v {
            Value::Lit { w, n } => {
                0u8.hash(h);
                format!("{w:?}").hash(h);
                n.hash(h);
            }
            Value::IntTy(w) => {
                7u8.hash(h);
                format!("{w:?}").hash(h);
            }
            Value::Sort(s) => {
                8u8.hash(h);
                format!("{s:?}").hash(h);
            }
            Value::Ind { ind, params } => {
                9u8.hash(h);
                ind.hash(h);
                for p in params {
                    go(p, depth - 1, h);
                }
            }
            Value::Ctor { ind, ctor, args, .. } => {
                1u8.hash(h);
                ind.hash(h);
                ctor.hash(h);
                for a in args {
                    if let Arg::Rel(x) = a {
                        go(x, depth - 1, h);
                    }
                }
            }
            Value::Pair { fst, snd } => {
                2u8.hash(h);
                go(fst, depth - 1, h);
                if let Arg::Rel(x) = snd {
                    go(x, depth - 1, h);
                }
            }
            Value::Neu(n) => {
                3u8.hash(h);
                match &n.head {
                    Head::Var(l) => {
                        0u8.hash(h);
                        l.hash(h);
                    }
                    Head::Global { def, args } => {
                        1u8.hash(h);
                        def.hash(h);
                        for a in args {
                            if let Arg::Rel(x) = a {
                                go(x, depth - 1, h);
                            }
                        }
                    }
                    Head::Prim { op, args, .. } => {
                        2u8.hash(h);
                        format!("{op:?}").hash(h);
                        for x in args {
                            go(x, depth - 1, h);
                        }
                    }
                    _ => (std::rc::Rc::as_ptr(v) as usize).hash(h),
                }
                for e in &n.spine {
                    match e {
                        sandblaster_kernel::value::Elim::Fst => 4u8.hash(h),
                        sandblaster_kernel::value::Elim::Snd => 5u8.hash(h),
                        sandblaster_kernel::value::Elim::App(Arg::Rel(x)) => go(x, depth - 1, h),
                        sandblaster_kernel::value::Elim::App(Arg::Irr(_)) => 6u8.hash(h),
                        // a field projection (every arm a variable): by the
                        // field, so the same projection built twice (a
                        // fact lemma's statement, the source's `s.f`)
                        // shares its bounds
                        sandblaster_kernel::value::Elim::Match { ind, arms, .. } if arms.iter().all(|a| matches!(&*a.body, sandblaster_kernel::term::Term::Var(_))) => {
                            10u8.hash(h);
                            ind.hash(h);
                            for a in arms {
                                if let sandblaster_kernel::term::Term::Var(k) = &*a.body {
                                    k.hash(h);
                                }
                            }
                        }
                        sandblaster_kernel::value::Elim::Match { .. } => (std::rc::Rc::as_ptr(v) as usize).hash(h),
                    }
                }
            }
            _ => (std::rc::Rc::as_ptr(v) as usize).hash(h),
        }
    }
    go(v, depth, &mut h);
    let _ = h.finish().hash(&mut std::collections::hash_map::DefaultHasher::new());
    h.finish()
}

fn prim_of(v: &V) -> Option<(PrimOp, &[V])> {
    match &**v {
        Value::Neu(n) if n.spine.is_empty() => match &n.head {
            Head::Prim { op, args, .. } => Some((*op, args)),
            _ => None,
        },
        _ => None,
    }
}

fn lit_of(v: &V) -> Option<BigInt> {
    match &**v {
        Value::Lit { n, .. } => Some(n.clone()),
        _ => None,
    }
}

/// The linear leaves of a value (what linear arithmetic sees as atoms):
/// below additions, subtractions, literal multiples and widening casts.
fn linear_atoms(v: &V, out: &mut Vec<u64>, budget: &mut u32) {
    if *budget == 0 {
        return;
    }
    *budget -= 1;
    if lit_of(v).is_some() {
        return;
    }
    match prim_of(v) {
        Some((PrimOp::Add(_) | PrimOp::Sub(_) | PrimOp::WAdd(_) | PrimOp::WSub(_) | PrimOp::IAdd | PrimOp::ISub, args)) => {
            for a in args {
                linear_atoms(a, out, budget);
            }
        }
        Some((PrimOp::Mul(_) | PrimOp::WMul(_) | PrimOp::IMul, args)) if args.iter().any(|a| lit_of(a).is_some()) => {
            for a in args {
                linear_atoms(a, out, budget);
            }
        }
        Some((PrimOp::Cast { .. } | PrimOp::INeg, args)) => linear_atoms(&args[0], out, budget),
        _ => out.push(vkey(v, 24)),
    }
}

/// The literal bounds the facts of `st` give (by atom key), and the atoms
/// that occur in facts relating several atoms.
struct Bounds {
    by_key: HashMap<u64, Iv>,
    /// The facts (by level) each bound came from.
    from: HashMap<u64, Vec<u32>>,
    relational: std::collections::HashSet<u64>,
    /// The facts whose bounds a range computation read.
    used: std::cell::RefCell<Vec<u32>>,
    /// The fact being read (while building).
    cur: u32,
}

use std::collections::HashMap;

fn bool_lit(v: &V) -> Option<bool> {
    match &**v {
        Value::Ctor { ctor, args, .. } if args.is_empty() && *ctor <= 1 => Some(*ctor == 1),
        _ => None,
    }
}

impl Bounds {
    fn empty() -> Bounds {
        Bounds { by_key: HashMap::new(), from: HashMap::new(), relational: Default::default(), used: Default::default(), cur: 0 }
    }

    fn of(st: &St) -> Bounds {
        let mut b = Bounds { by_key: HashMap::new(), from: HashMap::new(), relational: std::collections::HashSet::new(), used: std::cell::RefCell::new(Vec::new()), cur: 0 };
        for f in &st.facts {
            b.cur = f.lvl;
            let Value::Eq { lhs, rhs, .. } = &*f.ty else { continue };
            let (cmp, truth) = match bool_lit(rhs) {
                Some(t) => (lhs.clone(), t),
                None => {
                    // `Eq(IntTy, a, b)`: a two-sided bound when one side is a literal
                    match (lit_of(lhs), lit_of(rhs)) {
                        (Some(n), None) => b.bound(rhs, Iv::exact(n)),
                        (None, Some(n)) => b.bound(lhs, Iv::exact(n)),
                        _ => b.relate(&[lhs.clone(), rhs.clone()]),
                    }
                    continue;
                }
            };
            let Some((op, args)) = prim_of(&cmp) else { continue };
            if args.len() != 2 {
                continue;
            }
            // normalize `x op n` / `n op x` with `truth` into a bound on x
            let (x, n, flip) = match (lit_of(&args[0]), lit_of(&args[1])) {
                (None, Some(n)) => (args[0].clone(), n, false),
                (Some(n), None) => (args[1].clone(), n, true),
                (None, None) => {
                    b.relate(&[args[0].clone(), args[1].clone()]);
                    continue;
                }
                _ => continue,
            };
            let one = BigInt::one();
            // the relation `x R n` that holds
            // an unsigned `x ≠ 0` keeps only `x ≥ 1` (design §6.3)
            if matches!((op, truth), (PrimOp::Ne(w), true) | (PrimOp::Eq(w), false) if w.bits().is_some()) && n.is_zero() {
                b.bound(&x, Iv { lo: Some(BigInt::one()), hi: None });
                continue;
            }
            let rel = match (op, truth) {
                (PrimOp::Lt(_), true) | (PrimOp::Ge(_), false) => Some("lt"),
                (PrimOp::Le(_), true) | (PrimOp::Gt(_), false) => Some("le"),
                (PrimOp::Gt(_), true) | (PrimOp::Le(_), false) => Some("gt"),
                (PrimOp::Ge(_), true) | (PrimOp::Lt(_), false) => Some("ge"),
                (PrimOp::Eq(_), true) => Some("eq"),
                _ => None,
            };
            let Some(rel) = rel else { continue };
            let rel = if flip {
                match rel {
                    "lt" => "gt",
                    "le" => "ge",
                    "gt" => "lt",
                    "ge" => "le",
                    r => r,
                }
            } else {
                rel
            };
            let iv = match rel {
                "lt" => Iv { lo: None, hi: Some(n - &one) },
                "le" => Iv { lo: None, hi: Some(n) },
                "gt" => Iv { lo: Some(n + &one), hi: None },
                "ge" => Iv { lo: Some(n), hi: None },
                _ => Iv::exact(n),
            };
            let mut atoms = Vec::new();
            let mut bud = 64;
            linear_atoms(&x, &mut atoms, &mut bud);
            if atoms.len() >= 2 {
                b.relational.extend(atoms);
            } else {
                b.bound(&x, iv);
            }
        }
        b
    }

    fn bound(&mut self, x: &V, iv: Iv) {
        let k = vkey(x, 24);
        let cur = self.by_key.remove(&k).unwrap_or(Iv { lo: None, hi: None });
        self.by_key.insert(k, cur.meet(&iv));
        self.from.entry(k).or_default().push(self.cur);
    }

    fn relate(&mut self, vs: &[V]) {
        for v in vs {
            let mut atoms = Vec::new();
            let mut bud = 64;
            linear_atoms(v, &mut atoms, &mut bud);
            self.relational.extend(atoms);
        }
    }

    /// The interval of `v : IntTy(w)`.
    fn range(&self, v: &V, w: Width, fuel: &mut u32) -> Iv {
        let ty = Iv::width(w);
        if *fuel == 0 {
            return ty;
        }
        *fuel -= 1;
        if let Some(n) = lit_of(v) {
            return Iv::exact(n);
        }
        let key = vkey(v, 24);
        let known = self.by_key.get(&key).cloned().unwrap_or(Iv { lo: None, hi: None });
        if let Some(fs) = self.from.get(&key) {
            self.used.borrow_mut().extend(fs.iter().copied());
        }
        let two = |k: u64| -> BigInt { BigInt::one() << (k as usize) };
        let derived = match prim_of(v) {
            Some((op, args)) => match op {
                PrimOp::Or(x) => {
                    let (a, b) = (self.range(&args[0], x, fuel), self.range(&args[1], x, fuel));
                    Iv { lo: a.lo.clone().zip(b.lo.clone()).map(|(p, q)| p.max(q)), hi: a.hi.zip(b.hi).map(|(p, q)| p + q) }
                }
                PrimOp::And(x) => {
                    let (a, b) = (self.range(&args[0], x, fuel), self.range(&args[1], x, fuel));
                    // `a & (2^k − 1)` with `a < 2^k` is `a`
                    let mask_covers = |m: &Iv, o: &Iv| m.lo.is_some() && m.lo == m.hi && m.lo.as_ref().is_some_and(|m| { let p = m + BigInt::one(); p.is_positive() && (&p & (&p - BigInt::one())).is_zero() }) && o.hi.as_ref().zip(m.hi.as_ref()).is_some_and(|(h, m)| h <= m);
                    if mask_covers(&b, &a) {
                        a
                    } else if mask_covers(&a, &b) {
                        b
                    } else {
                        let hi = match (a.hi, b.hi) {
                            (Some(p), Some(q)) => Some(p.min(q)),
                            (p, q) => p.or(q),
                        };
                        Iv { lo: Some(BigInt::zero()), hi }
                    }
                }
                PrimOp::Shl(x) | PrimOp::WShl(x) => match (lit_of(&args[1]), x.bits()) {
                    (Some(k), Some(bits)) if k >= BigInt::zero() && k < BigInt::from(bits) => {
                        let k: u64 = num_traits::ToPrimitive::to_u64(&k).unwrap_or(0);
                        let a = self.range(&args[0], x, fuel);
                        match (&a.lo, &a.hi) {
                            (Some(lo), Some(hi)) if (hi.clone() << (k as usize)) <= sandblaster_kernel::prim::max_of(x) => Iv { lo: Some(lo * two(k)), hi: Some(hi * two(k)) },
                            _ => Iv::width(x),
                        }
                    }
                    _ => Iv::width(x),
                },
                PrimOp::Shr(x) | PrimOp::WShr(x) => match lit_of(&args[1]) {
                    Some(k) if k >= BigInt::zero() => {
                        let k: u64 = num_traits::ToPrimitive::to_u64(&k).unwrap_or(0);
                        let a = self.range(&args[0], x, fuel);
                        Iv { lo: a.lo.map(|p| p >> (k as usize)), hi: a.hi.map(|p| p >> (k as usize)) }
                    }
                    _ => Iv { lo: Some(BigInt::zero()), hi: self.range(&args[0], x, fuel).hi },
                },
                PrimOp::Cast { from, to } if to == Width::Int || from.bits().zip(to.bits()).is_some_and(|(f, t)| f <= t) => self.range(&args[0], from, fuel),
                PrimOp::Add(_) | PrimOp::WAdd(_) | PrimOp::IAdd | PrimOp::Sub(_) | PrimOp::WSub(_) | PrimOp::ISub => {
                    let wx = match op {
                        PrimOp::Add(x) | PrimOp::WAdd(x) | PrimOp::Sub(x) | PrimOp::WSub(x) => x,
                        _ => Width::Int,
                    };
                    let x = wx;
                    let (a, b) = (self.range(&args[0], wx, fuel), self.range(&args[1], wx, fuel));
                    let sub = matches!(op, PrimOp::Sub(_) | PrimOp::WSub(_) | PrimOp::ISub);
                    let exact = !matches!(op, PrimOp::WAdd(_) | PrimOp::WSub(_));
                    if !exact {
                        Iv::width(x)
                    } else if sub {
                        Iv { lo: a.lo.zip(b.hi.clone()).map(|(p, q)| p - q), hi: a.hi.zip(b.lo).map(|(p, q)| p - q) }
                    } else {
                        Iv { lo: a.lo.zip(b.lo).map(|(p, q)| p + q), hi: a.hi.zip(b.hi).map(|(p, q)| p + q) }
                    }
                }
                PrimOp::Mul(_) | PrimOp::IMul => match (lit_of(&args[0]), lit_of(&args[1])) {
                    (Some(k), None) | (None, Some(k)) if !k.is_negative() => {
                        let o = if lit_of(&args[0]).is_some() { &args[1] } else { &args[0] };
                        let wx = if let PrimOp::Mul(x) = op { x } else { Width::Int };
                        let a = self.range(o, wx, fuel);
                        Iv { lo: a.lo.map(|p| p * &k), hi: a.hi.map(|p| p * &k) }
                    }
                    _ => Iv { lo: None, hi: None },
                },
                _ => Iv { lo: None, hi: None },
            },
            None => Iv { lo: None, hi: None },
        };
        ty.meet(&known).meet(&derived)
    }
}

/// See [`Decidable`]; with [`Decidable::ByIntervals`], the facts (by
/// level) whose bounds decided it — the only ones a query needs.
pub fn decidable(st: &St, c: &V) -> Decidable {
    decidable_with(st, c).0
}

/// [`decidable`] and the facts that decide it by intervals.
pub fn decidable_with(st: &St, c: &V) -> (Decidable, Vec<u32>) {
    let Some((op, args)) = prim_of(c) else {
        // boolean combinations and variables: left to the query
        return (Decidable::Relational, vec![]);
    };
    let w = match op {
        PrimOp::Lt(w) | PrimOp::Le(w) | PrimOp::Gt(w) | PrimOp::Ge(w) | PrimOp::Eq(w) | PrimOp::Ne(w) => w,
        _ => return (Decidable::Relational, vec![]),
    };
    if args.len() != 2 {
        return (Decidable::Relational, vec![]);
    }
    let b = Bounds::of(st);
    let mut atoms = Vec::new();
    let mut bud = 256;
    for a in args {
        linear_atoms(a, &mut atoms, &mut bud);
    }
    if atoms.iter().any(|a| b.relational.contains(a)) {
        return (Decidable::Relational, vec![]);
    }
    let decides = |b: &Bounds| -> Option<bool> { interval_outcome(b, op, w, &args[0], &args[1]) };
    // the operations' ranges alone first (no fact needed), then with the
    // facts' bounds
    let bare = Bounds::empty();
    if decides(&bare).is_some() {
        return (Decidable::ByIntervals, vec![]);
    }
    if decides(&b).is_some() {
        let mut used = b.used.into_inner();
        used.sort();
        used.dedup();
        (Decidable::ByIntervals, used)
    } else {
        (Decidable::No, vec![])
    }
}

/// The comparison `x op y` (at width `w`) as the intervals decide it.
fn interval_outcome(b: &Bounds, op: PrimOp, w: Width, xv: &V, yv: &V) -> Option<bool> {
    let mut fuel = 4096;
    let (x, y) = (b.range(xv, w, &mut fuel), b.range(yv, w, &mut fuel));
    let le = |p: &Option<BigInt>, q: &Option<BigInt>| p.as_ref().zip(q.as_ref()).is_some_and(|(p, q)| p <= q);
    let lt = |p: &Option<BigInt>, q: &Option<BigInt>| p.as_ref().zip(q.as_ref()).is_some_and(|(p, q)| p < q);
    // `x < y` / `x ≤ y` true, or false
    let (t, f) = match op {
        PrimOp::Lt(_) => (lt(&x.hi, &y.lo), le(&y.hi, &x.lo)),
        PrimOp::Ge(_) => (le(&y.hi, &x.lo), lt(&x.hi, &y.lo)),
        PrimOp::Le(_) => (le(&x.hi, &y.lo), lt(&y.hi, &x.lo)),
        PrimOp::Gt(_) => (lt(&y.hi, &x.lo), le(&x.hi, &y.lo)),
        PrimOp::Eq(_) | PrimOp::Ne(_) => {
            let apart = lt(&x.hi, &y.lo) || lt(&y.hi, &x.lo);
            let same = x.lo.is_some() && x.lo == x.hi && x.lo == y.lo && y.lo == y.hi;
            if matches!(op, PrimOp::Eq(_)) { (same, apart) } else { (apart, same) }
        }
        _ => (false, false),
    };
    if t {
        Some(true)
    } else if f {
        Some(false)
    } else {
        None
    }
}

/// Which bound of a value a decision reads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    Upper,
    Lower,
}

// ---------------------------------------------------------------------------
// Decisions over generalized leaves.
// ---------------------------------------------------------------------------

thread_local! {
    /// The kernel's `Bool` (for the canonical proofs of [`decide_generalized`]).
    static BOOL_IND: std::cell::Cell<Option<sandblaster_kernel::term::IndId>> = const { std::cell::Cell::new(None) };
}

/// A comparison over a bit-level expression whose operations carry no
/// proof about their operands (`|`, `&`, `^`, casts, wrapping arithmetic,
/// shifts by a width-checked amount), decided with its leaves — the
/// maximal operands that are not such operations or literals (element
/// reads, parameters, calls) — generalized to fresh variables of their
/// machine types (design §6.6, generalization, applied to one decision).
/// The query then reads small atoms: an element read `xs[k]` of a driven
/// reader carries the proofs of its path in its irrelevant arguments,
/// which a query over the original condition reads back into every
/// hypothesis. The proof is `(λ x̄. p) leaves` (β), at `st`'s depth; with
/// `proof = false` (the driver, whose certificates only stand in for the
/// irrelevant path equation of the arm it continues with, never checked:
/// the proof builder re-derives every decision) it is `Erased` and the
/// leaves are never read back. `None` when `c` is not of that shape or the
/// query does not decide it.
pub fn decide_generalized(e: &mut crate::auto::search::Engine<'_>, st: &St, c: &V, facts: &[u32], proof: bool) -> Option<(bool, sandblaster_kernel::term::Tm)> {
    decide_generalized_at(e, st, c, None, facts, proof)
}

/// [`decide_generalized`] where `c` is the value of the term `c_tm`: the
/// proof applies the leaves' own subterms of `c_tm` (shared with the goal,
/// never read back from their values).
pub fn decide_generalized_at(e: &mut crate::auto::search::Engine<'_>, st: &St, c: &V, c_tm: Option<&sandblaster_kernel::term::Tm>, facts: &[u32], proof: bool) -> Option<(bool, sandblaster_kernel::term::Tm)> {
    use sandblaster_kernel::term::{Rel, Term, Tm};
    use sandblaster_kernel::util::mk;
    let (op, args) = prim_of(c)?;
    let w = match op {
        PrimOp::Lt(w) | PrimOp::Le(w) | PrimOp::Gt(w) | PrimOp::Ge(w) | PrimOp::Eq(w) | PrimOp::Ne(w) => w,
        _ => return None,
    };
    w.bits()?;
    // the bounds the decision reads: with the facts it may use
    let mut bst = st.clone();
    bst.facts.retain(|f| facts.contains(&f.lvl));
    let bounds = Bounds::of(&bst);
    let outcome = interval_outcome(&bounds, op, w, &args[0], &args[1]);
    // per side, the bound that decides: `x ≤ y` true reads x's upper and
    // y's lower bound, false the other two
    let dirs: [Option<Dir>; 2] = match (op, outcome) {
        (PrimOp::Lt(_) | PrimOp::Le(_), Some(true)) | (PrimOp::Gt(_) | PrimOp::Ge(_), Some(false)) => [Some(Dir::Upper), Some(Dir::Lower)],
        (PrimOp::Lt(_) | PrimOp::Le(_), Some(false)) | (PrimOp::Gt(_) | PrimOp::Ge(_), Some(true)) => [Some(Dir::Lower), Some(Dir::Upper)],
        _ => [None, None],
    };
    // the leaves, deduplicated by key, with their widths
    let mut leaves: Vec<(u64, V, Width)> = Vec::new();
    // an operand the bound does not read is a leaf too (a disjunction's
    // lower bound needs only its larger operand's)
    fn collect(v: &V, w: Width, leaves: &mut Vec<(u64, V, Width)>, dir: Option<Dir>, b: &Bounds) -> bool {
        if lit_of(v).is_some() {
            return true;
        }
        if let (Some(Dir::Lower), Some((PrimOp::Or(x), args))) = (dir, prim_of(v)) {
            let mut fuel = 4096;
            let (ra, rb) = (b.range(&args[0], x, &mut fuel), b.range(&args[1], x, &mut fuel));
            let keep = if rb.lo >= ra.lo { 1 } else { 0 };
            return collect(&args[keep], x, leaves, dir, b) && leaf(&args[1 - keep], x, leaves);
        }
        if dir.is_none() && prim_of(v).is_some() && !matches!(prim_of(v), Some((PrimOp::Or(_) | PrimOp::And(_) | PrimOp::Xor(_) | PrimOp::Cast { .. } | PrimOp::Shl(_) | PrimOp::WShl(_) | PrimOp::Shr(_) | PrimOp::WShr(_), _))) {
            return leaf(v, w, leaves);
        }
        match prim_of(v) {
            Some((op, args)) => {
                let aw: Vec<Width> = match op {
                    PrimOp::Or(x) | PrimOp::And(x) | PrimOp::Xor(x) | PrimOp::WAdd(x) | PrimOp::WSub(x) | PrimOp::WMul(x) => vec![x, x],
                    PrimOp::Not(x) | PrimOp::WNeg(x) => vec![x],
                    PrimOp::WShl(x) | PrimOp::WShr(x) | PrimOp::Shl(x) | PrimOp::Shr(x) | PrimOp::Rotl(x) | PrimOp::Rotr(x) => vec![x, Width::U32],
                    PrimOp::Cast { from, .. } => vec![from],
                    _ => return false,
                };
                // a shift's width obligation must be about a literal amount
                if matches!(op, PrimOp::Shl(_) | PrimOp::Shr(_)) && lit_of(&args[1]).is_none() {
                    return false;
                }
                args.iter().zip(aw).all(|(a, aw)| collect(a, aw, leaves, dir, b))
            }
            None => leaf(v, w, leaves),
        }
    }
    fn leaf(v: &V, w: Width, leaves: &mut Vec<(u64, V, Width)>) -> bool {
        if lit_of(v).is_some() {
            return true;
        }
        if w.bits().is_none() {
            return false;
        }
        let k = vkey(v, 24);
        if !leaves.iter().any(|(k2, _, _)| *k2 == k) {
            leaves.push((k, v.clone(), w));
        }
        true
    }
    let ok = args.iter().zip(dirs).all(|(a, d)| collect(a, w, &mut leaves, d, &bounds));
    if std::env::var_os("SANDBLASTER_OPT_TRACE_SPLITS").is_some() {
        eprintln!("opt: drive: generalized decision: outcome {outcome:?}, {} leaves, {} facts (ok {ok})", leaves.len(), facts.len());
    }
    if !ok || leaves.is_empty() || leaves.len() > 32 {
        return None;
    }
    // nothing to gain when every leaf is a variable already
    if leaves.iter().all(|(_, v, _)| matches!(&**v, Value::Neu(n) if matches!(n.head, Head::Var(_)) && n.spine.is_empty())) {
        return None;
    }
    let d = st.depth();
    // the generalized problem lives in a context of its own: the variables
    // and the facts about them (nothing else of the path matters to it, and
    // its proof is closed, so it moves to any depth)
    let mut st2 = St::new(e.env, &sandblaster_kernel::api::Ctx::default(), 0);
    let mut vars: Vec<(u64, V)> = Vec::new();
    for (i, (k, _, lw)) in leaves.iter().enumerate() {
        let ty: V = std::rc::Rc::new(Value::IntTy(*lw));
        let en = st2.push_raw(e.env, std::rc::Rc::from(format!("g{i}").as_str()), Rel::Rel, ty);
        let Arg::Rel(x) = crate::auto::util::entry_arg(&en) else { return None };
        vars.push((*k, x));
    }
    /// `v` with the leaves replaced (the same `Rc` when nothing is).
    fn subst(v: &V, vars: &[(u64, V)]) -> V {
        if lit_of(v).is_some() {
            return v.clone();
        }
        let k = vkey(v, 24);
        if let Some((_, x)) = vars.iter().find(|(k2, _)| *k2 == k) {
            return x.clone();
        }
        if let Some((op, args)) = prim_of(v) {
            let Value::Neu(n) = &**v else { return v.clone() };
            let Head::Prim { proofs, .. } = &n.head else { return v.clone() };
            let args2: Vec<V> = args.iter().map(|a| subst(a, vars)).collect();
            // a shift by a literal gets the canonical proof of its width
            // obligation (`refl(Bool, k < w)`): the one it carries may be
            // the whole chain of an unrolled recursion's `requires` proofs
            let canonical = match (op, args2.get(1).and_then(lit_of)) {
                (PrimOp::Shl(w) | PrimOp::Shr(w), Some(k)) if args2.len() == 2 && proofs.len() == 1 => w.bits().map(|bits| (k, bits)),
                _ => None,
            };
            if let Some((k, bits)) = canonical
                && let Some(b) = BOOL_IND.with(|c| c.get())
            {
                use sandblaster_kernel::util::mk;
                let lt = sandblaster_kernel::prim::prim0(PrimOp::Lt(Width::U32), vec![mk::lit(Width::U32, k), mk::lit(Width::U32, BigInt::from(bits))]);
                let pf = mk::refl(mk::bool_ty(b), lt);
                let c = sandblaster_kernel::value::Closure { env: Default::default(), body: pf };
                return std::rc::Rc::new(Value::Neu(sandblaster_kernel::value::Neutral { head: Head::Prim { op, args: args2, proofs: vec![c] }, spine: vec![] }));
            }
            if args2.iter().zip(args).all(|(a, b)| std::rc::Rc::ptr_eq(a, b)) {
                return v.clone();
            }
            return std::rc::Rc::new(Value::Neu(sandblaster_kernel::value::Neutral { head: Head::Prim { op, args: args2, proofs: proofs.clone() }, spine: vec![] }));
        }
        v.clone()
    }
    BOOL_IND.with(|c| c.set(Some(e.n.bool_ind)));
    let c2 = subst(c, &vars);
    // the given facts, over the variables: `Eq(Bool, cmp(a, b), t)` with
    // the leaves of `a`, `b` replaced (abstracted too, as hypotheses)
    st2.facts.clear();
    let mut hyps: Vec<(u32, V, St)> = Vec::new();
    for f in st.facts.iter().filter(|f| facts.contains(&f.lvl)) {
        let Value::Eq { ty, lhs, rhs } = &*f.ty else { continue };
        let lhs2 = subst(lhs, &vars);
        let rhs2 = subst(rhs, &vars);
        // (every atom of the generalized condition is a leaf: a fact that
        // mentions none cannot matter)
        if std::rc::Rc::ptr_eq(&lhs2, lhs) && std::rc::Rc::ptr_eq(&rhs2, rhs) {
            continue;
        }
        let ty2: V = std::rc::Rc::new(Value::Eq { ty: ty.clone(), lhs: lhs2, rhs: rhs2 });
        let lvl = st2.depth();
        let before = if proof { Some(st2.clone()) } else { None };
        st2.push_raw(e.env, std::rc::Rc::from(format!("gh{lvl}").as_str()), Rel::Irr, ty2.clone());
        st2.add_ctx_fact(lvl, ty2.clone(), crate::auto::state::Origin::Derived("generalized"));
        hyps.push((f.lvl, ty2, before.unwrap_or_else(|| st.clone())));
    }
    if std::env::var_os("SANDBLASTER_OPT_TRACE_SPLITS").is_some() {
        eprintln!("opt: drive: generalized: {}", e.show(&st2, &c2).chars().take(300).collect::<String>());
        for f in &st2.facts {
            eprintln!("opt: drive: generalized fact {}", e.show(&st2, &f.ty).chars().take(200).collect::<String>());
        }
    }
    // a fresh search over the generalized problem (its own depth, caches
    // and budget share)
    let (b, p) = {
        e.settle();
        let mut b2 = sandblaster_kernel::value::Budget { steps: e.b.steps };
        let start = b2.steps;
        let r = {
            let mut e2 = crate::auto::search::Engine::new(e.env, &mut b2, e.cfg, e.db, vec![], 0);
            e2.decide_bool(&st2, &c2)
        };
        e.b.steps = e.b.steps.saturating_sub(start - b2.steps);
        r.ok()??
    };
    if !proof {
        return Some((b, std::rc::Rc::new(Term::Erased)));
    }
    // λ x̄ h̄. p applied to the leaves and the facts' proofs (at `st`'s
    // depth). The facts' binders are relevant: `p` may use them as
    // `linarith` hypotheses (or be one of them, a fact that states the
    // condition — an invariant of a value, say), relevant positions of the
    // proof, and an irrelevant binder bound inside the irrelevant position
    // the decision's proof goes to is not usable there (the kernel's
    // relevance rule). The facts' own proofs, bound outside that position,
    // are usable relevantly in it.
    let mut lam: Tm = p;
    for (j, (_, ty2, before)) in hyps.iter().enumerate().rev() {
        let dom = e.quote(before, ty2);
        lam = mk::lam(&format!("gh{j}"), Rel::Rel, dom, lam);
    }
    for (i, (_, _, lw)) in leaves.iter().enumerate().rev() {
        lam = mk::lam(&format!("g{i}"), Rel::Rel, std::rc::Rc::new(Term::IntTy(*lw)), lam);
    }
    // the leaves' terms: subterms of `c_tm` whose values have the leaves'
    // keys, when given (shared with the goal), else read back
    let mut found: Vec<Option<Tm>> = vec![None; leaves.len()];
    if let Some(ct) = c_tm {
        fn find(e: &mut crate::auto::search::Engine<'_>, st: &St, t: &Tm, leaves: &[(u64, V, Width)], found: &mut Vec<Option<Tm>>, budget: &mut u32) {
            if *budget == 0 || found.iter().all(|f| f.is_some()) {
                return;
            }
            *budget -= 1;
            if matches!(&**t, Term::Lit { .. }) {
                return;
            }
            if let Ok(v) = st.eval(e.env, t, e.b) {
                let k = vkey(&v, 24);
                if let Some(i) = leaves.iter().position(|(k2, _, _)| *k2 == k)
                    && found[i].is_none()
                {
                    found[i] = Some(t.clone());
                    return;
                }
            }
            if let Term::Prim { args, .. } = &**t {
                for a in args {
                    find(e, st, a, leaves, found, budget);
                }
            }
        }
        let mut budget = 512;
        find(e, st, ct, &leaves, &mut found, &mut budget);
    }
    let mut out = lam;
    for ((_, v, _), f) in leaves.iter().zip(found) {
        let t = f.unwrap_or_else(|| e.quote(st, v));
        out = mk::app(out, t);
    }
    for (lvl, _, _) in &hyps {
        out = mk::app(out, st.var(*lvl));
    }
    let _ = d;
    Some((b, out))
}
