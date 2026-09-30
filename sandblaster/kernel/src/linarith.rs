//! Linear arithmetic certificates (DESIGN.md §5.8).
//!
//! The public shape of [`LinSystem`] is shared with the untrusted certificate
//! search in the front end: both sides must agree on atoms and on the
//! canonical constraint order.
//!
//! **Linearization** (over ℤ; every encoding is a true definitional fact):
//! literals; checked `add/sub`; checked `mul` by a literal; `iadd/isub/ineg`
//! and `imul` by a literal; `to_int`, `of_int`, widening and equal-width
//! casts are transparent. Definitional atoms with their defining constraints:
//! * `div/rem` (checked, by a literal `k > 0`), `idiv/imod` by a literal
//!   `k > 0`, `wshr/shr` by a literal `s` (divisor `2^(s mod w)`), `and` with
//!   a literal mask `2^k − 1`, truncating casts (divisor `2^bits(to)`): a
//!   shared pair `(q, r)` per `(a, k)` with `a − k·q − r = 0`, `−r ≤ 0`,
//!   `r − (k−1) ≤ 0`;
//! * `wadd(a, b)`: atom `res` and carry `c` with `res − a − b + 2^w·c = 0`,
//!   `0 ≤ c ≤ 1`; `wsub(a, b)`: `res − a + b − 2^w·c = 0`, `0 ≤ c ≤ 1`;
//!   `wmul(a, k)`: `res − k·a + 2^w·c = 0`, `0 ≤ c ≤ k−1`; `wshl/shl(a, s)`:
//!   `res − 2^s·a + 2^w·c = 0`, `0 ≤ c ≤ 2^s − 1`.
//!
//! Every other term is an atom, identified up to conversion. Machine-typed
//! atoms (including definitional ones) get `−a ≤ 0`, `a − (2^w−1) ≤ 0`;
//! `seq::len` atoms get `−a ≤ 0`.
//!
//! **Canonical order** of a problem: one constraint per hypothesis (in
//! order), then the negated goal (absent for an `Empty` goal), then the
//! implicit constraints (atom bounds and definitions) in creation order.
//! An equality goal (`eq … true`, `ne … false`, `Eq(IntTy w, a, b)`) yields
//! two problems (negations `a < b` and `a > b`); the certificate is the
//! concatenation of their certificates.
//!
//! **Certificate check**: exact bignum rationals (scaled by the lcm of the
//! denominators); `≤` constraints need nonnegative multipliers; accept iff
//! all atom coefficients of `Σ cᵢ·eᵢ` are 0 and its constant is positive.
//! This check is the trusted part of the rule. Since phase 3 the checker
//! treats a term's certificate as a hint and, when it fails, searches one
//! (`search_cert`, untrusted `lincert`) whose result goes through the same
//! check (see `Checker::infer_linarith`). Shared value nodes are linearized
//! once (memo), so value DAGs are not walked as trees.

use std::collections::BTreeMap;
use std::rc::Rc;

use num_integer::Integer;
use num_traits::{One, Signed, Zero};

use crate::api::{Env, KernelErrorKind as K};
use crate::check::{Cx, KR, kerr};
use crate::conv::Conv;
use crate::prim::{self, as_lit, as_prim};
use crate::term::{BigInt, Lvl, PrimOp, Rat, Tm, Width};
use crate::util::mk;
use crate::value::{Budget, Head, Neutral, V, Value};

/// Kind of a normalized constraint `e ≤ 0` or `e = 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstraintKind {
    Le0,
    Eq0,
}

/// Where a constraint came from (for diagnostics and certificate search).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstraintOrigin {
    Hyp(usize),
    NegatedGoal,
    AtomBound(usize),
    Definition(usize),
}

/// `Σ coeffs[i].1 · atom[coeffs[i].0] + constant  (≤ | =)  0`.
#[derive(Clone, Debug)]
pub struct Constraint {
    pub coeffs: Vec<(usize, BigInt)>,
    pub constant: BigInt,
    pub kind: ConstraintKind,
    pub origin: ConstraintOrigin,
}

/// The linear system for one refutation (an equality goal produces two).
#[derive(Clone, Debug)]
pub struct LinSystem {
    /// Canonical atom terms in creation order.
    pub atoms: Vec<Tm>,
    /// Refutation problems; each is a list of constraints in canonical order.
    pub problems: Vec<Vec<Constraint>>,
}

/// A linear expression: coefficients by atom index plus a constant.
#[derive(Clone, Debug, Default)]
struct Lin {
    coeffs: BTreeMap<usize, BigInt>,
    constant: BigInt,
}

impl Lin {
    fn konst(n: BigInt) -> Lin {
        Lin { coeffs: BTreeMap::new(), constant: n }
    }
    fn atom(i: usize) -> Lin {
        let mut c = BTreeMap::new();
        c.insert(i, BigInt::one());
        Lin { coeffs: c, constant: BigInt::zero() }
    }
    fn add(mut self, o: &Lin, k: &BigInt) -> Lin {
        for (a, c) in &o.coeffs {
            let e = self.coeffs.entry(*a).or_insert_with(BigInt::zero);
            *e += c * k;
        }
        self.constant += &o.constant * k;
        self.coeffs.retain(|_, c| !c.is_zero());
        self
    }
    fn scale(self, k: &BigInt) -> Lin {
        Lin::default().add(&self, k)
    }
    fn plus(self, o: &Lin) -> Lin {
        self.add(o, &BigInt::one())
    }
    fn minus(self, o: &Lin) -> Lin {
        self.add(o, &-BigInt::one())
    }
    fn plus_const(mut self, k: i64) -> Lin {
        self.constant += k;
        self
    }
    fn constraint(self, kind: ConstraintKind, origin: ConstraintOrigin) -> Constraint {
        Constraint { coeffs: self.coeffs.into_iter().collect(), constant: self.constant, kind, origin }
    }
}

/// Builds an atom's term from a quoting function.
type TermBuilder = Box<dyn Fn(&mut dyn FnMut(&V, Width) -> Tm) -> Tm>;

enum AtomTerm {
    /// Quote this value (with its width as expected type).
    Value(V),
    /// A term built from quoted subvalues.
    Built(TermBuilder),
}

struct Atom {
    /// The value the atom stands for, when identification by conversion
    /// applies (carries have none).
    src: Option<V>,
    width: Width,
    term: AtomTerm,
}

struct DivMod {
    a: V,
    k: BigInt,
    int: bool,
    q: usize,
    r: usize,
}

struct Linz<'a> {
    env: &'a Env,
    depth: Lvl,
    atoms: Vec<Atom>,
    implicit: Vec<Constraint>,
    divmods: Vec<DivMod>,
    ndefs: usize,
    /// Linear forms of shared value nodes (a value DAG is linearized once
    /// per node, not once per path; the node is kept alive in `memo_keep`).
    /// Linearization is deterministic given the atoms found so far, and a
    /// node's atoms are found again by conversion, so a memo hit returns
    /// the form a second walk would build.
    memo: crate::util::FxMap<(usize, Width), Lin>,
    memo_keep: Vec<V>,
}

fn two_pow(k: u64) -> BigInt {
    BigInt::one() << k
}

/// `k > 0` with `k = 2^j − 1` gives `Some(j)`.
fn mask_bits(k: &BigInt) -> Option<u64> {
    let k1 = k + 1u8;
    if k.is_negative() || !(&k1 & (&k1 - 1u8)).is_zero() {
        return None;
    }
    Some(k1.bits() - 1)
}

impl<'a> Linz<'a> {
    fn conv(&self, a: &V, b: &V, bud: &mut Budget) -> KR<bool> {
        Ok(Conv::new(self.env).conv(self.depth, a, b, bud)?)
    }

    fn is_len(&self, v: &V) -> bool {
        matches!(&**v, Value::Neu(Neutral { head: Head::Global { def, .. }, spine }) if spine.is_empty() && Some(*def) == self.env.known.len)
    }

    fn new_atom(&mut self, src: Option<V>, width: Width, term: AtomTerm) -> usize {
        let i = self.atoms.len();
        let len_atom = src.as_ref().is_some_and(|v| self.is_len(v));
        self.atoms.push(Atom { src, width, term });
        if let Some(bits) = width.bits() {
            self.implicit.push(Lin::atom(i).scale(&-BigInt::one()).constraint(ConstraintKind::Le0, ConstraintOrigin::AtomBound(i)));
            let max = two_pow(bits as u64) - 1u8;
            self.implicit.push(Lin::atom(i).plus(&Lin::konst(-max)).constraint(ConstraintKind::Le0, ConstraintOrigin::AtomBound(i)));
        } else if len_atom {
            self.implicit.push(Lin::atom(i).scale(&-BigInt::one()).constraint(ConstraintKind::Le0, ConstraintOrigin::AtomBound(i)));
        }
        i
    }

    fn define(&mut self, e: Lin, kind: ConstraintKind) {
        let d = self.ndefs;
        self.implicit.push(e.constraint(kind, ConstraintOrigin::Definition(d)));
    }

    /// Find an atom standing for `v` (up to conversion).
    fn find_atom(&self, v: &V, bud: &mut Budget) -> KR<Option<usize>> {
        for (i, a) in self.atoms.iter().enumerate() {
            if let Some(s) = &a.src
                && self.conv(s, v, bud)?
            {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    fn atom(&mut self, v: &V, w: Width, bud: &mut Budget) -> KR<Lin> {
        if let Some(i) = self.find_atom(v, bud)? {
            return Ok(Lin::atom(i));
        }
        let i = self.new_atom(Some(v.clone()), w, AtomTerm::Value(v.clone()));
        Ok(Lin::atom(i))
    }

    /// The shared `(q, r)` pair of `a = k·q + r` (a of width `w`).
    fn divmod(&mut self, a: &V, w: Width, k: BigInt, bud: &mut Budget) -> KR<(usize, usize)> {
        let int = w == Width::Int;
        for dm in &self.divmods {
            if dm.int == int && dm.k == k && self.conv(&dm.a, a, bud)? {
                return Ok((dm.q, dm.r));
            }
        }
        let la = self.lin(a, w, bud)?;
        let (a1, k1, k2) = (a.clone(), k.clone(), k.clone());
        let qt = AtomTerm::Built(Box::new(move |q: &mut dyn FnMut(&V, Width) -> Tm| {
            let at = if w == Width::Int { q(&a1, w) } else { prim::prim0(PrimOp::Cast { from: w, to: Width::Int }, vec![q(&a1, w)]) };
            prim::prim0(PrimOp::IDiv, vec![at, mk::lit(Width::Int, k1.clone())])
        }));
        let a2 = a.clone();
        let rt = AtomTerm::Built(Box::new(move |q: &mut dyn FnMut(&V, Width) -> Tm| {
            let at = if w == Width::Int { q(&a2, w) } else { prim::prim0(PrimOp::Cast { from: w, to: Width::Int }, vec![q(&a2, w)]) };
            prim::prim0(PrimOp::IMod, vec![at, mk::lit(Width::Int, k2.clone())])
        }));
        let qi = self.new_atom(None, w, qt);
        let ri = self.new_atom(None, w, rt);
        // a − k·q − r = 0, −r ≤ 0, r − (k−1) ≤ 0
        self.define(la.minus(&Lin::atom(qi).scale(&k)).minus(&Lin::atom(ri)), ConstraintKind::Eq0);
        self.define(Lin::atom(ri).scale(&-BigInt::one()), ConstraintKind::Le0);
        self.define(Lin::atom(ri).plus(&Lin::konst(-(&k - 1u8))), ConstraintKind::Le0);
        self.ndefs += 1;
        self.divmods.push(DivMod { a: a.clone(), k, int, q: qi, r: ri });
        Ok((qi, ri))
    }

    /// Definitions for wrapping ops: creates `res` (source `v`, width `w`) and
    /// a carry `c ∈ [0, cmax]` with `res − e + sign·2^w·c = 0`.
    #[allow(clippy::too_many_arguments)]
    fn wrap_def(&mut self, v: &V, w: Width, e: Lin, sign: i64, cmax: BigInt, carry: AtomTerm, bud: &mut Budget) -> KR<Lin> {
        if let Some(i) = self.find_atom(v, bud)? {
            return Ok(Lin::atom(i));
        }
        let res = self.new_atom(Some(v.clone()), w, AtomTerm::Value(v.clone()));
        let modulus = two_pow(prim::bits(w) as u64);
        let c = self.new_atom(None, Width::Int, carry);
        self.define(Lin::atom(res).minus(&e).plus(&Lin::atom(c).scale(&(BigInt::from(sign) * &modulus))), ConstraintKind::Eq0);
        self.define(Lin::atom(c).scale(&-BigInt::one()), ConstraintKind::Le0);
        self.define(Lin::atom(c).plus(&Lin::konst(-cmax)), ConstraintKind::Le0);
        self.ndefs += 1;
        Ok(Lin::atom(res))
    }

    /// Linearize `v : IntTy(w)` (memoized for shared nodes).
    fn lin(&mut self, v: &V, w: Width, bud: &mut Budget) -> KR<Lin> {
        if Rc::strong_count(v) > 1 && as_prim(v).is_some() {
            let key = (Rc::as_ptr(v) as *const () as usize, w);
            if let Some(l) = self.memo.get(&key) {
                crate::util::tick(bud)?;
                return Ok(l.clone());
            }
            let l = self.lin_node(v, w, bud)?;
            self.memo.insert(key, l.clone());
            self.memo_keep.push(v.clone());
            return Ok(l);
        }
        self.lin_node(v, w, bud)
    }

    fn lin_node(&mut self, v: &V, w: Width, bud: &mut Budget) -> KR<Lin> {
        crate::util::tick(bud)?;
        if let Some(n) = as_lit(v) {
            return Ok(Lin::konst(n.clone()));
        }
        let Some((op, args)) = as_prim(v) else { return self.atom(v, w, bud) };
        let args: Vec<V> = args.to_vec();
        use PrimOp::*;
        let lit_side = |args: &[V]| -> Option<(BigInt, V)> {
            if let Some(k) = as_lit(&args[1]) {
                Some((k.clone(), args[0].clone()))
            } else {
                as_lit(&args[0]).map(|k| (k.clone(), args[1].clone()))
            }
        };
        match op {
            Add(x) => Ok(self.lin(&args[0], x, bud)?.plus(&self.lin(&args[1], x, bud)?)),
            Sub(x) => Ok(self.lin(&args[0], x, bud)?.minus(&self.lin(&args[1], x, bud)?)),
            IAdd => Ok(self.lin(&args[0], Width::Int, bud)?.plus(&self.lin(&args[1], Width::Int, bud)?)),
            ISub => Ok(self.lin(&args[0], Width::Int, bud)?.minus(&self.lin(&args[1], Width::Int, bud)?)),
            INeg => Ok(self.lin(&args[0], Width::Int, bud)?.scale(&-BigInt::one())),
            Mul(_) | IMul => {
                let x = if let Mul(x) = op { x } else { Width::Int };
                match lit_side(&args) {
                    Some((k, o)) => Ok(self.lin(&o, x, bud)?.scale(&k)),
                    None => self.atom(v, w, bud),
                }
            }
            Cast { from, to } if to == Width::Int || prim::bits(from) <= prim::bits(to) => self.lin(&args[0], from, bud),
            OfInt(_) => self.lin(&args[0], Width::Int, bud),
            Div(_) | Rem(_) | IDiv | IMod => {
                let x = match op {
                    Div(x) | Rem(x) => x,
                    _ => Width::Int,
                };
                match as_lit(&args[1]) {
                    Some(k) if k.is_positive() => {
                        let (q, r) = self.divmod(&args[0], x, k.clone(), bud)?;
                        Ok(Lin::atom(if matches!(op, Div(_) | IDiv) { q } else { r }))
                    }
                    _ => self.atom(v, w, bud),
                }
            }
            WShr(x) | Shr(x) => match as_lit(&args[1]) {
                Some(s) => {
                    let s = (s % prim::bits(x)).try_into().unwrap_or(0u64);
                    if s == 0 {
                        self.lin(&args[0], x, bud)
                    } else {
                        let (q, _) = self.divmod(&args[0], x, two_pow(s), bud)?;
                        Ok(Lin::atom(q))
                    }
                }
                None => self.atom(v, w, bud),
            },
            And(x) => match lit_side(&args).and_then(|(m, o)| mask_bits(&m).map(|k| (k, o))) {
                Some((0, _)) => Ok(Lin::konst(BigInt::zero())),
                Some((k, o)) if k >= prim::bits(x) as u64 => self.lin(&o, x, bud),
                Some((k, o)) => {
                    let (_, r) = self.divmod(&o, x, two_pow(k), bud)?;
                    Ok(Lin::atom(r))
                }
                None => self.atom(v, w, bud),
            },
            Cast { from, to } => {
                // Truncating cast: remainder modulo 2^bits(to).
                let (_, r) = self.divmod(&args[0], from, two_pow(prim::bits(to) as u64), bud)?;
                Ok(Lin::atom(r))
            }
            WShl(x) | Shl(x) => match as_lit(&args[1]) {
                Some(s) => {
                    let s: u64 = (s % prim::bits(x)).try_into().unwrap_or(0);
                    if s == 0 {
                        return self.lin(&args[0], x, bud);
                    }
                    let la = self.lin(&args[0], x, bud)?;
                    let carry = carry_term(Carry::Mul(args[0].clone(), two_pow(s)), x);
                    self.wrap_def(v, x, la.scale(&two_pow(s)), 1, two_pow(s) - 1u8, carry, bud)
                }
                None => self.atom(v, w, bud),
            },
            WAdd(x) => {
                let e = self.lin(&args[0], x, bud)?.plus(&self.lin(&args[1], x, bud)?);
                let carry = carry_term(Carry::Add(args[0].clone(), args[1].clone()), x);
                self.wrap_def(v, x, e, 1, BigInt::one(), carry, bud)
            }
            WSub(x) => {
                let e = self.lin(&args[0], x, bud)?.minus(&self.lin(&args[1], x, bud)?);
                let carry = carry_term(Carry::Sub(args[0].clone(), args[1].clone()), x);
                self.wrap_def(v, x, e, -1, BigInt::one(), carry, bud)
            }
            WMul(x) => match lit_side(&args) {
                Some((k, _)) if k.is_zero() => Ok(Lin::konst(BigInt::zero())),
                Some((k, o)) => {
                    let e = self.lin(&o, x, bud)?.scale(&k);
                    let carry = carry_term(Carry::Mul(o.clone(), k.clone()), x);
                    self.wrap_def(v, x, e, 1, k - 1u8, carry, bud)
                }
                None => self.atom(v, w, bud),
            },
            _ => self.atom(v, w, bud),
        }
    }

    fn bool_of(&self, v: &V) -> Option<bool> {
        match &**v {
            Value::Ctor { ind, ctor, .. } if *ind == self.env.bool_id => Some(*ctor == 1),
            _ => None,
        }
    }

    /// Decompose a proposition into a comparison: `Ok(Cmp(op, w, la, lb,
    /// truth))`, a trivial boolean equation, or an integer equation.
    fn prop(&mut self, v: &V, bud: &mut Budget) -> KR<Prop> {
        let Value::Eq { ty, lhs, rhs } = &**v else {
            return Err(kerr(K::Linarith, "linarith: unsupported proposition (expected Eq(Bool, cmp, b) or Eq(IntTy, a, b))"));
        };
        match &**ty {
            Value::Ind { ind, .. } if *ind == self.env.bool_id => {
                let truth =
                    self.bool_of(rhs).ok_or_else(|| kerr(K::Linarith, "linarith: right side of a Bool equation must be a literal"))?;
                if let Some(l) = self.bool_of(lhs) {
                    return Ok(Prop::Trivial(l == truth));
                }
                let (op, args) = as_prim(lhs).ok_or_else(|| kerr(K::Linarith, "linarith: left side must be a comparison"))?;
                let (w, kind) = match op {
                    PrimOp::Eq(w) => (w, Cmp::Eq),
                    PrimOp::Ne(w) => (w, Cmp::Ne),
                    PrimOp::Lt(w) => (w, Cmp::Lt),
                    PrimOp::Le(w) => (w, Cmp::Le),
                    PrimOp::Gt(w) => (w, Cmp::Gt),
                    PrimOp::Ge(w) => (w, Cmp::Ge),
                    _ => return Err(kerr(K::Linarith, "linarith: left side must be a comparison")),
                };
                let args = args.to_vec();
                let la = self.lin(&args[0], w, bud)?;
                let lb = self.lin(&args[1], w, bud)?;
                Ok(Prop::Cmp(kind, la, lb, truth))
            }
            Value::IntTy(w) => {
                let la = self.lin(lhs, *w, bud)?;
                let lb = self.lin(rhs, *w, bud)?;
                Ok(Prop::Cmp(Cmp::Eq, la, lb, true))
            }
            _ => Err(kerr(K::Linarith, "linarith: unsupported equation type")),
        }
    }
}

/// Operands of a wrapping op, for the informative carry term.
enum Carry {
    Add(V, V),
    Sub(V, V),
    Mul(V, BigInt),
}

/// The carry of a wrapping op as an `Int` term: `idiv(a + b, 2^w)`,
/// `−idiv(a − b, 2^w)`, `idiv(a·k, 2^w)`.
fn carry_term(c: Carry, w: Width) -> AtomTerm {
    AtomTerm::Built(Box::new(move |q: &mut dyn FnMut(&V, Width) -> Tm| {
        let ti = |t: Tm| prim::prim0(PrimOp::Cast { from: w, to: Width::Int }, vec![t]);
        let m = mk::lit(Width::Int, two_pow(prim::bits(w) as u64));
        let idiv = |t: Tm| prim::prim0(PrimOp::IDiv, vec![t, m.clone()]);
        match &c {
            Carry::Add(a, b) => idiv(prim::prim0(PrimOp::IAdd, vec![ti(q(a, w)), ti(q(b, w))])),
            Carry::Sub(a, b) => prim::prim0(PrimOp::INeg, vec![idiv(prim::prim0(PrimOp::ISub, vec![ti(q(a, w)), ti(q(b, w))]))]),
            Carry::Mul(a, k) => idiv(prim::prim0(PrimOp::IMul, vec![ti(q(a, w)), mk::lit(Width::Int, k.clone())])),
        }
    }))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

enum Prop {
    Cmp(Cmp, Lin, Lin, bool),
    Trivial(bool),
}

/// The constraint for "cmp(a, b) = truth", or `None` if it is disjunctive.
fn cmp_constraint(c: Cmp, la: &Lin, lb: &Lin, truth: bool) -> Option<(ConstraintKind, Lin)> {
    use ConstraintKind::*;
    let amb = la.clone().minus(lb);
    let bma = lb.clone().minus(la);
    Some(match (c, truth) {
        (Cmp::Lt, true) | (Cmp::Ge, false) => (Le0, amb.plus_const(1)),
        (Cmp::Lt, false) | (Cmp::Ge, true) => (Le0, bma),
        (Cmp::Le, true) | (Cmp::Gt, false) => (Le0, amb),
        (Cmp::Le, false) | (Cmp::Gt, true) => (Le0, bma.plus_const(1)),
        (Cmp::Eq, true) | (Cmp::Ne, false) => (Eq0, amb),
        (Cmp::Eq, false) | (Cmp::Ne, true) => return None,
    })
}

/// Build the linear system for stated hypotheses and a goal (all values in
/// the context `cx`).
pub(crate) fn build(env: &Env, cx: &Cx, stated: &[V], goal: &V, bud: &mut Budget) -> KR<LinSystem> {
    let mut lz = Linz {
        env,
        depth: cx.depth(),
        atoms: Vec::new(),
        implicit: Vec::new(),
        divmods: Vec::new(),
        ndefs: 0,
        memo: Default::default(),
        memo_keep: Vec::new(),
    };
    let mut hyps = Vec::with_capacity(stated.len());
    for (i, s) in stated.iter().enumerate() {
        let c = match lz.prop(s, bud)? {
            Prop::Trivial(true) => (ConstraintKind::Eq0, Lin::default()),
            Prop::Trivial(false) => (ConstraintKind::Le0, Lin::konst(BigInt::one())),
            Prop::Cmp(k, la, lb, t) => cmp_constraint(k, &la, &lb, t)
                .ok_or_else(|| kerr(K::Linarith, format!("linarith: hypothesis {i} is disjunctive (eq … false / ne … true)")))?,
        };
        hyps.push(c.1.constraint(c.0, ConstraintOrigin::Hyp(i)));
    }
    // Negated goal(s).
    let negs: Vec<Option<(ConstraintKind, Lin)>> = match &**goal {
        Value::Ind { ind, .. } if *ind == env.empty_id => vec![None],
        _ => match lz.prop(goal, bud)? {
            Prop::Trivial(true) => vec![Some((ConstraintKind::Le0, Lin::konst(BigInt::one())))],
            Prop::Trivial(false) => vec![Some((ConstraintKind::Le0, Lin::default()))],
            Prop::Cmp(k, la, lb, t) => match cmp_constraint(k, &la, &lb, !t) {
                Some(c) => vec![Some(c)],
                None => vec![
                    Some((ConstraintKind::Le0, la.clone().minus(&lb).plus_const(1))),
                    Some((ConstraintKind::Le0, lb.minus(&la).plus_const(1))),
                ],
            },
        },
    };
    let mut problems = Vec::with_capacity(negs.len());
    for n in negs {
        let mut p = hyps.clone();
        if let Some((k, e)) = n {
            p.push(e.constraint(k, ConstraintOrigin::NegatedGoal));
        }
        p.extend(lz.implicit.iter().cloned());
        problems.push(p);
    }
    // Atom terms.
    let mut qt = crate::quote::Quoter::typed(env, cx.types());
    let depth = cx.depth();
    let mut quote = |v: &V, w: Width| qt.q(depth, v, Some(&Rc::new(Value::IntTy(w))));
    let atoms = lz
        .atoms
        .iter()
        .map(|a| match &a.term {
            AtomTerm::Value(v) => quote(v, a.width),
            AtomTerm::Built(f) => f(&mut quote),
        })
        .collect();
    Ok(LinSystem { atoms, problems })
}

/// Is `v` a §5.8 hypothesis form (`Eq(Bool, cmp_w(a, b), true|false)` with a
/// comparison that is not disjunctive, a trivial `Eq(Bool, lit, lit)`, or
/// `Eq(IntTy w, a, b)`)?
pub(crate) fn is_hyp_form(env: &Env, v: &V) -> bool {
    let Value::Eq { ty, lhs, rhs } = &**v else { return false };
    match &**ty {
        Value::IntTy(_) => true,
        Value::Ind { ind, .. } if *ind == env.bool_id => {
            let lit = |x: &V| match &**x {
                Value::Ctor { ind, ctor, .. } if *ind == env.bool_id => Some(*ctor == 1),
                _ => None,
            };
            let Some(truth) = lit(rhs) else { return false };
            if lit(lhs).is_some() {
                return true;
            }
            match as_prim(lhs) {
                Some((PrimOp::Eq(_), _)) => truth,
                Some((PrimOp::Ne(_), _)) => !truth,
                Some((PrimOp::Lt(_) | PrimOp::Le(_) | PrimOp::Gt(_) | PrimOp::Ge(_), _)) => true,
                _ => false,
            }
        }
        _ => false,
    }
}

/// Search a certificate for every problem of `sys` (concatenated in problem
/// order) with the untrusted simplex of [`crate::lincert`]; `Ok(None)` if
/// some problem is feasible over the rationals. The caller verifies the
/// result with [`check_cert`].
pub(crate) fn search_cert(sys: &LinSystem, b: &mut Budget) -> Result<Option<Vec<Rat>>, crate::value::EvalError> {
    let mut out = Vec::new();
    for p in &sys.problems {
        match crate::lincert::farkas(p, sys.atoms.len(), b)? {
            Some(c) => out.extend(c),
            None => return Ok(None),
        }
    }
    Ok(Some(out))
}

/// The kernel's exact certificate check (see module docs), exposed for
/// automation and tests: `Ok(())` iff `cert` refutes every problem of `sys`.
/// Since phase 3 the `Linarith` rule also accepts a term whose certificate
/// fails this check when the kernel's own search finds one that passes it.
pub fn check_certificate(sys: &LinSystem, cert: &[Rat]) -> Result<(), String> {
    check_cert(sys, cert).map_err(|e| e.message)
}

/// Check a certificate against a system (see module docs).
pub(crate) fn check_cert(sys: &LinSystem, cert: &[Rat]) -> KR<()> {
    let total: usize = sys.problems.iter().map(|p| p.len()).sum();
    if cert.len() != total {
        return Err(kerr(K::Linarith, format!("linarith: certificate has {} entries, the system has {total} constraints", cert.len())));
    }
    let mut off = 0;
    for (pi, p) in sys.problems.iter().enumerate() {
        let c = &cert[off..off + p.len()];
        off += p.len();
        check_problem(p, c).map_err(|m| kerr(K::Linarith, format!("linarith: problem {pi}: {m}")))?;
    }
    Ok(())
}

fn check_problem(p: &[Constraint], cert: &[Rat]) -> Result<(), String> {
    let mut l = BigInt::one();
    for r in cert {
        if !r.den.is_positive() {
            return Err("certificate denominators must be positive".into());
        }
        l = l.lcm(&r.den);
    }
    let mut sum: BTreeMap<usize, BigInt> = BTreeMap::new();
    let mut constant = BigInt::zero();
    for (c, r) in p.iter().zip(cert) {
        if c.kind == ConstraintKind::Le0 && r.num.is_negative() {
            return Err("negative multiplier for a ≤ constraint".into());
        }
        if r.num.is_zero() {
            continue;
        }
        let m = &r.num * (&l / &r.den);
        for (a, k) in &c.coeffs {
            *sum.entry(*a).or_insert_with(BigInt::zero) += &m * k;
        }
        constant += &m * &c.constant;
    }
    if let Some((a, _)) = sum.iter().find(|(_, k)| !k.is_zero()) {
        return Err(format!("combination leaves a nonzero coefficient for atom {a}"));
    }
    if !constant.is_positive() {
        return Err("combination's constant is not positive".into());
    }
    Ok(())
}
