//! Primitive operations (DESIGN.md §5.7).
//!
//! * [`prim_sig`]: typing signature of every [`PrimOp`] (argument widths,
//!   result type, number of irrelevant proof slots).
//! * [`prim_obligations`]: the exact proposition each proof slot of a
//!   checked op must prove. These shapes are part of the kernel contract
//!   (front end and automation build proofs against them).
//! * `eval_lits`: evaluation on literals with exact Rust semantics
//!   (wrapping ops mod 2^w, shift/rotate amounts mod w, truncating /
//!   zero-extending casts, checked ops stuck outside their domain, checked
//!   `Shl/Shr` evaluating as wrapping shifts, exact bignum `Int` with the
//!   [`INT_BITS_LIMIT`] implementation limit, Euclidean `IDiv/IMod` with
//!   `x/0 = 0`, `x%0 = x`).
//! * `simplify`: the §5.7 simplifications on neutral operands. Each rule
//!   is an identity for every op family it is applied to (see the per-rule
//!   comments); literals it produces are always in range.

use std::rc::Rc;

use num_integer::Integer;
use num_traits::{Signed, ToPrimitive, Zero};

use crate::term::{BigInt, IndId, PrimOp, Rel, Term, Tm, Width};
use crate::util::mk;
use crate::value::{EvalError, Head, Neutral, V, Value};

/// Ghost `Int` values may use at most this many bits; exceeding it is
/// [`EvalError::IntOverflow`] (never wraparound).
pub const INT_BITS_LIMIT: u64 = 4096;

/// Result type of a primitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimTy {
    Int(Width),
    Bool,
}

/// Typing signature of a primitive.
#[derive(Clone, Debug)]
pub struct PrimSig {
    /// Widths of the relevant arguments, in order.
    pub args: Vec<Width>,
    pub result: PrimTy,
    /// Number of irrelevant proof slots.
    pub proofs: usize,
}

fn machine(w: Width) -> bool {
    w != Width::Int
}

/// The signature of `op`, or `None` if the op is ill-formed (e.g. a
/// wrapping op at width `Int`, or a `Cast` from `Int`).
pub fn prim_sig(op: PrimOp) -> Option<PrimSig> {
    use PrimOp::*;
    use Width::*;
    let s = |args: Vec<Width>, result: PrimTy, proofs: usize| Some(PrimSig { args, result, proofs });
    match op {
        WAdd(w) | WSub(w) | WMul(w) | And(w) | Or(w) | Xor(w) | Min(w) | Max(w) | SatAdd(w) | SatSub(w) | SatMul(w) if machine(w) => {
            s(vec![w, w], PrimTy::Int(w), 0)
        }
        WNeg(w) | Not(w) | SwapBytes(w) if machine(w) => s(vec![w], PrimTy::Int(w), 0),
        WShl(w) | WShr(w) | Rotl(w) | Rotr(w) if machine(w) => s(vec![w, U32], PrimTy::Int(w), 0),
        CountOnes(w) | LeadingZeros(w) | TrailingZeros(w) if machine(w) => s(vec![w], PrimTy::Int(U32), 0),
        Eq(w) | Ne(w) | Lt(w) | Le(w) | Gt(w) | Ge(w) => s(vec![w, w], PrimTy::Bool, 0),
        Cast { from, to } if machine(from) => s(vec![from], PrimTy::Int(to), 0),
        IntToSat(w) if machine(w) => s(vec![Int], PrimTy::Int(w), 0),
        IAdd | ISub | IMul | IDiv | IMod => s(vec![Int, Int], PrimTy::Int(Int), 0),
        INeg => s(vec![Int], PrimTy::Int(Int), 0),
        Add(w) | Sub(w) | Mul(w) | Div(w) | Rem(w) if machine(w) => s(vec![w, w], PrimTy::Int(w), 1),
        Shl(w) | Shr(w) if machine(w) => s(vec![w, U32], PrimTy::Int(w), 1),
        OfInt(w) if machine(w) => s(vec![Int], PrimTy::Int(w), 2),
        _ => None,
    }
}

/// Checked ops that are stuck outside their domain (used by the §5.6
/// unfolding policy). Checked shifts are total (they evaluate as wrapping
/// shifts), so they are not partial.
pub fn is_partial(op: PrimOp) -> bool {
    use PrimOp::*;
    matches!(op, Add(_) | Sub(_) | Mul(_) | Div(_) | Rem(_) | OfInt(_))
}

/// Number of bits of a machine width (panics on `Int`; callers check).
pub(crate) fn bits(w: Width) -> u32 {
    w.bits().unwrap_or(0)
}

/// `2^w − 1` for a machine width.
pub fn max_of(w: Width) -> BigInt {
    (BigInt::from(1u8) << bits(w)) - 1u8
}

fn mask64(w: Width) -> u64 {
    let b = bits(w);
    if b >= 64 { u64::MAX } else { (1u64 << b) - 1 }
}

/// The propositions the proof slots of `op` must prove, as terms over the
/// argument terms `args` (in the context of the application):
///
/// | op | obligation |
/// | --- | --- |
/// | `Add(w)(a, b)` | `Eq(Bool, le_int(iadd(to_int a, to_int b), 2^w−1), true)` |
/// | `Sub(w)(a, b)` | `Eq(Bool, le_w(b, a), true)` |
/// | `Mul(w)(a, b)` | `Eq(Bool, le_int(imul(to_int a, to_int b), 2^w−1), true)` |
/// | `Div(w)`, `Rem(w)` `(a, b)` | `Eq(Bool, ne_w(b, 0), true)` |
/// | `Shl(w)`, `Shr(w)` `(a, s)` | `Eq(Bool, lt_u32(s, bits(w)), true)` |
/// | `OfInt(w)(i)` | `Eq(Bool, le_int(0, i), true)`, `Eq(Bool, le_int(i, 2^w−1), true)` |
///
/// where `to_int x` is `Cast { from: w, to: Int }`.
pub fn prim_obligations(op: PrimOp, args: &[Tm], bool_ind: IndId) -> Vec<Tm> {
    use PrimOp::*;
    let to_int = |w: Width, t: &Tm| mk::prim(Cast { from: w, to: Width::Int }, vec![t.clone()], vec![]);
    let t = |p: Tm| mk::eq_bool(bool_ind, p, true);
    if args.len() != prim_sig(op).map(|s| s.args.len()).unwrap_or(usize::MAX) {
        return vec![];
    }
    match op {
        Add(w) => vec![t(mk::prim(
            Le(Width::Int),
            vec![mk::prim(IAdd, vec![to_int(w, &args[0]), to_int(w, &args[1])], vec![]), mk::lit(Width::Int, max_of(w))],
            vec![],
        ))],
        Sub(w) => vec![t(mk::prim(Le(w), vec![args[1].clone(), args[0].clone()], vec![]))],
        Mul(w) => vec![t(mk::prim(
            Le(Width::Int),
            vec![mk::prim(IMul, vec![to_int(w, &args[0]), to_int(w, &args[1])], vec![]), mk::lit(Width::Int, max_of(w))],
            vec![],
        ))],
        Div(w) | Rem(w) => vec![t(mk::prim(Ne(w), vec![args[1].clone(), mk::lit(w, 0u8)], vec![]))],
        Shl(w) | Shr(w) => vec![t(mk::prim(Lt(Width::U32), vec![args[1].clone(), mk::lit(Width::U32, bits(w))], vec![]))],
        OfInt(w) => vec![
            t(mk::prim(Le(Width::Int), vec![mk::lit(Width::Int, 0u8), args[0].clone()], vec![])),
            t(mk::prim(Le(Width::Int), vec![args[0].clone(), mk::lit(Width::Int, max_of(w))], vec![])),
        ],
        _ => vec![],
    }
}

/// Result of evaluating a primitive on literals (see [`eval_prim`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LitOut {
    Int(Width, BigInt),
    Bool(bool),
}

/// Evaluate a primitive on literal arguments exactly as the evaluator does
/// (public for testing against native Rust semantics). `Ok(None)` means the
/// application is stuck (a checked op outside its domain).
pub fn eval_prim(op: PrimOp, args: &[BigInt]) -> Result<Option<LitOut>, EvalError> {
    let refs: Vec<&BigInt> = args.iter().collect();
    eval_lits(op, &refs)
}

/// Check the `Int` implementation limit.
pub(crate) fn check_int(n: &BigInt) -> Result<(), EvalError> {
    if n.bits() > INT_BITS_LIMIT { Err(EvalError::IntOverflow) } else { Ok(()) }
}

fn to_u64_in(w: Width, n: &BigInt) -> Option<u64> {
    let v = n.to_u64()?;
    if v <= mask64(w) { Some(v) } else { None }
}

/// Euclidean division with `x / 0 = 0`, `x % 0 = x` (DESIGN.md §5.7).
pub(crate) fn euclid(a: &BigInt, b: &BigInt) -> (BigInt, BigInt) {
    if b.is_zero() {
        return (BigInt::zero(), a.clone());
    }
    let r = a.mod_floor(&b.abs());
    let q = (a - &r) / b;
    (q, r)
}

/// Evaluate `op` on literal arguments. `Ok(None)` means stuck: a checked op
/// outside its domain, or an ill-typed literal.
pub(crate) fn eval_lits(op: PrimOp, a: &[&BigInt]) -> Result<Option<LitOut>, EvalError> {
    use PrimOp::*;
    let Some(sig) = prim_sig(op) else { return Ok(None) };
    if a.len() != sig.args.len() {
        return Ok(None);
    }
    // Machine arguments as u64 (ill-typed literals are stuck); Int arguments
    // are checked against the implementation limit.
    let mut m = [0u64; 2];
    for (i, (&w, n)) in sig.args.iter().zip(a.iter()).enumerate() {
        if w == Width::Int {
            check_int(n)?;
        } else {
            match to_u64_in(w, n) {
                Some(v) => m[i] = v,
                None => return Ok(None),
            }
        }
    }
    let exact = |n: BigInt| -> Result<Option<LitOut>, EvalError> {
        check_int(&n)?;
        Ok(Some(LitOut::Int(Width::Int, n)))
    };
    match op {
        Eq(Width::Int) => Ok(Some(LitOut::Bool(a[0] == a[1]))),
        Ne(Width::Int) => Ok(Some(LitOut::Bool(a[0] != a[1]))),
        Lt(Width::Int) => Ok(Some(LitOut::Bool(a[0] < a[1]))),
        Le(Width::Int) => Ok(Some(LitOut::Bool(a[0] <= a[1]))),
        Gt(Width::Int) => Ok(Some(LitOut::Bool(a[0] > a[1]))),
        Ge(Width::Int) => Ok(Some(LitOut::Bool(a[0] >= a[1]))),
        Cast { to: Width::Int, .. } => exact(BigInt::from(m[0])),
        IntToSat(w) => {
            let n = a[0];
            let v = if n.is_negative() { 0 } else { n.to_u64().map(|v| v.min(mask64(w))).unwrap_or(mask64(w)) };
            Ok(Some(LitOut::Int(w, BigInt::from(v))))
        }
        IAdd => exact(a[0] + a[1]),
        ISub => exact(a[0] - a[1]),
        IMul => exact(a[0] * a[1]),
        INeg => exact(-a[0]),
        IDiv => exact(euclid(a[0], a[1]).0),
        IMod => exact(euclid(a[0], a[1]).1),
        OfInt(w) => {
            let n = a[0];
            match n.to_u64() {
                Some(v) if !n.is_negative() && v <= mask64(w) => Ok(Some(LitOut::Int(w, BigInt::from(v)))),
                _ => Ok(None),
            }
        }
        _ => Ok(match eval_machine(op, m[0], m[1]) {
            Some(Lit64::Int(w, v)) => Some(LitOut::Int(w, BigInt::from(v))),
            Some(Lit64::Bool(b)) => Some(LitOut::Bool(b)),
            None => None,
        }),
    }
}

/// Result of [`eval_machine`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lit64 {
    Int(Width, u64),
    Bool(bool),
}

/// Evaluate an op whose arguments and result are machine integers or `Bool`
/// on `u64` operands (already in range; `y` is ignored by unary ops). The
/// single implementation of the machine semantics: [`eval_lits`] delegates
/// to it, and the `BvRefl` tripwire (DESIGN.md §9.8) evaluates with it.
/// `None`: stuck (a checked op outside its domain) or not a machine op.
pub(crate) fn eval_machine(op: PrimOp, x: u64, y: u64) -> Option<Lit64> {
    use PrimOp::*;
    let int = |w: Width, v: u64| Some(Lit64::Int(w, v));
    let boolean = |b: bool| Some(Lit64::Bool(b));
    match op {
        WAdd(w) => int(w, x.wrapping_add(y) & mask64(w)),
        WSub(w) => int(w, x.wrapping_sub(y) & mask64(w)),
        WMul(w) => int(w, x.wrapping_mul(y) & mask64(w)),
        WNeg(w) => int(w, 0u64.wrapping_sub(x) & mask64(w)),
        And(w) => int(w, x & y),
        Or(w) => int(w, x | y),
        Xor(w) => int(w, x ^ y),
        Not(w) => int(w, !x & mask64(w)),
        WShl(w) | Shl(w) => int(w, (x << (y % bits(w) as u64)) & mask64(w)),
        WShr(w) | Shr(w) => int(w, x >> (y % bits(w) as u64)),
        Rotl(w) | Rotr(w) => {
            let b = bits(w) as u64;
            let r = y % b;
            let r = if matches!(op, Rotr(_)) { (b - r) % b } else { r };
            let v = if r == 0 { x } else { ((x << r) | (x >> (b - r))) & mask64(w) };
            int(w, v)
        }
        Min(w) => int(w, x.min(y)),
        Max(w) => int(w, x.max(y)),
        SatAdd(w) => int(w, (x as u128 + y as u128).min(mask64(w) as u128) as u64),
        SatSub(w) => int(w, x.saturating_sub(y)),
        SatMul(w) => int(w, (x as u128 * y as u128).min(mask64(w) as u128) as u64),
        CountOnes(_) => int(Width::U32, x.count_ones() as u64),
        LeadingZeros(w) => int(Width::U32, (x.leading_zeros() - (64 - bits(w))) as u64),
        TrailingZeros(w) => int(Width::U32, if x == 0 { bits(w) as u64 } else { x.trailing_zeros() as u64 }),
        SwapBytes(w) => int(
            w,
            match bits(w) {
                8 => x,
                16 => (x as u16).swap_bytes() as u64,
                32 => (x as u32).swap_bytes() as u64,
                _ => x.swap_bytes(),
            },
        ),
        Eq(w) if w != Width::Int => boolean(x == y),
        Ne(w) if w != Width::Int => boolean(x != y),
        Lt(w) if w != Width::Int => boolean(x < y),
        Le(w) if w != Width::Int => boolean(x <= y),
        Gt(w) if w != Width::Int => boolean(x > y),
        Ge(w) if w != Width::Int => boolean(x >= y),
        Cast { from, to } if from != Width::Int && to != Width::Int => int(to, x & mask64(to)),
        Add(w) => {
            let s = x as u128 + y as u128;
            if s <= mask64(w) as u128 { int(w, s as u64) } else { None }
        }
        Sub(w) => {
            if y <= x {
                int(w, x - y)
            } else {
                None
            }
        }
        Mul(w) => {
            let p = x as u128 * y as u128;
            if p <= mask64(w) as u128 { int(w, p as u64) } else { None }
        }
        Div(w) => x.checked_div(y).and_then(|q| int(w, q)),
        Rem(w) => {
            if y != 0 {
                int(w, x % y)
            } else {
                None
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Neutral simplifications (DESIGN.md §5.7).
// ---------------------------------------------------------------------------

/// Outcome of [`simplify`].
pub(crate) enum Simp {
    /// No rule applies.
    Keep,
    /// The application equals this value.
    Value(V),
    /// The application equals this (simpler) application; the original proof
    /// closures are kept (they are irrelevant and never inspected).
    Rebuild(PrimOp, Vec<V>),
}

pub(crate) fn lit_v(w: Width, n: impl Into<BigInt>) -> V {
    Rc::new(Value::Lit { w, n: n.into() })
}

pub(crate) fn bool_v(bool_ind: IndId, b: bool) -> V {
    Rc::new(Value::Ctor { ind: bool_ind, ctor: b as u32, params: vec![], args: vec![] })
}

/// The literal a value denotes, if it is one.
pub(crate) fn as_lit(v: &V) -> Option<&BigInt> {
    match &**v {
        Value::Lit { n, .. } => Some(n),
        _ => None,
    }
}

/// A neutral primitive application with an empty spine.
pub(crate) fn as_prim(v: &V) -> Option<(PrimOp, &[V])> {
    match &**v {
        Value::Neu(Neutral { head: Head::Prim { op, args, .. }, spine }) if spine.is_empty() => Some((*op, args)),
        _ => None,
    }
}

fn commutative(op: PrimOp) -> bool {
    use PrimOp::*;
    matches!(
        op,
        WAdd(_)
            | WMul(_)
            | And(_)
            | Or(_)
            | Xor(_)
            | Min(_)
            | Max(_)
            | SatAdd(_)
            | SatMul(_)
            | Eq(_)
            | Ne(_)
            | Add(_)
            | Mul(_)
            | IAdd
            | IMul
    )
}

/// Width of the operands of an arithmetic op family member.
fn add_family(op: PrimOp) -> Option<Width> {
    match op {
        PrimOp::WAdd(w) | PrimOp::Add(w) => Some(w),
        PrimOp::IAdd => Some(Width::Int),
        _ => None,
    }
}

fn is_lit_eq(v: &V, n: u64) -> bool {
    as_lit(v).is_some_and(|x| *x == BigInt::from(n))
}

/// Apply the first applicable §5.7 rule to `op(args)` where not every
/// relevant argument is a literal.
pub(crate) fn simplify(op: PrimOp, args: &[V], bool_ind: IndId) -> Simp {
    use PrimOp::*;
    // Literal operands of commutative ops move right: op(c, x) → op(x, c).
    // (Identity by commutativity; for checked ops the obligation is
    // symmetric.)
    if commutative(op) && args.len() == 2 && as_lit(&args[0]).is_some() && as_lit(&args[1]).is_none() {
        return Simp::Rebuild(op, vec![args[1].clone(), args[0].clone()]);
    }
    match op {
        // x + 0 → x (wrapping, checked, Int).
        WAdd(_) | Add(_) | IAdd if is_lit_eq(&args[1], 0) => Simp::Value(args[0].clone()),
        // (x + c1) + c2 → x + (c1 + c2): wrapping mod 2^w; checked only if
        // c1 + c2 ≤ MAX (always the case when the outer add is in domain);
        // Int exact. Only for the same op.
        WAdd(_) | Add(_) | IAdd => {
            let (Some(c2), Some((op2, inner))) = (as_lit(&args[1]), as_prim(&args[0])) else { return Simp::Keep };
            if op2 != op {
                return Simp::Keep;
            }
            let Some(c1) = as_lit(&inner[1]) else { return Simp::Keep };
            let s = c1 + c2;
            let s = match op {
                WAdd(w) => s.mod_floor(&(max_of(w) + 1u8)),
                Add(w) if s > max_of(w) => return Simp::Keep,
                IAdd if s.bits() > INT_BITS_LIMIT => return Simp::Keep,
                _ => s,
            };
            let w = match op {
                WAdd(w) | Add(w) => w,
                _ => Width::Int,
            };
            Simp::Rebuild(op, vec![inner[0].clone(), lit_v(w, s)])
        }
        // x − 0 → x.
        WSub(_) | Sub(_) | ISub if is_lit_eq(&args[1], 0) => Simp::Value(args[0].clone()),
        // (x + c) − c → x: for machine widths any of wadd/add under any of
        // wsub/sub (mod 2^w, and exact when the checked op is in domain);
        // for Int iadd under isub.
        WSub(w) | Sub(w) => match (as_lit(&args[1]), as_prim(&args[0])) {
            (Some(c), Some((op2, inner))) if add_family(op2) == Some(w) && as_lit(&inner[1]) == Some(c) => Simp::Value(inner[0].clone()),
            _ => Simp::Keep,
        },
        ISub => match (as_lit(&args[1]), as_prim(&args[0])) {
            (Some(c), Some((IAdd, inner))) if as_lit(&inner[1]) == Some(c) => Simp::Value(inner[0].clone()),
            _ => Simp::Keep,
        },
        // x · 1 → x, x · 0 → 0.
        WMul(w) | Mul(w) if is_lit_eq(&args[1], 1) => {
            let _ = w;
            Simp::Value(args[0].clone())
        }
        WMul(w) | Mul(w) if is_lit_eq(&args[1], 0) => Simp::Value(lit_v(w, 0u8)),
        IMul if is_lit_eq(&args[1], 1) => Simp::Value(args[0].clone()),
        IMul if is_lit_eq(&args[1], 0) => Simp::Value(lit_v(Width::Int, 0u8)),
        // For a checked add with literal c > 0 (so x + c ≥ c ≥ 1 exactly):
        // eq(x+c, 0) → false, ne(x+c, 0) → true, lt(0, x+c) → true,
        // gt(x+c, 0) → true, le(1, x+c) → true, ge(x+c, 1) → true.
        Eq(w) | Ne(w) | Gt(w) | Ge(w) => {
            let limit = if matches!(op, Ge(_)) { 1 } else { 0 };
            if pos_checked_add(&args[0], w) && is_lit_eq(&args[1], limit) {
                Simp::Value(bool_v(bool_ind, !matches!(op, Eq(_))))
            } else {
                Simp::Keep
            }
        }
        Lt(w) | Le(w) => {
            let limit = if matches!(op, Le(_)) { 1 } else { 0 };
            if pos_checked_add(&args[1], w) && is_lit_eq(&args[0], limit) { Simp::Value(bool_v(bool_ind, true)) } else { Simp::Keep }
        }
        // Widening casts collapse: cast_{b→c}(cast_{a→b}(x)) → cast_{a→c}(x)
        // when bits(a) ≤ bits(b) (the inner cast is exact, so the composite
        // is the cast of x itself); cast_{a→a}(x) → x.
        Cast { from, to } => {
            if from == to {
                return Simp::Value(args[0].clone());
            }
            if let Some((Cast { from: a, to: b }, inner)) = as_prim(&args[0])
                && b == from
                && bits(a) <= bits(b)
            {
                return if a == to { Simp::Value(inner[0].clone()) } else { Simp::Rebuild(Cast { from: a, to }, vec![inner[0].clone()]) };
            }
            // to_int(of_int_w(i)) → i (of_int is exact on its domain).
            if to == Width::Int
                && let Some((OfInt(w), inner)) = as_prim(&args[0])
                && w == from
            {
                return Simp::Value(inner[0].clone());
            }
            Simp::Keep
        }
        // of_int_w(to_int(x : a)) → x when a = w, and → cast_{a→w}(x) when
        // bits(a) < bits(w) (the value of x fits in w).
        OfInt(w) => match as_prim(&args[0]) {
            Some((Cast { from: a, to: Width::Int }, inner)) if a == w => Simp::Value(inner[0].clone()),
            Some((Cast { from: a, to: Width::Int }, inner)) if bits(a) <= bits(w) => {
                Simp::Rebuild(Cast { from: a, to: w }, vec![inner[0].clone()])
            }
            _ => Simp::Keep,
        },
        _ => Simp::Keep,
    }
}

/// `v` is a checked `Add(w)(x, c)` with literal `c > 0`.
fn pos_checked_add(v: &V, w: Width) -> bool {
    matches!(as_prim(v), Some((PrimOp::Add(w2), inner)) if w2 == w && as_lit(&inner[1]).is_some_and(|c| c.is_positive()))
}

/// Primitive op names used by the core text syntax (`#name`), e.g.
/// `wadd_u32`, `cast_u8_int`, `iadd`, `of_int_u64`.
pub fn prim_name(op: PrimOp) -> String {
    use PrimOp::*;
    let w = width_suffix;
    match op {
        WAdd(x) => format!("wadd_{}", w(x)),
        WSub(x) => format!("wsub_{}", w(x)),
        WMul(x) => format!("wmul_{}", w(x)),
        WNeg(x) => format!("wneg_{}", w(x)),
        And(x) => format!("and_{}", w(x)),
        Or(x) => format!("or_{}", w(x)),
        Xor(x) => format!("xor_{}", w(x)),
        Not(x) => format!("not_{}", w(x)),
        WShl(x) => format!("wshl_{}", w(x)),
        WShr(x) => format!("wshr_{}", w(x)),
        Rotl(x) => format!("rotl_{}", w(x)),
        Rotr(x) => format!("rotr_{}", w(x)),
        Min(x) => format!("min_{}", w(x)),
        Max(x) => format!("max_{}", w(x)),
        SatAdd(x) => format!("sat_add_{}", w(x)),
        SatSub(x) => format!("sat_sub_{}", w(x)),
        SatMul(x) => format!("sat_mul_{}", w(x)),
        CountOnes(x) => format!("count_ones_{}", w(x)),
        LeadingZeros(x) => format!("leading_zeros_{}", w(x)),
        TrailingZeros(x) => format!("trailing_zeros_{}", w(x)),
        SwapBytes(x) => format!("swap_bytes_{}", w(x)),
        Eq(x) => format!("eq_{}", w(x)),
        Ne(x) => format!("ne_{}", w(x)),
        Lt(x) => format!("lt_{}", w(x)),
        Le(x) => format!("le_{}", w(x)),
        Gt(x) => format!("gt_{}", w(x)),
        Ge(x) => format!("ge_{}", w(x)),
        Cast { from, to } => format!("cast_{}_{}", w(from), w(to)),
        IntToSat(x) => format!("int_to_sat_{}", w(x)),
        IAdd => "iadd".into(),
        ISub => "isub".into(),
        IMul => "imul".into(),
        INeg => "ineg".into(),
        IDiv => "idiv".into(),
        IMod => "imod".into(),
        Add(x) => format!("add_{}", w(x)),
        Sub(x) => format!("sub_{}", w(x)),
        Mul(x) => format!("mul_{}", w(x)),
        Div(x) => format!("div_{}", w(x)),
        Rem(x) => format!("rem_{}", w(x)),
        Shl(x) => format!("shl_{}", w(x)),
        Shr(x) => format!("shr_{}", w(x)),
        OfInt(x) => format!("of_int_{}", w(x)),
    }
}

/// Lower-case width suffix used by literals and prim names.
pub fn width_suffix(w: Width) -> &'static str {
    match w {
        Width::U8 => "u8",
        Width::U16 => "u16",
        Width::U32 => "u32",
        Width::U64 => "u64",
        Width::Usize => "usize",
        Width::Int => "int",
    }
}

/// Parse a width suffix.
pub fn parse_width(s: &str) -> Option<Width> {
    Some(match s {
        "u8" => Width::U8,
        "u16" => Width::U16,
        "u32" => Width::U32,
        "u64" => Width::U64,
        "usize" => Width::Usize,
        "int" => Width::Int,
        _ => return None,
    })
}

/// Inverse of [`prim_name`].
pub fn parse_prim_name(s: &str) -> Option<PrimOp> {
    use PrimOp::*;
    match s {
        "iadd" => return Some(IAdd),
        "isub" => return Some(ISub),
        "imul" => return Some(IMul),
        "ineg" => return Some(INeg),
        "idiv" => return Some(IDiv),
        "imod" => return Some(IMod),
        _ => {}
    }
    if let Some(rest) = s.strip_prefix("cast_") {
        let (a, b) = rest.split_once('_')?;
        return Some(Cast { from: parse_width(a)?, to: parse_width(b)? });
    }
    let (base, w) = s.rsplit_once('_')?;
    let w = parse_width(w)?;
    let op = match base {
        "wadd" => WAdd(w),
        "wsub" => WSub(w),
        "wmul" => WMul(w),
        "wneg" => WNeg(w),
        "and" => And(w),
        "or" => Or(w),
        "xor" => Xor(w),
        "not" => Not(w),
        "wshl" => WShl(w),
        "wshr" => WShr(w),
        "rotl" => Rotl(w),
        "rotr" => Rotr(w),
        "min" => Min(w),
        "max" => Max(w),
        "sat_add" => SatAdd(w),
        "sat_sub" => SatSub(w),
        "sat_mul" => SatMul(w),
        "count_ones" => CountOnes(w),
        "leading_zeros" => LeadingZeros(w),
        "trailing_zeros" => TrailingZeros(w),
        "swap_bytes" => SwapBytes(w),
        "eq" => Eq(w),
        "ne" => Ne(w),
        "lt" => Lt(w),
        "le" => Le(w),
        "gt" => Gt(w),
        "ge" => Ge(w),
        "int_to_sat" => IntToSat(w),
        "add" => Add(w),
        "sub" => Sub(w),
        "mul" => Mul(w),
        "div" => Div(w),
        "rem" => Rem(w),
        "shl" => Shl(w),
        "shr" => Shr(w),
        "of_int" => OfInt(w),
        _ => return None,
    };
    prim_sig(op).map(|_| op)
}

/// Relevance of the `i`-th argument position of a `Prim` term: relevant
/// arguments first, then irrelevant proofs.
pub fn prim_arg_rel(op: PrimOp, i: usize) -> Rel {
    match prim_sig(op) {
        Some(s) if i < s.args.len() => Rel::Rel,
        _ => Rel::Irr,
    }
}

/// Convenience: `Term::Prim` with no proofs.
pub fn prim0(op: PrimOp, args: Vec<Tm>) -> Tm {
    Rc::new(Term::Prim { op, args, proofs: vec![] })
}
