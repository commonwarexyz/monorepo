//! Closed-form expressions of Σ2 (optimizer design §7.2–§7.4): the language
//! the loop summarizer classifies, synthesizes, validates and renders in.
//!
//! A [`CE`] is a small typed expression over the **ghost inputs** of a loop
//! summary (the entry values of its dynamic state, [`CE::Var`]) and, in a
//! per-variable closed form, the **iteration index** `j` ([`CE::J`], the
//! number of iterations done). It is used three ways:
//!
//! * evaluated natively on sample inputs ([`CE::eval`]; the semantics are the
//!   kernel's primitive semantics — wrapping arithmetic, shift amounts mod the
//!   width, `lz(0) = w` — so traces and synthesis agree with the kernel; the
//!   chosen candidates are validated again by kernel evaluation);
//! * rendered as core text at a literal `j` ([`CE::text`] with `J` bound to a
//!   literal): the per-literal lemma statements, where every shift amount and
//!   mask becomes a literal (the fragment of `BvRefl` and linear arithmetic);
//! * rendered with `j` replaced by an expression (a synthesized witness): the
//!   closed form printed in the emitted code.
//!
//! Everything here is untrusted: a wrong closed form only fails its lemmas.

use std::fmt::Write as _;
use std::rc::Rc;

use sandblaster_kernel::term::{PrimOp, Width};

/// A value of the native evaluator: a machine word (as `u128`, masked to
/// its width), a boolean, or `Int` (as `i128`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Val {
    W(Width, u128),
    B(bool),
    I(i128),
}

impl Val {
    pub fn as_u128(self) -> Option<u128> {
        match self {
            Val::W(_, n) => Some(n),
            Val::I(n) if n >= 0 => Some(n as u128),
            _ => None,
        }
    }
    pub fn as_bool(self) -> Option<bool> {
        match self {
            Val::B(b) => Some(b),
            _ => None,
        }
    }
}

/// The type of an expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ty {
    W(Width),
    Bool,
}

pub fn bits(w: Width) -> u32 {
    w.bits().unwrap_or(128)
}

pub fn mask(w: Width) -> u128 {
    let b = bits(w);
    if b >= 128 { u128::MAX } else { (1u128 << b) - 1 }
}

/// A closed-form expression (see the module docs). Shared (`Rc`).
pub type E = Rc<CE>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CE {
    /// Ghost input `i` (of the given width).
    Var(u32, Width),
    /// The iteration index `j` (`U32`).
    J,
    Lit(Width, u128),
    BoolLit(bool),
    /// A total primitive (the ops of [`total_op`]).
    Op(PrimOp, Vec<E>),
    /// `x >> a` as mathematics: `0` when `a ≥ w` (a per-variable closed
    /// form: a shift by `k` applied `j` times).
    ShrSat(E, E),
    /// `x << a` as mathematics, truncated to the width: `0` when `a ≥ w`.
    ShlSat(E, E),
    /// `x / c` for a literal `c > 0` (checked division; the proof is closed).
    DivLit(E, u128),
    /// `if c { a } else { b }`.
    Ite(E, E, E),
}

/// Whether `op` is a total primitive the language uses.
pub fn total_op(op: PrimOp) -> bool {
    use PrimOp::*;
    matches!(
        op,
        WAdd(_)
            | WSub(_)
            | WMul(_)
            | And(_)
            | Or(_)
            | Xor(_)
            | Not(_)
            | WShl(_)
            | WShr(_)
            | Min(_)
            | Max(_)
            | SatAdd(_)
            | SatSub(_)
            | CountOnes(_)
            | LeadingZeros(_)
            | TrailingZeros(_)
            | Eq(_)
            | Ne(_)
            | Lt(_)
            | Le(_)
            | Gt(_)
            | Ge(_)
            | Cast { .. }
            | IAdd
            | ISub
            | IMul
    )
}

pub fn var(i: u32, w: Width) -> E {
    Rc::new(CE::Var(i, w))
}
pub fn j() -> E {
    Rc::new(CE::J)
}
pub fn lit(w: Width, n: u128) -> E {
    Rc::new(CE::Lit(w, n & mask(w)))
}
pub fn op(o: PrimOp, args: Vec<E>) -> E {
    Rc::new(CE::Op(o, args))
}
pub fn op2(o: PrimOp, a: E, b: E) -> E {
    op(o, vec![a, b])
}
pub fn ite(c: E, a: E, b: E) -> E {
    Rc::new(CE::Ite(c, a, b))
}

impl CE {
    /// The expression's type.
    pub fn ty(&self) -> Ty {
        use PrimOp::*;
        match self {
            CE::Var(_, w) | CE::Lit(w, _) => Ty::W(*w),
            CE::J => Ty::W(Width::U32),
            CE::BoolLit(_) => Ty::Bool,
            CE::ShrSat(x, _) | CE::ShlSat(x, _) | CE::DivLit(x, _) => x.ty(),
            CE::Ite(_, a, _) => a.ty(),
            CE::Op(o, args) => match o {
                Eq(_) | Ne(_) | Lt(_) | Le(_) | Gt(_) | Ge(_) => Ty::Bool,
                CountOnes(_) | LeadingZeros(_) | TrailingZeros(_) => Ty::W(Width::U32),
                Cast { to, .. } => Ty::W(*to),
                IAdd | ISub | IMul => Ty::W(Width::Int),
                _ => args.first().map(|a| a.ty()).unwrap_or(Ty::Bool),
            },
        }
    }

    pub fn width(&self) -> Option<Width> {
        match self.ty() {
            Ty::W(w) => Some(w),
            Ty::Bool => None,
        }
    }

    /// Size (nodes).
    pub fn size(&self) -> usize {
        match self {
            CE::Var(..) | CE::J | CE::Lit(..) | CE::BoolLit(_) => 1,
            CE::Op(_, a) => 1 + a.iter().map(|x| x.size()).sum::<usize>(),
            CE::ShrSat(a, b) | CE::ShlSat(a, b) => 1 + a.size() + b.size(),
            CE::DivLit(a, _) => 2 + a.size(),
            CE::Ite(c, a, b) => 1 + c.size() + a.size() + b.size(),
        }
    }

    /// Whether `J` occurs.
    pub fn has_j(&self) -> bool {
        match self {
            CE::J => true,
            CE::Var(..) | CE::Lit(..) | CE::BoolLit(_) => false,
            CE::Op(_, a) => a.iter().any(|x| x.has_j()),
            CE::ShrSat(a, b) | CE::ShlSat(a, b) => a.has_j() || b.has_j(),
            CE::DivLit(a, _) => a.has_j(),
            CE::Ite(c, a, b) => c.has_j() || a.has_j() || b.has_j(),
        }
    }

    /// The ghost inputs that occur.
    pub fn vars(&self, out: &mut Vec<u32>) {
        match self {
            CE::Var(i, _) => {
                if !out.contains(i) {
                    out.push(*i)
                }
            }
            CE::J | CE::Lit(..) | CE::BoolLit(_) => {}
            CE::Op(_, a) => a.iter().for_each(|x| x.vars(out)),
            CE::ShrSat(a, b) | CE::ShlSat(a, b) => {
                a.vars(out);
                b.vars(out)
            }
            CE::DivLit(a, _) => a.vars(out),
            CE::Ite(c, a, b) => {
                c.vars(out);
                a.vars(out);
                b.vars(out)
            }
        }
    }

    /// Native evaluation with `vars` for the ghost inputs and `jv` for `J`
    /// (`None` on a type error or an undefined value).
    pub fn eval(&self, vars: &[u128], jv: Option<u128>) -> Option<Val> {
        Some(match self {
            CE::Var(i, w) => Val::W(*w, *vars.get(*i as usize)? & mask(*w)),
            CE::J => Val::W(Width::U32, jv?),
            CE::Lit(Width::Int, n) => Val::I(*n as i128),
            CE::Lit(w, n) => Val::W(*w, *n),
            CE::BoolLit(b) => Val::B(*b),
            CE::Ite(c, a, b) => {
                if c.eval(vars, jv)?.as_bool()? {
                    a.eval(vars, jv)?
                } else {
                    b.eval(vars, jv)?
                }
            }
            CE::ShrSat(x, a) => {
                let (w, xv) = word(x.eval(vars, jv)?)?;
                let av = a.eval(vars, jv)?.as_u128()?;
                Val::W(w, if av >= bits(w) as u128 { 0 } else { xv >> av })
            }
            CE::ShlSat(x, a) => {
                let (w, xv) = word(x.eval(vars, jv)?)?;
                let av = a.eval(vars, jv)?.as_u128()?;
                Val::W(w, if av >= bits(w) as u128 { 0 } else { (xv << av) & mask(w) })
            }
            CE::DivLit(x, c) => {
                let (w, xv) = word(x.eval(vars, jv)?)?;
                if *c == 0 {
                    return None;
                }
                Val::W(w, xv / c)
            }
            CE::Op(o, args) => {
                let vs: Vec<Val> = args.iter().map(|a| a.eval(vars, jv)).collect::<Option<_>>()?;
                eval_op(*o, &vs)?
            }
        })
    }
}

fn word(v: Val) -> Option<(Width, u128)> {
    match v {
        Val::W(w, n) => Some((w, n)),
        _ => None,
    }
}

/// A total primitive on native values (the kernel's semantics).
pub fn eval_op(o: PrimOp, vs: &[Val]) -> Option<Val> {
    use PrimOp::*;
    let w1 = |i: usize| -> Option<u128> { vs.get(i)?.as_u128() };
    let int = |i: usize| -> Option<i128> {
        match vs.get(i)? {
            Val::I(n) => Some(*n),
            Val::W(_, n) => Some(*n as i128),
            _ => None,
        }
    };
    Some(match o {
        WAdd(w) => Val::W(w, w1(0)?.wrapping_add(w1(1)?) & mask(w)),
        WSub(w) => Val::W(w, w1(0)?.wrapping_sub(w1(1)?) & mask(w)),
        WMul(w) => Val::W(w, w1(0)?.wrapping_mul(w1(1)?) & mask(w)),
        And(w) => Val::W(w, w1(0)? & w1(1)?),
        Or(w) => Val::W(w, w1(0)? | w1(1)?),
        Xor(w) => Val::W(w, w1(0)? ^ w1(1)?),
        Not(w) => Val::W(w, !w1(0)? & mask(w)),
        WShl(w) => Val::W(w, (w1(0)? << (w1(1)? % bits(w) as u128)) & mask(w)),
        WShr(w) => Val::W(w, w1(0)? >> (w1(1)? % bits(w) as u128)),
        Min(w) => Val::W(w, w1(0)?.min(w1(1)?)),
        Max(w) => Val::W(w, w1(0)?.max(w1(1)?)),
        SatAdd(w) => Val::W(w, (w1(0)? + w1(1)?).min(mask(w))),
        SatSub(w) => Val::W(w, w1(0)?.saturating_sub(w1(1)?)),
        CountOnes(_) => Val::W(Width::U32, w1(0)?.count_ones() as u128),
        LeadingZeros(w) => {
            let x = w1(0)?;
            Val::W(Width::U32, if x == 0 { bits(w) as u128 } else { (bits(w) - (128 - x.leading_zeros())) as u128 })
        }
        TrailingZeros(w) => {
            let x = w1(0)?;
            Val::W(Width::U32, if x == 0 { bits(w) as u128 } else { x.trailing_zeros() as u128 })
        }
        Eq(_) => Val::B(int(0)? == int(1)?),
        Ne(_) => Val::B(int(0)? != int(1)?),
        Lt(_) => Val::B(int(0)? < int(1)?),
        Le(_) => Val::B(int(0)? <= int(1)?),
        Gt(_) => Val::B(int(0)? > int(1)?),
        Ge(_) => Val::B(int(0)? >= int(1)?),
        Cast { to: Width::Int, .. } => Val::I(int(0)?),
        Cast { to, .. } => Val::W(to, (int(0)? as u128) & mask(to)),
        IAdd => Val::I(int(0)?.checked_add(int(1)?)?),
        ISub => Val::I(int(0)?.checked_sub(int(1)?)?),
        IMul => Val::I(int(0)?.checked_mul(int(1)?)?),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Substitution and simplification.
// ---------------------------------------------------------------------------

/// `e` with `J` replaced by `by`.
pub fn subst_j(e: &E, by: &E) -> E {
    match &**e {
        CE::J => by.clone(),
        CE::Var(..) | CE::Lit(..) | CE::BoolLit(_) => e.clone(),
        CE::Op(o, a) => op(*o, a.iter().map(|x| subst_j(x, by)).collect()),
        CE::ShrSat(a, b) => Rc::new(CE::ShrSat(subst_j(a, by), subst_j(b, by))),
        CE::ShlSat(a, b) => Rc::new(CE::ShlSat(subst_j(a, by), subst_j(b, by))),
        CE::DivLit(a, c) => Rc::new(CE::DivLit(subst_j(a, by), *c)),
        CE::Ite(c, a, b) => ite(subst_j(c, by), subst_j(a, by), subst_j(b, by)),
    }
}

/// `e` with ghost `i` replaced by `by[i]` (where given).
pub fn subst_vars(e: &E, by: &[Option<E>]) -> E {
    match &**e {
        CE::Var(i, _) => by.get(*i as usize).cloned().flatten().unwrap_or_else(|| e.clone()),
        CE::J | CE::Lit(..) | CE::BoolLit(_) => e.clone(),
        CE::Op(o, a) => op(*o, a.iter().map(|x| subst_vars(x, by)).collect()),
        CE::ShrSat(a, b) => Rc::new(CE::ShrSat(subst_vars(a, by), subst_vars(b, by))),
        CE::ShlSat(a, b) => Rc::new(CE::ShlSat(subst_vars(a, by), subst_vars(b, by))),
        CE::DivLit(a, c) => Rc::new(CE::DivLit(subst_vars(a, by), *c)),
        CE::Ite(c, a, b) => ite(subst_vars(c, by), subst_vars(a, by), subst_vars(b, by)),
    }
}

/// Constant folding (sub-terms without `Var` and, when `jv` is given, with
/// `J` bound) and the saturating shifts at a literal amount (a plain shift
/// below the width, `0` at or above it). The result has the same value as
/// `e` wherever `e` is defined.
pub fn fold(e: &E, jv: Option<u128>) -> E {
    let r = match &**e {
        CE::J => match jv {
            Some(v) => return lit(Width::U32, v),
            None => return e.clone(),
        },
        CE::Var(..) | CE::Lit(..) | CE::BoolLit(_) => return e.clone(),
        CE::Op(o, a) => op(*o, a.iter().map(|x| fold(x, jv)).collect()),
        CE::ShrSat(a, b) => {
            let (a, b) = (fold(a, jv), fold(b, jv));
            if let (CE::Lit(_, n), Some(w)) = (&*b, a.width()) {
                if *n >= bits(w) as u128 {
                    return lit(w, 0);
                }
                // (a shift by 0 stays: `x >> 0` is the atom the library's
                // lemmas at 0 state, `x` is not the same atom)
                op2(PrimOp::WShr(w), a, b)
            } else {
                Rc::new(CE::ShrSat(a, b))
            }
        }
        CE::ShlSat(a, b) => {
            let (a, b) = (fold(a, jv), fold(b, jv));
            if let (CE::Lit(_, n), Some(w)) = (&*b, a.width()) {
                if *n >= bits(w) as u128 {
                    return lit(w, 0);
                }
                if *n == 0 {
                    return a;
                }
                op2(PrimOp::WShl(w), a, b)
            } else {
                Rc::new(CE::ShlSat(a, b))
            }
        }
        CE::DivLit(a, c) => Rc::new(CE::DivLit(fold(a, jv), *c)),
        CE::Ite(c, a, b) => {
            let c = fold(c, jv);
            match &*c {
                CE::BoolLit(true) => return fold(a, jv),
                CE::BoolLit(false) => return fold(b, jv),
                _ => ite(c, fold(a, jv), fold(b, jv)),
            }
        }
    };
    // a closed sub-term: its value
    let mut vs = Vec::new();
    r.vars(&mut vs);
    if vs.is_empty() && (!r.has_j()) {
        if let Some(v) = r.eval(&[], jv) {
            return match v {
                Val::W(w, n) => lit(w, n),
                Val::B(b) => Rc::new(CE::BoolLit(b)),
                Val::I(n) if n >= 0 => lit(Width::Int, n as u128),
                Val::I(_) => r,
            };
        }
    }
    r
}

// ---------------------------------------------------------------------------
// Core text.
// ---------------------------------------------------------------------------

/// A literal in core syntax.
pub fn lit_text(w: Width, n: u128) -> String {
    format!("{n}{}", sandblaster_kernel::prim::width_suffix(w))
}

impl CE {
    /// Core text (kernel syntax) of the expression; `names[i]` is ghost
    /// `i`'s binder name, `jtext` the text standing for `J` (a literal, or
    /// an expression). Saturating shifts must be folded away first (at a
    /// literal amount) or are rendered as a select.
    pub fn text(&self, names: &[String], jtext: Option<&str>) -> String {
        let mut s = String::new();
        self.write(&mut s, names, jtext);
        s
    }

    fn write(&self, s: &mut String, names: &[String], jtext: Option<&str>) {
        use PrimOp::{WShl, WShr};
        match self {
            CE::Var(i, _) => s.push_str(names.get(*i as usize).map(|x| x.as_str()).unwrap_or("?")),
            CE::J => s.push_str(jtext.unwrap_or("?j")),
            CE::Lit(w, n) => s.push_str(&lit_text(*w, *n)),
            CE::BoolLit(b) => s.push_str(if *b { "true" } else { "false" }),
            CE::Op(o, args) => {
                let _ = write!(s, "#{}(", sandblaster_kernel::prim::prim_name(*o));
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    a.write(s, names, jtext);
                }
                s.push(')');
            }
            CE::DivLit(x, c) => {
                let w = x.width().unwrap_or(Width::U64);
                let _ = write!(s, "#div_{}(", sandblaster_kernel::prim::width_suffix(w));
                x.write(s, names, jtext);
                let _ = write!(s, ", {}; refl(Bool, true))", lit_text(w, *c));
            }
            CE::ShrSat(x, a) | CE::ShlSat(x, a) => {
                // `if a < w { x op a } else { 0 }`
                let w = x.width().unwrap_or(Width::U64);
                let ws = sandblaster_kernel::prim::width_suffix(w);
                let o = if matches!(self, CE::ShrSat(..)) { WShr(w) } else { WShl(w) };
                let aw = a.width().unwrap_or(Width::U32);
                let mut at = String::new();
                a.write(&mut at, names, jtext);
                let mut xt = String::new();
                x.write(&mut xt, names, jtext);
                let _ = write!(
                    s,
                    "match #lt_{}({at}, {}) : Bool as _ return {} with | false => 0{ws} | true => #{}({xt}, {at}) end",
                    sandblaster_kernel::prim::width_suffix(aw),
                    lit_text(aw, bits(w) as u128),
                    ty_text(Ty::W(w)),
                    sandblaster_kernel::prim::prim_name(o)
                );
            }
            CE::Ite(c, a, b) => {
                let mut ct = String::new();
                c.write(&mut ct, names, jtext);
                let _ = write!(s, "match {ct} : Bool as _ return {} with | false => ", ty_text(a.ty()));
                b.write(s, names, jtext);
                s.push_str(" | true => ");
                a.write(s, names, jtext);
                s.push_str(" end");
            }
        }
    }
}

/// Core text of a type.
pub fn ty_text(t: Ty) -> String {
    match t {
        Ty::Bool => "Bool".into(),
        Ty::W(w) => match w {
            Width::U8 => "U8".into(),
            Width::U16 => "U16".into(),
            Width::U32 => "U32".into(),
            Width::U64 => "U64".into(),
            Width::Usize => "Usize".into(),
            Width::Int => "Int".into(),
        },
    }
}

/// Human-readable form (the report).
pub fn show(e: &CE, names: &[String]) -> String {
    use PrimOp::*;
    #[allow(unused)]
    let n = |x: &E| show(x, names);
    match e {
        CE::Var(i, _) => names.get(*i as usize).cloned().unwrap_or_else(|| format!("g{i}")),
        CE::J => "j".into(),
        CE::Lit(_, v) => v.to_string(),
        CE::BoolLit(b) => b.to_string(),
        CE::ShrSat(a, b) => format!("({} >> {})", n(a), n(b)),
        CE::ShlSat(a, b) => format!("({} << {})", n(a), n(b)),
        CE::DivLit(a, c) => format!("({} / {c})", n(a)),
        CE::Ite(c, a, b) => format!("(if {} {{ {} }} else {{ {} }})", n(c), n(a), n(b)),
        CE::Op(o, a) => {
            let bin = |sym: &str| format!("({} {sym} {})", n(&a[0]), n(&a[1]));
            match o {
                WAdd(_) | IAdd => bin("+"),
                WSub(_) | ISub => bin("-"),
                WMul(_) | IMul => bin("*"),
                And(_) => bin("&"),
                Or(_) => bin("|"),
                Xor(_) => bin("^"),
                WShl(_) => bin("<<"),
                WShr(_) => bin(">>"),
                Eq(_) => bin("=="),
                Ne(_) => bin("!="),
                Lt(_) => bin("<"),
                Le(_) => bin("<="),
                Gt(_) => bin(">"),
                Ge(_) => bin(">="),
                Not(_) => format!("!{}", n(&a[0])),
                Min(_) => format!("min({}, {})", n(&a[0]), n(&a[1])),
                Max(_) => format!("max({}, {})", n(&a[0]), n(&a[1])),
                SatSub(_) => format!("{}.sat_sub({})", n(&a[0]), n(&a[1])),
                SatAdd(_) => format!("{}.sat_add({})", n(&a[0]), n(&a[1])),
                CountOnes(_) => format!("popcnt({})", n(&a[0])),
                LeadingZeros(_) => format!("lz({})", n(&a[0])),
                TrailingZeros(_) => format!("tz({})", n(&a[0])),
                Cast { to, .. } => format!("({} as {to:?})", n(&a[0])),
                _ => format!("{o:?}({})", a.iter().map(n).collect::<Vec<_>>().join(", ")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_matches_kernel_prims() {
        use num_traits::ToPrimitive;
        let ops = [
            PrimOp::WAdd(Width::U64),
            PrimOp::WSub(Width::U64),
            PrimOp::And(Width::U64),
            PrimOp::Xor(Width::U64),
            PrimOp::WShr(Width::U64),
            PrimOp::WShl(Width::U64),
            PrimOp::SatSub(Width::U64),
            PrimOp::LeadingZeros(Width::U64),
            PrimOp::TrailingZeros(Width::U64),
            PrimOp::CountOnes(Width::U64),
            PrimOp::Lt(Width::U64),
        ];
        let samples: [u64; 6] = [0, 1, 7, 1 << 62, u64::MAX, 0x1234_5678_9abc_def0];
        for o in ops {
            for &a in &samples {
                for &b in &samples {
                    let unary = matches!(o, PrimOp::LeadingZeros(_) | PrimOp::TrailingZeros(_) | PrimOp::CountOnes(_));
                    let b32 = if matches!(o, PrimOp::WShr(_) | PrimOp::WShl(_)) { b % 200 } else { b };
                    let args: Vec<num_bigint::BigInt> = if unary { vec![a.into()] } else { vec![a.into(), b32.into()] };
                    let k = sandblaster_kernel::prim::eval_prim(o, &args).unwrap().unwrap();
                    let vs: Vec<Val> = if unary {
                        vec![Val::W(Width::U64, a as u128)]
                    } else if matches!(o, PrimOp::WShr(_) | PrimOp::WShl(_)) {
                        vec![Val::W(Width::U64, a as u128), Val::W(Width::U32, b32 as u128)]
                    } else {
                        vec![Val::W(Width::U64, a as u128), Val::W(Width::U64, b as u128)]
                    };
                    let n = eval_op(o, &vs).unwrap();
                    match k {
                        sandblaster_kernel::prim::LitOut::Int(_, v) => assert_eq!(n.as_u128().unwrap(), v.to_u128().unwrap(), "{o:?} {a} {b}"),
                        sandblaster_kernel::prim::LitOut::Bool(v) => assert_eq!(n, Val::B(v), "{o:?} {a} {b}"),
                    }
                }
            }
        }
    }
}
