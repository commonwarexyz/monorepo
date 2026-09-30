//! The fixed list of trusted axiom schemas (DESIGN.md §5.10).
//!
//! Each schema is instantiated per width (an [`AxiomId`] encodes `schema ·
//! 8 + width`); `mul_mono` exists only at `Int`, every other schema only at
//! machine widths. An axiom is a Π telescope (data parameters relevant,
//! hypotheses irrelevant) and a statement; `Axiom { ax, args }` is a
//! full application and never computes.
//!
//! Justification in the set model (all are facts about unsigned integers
//! `0 ≤ a, b < 2^w` and the exact Rust semantics of the primitives):
//! `a & b ≤ a, b`; `a | b ≥ a, b`; `a | b ≤ a + b` (no bit is counted twice);
//! `a ^ b ≤ a | b` (bitwise ⊆); `a >> s ≤ a`; `min`/`max`/saturating ops by
//! cases on the comparison; `count_ones(a) ≤ w`; rotations are inverse
//! bijections; `int_to_sat` clamps; `mul_mono` over ℤ; checked `div/rem` are
//! Euclidean division on naturals when the divisor is nonzero; `a % b < b`;
//! K1 (optimizer design §11.4): `count_ones(a)` is the sum of the bits of
//! `a`, `leading_zeros(a)` counts the `m < w` with `a < 2^m`, and
//! `trailing_zeros(a)` counts the `1 ≤ m ≤ w` with `a & (2^m − 1) = 0` (sums
//! in `Int`). Every schema is tested exhaustively over `U8` and `U16` (one
//! argument exhaustive, the other over a dense grid at `U16`) and at
//! `U64`/`Usize` boundaries against an independent Rust computation; K1 also
//! at 10^7 random and every one-bit/prefix/suffix value (`tests/axioms.rs`).
//! Retired schemas keep their slot (ids never change) and are valid at no
//! width: the four `leading/trailing_zeros_le/lt` bounds are checked lemmas
//! (`sandblaster/front/lemmas/bits.core`) derived from K1.

use std::rc::Rc;

use crate::api::Env;
use crate::prim::{max_of, prim0};
use crate::term::{AxiomId, IndId, Lvl, Name, PrimOp, Rel, Tm, Width};
use crate::util::mk;
use crate::value::{Arg, Budget, EnvEntry, V, VEnv};

/// A parameter telescope: names, relevances and types (each in the context
/// of the previous parameters).
pub type Params = Vec<(Name, Rel, Tm)>;

/// Axiom schemas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Schema {
    AndLeLeft,
    AndLeRight,
    OrGeLeft,
    OrGeRight,
    OrLeAdd,
    XorLeOr,
    ShrLe,
    MinDefLe,
    MinDefGt,
    MaxDefLe,
    MaxDefGt,
    SatSubDefLe,
    SatSubDefGt,
    SatAddDefLe,
    SatAddDefGt,
    CountOnesLe,
    RotrRotl,
    IntToSatDefIn,
    IntToSatDefLo,
    IntToSatDefHi,
    MulMono,
    DivDef,
    RemDef,
    RemLt,
    // Retired (O3): lemmas `bits::{leading,trailing}_zeros_{le,lt}_<w>`.
    LeadingZerosLe,
    TrailingZerosLe,
    LeadingZerosLt,
    TrailingZerosLt,
    CountOnesDef,
    LeadingZerosDef,
    TrailingZerosDef,
}

/// Every schema, in id order (new schemas are appended, so existing ids
/// never change).
pub const SCHEMAS: [Schema; 31] = [
    Schema::AndLeLeft,
    Schema::AndLeRight,
    Schema::OrGeLeft,
    Schema::OrGeRight,
    Schema::OrLeAdd,
    Schema::XorLeOr,
    Schema::ShrLe,
    Schema::MinDefLe,
    Schema::MinDefGt,
    Schema::MaxDefLe,
    Schema::MaxDefGt,
    Schema::SatSubDefLe,
    Schema::SatSubDefGt,
    Schema::SatAddDefLe,
    Schema::SatAddDefGt,
    Schema::CountOnesLe,
    Schema::RotrRotl,
    Schema::IntToSatDefIn,
    Schema::IntToSatDefLo,
    Schema::IntToSatDefHi,
    Schema::MulMono,
    Schema::DivDef,
    Schema::RemDef,
    Schema::RemLt,
    Schema::LeadingZerosLe,
    Schema::TrailingZerosLe,
    Schema::LeadingZerosLt,
    Schema::TrailingZerosLt,
    Schema::CountOnesDef,
    Schema::LeadingZerosDef,
    Schema::TrailingZerosDef,
];

const WIDTHS: [Width; 6] = [Width::U8, Width::U16, Width::U32, Width::U64, Width::Usize, Width::Int];

impl Schema {
    /// Snake-case name (the core syntax writes `axiom[<name>_<width>]`).
    pub fn name(self) -> &'static str {
        match self {
            Schema::AndLeLeft => "and_le_left",
            Schema::AndLeRight => "and_le_right",
            Schema::OrGeLeft => "or_ge_left",
            Schema::OrGeRight => "or_ge_right",
            Schema::OrLeAdd => "or_le_add",
            Schema::XorLeOr => "xor_le_or",
            Schema::ShrLe => "shr_le",
            Schema::MinDefLe => "min_def_le",
            Schema::MinDefGt => "min_def_gt",
            Schema::MaxDefLe => "max_def_le",
            Schema::MaxDefGt => "max_def_gt",
            Schema::SatSubDefLe => "sat_sub_def_le",
            Schema::SatSubDefGt => "sat_sub_def_gt",
            Schema::SatAddDefLe => "sat_add_def_le",
            Schema::SatAddDefGt => "sat_add_def_gt",
            Schema::CountOnesLe => "count_ones_le",
            Schema::RotrRotl => "rotr_rotl",
            Schema::IntToSatDefIn => "int_to_sat_def_in",
            Schema::IntToSatDefLo => "int_to_sat_def_lo",
            Schema::IntToSatDefHi => "int_to_sat_def_hi",
            Schema::MulMono => "mul_mono",
            Schema::DivDef => "div_def",
            Schema::RemDef => "rem_def",
            Schema::RemLt => "rem_lt",
            Schema::LeadingZerosLe => "leading_zeros_le",
            Schema::TrailingZerosLe => "trailing_zeros_le",
            Schema::LeadingZerosLt => "leading_zeros_lt",
            Schema::TrailingZerosLt => "trailing_zeros_lt",
            Schema::CountOnesDef => "count_ones_def",
            Schema::LeadingZerosDef => "leading_zeros_def",
            Schema::TrailingZerosDef => "trailing_zeros_def",
        }
    }

    /// Is the schema instantiable at `w`? (Retired schemas: nowhere.)
    pub fn valid_at(self, w: Width) -> bool {
        use Schema::*;
        !matches!(self, LeadingZerosLe | TrailingZerosLe | LeadingZerosLt | TrailingZerosLt) && (self == MulMono) == (w == Width::Int)
    }
}

/// The id of `schema` at width `w` (`None` if not instantiable there).
pub fn axiom_id(s: Schema, w: Width) -> Option<AxiomId> {
    if !s.valid_at(w) {
        return None;
    }
    let si = SCHEMAS.iter().position(|x| *x == s)? as u32;
    let wi = WIDTHS.iter().position(|x| *x == w)? as u32;
    Some(AxiomId(si * 8 + wi))
}

/// Decode an axiom id.
pub fn decode(ax: AxiomId) -> Option<(Schema, Width)> {
    let s = *SCHEMAS.get((ax.0 / 8) as usize)?;
    let w = *WIDTHS.get((ax.0 % 8) as usize)?;
    if s.valid_at(w) { Some((s, w)) } else { None }
}

/// `and_le_left_u32`, `mul_mono_int`, …
pub fn axiom_name(ax: AxiomId) -> String {
    match decode(ax) {
        Some((s, w)) => format!("{}_{}", s.name(), crate::prim::width_suffix(w)),
        None => format!("invalid_axiom_{}", ax.0),
    }
}

/// Inverse of [`axiom_name`].
pub fn axiom_by_name(n: &str) -> Option<AxiomId> {
    let (base, w) = n.rsplit_once('_')?;
    let w = crate::prim::parse_width(w)?;
    let s = SCHEMAS.iter().find(|s| s.name() == base)?;
    axiom_id(*s, w)
}

/// Relevance of the parameters of an axiom.
pub fn axiom_param_rels(ax: AxiomId) -> Vec<Rel> {
    telescope(ax, IndId(0)).map(|(ps, _)| ps.iter().map(|p| p.1).collect()).unwrap_or_default()
}

/// The parameter telescope (each type in the context of the previous
/// parameters) and the statement (in the context of all parameters).
pub fn telescope(ax: AxiomId, bool_ind: IndId) -> Option<(Params, Tm)> {
    use PrimOp::*;
    let (s, w) = decode(ax)?;
    let int = Width::Int;
    let wt = || mk::int_ty(w);
    let it = || mk::int_ty(int);
    let u32t = || mk::int_ty(Width::U32);
    let n = |x: &str| -> Name { Rc::from(x) };
    let v = mk::var;
    let p = |op: PrimOp, args: Vec<Tm>| prim0(op, args);
    let to_int = |t: Tm| prim0(Cast { from: w, to: int }, vec![t]);
    let holds = |t: Tm| mk::eq_bool(bool_ind, t, true);
    let fails = |t: Tm| mk::eq_bool(bool_ind, t, false);
    let lit = |x: u64| mk::lit(w, x);
    let max_w = || mk::lit(w, max_of(w));
    let max_i = || mk::lit(int, max_of(w));
    let ab = || vec![(n("a"), Rel::Rel, wt()), (n("b"), Rel::Rel, wt())];
    let with_h = |mut ps: Params, h: Tm| {
        ps.push((n("h"), Rel::Irr, h));
        ps
    };
    // In a telescope [a, b]: a = Var(1), b = Var(0); with h: a = 2, b = 1.
    Some(match s {
        Schema::AndLeLeft => (ab(), holds(p(Le(w), vec![p(And(w), vec![v(1), v(0)]), v(1)]))),
        Schema::AndLeRight => (ab(), holds(p(Le(w), vec![p(And(w), vec![v(1), v(0)]), v(0)]))),
        Schema::OrGeLeft => (ab(), holds(p(Le(w), vec![v(1), p(Or(w), vec![v(1), v(0)])]))),
        Schema::OrGeRight => (ab(), holds(p(Le(w), vec![v(0), p(Or(w), vec![v(1), v(0)])]))),
        Schema::OrLeAdd => (ab(), holds(p(Le(int), vec![to_int(p(Or(w), vec![v(1), v(0)])), p(IAdd, vec![to_int(v(1)), to_int(v(0))])]))),
        Schema::XorLeOr => (ab(), holds(p(Le(w), vec![p(Xor(w), vec![v(1), v(0)]), p(Or(w), vec![v(1), v(0)])]))),
        Schema::ShrLe => {
            (vec![(n("a"), Rel::Rel, wt()), (n("s"), Rel::Rel, u32t())], holds(p(Le(w), vec![p(WShr(w), vec![v(1), v(0)]), v(1)])))
        }
        Schema::MinDefLe => (with_h(ab(), holds(p(Le(w), vec![v(1), v(0)]))), mk::eq(wt(), p(Min(w), vec![v(2), v(1)]), v(2))),
        Schema::MinDefGt => (with_h(ab(), fails(p(Le(w), vec![v(1), v(0)]))), mk::eq(wt(), p(Min(w), vec![v(2), v(1)]), v(1))),
        Schema::MaxDefLe => (with_h(ab(), holds(p(Le(w), vec![v(1), v(0)]))), mk::eq(wt(), p(Max(w), vec![v(2), v(1)]), v(1))),
        Schema::MaxDefGt => (with_h(ab(), fails(p(Le(w), vec![v(1), v(0)]))), mk::eq(wt(), p(Max(w), vec![v(2), v(1)]), v(2))),
        Schema::SatSubDefLe => (
            with_h(ab(), holds(p(Le(w), vec![v(0), v(1)]))),
            mk::eq(it(), to_int(p(SatSub(w), vec![v(2), v(1)])), p(ISub, vec![to_int(v(2)), to_int(v(1))])),
        ),
        Schema::SatSubDefGt => (with_h(ab(), fails(p(Le(w), vec![v(0), v(1)]))), mk::eq(wt(), p(SatSub(w), vec![v(2), v(1)]), lit(0))),
        Schema::SatAddDefLe => (
            with_h(ab(), holds(p(Le(int), vec![p(IAdd, vec![to_int(v(1)), to_int(v(0))]), max_i()]))),
            mk::eq(it(), to_int(p(SatAdd(w), vec![v(2), v(1)])), p(IAdd, vec![to_int(v(2)), to_int(v(1))])),
        ),
        Schema::SatAddDefGt => (
            with_h(ab(), fails(p(Le(int), vec![p(IAdd, vec![to_int(v(1)), to_int(v(0))]), max_i()]))),
            mk::eq(wt(), p(SatAdd(w), vec![v(2), v(1)]), max_w()),
        ),
        Schema::CountOnesLe => (
            vec![(n("a"), Rel::Rel, wt())],
            holds(p(Le(Width::U32), vec![p(CountOnes(w), vec![v(0)]), mk::lit(Width::U32, crate::prim::bits(w))])),
        ),
        Schema::RotrRotl => (
            vec![(n("a"), Rel::Rel, wt()), (n("s"), Rel::Rel, u32t())],
            mk::eq(wt(), p(Rotr(w), vec![p(Rotl(w), vec![v(1), v(0)]), v(0)]), v(1)),
        ),
        Schema::IntToSatDefIn => (
            vec![
                (n("i"), Rel::Rel, it()),
                (n("h0"), Rel::Irr, holds(p(Le(int), vec![mk::lit(int, 0u8), v(0)]))),
                (n("h1"), Rel::Irr, holds(p(Le(int), vec![v(1), max_i()]))),
            ],
            mk::eq(it(), to_int(p(IntToSat(w), vec![v(2)])), v(2)),
        ),
        Schema::IntToSatDefLo => (
            vec![(n("i"), Rel::Rel, it()), (n("h"), Rel::Irr, holds(p(Lt(int), vec![v(0), mk::lit(int, 0u8)])))],
            mk::eq(wt(), p(IntToSat(w), vec![v(1)]), lit(0)),
        ),
        Schema::IntToSatDefHi => (
            vec![(n("i"), Rel::Rel, it()), (n("h"), Rel::Irr, holds(p(Lt(int), vec![max_i(), v(0)])))],
            mk::eq(wt(), p(IntToSat(w), vec![v(1)]), max_w()),
        ),
        Schema::MulMono => (
            vec![
                (n("a"), Rel::Rel, it()),
                (n("A"), Rel::Rel, it()),
                (n("b"), Rel::Rel, it()),
                (n("B"), Rel::Rel, it()),
                (n("h1"), Rel::Irr, holds(p(Le(int), vec![mk::lit(int, 0u8), v(3)]))),
                (n("h2"), Rel::Irr, holds(p(Le(int), vec![v(4), v(3)]))),
                (n("h3"), Rel::Irr, holds(p(Le(int), vec![mk::lit(int, 0u8), v(3)]))),
                (n("h4"), Rel::Irr, holds(p(Le(int), vec![v(4), v(3)]))),
            ],
            // a = 7, A = 6, b = 5, B = 4 under the four hypotheses.
            holds(p(Le(int), vec![p(IMul, vec![v(7), v(5)]), p(IMul, vec![v(6), v(4)])])),
        ),
        Schema::DivDef | Schema::RemDef => {
            let (op, iop) = if s == Schema::DivDef { (Div(w), IDiv) } else { (Rem(w), IMod) };
            (
                with_h(ab(), holds(p(Ne(w), vec![v(0), lit(0)]))),
                mk::eq(it(), to_int(mk::prim(op, vec![v(2), v(1)], vec![v(0)])), p(iop, vec![to_int(v(2)), to_int(v(1))])),
            )
        }
        Schema::RemLt => {
            (with_h(ab(), holds(p(Ne(w), vec![v(0), lit(0)]))), holds(p(Lt(w), vec![mk::prim(Rem(w), vec![v(2), v(1)], vec![v(0)]), v(1)])))
        }
        // K1: definitions in `Int`, `[b]` = `match b return Int with false => 0 | true => 1`:
        // count_ones = Σ_{i<w} (a >> i) & 1; leading_zeros = Σ_{m<w} [a < 2^m];
        // trailing_zeros = Σ_{1≤m≤w} [a & (2^m − 1) = 0].
        Schema::CountOnesDef | Schema::LeadingZerosDef | Schema::TrailingZerosDef => {
            let ind = |c: Tm| {
                let arms = vec![mk::arm(&[], mk::lit(int, 0u8)), mk::arm(&[], mk::lit(int, 1u8))];
                Rc::new(crate::term::Term::Match { ind: bool_ind, params: vec![], scrut: c, motive: it(), arms })
            };
            let (op, term): (PrimOp, &dyn Fn(u32) -> Tm) = match s {
                Schema::CountOnesDef => {
                    (CountOnes(w), &|i| to_int(p(And(w), vec![p(WShr(w), vec![v(0), mk::lit(Width::U32, i)]), lit(1)])))
                }
                Schema::LeadingZerosDef => (LeadingZeros(w), &|m| ind(p(Lt(w), vec![v(0), mk::lit(w, 1u128 << m)]))),
                _ => (TrailingZeros(w), &|m| ind(p(Eq(w), vec![p(And(w), vec![v(0), mk::lit(w, (1u128 << (m + 1)) - 1)]), lit(0)]))),
            };
            let sum = (1..crate::prim::bits(w)).fold(term(0), |acc, i| p(IAdd, vec![acc, term(i)]));
            (vec![(n("a"), Rel::Rel, wt())], mk::eq(it(), p(Cast { from: Width::U32, to: int }, vec![p(op, vec![v(0)])]), sum))
        }
        Schema::LeadingZerosLe | Schema::TrailingZerosLe | Schema::LeadingZerosLt | Schema::TrailingZerosLt => return None,
    })
}

/// The full Π type of an axiom (for automation).
pub fn axiom_type(env: &Env, ax: AxiomId) -> Option<Tm> {
    let (ps, stmt) = telescope(ax, env.bool_ind())?;
    Some(ps.into_iter().rev().fold(stmt, |acc, (name, rel, ty)| Rc::new(crate::term::Term::Pi { name, rel, dom: ty, cod: acc })))
}

/// The statement of an axiom instantiated with argument values.
pub(crate) fn axiom_type_value(env: &Env, ax: AxiomId, args: &[Arg], depth: Lvl) -> Option<V> {
    let (ps, stmt) = telescope(ax, env.bool_id)?;
    if ps.len() != args.len() {
        return None;
    }
    let venv = VEnv(Rc::new(args.iter().map(crate::util::arg_entry).collect::<Vec<EnvEntry>>()));
    let mut b = Budget { steps: 100_000 };
    crate::eval::Ev::new(env).eval(&venv, depth, &stmt, &mut b).ok()
}
