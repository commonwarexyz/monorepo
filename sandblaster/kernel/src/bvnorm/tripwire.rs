//! The `BvRefl` tripwire (DESIGN.md §9.8). **TRUSTED** (it can only reject).
//!
//! Before `BvRefl` accepts an equation that needed the normalizer, both
//! **original** value DAGs (the nodes visited by the normalizer, not its
//! normal forms) are evaluated on [`LANES`] valuations of their free atoms,
//! all at once (nodes in topological order):
//!
//! Lane values are stored flat (one `u64` per node and lane: the machine
//! value, the boolean, or a fingerprint of any other value), with the exact
//! values of ghost-integer nodes on the side.
//!
//! * lanes 0–3 are the corner valuations: every atom `0`, `~0`, `1`,
//!   `0x80…0` (at the atom's width);
//! * lanes 4–35 are pseudo-random: an atom's value is a hash of its
//!   structure — its head (variable level, global, axiom) and the *lane
//!   values* of its relevant arguments — and the lane, so atoms are
//!   uninterpreted functions of their concrete arguments and the valuation
//!   does not depend on the normalizer's classes (only an atom's width,
//!   used to mask its value, comes from the normalizer, and widths come from
//!   the primitives' signatures; a problem in which a class is used at two
//!   widths is rejected before the tripwire runs).
//!
//! Primitives are computed with the kernel's literal semantics
//! ([`crate::prim::eval_machine`] / [`crate::prim::eval_lits`]); checked
//! `add/sub/mul` as their wrapping forms (the normalizer's reading, see
//! [`super::word`] rule 1); a checked op outside its domain (division by
//! zero, `of_int` out of range) is an uninterpreted value of its arguments.
//! A match on a `Bool` takes, per lane, the arm selected by the scrutinee's
//! lane value; closures (λ bodies, Π/Σ codomains, match arms, transport
//! motives) are the lane values of their instances at a fresh variable (an
//! atom like any other). Any mismatch between the two roots rejects.

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use super::{Node, Norm, Shape, mask, width_code};
use crate::prim::{Lit64, LitOut, PrimTy, eval_lits, eval_machine, prim_sig};
use crate::term::{PrimOp, Rel, Width};
use crate::util::{FxMap, tick};
use crate::value::{Budget, EvalError};

/// Corner valuations.
pub(crate) const CORNERS: usize = 4;
/// Total number of valuations (4 corners + 32 pseudo-random).
pub(crate) const LANES: usize = CORNERS + 32;

fn splitmix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn mix(h: u64, x: u64) -> u64 {
    splitmix(h.rotate_left(23) ^ x)
}

/// Fingerprint of a ghost integer.
fn fp_big(n: &BigInt) -> u64 {
    n.to_signed_bytes_le().iter().fold(0x1234_5678, |h, &b| mix(h, b as u64))
}

/// Lane values of all nodes.
struct Tw {
    /// `LANES` entries per node: machine value, boolean (0/1), or the
    /// fingerprint of any other value (for ghost integers, of the integer).
    w: Vec<u64>,
    /// Exact lane values of ghost-integer nodes.
    big: FxMap<u32, Vec<BigInt>>,
}

impl Tw {
    fn lanes(&self, i: u32) -> &[u64] {
        &self.w[i as usize * LANES..(i as usize + 1) * LANES]
    }
}

/// The value of an atom with structural hash `h` on `lane`, at `width`
/// (`None` for ghost integers: see [`atom_big`]).
fn atom(h: u64, lane: usize, width: Option<Width>) -> u64 {
    match width {
        Some(w) if w != Width::Int => {
            let m = mask(w);
            match lane {
                0 => 0,
                1 => m,
                2 => 1,
                3 => (m >> 1) + 1,
                _ => mix(h, lane as u64) & m,
            }
        }
        _ => match lane {
            0 => 0,
            1 => u64::MAX,
            2 => 1,
            3 => 1 << 63,
            _ => mix(h, lane as u64),
        },
    }
}

fn atom_big(h: u64, lane: usize) -> BigInt {
    match lane {
        0 => BigInt::from(0),
        1 => BigInt::from(-1),
        2 => BigInt::from(1),
        3 => BigInt::from(1u64 << 63),
        _ => BigInt::from(mix(h, lane as u64) as i64),
    }
}

fn prim_code(op: PrimOp) -> u64 {
    crate::prim::prim_name(op).bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| mix(h, b as u64))
}

fn lane_desc(lane: usize) -> String {
    match lane {
        0 => "the corner valuation with every atom 0".into(),
        1 => "the corner valuation with every atom ~0".into(),
        2 => "the corner valuation with every atom 1".into(),
        3 => "the corner valuation with every atom 0x80…0".into(),
        k => format!("pseudo-random valuation #{}", k - CORNERS),
    }
}

/// Compute the lanes of node `idx` into `out` (and its exact ghost-integer
/// lanes, if any).
fn node_lanes(norm: &Norm, node: &Node, tw: &Tw, out: &mut [u64; LANES]) -> Option<Vec<BigInt>> {
    let kid = |i: usize| tw.lanes(node.kids[i]);
    let kid_big = |i: usize| tw.big.get(&node.kids[i]);
    let width = norm.classes[node.class as usize].width;
    let is_big = width == Some(Width::Int);
    let hash_kids = |seed: u64, tag: u64, extra: &[u64], lane: usize| {
        let mut h = extra.iter().fold(mix(seed, tag), |h, &x| mix(h, x));
        for i in 0..node.kids.len() {
            h = mix(h, kid(i)[lane]);
        }
        h
    };
    let structural = |out: &mut [u64; LANES], tag: u64, extra: &[u64]| {
        for (lane, o) in out.iter_mut().enumerate() {
            *o = hash_kids(0x9a7e_5eed, tag, extra, lane);
        }
        None
    };
    let atomic = |out: &mut [u64; LANES], tag: u64, extra: &[u64]| {
        if is_big {
            let v: Vec<BigInt> = (0..LANES).map(|lane| atom_big(hash_kids(0xa70e_5eed, tag, extra, lane), lane)).collect();
            for (o, n) in out.iter_mut().zip(&v) {
                *o = fp_big(n);
            }
            return Some(v);
        }
        for (lane, o) in out.iter_mut().enumerate() {
            *o = atom(hash_kids(0xa70e_5eed, tag, extra, lane), lane, width);
        }
        None
    };
    let rels_code = |rels: &[Rel]| rels.iter().fold(1u64, |h, r| mix(h, matches!(r, Rel::Irr) as u64));
    let copy_kid = |out: &mut [u64; LANES], i: usize| {
        out.copy_from_slice(kid(i));
        kid_big(i).cloned()
    };
    match &node.shape {
        Shape::Lit(Width::Int, n) => {
            out.fill(fp_big(n));
            Some(vec![n.clone(); LANES])
        }
        Shape::Lit(_, n) => {
            out.fill(n.to_u64().unwrap_or(0));
            None
        }
        Shape::Prim(op) => prim_lanes(*op, node, tw, out),
        Shape::PairEta | Shape::Unfolded => copy_kid(out, 0),
        Shape::Ctor { ind, ctor, nparams, rels } => {
            if *ind == norm.env.bool_ind() && rels.is_empty() {
                out.fill(*ctor as u64);
                None
            } else {
                structural(out, 1, &[ind.0 as u64, *ctor as u64, *nparams as u64, rels_code(rels)])
            }
        }
        Shape::Pair(has_snd) => structural(out, 2, &[*has_snd as u64]),
        Shape::Sort(s) => structural(out, 3, &[matches!(s, crate::term::Sort::Kind) as u64]),
        Shape::IntTy(w) => structural(out, 4, &[width_code(*w)]),
        Shape::Pi(r) => structural(out, 5, &[matches!(r, Rel::Irr) as u64]),
        Shape::Lam(r) => structural(out, 6, &[matches!(r, Rel::Irr) as u64]),
        Shape::Sigma(r) => structural(out, 7, &[matches!(r, Rel::Irr) as u64]),
        Shape::Eq => structural(out, 8, &[]),
        Shape::Refl => structural(out, 9, &[]),
        Shape::Ind(ind) => structural(out, 10, &[ind.0 as u64]),
        Shape::Absurd => structural(out, 11, &[]),
        Shape::Transport => structural(out, 12, &[]),
        Shape::Var(l) => atomic(out, 20, &[l.0 as u64]),
        Shape::Global { def, rels } => atomic(out, 21, &[def.0 as u64, rels_code(rels)]),
        Shape::Axiom { ax, rels } => atomic(out, 22, &[ax.0 as u64, rels_code(rels)]),
        Shape::App(irr) => atomic(out, 23, &[*irr as u64]),
        Shape::Fst => atomic(out, 24, &[]),
        Shape::Snd => atomic(out, 25, &[]),
        Shape::Match { ind, nparams, nfields } => {
            if *ind == norm.env.bool_ind() && nfields.as_slice() == [0, 0] {
                let arms = [1 + nparams, 2 + nparams];
                let mut big: Option<Vec<BigInt>> = None;
                for (lane, o) in out.iter_mut().enumerate() {
                    let arm = arms[(kid(0)[lane] & 1) as usize];
                    *o = kid(arm)[lane];
                    if let Some(b) = kid_big(arm) {
                        big.get_or_insert_with(|| vec![BigInt::from(0); LANES])[lane] = b[lane].clone();
                    }
                }
                big
            } else {
                atomic(out, 26, &[ind.0 as u64, *nparams as u64])
            }
        }
    }
}

/// A primitive on every lane: machine operations on the flat lanes; ghost
/// integers through the exact literal evaluator.
fn prim_lanes(op: PrimOp, node: &Node, tw: &Tw, out: &mut [u64; LANES]) -> Option<Vec<BigInt>> {
    use PrimOp::*;
    // Checked forms as their wrapping forms (see the module docs).
    let op = match op {
        Add(w) => WAdd(w),
        Sub(w) => WSub(w),
        Mul(w) => WMul(w),
        o => o,
    };
    let kids: Vec<&[u64]> = node.kids.iter().map(|&k| tw.lanes(k)).collect();
    let stuck = |lane: usize| kids.iter().fold(mix(0x5717_c4ed, prim_code(op)), |h, k| mix(h, k[lane]));
    let sig = prim_sig(op);
    let exact = sig.as_ref().is_none_or(|s| s.result == PrimTy::Int(Width::Int) || s.args.contains(&Width::Int))
        || node.kids.iter().any(|k| tw.big.contains_key(k));
    if !exact && kids.len() <= 2 {
        for (lane, o) in out.iter_mut().enumerate() {
            let x = kids.first().map(|k| k[lane]).unwrap_or(0);
            let y = kids.get(1).map(|k| k[lane]).unwrap_or(0);
            *o = match eval_machine(op, x, y) {
                Some(Lit64::Int(_, v)) => v,
                Some(Lit64::Bool(b)) => b as u64,
                None => stuck(lane),
            };
        }
        return None;
    }
    let mut big_out: Option<Vec<BigInt>> = None;
    for (lane, o) in out.iter_mut().enumerate() {
        let args: Vec<BigInt> = node
            .kids
            .iter()
            .map(|k| match tw.big.get(k) {
                Some(b) => b[lane].clone(),
                None => BigInt::from(tw.lanes(*k)[lane]),
            })
            .collect();
        let refs: Vec<&BigInt> = args.iter().collect();
        *o = match eval_lits(op, &refs) {
            Ok(Some(LitOut::Int(Width::Int, n))) => {
                let f = fp_big(&n);
                big_out.get_or_insert_with(|| vec![BigInt::from(0); LANES])[lane] = n;
                f
            }
            Ok(Some(LitOut::Int(_, n))) => n.to_u64().unwrap_or(0),
            Ok(Some(LitOut::Bool(b))) => b as u64,
            _ => stuck(lane),
        };
    }
    big_out
}

/// Evaluate every node up to the roots on all lanes; `Some(message)` on a
/// mismatch between the roots.
pub(crate) fn check(norm: &Norm, li: u32, ri: u32, b: &mut Budget) -> Result<Option<String>, EvalError> {
    let upto = li.max(ri) as usize + 1;
    let mut tw = Tw { w: Vec::with_capacity(upto * LANES), big: FxMap::default() };
    let mut out = [0u64; LANES];
    for (i, n) in norm.nodes[..upto].iter().enumerate() {
        tick(b)?;
        let big = node_lanes(norm, n, &tw, &mut out);
        tw.w.extend_from_slice(&out);
        if let Some(v) = big {
            tw.big.insert(i as u32, v);
        }
    }
    let (lv, rv) = (tw.lanes(li), tw.lanes(ri));
    let (lb, rb) = (tw.big.get(&li), tw.big.get(&ri));
    for lane in 0..LANES {
        let differ = match (lb, rb) {
            (Some(x), Some(y)) => x[lane] != y[lane],
            (None, None) => lv[lane] != rv[lane],
            _ => true,
        };
        if differ {
            let show = |w: &[u64], big: Option<&Vec<BigInt>>| match big {
                Some(v) => format!("{}", v[lane]),
                None => format!("{:#x}", w[lane]),
            };
            return Ok(Some(format!("the sides differ on {}: lhs = {}, rhs = {}", lane_desc(lane), show(lv, lb), show(rv, rb))));
        }
    }
    Ok(None)
}
