//! Enumerative synthesis (optimizer design §7.4): bottom-up enumeration of
//! closed-form expressions with observational-equivalence pruning over the
//! sample vector (EUSolver / Brahma style).
//!
//! The unknowns are witness iterations (the iteration at which a
//! `FirstMatch` payload is set, or a search exits) as functions of the ghost
//! inputs. The grammar: the inputs and the constants of the loop's
//! [`Pool`] (the width's `{0, 1, 2, W−1, W}` and the constants harvested
//! from the loop itself: its literals and their neighbours, its shift
//! amounts `k`, `k − 1`, `2^k`); `+ − ^ & | min max`, `<<` and `>>` by
//! terms, `/c` for the pool's divisors (`2`, the shift amounts, the loop's
//! literal divisors), `lz`, `tz`, `popcnt`, and width casts. Two expressions with the same values on
//! every sample are one class (the smaller is kept), so the search space is
//! the set of distinct behaviours. Bounds: size ≤ [`MAX_SIZE`], at most
//! [`MAX_CANDIDATES`] classes. Deterministic: candidates are generated in a
//! fixed order and the first match (smallest size, then generation order)
//! wins.

use std::collections::HashMap;

use sandblaster_kernel::term::{PrimOp, Width};

use super::expr::{self, CE, E, Ty, Val};
use super::pool::Pool;

pub const MAX_SIZE: usize = 7;
pub const MAX_CANDIDATES: usize = 200_000;

/// A typed pool entry: the expression and its values on the samples.
#[derive(Clone)]
struct Cand {
    e: E,
    vals: Vec<Val>,
}

/// The result of a synthesis run.
pub struct Found {
    pub expr: E,
    /// Classes enumerated.
    pub candidates: usize,
}

/// Synthesizes an expression over the inputs (ghost `i` has width
/// `widths[i]`; `inputs[s][i]` is its value on sample `s`) whose value on
/// every sample is `target[s]` (of type `ty`). `extra` leaves (e.g. `lz` of
/// an input) may be given with their values. `pool`: the loop's constants.
pub fn synthesize(widths: &[Width], inputs: &[Vec<u128>], target: &[Val], ty: Ty, max_size: usize, pool: &Pool) -> Option<Found> {
    synthesize_with(widths, inputs, target, ty, max_size, pool, &|_| true)
}

/// Samples the enumeration runs on (a found candidate is then checked on
/// every sample; a counterexample joins the working set and the enumeration
/// restarts, at most [`MAX_ROUNDS`] times).
pub const WORK_SAMPLES: usize = 48;
pub const MAX_ROUNDS: usize = 4;

/// [`synthesize`] accepting only candidates `accept` allows (a matching
/// candidate it refuses does not claim its behaviour, so an accepted
/// equivalent may still be found). The enumeration runs on a deterministic
/// working set of at most [`WORK_SAMPLES`] samples (counterexample-guided:
/// the result matches every sample).
pub fn synthesize_with(widths: &[Width], inputs: &[Vec<u128>], target: &[Val], ty: Ty, max_size: usize, pool: &Pool, accept: &dyn Fn(&E) -> bool) -> Option<Found> {
    let n = inputs.len();
    if n <= WORK_SAMPLES {
        return enumerate(widths, inputs, target, ty, max_size, pool, accept);
    }
    // the working set: evenly strided (profile and corner samples come first)
    let mut idx: Vec<usize> = (0..WORK_SAMPLES).map(|i| i * n / WORK_SAMPLES).collect();
    let mut total = 0usize;
    for _ in 0..MAX_ROUNDS {
        let wi: Vec<Vec<u128>> = idx.iter().map(|i| inputs[*i].clone()).collect();
        let wt: Vec<Val> = idx.iter().map(|i| target[*i]).collect();
        let f = enumerate(widths, &wi, &wt, ty, max_size, pool, accept)?;
        total += f.candidates;
        match (0..n).find(|s| f.expr.eval(&inputs[*s], None) != Some(target[*s])) {
            None => return Some(Found { expr: f.expr, candidates: total }),
            Some(s) => idx.push(s),
        }
    }
    None
}

fn enumerate(widths: &[Width], inputs: &[Vec<u128>], target: &[Val], ty: Ty, max_size: usize, pool: &Pool, accept: &dyn Fn(&E) -> bool) -> Option<Found> {
    let n = inputs.len();
    if n == 0 || target.len() != n {
        return None;
    }
    let mut pools: Vec<Vec<Cand>> = vec![Vec::new(); max_size + 1];
    let mut seen: HashMap<(Ty, Vec<Val>), ()> = HashMap::new();
    let mut count = 0usize;
    let hit = |c: &Cand| c.e.ty() == ty && c.vals == target && accept(&c.e);
    let push = |pools: &mut Vec<Vec<Cand>>, size: usize, e: E, seen: &mut HashMap<(Ty, Vec<Val>), ()>, count: &mut usize| -> Option<Cand> {
        let vals: Vec<Val> = (0..n).map(|s| e.eval(&inputs[s], None)).collect::<Option<Vec<Val>>>()?;
        let key = (e.ty(), vals.clone());
        if seen.contains_key(&key) {
            return None;
        }
        // a refused match does not claim the target's behaviour
        let refused = e.ty() == ty && vals == target && !accept(&e);
        if refused {
            *count += 1;
            return None;
        }
        seen.insert(key, ());
        *count += 1;
        let c = Cand { e, vals };
        pools[size].push(c.clone());
        Some(c)
    };
    // size 1: inputs and constants
    let mut ws: Vec<Width> = widths.to_vec();
    ws.push(Width::U32);
    ws.sort_by_key(|w| expr::bits(*w));
    ws.dedup();
    for (i, w) in widths.iter().enumerate() {
        if let Some(c) = push(&mut pools, 1, expr::var(i as u32, *w), &mut seen, &mut count)
            && hit(&c)
        {
            return Some(Found { expr: c.e, candidates: count });
        }
    }
    let divisors = pool.divisors();
    for &w in &ws {
        for k in pool.leaves(w) {
            if k <= expr::mask(w)
                && let Some(c) = push(&mut pools, 1, expr::lit(w, k), &mut seen, &mut count)
                && hit(&c)
            {
                return Some(Found { expr: c.e, candidates: count });
            }
        }
    }
    for size in 2..=max_size {
        if count > MAX_CANDIDATES {
            return None;
        }
        // unary: lz, tz, popcnt, casts, /c (argument of size − 1 or − 2)
        let prev: Vec<Cand> = pools[size - 1].clone();
        for a in &prev {
            let Some(w) = a.e.width() else { continue };
            if w == Width::Int {
                continue;
            }
            let mut un: Vec<E> = vec![
                expr::op(PrimOp::LeadingZeros(w), vec![a.e.clone()]),
                expr::op(PrimOp::TrailingZeros(w), vec![a.e.clone()]),
                expr::op(PrimOp::CountOnes(w), vec![a.e.clone()]),
            ];
            for &to in &ws {
                if to != w {
                    un.push(expr::op(PrimOp::Cast { from: w, to }, vec![a.e.clone()]));
                }
            }
            for e in un {
                if let Some(c) = push(&mut pools, size, e, &mut seen, &mut count)
                    && hit(&c)
                {
                    return Some(Found { expr: c.e, candidates: count });
                }
            }
        }
        if size >= 3 {
            let prev2: Vec<Cand> = pools[size - 2].clone();
            for a in &prev2 {
                let Some(w) = a.e.width() else { continue };
                if w == Width::Int {
                    continue;
                }
                for &c in &divisors {
                    let e = std::rc::Rc::new(CE::DivLit(a.e.clone(), c));
                    if let Some(c) = push(&mut pools, size, e, &mut seen, &mut count)
                        && hit(&c)
                    {
                        return Some(Found { expr: c.e, candidates: count });
                    }
                }
            }
        }
        // binary: sizes i + (size − 1 − i)
        for i in 1..size - 1 {
            let k = size - 1 - i;
            let (left, right) = (pools[i].clone(), pools[k].clone());
            for a in &left {
                let Some(wa) = a.e.width() else { continue };
                if wa == Width::Int {
                    continue;
                }
                for b in &right {
                    if count > MAX_CANDIDATES {
                        return None;
                    }
                    let Some(wb) = b.e.width() else { continue };
                    let mut es: Vec<E> = Vec::new();
                    if wa == wb {
                        for o in [PrimOp::WSub(wa), PrimOp::Min(wa), PrimOp::Max(wa)] {
                            es.push(expr::op2(o, a.e.clone(), b.e.clone()));
                        }
                        // commutative ones once
                        if i <= k {
                            for o in [PrimOp::WAdd(wa), PrimOp::Xor(wa), PrimOp::And(wa), PrimOp::Or(wa)] {
                                es.push(expr::op2(o, a.e.clone(), b.e.clone()));
                            }
                        }
                    }
                    if wb == Width::U32 {
                        es.push(expr::op2(PrimOp::WShl(wa), a.e.clone(), b.e.clone()));
                        es.push(expr::op2(PrimOp::WShr(wa), a.e.clone(), b.e.clone()));
                    }
                    for e in es {
                        if let Some(c) = push(&mut pools, size, e, &mut seen, &mut count)
                            && hit(&c)
                        {
                            return Some(Found { expr: c.e, candidates: count });
                        }
                    }
                }
            }
        }
    }
    None
}

/// Synthesizes a comparison predicate `a ⋈ b` (`<`, `≤`, `==`) between two
/// of the given atoms (expressions with their values per sample) matching
/// the boolean `target`; the smallest pair in the given order wins.
pub fn predicate(atoms: &[(E, Vec<Val>)], target: &[bool]) -> Option<E> {
    for (a, va) in atoms {
        for (b, vb) in atoms {
            if a == b || a.ty() != b.ty() {
                continue;
            }
            let Some(w) = a.width() else { continue };
            for o in [PrimOp::Lt(w), PrimOp::Le(w), PrimOp::Eq(w)] {
                let ok = va.iter().zip(vb).zip(target).all(|((x, y), t)| expr::eval_op(o, &[*x, *y]).and_then(|v| v.as_bool()) == Some(*t));
                if ok {
                    return Some(expr::op2(o, a.clone(), b.clone()));
                }
            }
        }
    }
    None
}
