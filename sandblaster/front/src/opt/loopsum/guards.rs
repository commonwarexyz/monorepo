//! Guard trees (optimizer design §7.4): when no single expression of the
//! grammar matches a witness on every sample, the samples are partitioned
//! by one of the loop's own comparisons and each part is synthesized
//! separately (an EUSolver decision tree of depth one); the result is
//! `ite(guard, E₁, E₂)`. Predicates for `FirstMatch` loops (when the payload
//! is set, whether the result is set) are comparisons of two atoms.
//!
//! Every constant here comes from the loop ([`Pool`]): the thresholds of
//! `xᵢ < c` are the loop's own comparison literals and the per-iteration
//! boundaries of its shift amounts, and the template's divisors are the
//! pool's (never a fixed list of one target's constants).

use sandblaster_kernel::term::{PrimOp, Width};

use super::expr::{self, E, Ty, Val};
use super::pool::Pool;
use super::synth;

/// Guards tried for a depth-1 tree.
pub const MAX_GUARDS: usize = 8;

/// Candidate guards over the inputs, in the order tried: `xᵢ < xⱼ` (the
/// loop's own tests between inputs), `xᵢ == 0`, then `xᵢ < c` for the
/// pool's thresholds ([`Pool::thresholds`]).
pub fn candidate_guards(widths: &[Width], pool: &Pool) -> Vec<E> {
    // the comparisons of two inputs first (the loop's own tests), then
    // `xᵢ == 0`, then `xᵢ < c`
    let mut out = Vec::new();
    for (i, w) in widths.iter().enumerate() {
        for (k, w2) in widths.iter().enumerate() {
            if k != i && w2 == w {
                out.push(expr::op2(PrimOp::Lt(*w), expr::var(i as u32, *w), expr::var(k as u32, *w2)));
            }
        }
    }
    for (i, w) in widths.iter().enumerate() {
        out.push(expr::op2(PrimOp::Eq(*w), expr::var(i as u32, *w), expr::lit(*w, 0)));
    }
    for (i, w) in widths.iter().enumerate() {
        let x = expr::var(i as u32, *w);
        for c in pool.thresholds(*w) {
            out.push(expr::op2(PrimOp::Lt(*w), x.clone(), expr::lit(*w, c)));
        }
    }
    out
}

/// A witness as one expression, or as `ite(guard, E₁, E₂)` over a
/// candidate guard (each side synthesized on its part of the samples).
/// Returns the expression and the classes enumerated.
pub fn witness(widths: &[Width], inputs: &[Vec<u128>], target: &[Val], max_size: usize, pool: &Pool) -> Option<(E, usize)> {
    if let Some(e) = affine_atom(widths, inputs, target, pool) {
        return Some((e, 0));
    }
    if let Some(f) = synth::synthesize_with(widths, inputs, target, Ty::W(Width::U32), max_size, pool, &solvable) {
        return Some((f.expr, f.candidates));
    }
    let mut total = 0usize;
    // (a bounded number of guards: a failing witness must fail fast)
    for g in candidate_guards(widths, pool).into_iter().take(MAX_GUARDS) {
        let (mut ti, mut tt, mut fi, mut ft) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (x, t) in inputs.iter().zip(target) {
            match g.eval(x, None).and_then(|v| v.as_bool()) {
                Some(true) => {
                    ti.push(x.clone());
                    tt.push(*t);
                }
                Some(false) => {
                    fi.push(x.clone());
                    ft.push(*t);
                }
                None => return None,
            }
        }
        if ti.len() < 2 || fi.len() < 2 {
            continue;
        }
        let small = max_size.saturating_sub(2).max(1);
        let (Some(a), Some(b)) = (synth::synthesize_with(widths, &ti, &tt, Ty::W(Width::U32), small, pool, &solvable), synth::synthesize_with(widths, &fi, &ft, Ty::W(Width::U32), small, pool, &solvable)) else { continue };
        total += a.candidates + b.candidates;
        return Some((expr::ite(g, a.expr, b.expr), total));
    }
    None
}

/// Whether the prover can pin a witness to a literal: an affine function
/// of one bit-count atom whose operand is a variable or the `^` of two
/// (`super::lemmas::solve_atom` and the pinning lemmas), or a plain
/// variable-free / `J`-free expression of such atoms under `/c` is not.
pub fn solvable(e: &E) -> bool {
    use super::expr::CE;
    let Some((atom, _)) = super::lemmas::solve_atom(e, 0) else { return false };
    let CE::Op(op, a) = &*atom else { return false };
    let simple = |x: &E| matches!(&**x, CE::Var(..));
    match op {
        PrimOp::LeadingZeros(_) => simple(&a[0]) || matches!(&*a[0], CE::Op(PrimOp::Xor(_), xy) if simple(&xy[0]) && simple(&xy[1])),
        PrimOp::TrailingZeros(_) => simple(&a[0]),
        _ => false,
    }
}

/// The template library's shapes (design §7.4: proposed directly, the
/// enumeration stays the general path): a witness `c ± A` or `(c − A) / k`
/// for a bit-count atom `A` — `lz`, `tz` or `popcnt` of an input, of the
/// `^` of two inputs, or of `x | 1` (the generic operand that makes `lz`
/// and `tz` total) — with `k` one of the pool's divisors
/// ([`Pool::divisors`]: `2`, the loop's shift amounts and literal
/// divisors). The offset `c` is solved from the samples. Each candidate is
/// checked on every sample.
pub fn affine_atom(widths: &[Width], inputs: &[Vec<u128>], target: &[Val], pool: &Pool) -> Option<E> {
    let n = widths.len();
    let mut operands: Vec<E> = (0..n).map(|i| expr::var(i as u32, widths[i])).collect();
    for i in 0..n {
        for j in 0..n {
            if i != j && widths[i] == widths[j] {
                operands.push(expr::op2(PrimOp::Xor(widths[i]), expr::var(i as u32, widths[i]), expr::var(j as u32, widths[j])));
            }
        }
    }
    for i in 0..n {
        operands.push(expr::op2(PrimOp::Or(widths[i]), expr::var(i as u32, widths[i]), expr::lit(widths[i], 1)));
    }
    let tv: Option<Vec<i128>> = target.iter().map(|v| v.as_u128().map(|x| x as i128)).collect();
    let tv = tv?;
    let u32l = |c: i128| expr::lit(Width::U32, c as u128);
    let check = |e: &E| inputs.iter().zip(target).all(|(x, t)| e.eval(x, None) == Some(*t));
    for o in &operands {
        let w = o.width()?;
        for mk in [PrimOp::LeadingZeros(w), PrimOp::TrailingZeros(w), PrimOp::CountOnes(w)] {
            let a = expr::op(mk, vec![o.clone()]);
            let av: Option<Vec<i128>> = inputs.iter().map(|x| a.eval(x, None).and_then(|v| v.as_u128()).map(|v| v as i128)).collect();
            let Some(av) = av else { continue };
            // t = a + c
            let c = tv[0] - av[0];
            if av.iter().zip(&tv).all(|(a, t)| t - a == c) {
                let e = if c == 0 { a.clone() } else if c > 0 { expr::op2(PrimOp::WAdd(Width::U32), a.clone(), u32l(c)) } else { expr::op2(PrimOp::WSub(Width::U32), a.clone(), u32l(-c)) };
                if check(&e) {
                    return Some(e);
                }
            }
            // t = c − a
            let c = tv[0] + av[0];
            if c >= 0 && av.iter().zip(&tv).all(|(a, t)| t + a == c) {
                let e = expr::op2(PrimOp::WSub(Width::U32), u32l(c), a.clone());
                if check(&e) {
                    return Some(e);
                }
            }
            // t = (c − a) / k
            for k in pool.divisors().into_iter().filter_map(|k| i128::try_from(k).ok()).filter(|k| *k > 1 && *k <= 1 << 64) {
                // the offsets every sample allows: `k·t + a ≤ c < k·t + a + k`
                let lo = av.iter().zip(&tv).map(|(a, t)| k * t + a).max().unwrap_or(0).max(0);
                let hi = av.iter().zip(&tv).map(|(a, t)| k * t + a + k).min().unwrap_or(0);
                for c in lo..hi {
                    if av.iter().zip(&tv).all(|(a, t)| c - a >= 0 && (c - a) / k == *t) {
                        let e = std::rc::Rc::new(super::expr::CE::DivLit(expr::op2(PrimOp::WSub(Width::U32), u32l(c), a.clone()), k as u128));
                        if check(&e) {
                            return Some(e);
                        }
                    }
                }
            }
        }
    }
    None
}
