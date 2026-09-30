//! Fourier–Motzkin search for linear-arithmetic certificates (DESIGN.md
//! §5.8, §8.1 step 13). Untrusted: the kernel re-checks every certificate.
//!
//! Input is the kernel's own [`LinSystem`] (from `Env::linearize`), so atoms
//! and the canonical constraint order agree with the checker. For each
//! refutation problem we look for multipliers `λᵢ` (`λᵢ ≥ 0` for `≤ 0`
//! constraints, any sign for `= 0`) such that `Σ λᵢ·eᵢ` has zero atom
//! coefficients and a positive constant (Farkas). Equalities are used first
//! (Gaussian elimination), then inequalities are combined pairwise per
//! eliminated atom, choosing the atom with the least growth. Every derived
//! row carries its derivation from the original constraints (integer
//! coefficients over a common denominator), which becomes the certificate.
//!
//! Search is bounded ([`MAX_ROWS`]) and, inside a prover call, charged to
//! the goal's budget (one unit per coefficient of every derived row,
//! [`crate::auto::meter`]); running out is a failure, never a wrong
//! certificate.

use std::collections::{BTreeMap, HashSet};

use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};
use sandblaster_kernel::linarith::{ConstraintKind, LinSystem};
use sandblaster_kernel::term::Rat;

/// Bound on the number of live rows during elimination.
pub const MAX_ROWS: usize = 6000;

#[derive(Clone, Debug)]
struct Row {
    coeffs: BTreeMap<usize, BigInt>,
    constant: BigInt,
    eq: bool,
    /// Derivation: `row = (Σ deriv[i]·orig[i]) / den`, as a sparse map.
    deriv: BTreeMap<usize, BigInt>,
    den: BigInt,
}

impl Row {
    fn is_contradiction(&self) -> bool {
        self.coeffs.is_empty() && if self.eq { !self.constant.is_zero() } else { self.constant.is_positive() }
    }

    /// `a·self + b·other` (for inequalities `a, b > 0`; for an equality
    /// operand the corresponding factor may be negative).
    fn combine(&self, a: &BigInt, other: &Row, b: &BigInt) -> Row {
        let mut coeffs = BTreeMap::new();
        for (k, c) in &self.coeffs {
            coeffs.insert(*k, c * a);
        }
        for (k, c) in &other.coeffs {
            let e = coeffs.entry(*k).or_insert_with(BigInt::zero);
            *e += c * b;
        }
        coeffs.retain(|_, c| !c.is_zero());
        let constant = &self.constant * a + &other.constant * b;
        // derivations: self = d1/den1, other = d2/den2
        // a·d1/den1 + b·d2/den2 = (a·d1·den2 + b·d2·den1) / (den1·den2)
        let mut deriv = BTreeMap::new();
        for (k, c) in &self.deriv {
            deriv.insert(*k, c * a * &other.den);
        }
        for (k, c) in &other.deriv {
            let e = deriv.entry(*k).or_insert_with(BigInt::zero);
            *e += c * b * &self.den;
        }
        deriv.retain(|_, c: &mut BigInt| !c.is_zero());
        let den = &self.den * &other.den;
        crate::auto::meter::spend(1 + (coeffs.len() + deriv.len()) as u64);
        let mut r = Row { coeffs, constant, eq: self.eq && other.eq, deriv, den };
        r.normalize();
        r
    }

    /// Divides by the gcd of everything (keeps the derivation exact).
    fn normalize(&mut self) {
        let mut g = self.constant.abs();
        for c in self.coeffs.values() {
            g = gcd(&g, c);
        }
        for c in self.deriv.values() {
            g = gcd(&g, c);
        }
        g = gcd(&g, &self.den);
        if g > BigInt::one() {
            for c in self.coeffs.values_mut() {
                *c /= &g;
            }
            for c in self.deriv.values_mut() {
                *c /= &g;
            }
            self.constant /= &g;
            self.den /= &g;
        }
    }

    fn key(&self) -> (Vec<(usize, BigInt)>, BigInt, bool) {
        (self.coeffs.iter().map(|(k, v)| (*k, v.clone())).collect(), self.constant.clone(), self.eq)
    }
}

/// Greatest common divisor of the absolute values (`gcd(0, 0) = 0`).
pub fn gcd(a: &BigInt, b: &BigInt) -> BigInt {
    let (mut x, mut y) = (a.abs(), b.abs());
    while !y.is_zero() {
        let r = &x % &y;
        x = y;
        y = r;
    }
    x
}

/// Searches certificates for every problem of the system; the result is
/// their concatenation (the kernel's `cert` format).
pub fn certificate(sys: &LinSystem) -> Option<Vec<Rat>> {
    let mut out = Vec::new();
    for p in &sys.problems {
        let rows: Vec<Row> = p
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let mut coeffs = BTreeMap::new();
                for (a, k) in &c.coeffs {
                    if !k.is_zero() {
                        *coeffs.entry(*a).or_insert_with(BigInt::zero) += k;
                    }
                }
                coeffs.retain(|_, v: &mut BigInt| !v.is_zero());
                let mut deriv = BTreeMap::new();
                deriv.insert(i, BigInt::one());
                Row { coeffs, constant: c.constant.clone(), eq: c.kind == ConstraintKind::Eq0, deriv, den: BigInt::one() }
            })
            .collect();
        let found = refute(rows)?;
        let mut cert = vec![Rat { num: BigInt::zero(), den: BigInt::one() }; p.len()];
        let sign = if found.eq && found.constant.is_negative() { -BigInt::one() } else { BigInt::one() };
        for (i, c) in &found.deriv {
            let mut num = c * &sign;
            let mut den = found.den.clone();
            if den.is_negative() {
                num = -num;
                den = -den;
            }
            let g = gcd(&num, &den);
            let (num, den) = if g > BigInt::one() { (num / &g, den / &g) } else { (num, den) };
            cert[*i] = Rat { num, den };
        }
        // Inequality multipliers must be nonnegative; equality ones may be
        // negative. A derivation that violates this is a search bug: fail.
        for (i, c) in p.iter().enumerate() {
            if c.kind == ConstraintKind::Le0 && cert[i].num.is_negative() {
                return None;
            }
        }
        out.extend(cert);
    }
    Some(out)
}

/// Finds a contradiction row derivable from `rows`, or `None`.
fn refute(mut rows: Vec<Row>) -> Option<Row> {
    loop {
        // pivot bookkeeping (dedup, atom statistics) is charged per row
        if !crate::auto::meter::spend(1 + rows.len() as u64) {
            return None;
        }
        if let Some(r) = rows.iter().find(|r| r.is_contradiction()) {
            return Some(r.clone());
        }
        // dedup
        let mut seen = HashSet::new();
        rows.retain(|r| seen.insert(r.key()));
        // drop trivially satisfied rows (no atoms, not contradictions)
        rows.retain(|r| !r.coeffs.is_empty());
        if rows.is_empty() {
            return None;
        }
        // pick an atom: prefer one with an equality, else least growth
        let mut atoms: BTreeMap<usize, (usize, usize, bool)> = BTreeMap::new();
        for r in &rows {
            for (a, c) in &r.coeffs {
                let e = atoms.entry(*a).or_insert((0, 0, false));
                if r.eq {
                    e.2 = true;
                } else if c.is_positive() {
                    e.0 += 1;
                } else {
                    e.1 += 1;
                }
            }
        }
        let (&atom, &(np, nn, has_eq)) = atoms.iter().min_by_key(|(_, (p, n, e))| if *e { (0, 0usize) } else { (1, p * n) })?;
        if has_eq {
            let ei = rows.iter().position(|r| r.eq && r.coeffs.contains_key(&atom))?;
            let eqr = rows.remove(ei);
            let e = eqr.coeffs[&atom].clone();
            let mut next = Vec::with_capacity(rows.len());
            for r in rows {
                match r.coeffs.get(&atom).cloned() {
                    None => next.push(r),
                    Some(c) => {
                        // e·r − c·eq (if e > 0), (−e)·r + c·eq (if e < 0)
                        let nr = if e.is_positive() { r.combine(&e, &eqr, &-c) } else { r.combine(&-e.clone(), &eqr, &c) };
                        next.push(nr);
                    }
                }
            }
            rows = next;
        } else {
            if np * nn + rows.len() > MAX_ROWS {
                return None;
            }
            let (with, without): (Vec<Row>, Vec<Row>) = rows.into_iter().partition(|r| r.coeffs.contains_key(&atom));
            let (pos, neg): (Vec<Row>, Vec<Row>) = with.into_iter().partition(|r| r.coeffs[&atom].is_positive());
            let mut next = without;
            for p in &pos {
                let a = p.coeffs[&atom].clone();
                for n in &neg {
                    let b = -n.coeffs[&atom].clone();
                    next.push(p.combine(&b, n, &a));
                }
            }
            rows = next;
        }
    }
}
