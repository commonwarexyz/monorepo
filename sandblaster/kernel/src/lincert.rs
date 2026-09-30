//! Certificate search for `linarith` (DESIGN.md §5.8) — **not trusted**.
//!
//! Since phase 3 a `Linarith` term's certificate is a *hint*: if it does not
//! verify against the kernel's own linear system (typically because the
//! term was obtained by substitution — quoting a value instantiates the
//! proofs inside it, which removes or merges atoms and shifts the canonical
//! constraint positions), the checker searches for a certificate itself with
//! [`farkas`] and then verifies the result with the same exact check
//! (`linarith::check_cert`) that a given certificate goes through. A bug
//! here can therefore only lose certificates (a rejection), never make the
//! kernel accept a proposition that has no valid Farkas certificate over its
//! own linearization; this module is outside the trusted computing base even
//! though it lives in the kernel crate (see `AUDIT.md`).
//!
//! Method: phase I of the simplex method over exact rationals, Bland's rule
//! (terminating and deterministic). A refutation of `eᵢ ≤ 0` / `eᵢ = 0` is a
//! vector `c` with `cᵢ ≥ 0` for `≤` rows, `Σ cᵢ·aᵢⱼ = 0` for every atom `j`
//! and `Σ cᵢ·bᵢ = 1` (Farkas' lemma, constant normalized to 1). Every pivot
//! consumes budget.

use num_integer::Integer;
use num_traits::{One, Signed, Zero};

use crate::linarith::{Constraint, ConstraintKind};
use crate::term::{BigInt, Rat};
use crate::util::tick;
use crate::value::{Budget, EvalError};

/// Exact rational with a positive denominator, in lowest terms.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Q {
    n: BigInt,
    d: BigInt,
}

impl Q {
    fn int(n: BigInt) -> Q {
        Q { n, d: BigInt::one() }
    }
    fn zero() -> Q {
        Q::int(BigInt::zero())
    }
    fn one() -> Q {
        Q::int(BigInt::one())
    }
    fn norm(n: BigInt, d: BigInt) -> Q {
        let g = n.gcd(&d);
        let (mut n, mut d) = if g.is_zero() || g.is_one() { (n, d) } else { (n / &g, d / &g) };
        if d.is_negative() {
            n = -n;
            d = -d;
        }
        Q { n, d }
    }
    fn is_zero(&self) -> bool {
        self.n.is_zero()
    }
    fn is_neg(&self) -> bool {
        self.n.is_negative()
    }
    fn is_pos(&self) -> bool {
        self.n.is_positive()
    }
    fn add(&self, o: &Q) -> Q {
        Q::norm(&self.n * &o.d + &o.n * &self.d, &self.d * &o.d)
    }
    fn sub(&self, o: &Q) -> Q {
        Q::norm(&self.n * &o.d - &o.n * &self.d, &self.d * &o.d)
    }
    fn mul(&self, o: &Q) -> Q {
        Q::norm(&self.n * &o.n, &self.d * &o.d)
    }
    fn div(&self, o: &Q) -> Q {
        Q::norm(&self.n * &o.d, &self.d * &o.n)
    }
    fn lt(&self, o: &Q) -> bool {
        &self.n * &o.d < &o.n * &self.d
    }
}

/// Farkas multipliers (one per constraint, in order) refuting `p`, or
/// `Ok(None)` if `p` is feasible over the rationals (no certificate exists).
/// `natoms` bounds the atom indices.
pub(crate) fn farkas(p: &[Constraint], natoms: usize, b: &mut Budget) -> Result<Option<Vec<Rat>>, EvalError> {
    // Columns: one per ≤ constraint, two (±) per = constraint.
    let mut cols: Vec<(usize, bool)> = Vec::new();
    for (i, c) in p.iter().enumerate() {
        cols.push((i, true));
        if c.kind == ConstraintKind::Eq0 {
            cols.push((i, false));
        }
    }
    // Rows: the atoms that occur, then the constant row (= 1).
    let mut used = vec![false; natoms];
    for c in p {
        for (a, k) in &c.coeffs {
            if *a < natoms && !k.is_zero() {
                used[*a] = true;
            }
        }
    }
    let rows: Vec<usize> = (0..natoms).filter(|a| used[*a]).collect();
    let mut row_of = vec![usize::MAX; natoms];
    for (r, a) in rows.iter().enumerate() {
        row_of[*a] = r;
    }
    let m = rows.len() + 1;
    let n = cols.len();
    let width = n + m + 1;
    let mut t: Vec<Vec<Q>> = vec![vec![Q::zero(); width]; m];
    for (j, (ci, pos)) in cols.iter().enumerate() {
        let c = &p[*ci];
        let sign = |k: &BigInt| if *pos { k.clone() } else { -k.clone() };
        for (a, k) in &c.coeffs {
            if *a < natoms && !k.is_zero() {
                let r = row_of[*a];
                t[r][j] = t[r][j].add(&Q::int(sign(k)));
            }
        }
        t[m - 1][j] = Q::int(sign(&c.constant));
    }
    for (r, row) in t.iter_mut().enumerate() {
        row[n + r] = Q::one();
    }
    t[m - 1][width - 1] = Q::one();
    let mut basis: Vec<usize> = (0..m).map(|r| n + r).collect();
    // Phase-I objective (minimize the sum of the artificials): reduced
    // costs d_j = c_j − Σ_r t[r][j] (every artificial starts basic).
    let mut d: Vec<Q> = vec![Q::zero(); width];
    for (j, dj) in d.iter_mut().enumerate() {
        let cj = if j >= n && j < n + m { Q::one() } else { Q::zero() };
        let mut s = Q::zero();
        for row in &t {
            if !row[j].is_zero() {
                s = s.add(&row[j]);
            }
        }
        *dj = cj.sub(&s);
    }
    // Bland's rule: the smallest entering column with a negative reduced
    // cost; ties in the ratio test go to the smallest basic variable.
    while let Some(e) = (0..n + m).find(|&j| d[j].is_neg()) {
        let mut leave: Option<(usize, Q)> = None;
        for (r, row) in t.iter().enumerate() {
            tick(b)?;
            if row[e].is_pos() {
                let ratio = row[width - 1].div(&row[e]);
                let better = match &leave {
                    None => true,
                    Some((lr, lq)) => ratio.lt(lq) || (ratio == *lq && basis[r] < basis[*lr]),
                };
                if better {
                    leave = Some((r, ratio));
                }
            }
        }
        // Phase I is bounded below by 0, so some row always qualifies.
        let Some((r, _)) = leave else { return Ok(None) };
        pivot(&mut t, &mut d, r, e, b)?;
        basis[r] = e;
    }
    if !d[width - 1].is_zero() {
        return Ok(None);
    }
    let mut y = vec![Q::zero(); n];
    for (r, &bv) in basis.iter().enumerate() {
        if bv < n {
            y[bv] = t[r][width - 1].clone();
        }
    }
    let mut cert = vec![Q::zero(); p.len()];
    for (j, (ci, pos)) in cols.iter().enumerate() {
        if !y[j].is_zero() {
            cert[*ci] = if *pos { cert[*ci].add(&y[j]) } else { cert[*ci].sub(&y[j]) };
        }
    }
    Ok(Some(cert.into_iter().map(|q| Rat { num: q.n, den: q.d }).collect()))
}

/// Pivot on `(r, e)`: normalize row `r` and eliminate column `e` from the
/// other rows and from the reduced costs.
fn pivot(t: &mut [Vec<Q>], d: &mut [Q], r: usize, e: usize, b: &mut Budget) -> Result<(), EvalError> {
    let width = t[r].len();
    let pv = t[r][e].clone();
    if pv != Q::one() {
        for x in t[r].iter_mut() {
            if !x.is_zero() {
                *x = x.div(&pv);
            }
        }
    }
    let prow = t[r].clone();
    let nz: Vec<usize> = (0..width).filter(|&j| !prow[j].is_zero()).collect();
    for (i, row) in t.iter_mut().enumerate() {
        if i == r || row[e].is_zero() {
            continue;
        }
        tick(b)?;
        let f = row[e].clone();
        for &j in &nz {
            row[j] = row[j].sub(&f.mul(&prow[j]));
        }
    }
    if !d[e].is_zero() {
        let f = d[e].clone();
        for &j in &nz {
            d[j] = d[j].sub(&f.mul(&prow[j]));
        }
    }
    Ok(())
}
