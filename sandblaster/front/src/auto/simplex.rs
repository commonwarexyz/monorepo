//! Certificate search for the kernel's linear-arithmetic rule (DESIGN.md
//! §5.8, §8.1 step 13): phase-I simplex over exact rationals.
//!
//! A refutation problem is a list of constraints `eᵢ ≤ 0` / `eᵢ = 0` over
//! integer atoms (in the kernel's canonical order, from
//! `Env::linearize`). A certificate assigns a multiplier `cᵢ` to every
//! constraint (`cᵢ ≥ 0` for `≤`) such that `Σ cᵢ·eᵢ` has all atom
//! coefficients zero and a positive constant (Farkas' lemma). Normalizing the
//! constant to 1, the multipliers are a feasible point of
//!
//! ```text
//!   Σᵢ cᵢ·aᵢⱼ = 0   for every atom j
//!   Σᵢ cᵢ·bᵢ  = 1
//!   cᵢ ≥ 0          for ≤ constraints (= constraints: cᵢ = pᵢ − nᵢ, pᵢ, nᵢ ≥ 0)
//! ```
//!
//! which phase I of the simplex method decides (artificial variables,
//! Bland's rule, so it terminates and is deterministic). The result is
//! re-checked exactly before it is returned, so a bug here can only lose
//! certificates, never produce a wrong one (and the kernel checks anyway).

use num_bigint::BigInt;
use sandblaster_kernel::linarith::{Constraint, ConstraintKind, LinSystem};
use sandblaster_kernel::term::Rat;

use super::rat::Q;

/// Upper bound on simplex pivots per problem (a safety net; Bland's rule
/// terminates anyway).
const MAX_PIVOTS: usize = 20_000;

/// A certificate for every problem of `sys` (concatenated in problem
/// order), or `None` if some problem is feasible over the rationals (or too
/// large).
pub fn certificate(sys: &LinSystem) -> Option<Vec<Rat>> {
    let mut out = Vec::new();
    for p in &sys.problems {
        let c = farkas_staged(p, sys.atoms.len())?;
        out.extend(c.iter().map(Q::to_rat));
    }
    Some(out)
}

/// [`farkas`] on growing neighbourhoods of the hypotheses and the negated
/// goal: first the constraints over the atoms those mention (the implicit
/// atom bounds and definitions whose atoms are all among them), then one
/// more hop of atoms per round, then everything. A certificate of a subset
/// is one of the whole problem (zero multipliers elsewhere). The kernel's
/// systems carry many implicit constraints (two bounds per atom, three per
/// quotient/remainder pair) that a refutation rarely needs; a dense phase-I
/// simplex over all of them is slow (e.g. `count_ones(x) ≤ 64` from
/// `count_ones_def`: 256 atoms, 895 constraints). Implicit constraints that
/// share no atom with the neighbourhood are satisfiable on their own (they
/// are true facts), so when the neighbourhood stops growing the problem is
/// feasible.
pub fn farkas_staged(p: &[Constraint], natoms: usize) -> Option<Vec<Q>> {
    farkas_staged_point(p, natoms).ok()
}

/// [`farkas_staged`], or the feasible point of the last (largest)
/// neighbourhood when there is no certificate (see [`farkas_or_point`]).
pub fn farkas_staged_point(p: &[Constraint], natoms: usize) -> Result<Vec<Q>, Option<Vec<Option<Q>>>> {
    use sandblaster_kernel::linarith::ConstraintOrigin;
    let core = |c: &Constraint| matches!(c.origin, ConstraintOrigin::Hyp(_) | ConstraintOrigin::NegatedGoal);
    let mut inset = vec![false; natoms];
    for c in p.iter().filter(|c| core(c)) {
        for (a, _) in &c.coeffs {
            if *a < natoms {
                inset[*a] = true;
            }
        }
    }
    let mut last = 0usize;
    let mut point = None;
    loop {
        let sel: Vec<usize> = (0..p.len()).filter(|&i| core(&p[i]) || p[i].coeffs.iter().all(|(a, _)| *a < natoms && inset[*a])).collect();
        if sel.len() == p.len() {
            return farkas_or_point(p, natoms);
        }
        if sel.len() > last {
            last = sel.len();
            let sub: Vec<Constraint> = sel.iter().map(|&i| p[i].clone()).collect();
            match farkas_or_point(&sub, natoms) {
                Ok(c) => {
                    let mut full = vec![Q::zero(); p.len()];
                    for (k, &i) in sel.iter().enumerate() {
                        full[i] = c[k].clone();
                    }
                    return Ok(full);
                }
                Err(None) => return Err(None),
                Err(pt) => point = pt,
            }
        }
        // one more hop
        if !grow(p, natoms, &mut inset) {
            return Err(point);
        }
    }
}

/// Adds the atoms of every constraint that mentions an atom of `inset`
/// (one hop); whether it grew.
fn grow(p: &[Constraint], natoms: usize, inset: &mut [bool]) -> bool {
    let mut grew = false;
    for c in p {
        if c.coeffs.iter().any(|(a, _)| *a < natoms && inset[*a]) {
            for (a, _) in &c.coeffs {
                if *a < natoms && !inset[*a] {
                    inset[*a] = true;
                    grew = true;
                }
            }
        }
    }
    grew
}

/// A certificate for every problem of `sys`, searched from the negated
/// goal outwards: the first neighbourhood is the goal's atoms alone (not
/// every hypothesis's, as in [`farkas_staged_point`]), then one more hop
/// of atoms per round over every constraint. For a side condition that a
/// few of many hypotheses imply, the first neighbourhoods are small. When
/// the hypotheses are consistent this finds a certificate exactly when
/// [`certificate`] does: a minimal infeasible subsystem then contains the
/// negated goal and is connected through shared atoms, so it lies within
/// the goal's last neighbourhood. (Hypotheses contradictory among
/// themselves and unrelated to the goal refute nothing here.)
pub fn certificate_directed(sys: &LinSystem) -> Option<Vec<Rat>> {
    let mut out = Vec::new();
    for p in &sys.problems {
        let c = farkas_directed(p, sys.atoms.len())?;
        out.extend(c.iter().map(Q::to_rat));
    }
    Some(out)
}

/// [`farkas`] on the neighbourhoods of the negated goal (see
/// [`certificate_directed`]); `None` when the last one is feasible (or
/// the search gives up).
fn farkas_directed(p: &[Constraint], natoms: usize) -> Option<Vec<Q>> {
    use sandblaster_kernel::linarith::ConstraintOrigin;
    let goal = |c: &Constraint| matches!(c.origin, ConstraintOrigin::NegatedGoal);
    let mut inset = vec![false; natoms];
    for c in p.iter().filter(|c| goal(c)) {
        for (a, _) in &c.coeffs {
            if *a < natoms {
                inset[*a] = true;
            }
        }
    }
    let mut last = 0usize;
    loop {
        let sel: Vec<usize> = (0..p.len()).filter(|&i| goal(&p[i]) || p[i].coeffs.iter().all(|(a, _)| *a < natoms && inset[*a])).collect();
        if sel.len() == p.len() {
            return farkas_or_point(p, natoms).ok();
        }
        if sel.len() > last {
            last = sel.len();
            let sub: Vec<Constraint> = sel.iter().map(|&i| p[i].clone()).collect();
            match farkas_or_point(&sub, natoms) {
                Ok(c) => {
                    let mut full = vec![Q::zero(); p.len()];
                    for (k, &i) in sel.iter().enumerate() {
                        full[i] = c[k].clone();
                    }
                    return Some(full);
                }
                Err(None) => return None,
                Err(Some(_)) => {}
            }
        }
        if !grow(p, natoms, &mut inset) {
            return None;
        }
    }
}

/// Farkas multipliers (one per constraint) refuting `p`, if any.
pub fn farkas(p: &[Constraint], natoms: usize) -> Option<Vec<Q>> {
    farkas_or_point(p, natoms).ok()
}

/// Farkas multipliers refuting `p`, or — when `p` is feasible over the
/// rationals — a feasible point: one value per atom that occurs in `p`
/// (`None` for the others), read off the optimal phase-I tableau (the dual
/// values `y` of the atom rows divided by that of the constant row). The
/// point feeds branch-and-bound style integer cuts ([`super::arith`]).
/// `Err(None)` when the search gives up (pivot or budget limit).
pub fn farkas_or_point(p: &[Constraint], natoms: usize) -> Result<Vec<Q>, Option<Vec<Option<Q>>>> {
    farkas_impl(p, natoms)
}

fn farkas_impl(p: &[Constraint], natoms: usize) -> Result<Vec<Q>, Option<Vec<Option<Q>>>> {
    // Trivial refutation: a constraint with no atoms and a positive
    // constant (`c ≤ 0` / `c = 0` with c > 0), or `c = 0` with c < 0.
    for (i, c) in p.iter().enumerate() {
        if c.coeffs.iter().all(|(_, k)| k == &BigInt::from(0)) {
            let k = Q::int(c.constant.clone());
            let m = if k.is_pos() {
                Some(Q::one())
            } else if k.is_neg() && c.kind == ConstraintKind::Eq0 {
                Some(Q::int(BigInt::from(-1)))
            } else {
                None
            };
            if let Some(m) = m {
                let mut cert = vec![Q::zero(); p.len()];
                cert[i] = m;
                return Ok(cert);
            }
        }
    }
    // Columns: (constraint index, sign).
    let mut cols: Vec<(usize, i8)> = Vec::new();
    for (i, c) in p.iter().enumerate() {
        cols.push((i, 1));
        if c.kind == ConstraintKind::Eq0 {
            cols.push((i, -1));
        }
    }
    // Rows: atoms that occur, plus the constant row.
    let mut used = vec![false; natoms];
    for c in p {
        for (a, k) in &c.coeffs {
            if *a < natoms && k != &BigInt::from(0) {
                used[*a] = true;
            }
        }
    }
    let atom_rows: Vec<usize> = (0..natoms).filter(|a| used[*a]).collect();
    let m = atom_rows.len() + 1;
    let n = cols.len();
    // Dense tableau: m rows × (n structural + m artificial + 1 rhs).
    let width = n + m + 1;
    let mut t: Vec<Vec<Q>> = vec![vec![Q::zero(); width]; m];
    for (j, (ci, sign)) in cols.iter().enumerate() {
        let c = &p[*ci];
        let s = BigInt::from(*sign);
        for (a, k) in &c.coeffs {
            if let Some(r) = atom_rows.iter().position(|x| x == a) {
                t[r][j] = t[r][j].add(&Q::int(k * &s));
            }
        }
        t[m - 1][j] = Q::int(&c.constant * &s);
    }
    for (r, row) in t.iter_mut().enumerate() {
        row[n + r] = Q::one();
    }
    t[m - 1][width - 1] = Q::one();
    let mut basis: Vec<usize> = (0..m).map(|r| n + r).collect();
    // Phase-I objective: minimize Σ artificials. Reduced costs
    // d_j = c_j − Σ_r c_B(r)·t[r][j] with c = 1 on artificials.
    let mut d: Vec<Q> = vec![Q::zero(); width];
    for (j, dj) in d.iter_mut().enumerate().take(width) {
        let cj = if j >= n && j < n + m { Q::one() } else { Q::zero() };
        let mut s = Q::zero();
        for row in &t {
            if !row[j].is_zero() {
                s = s.add(&row[j]);
            }
        }
        *dj = cj.sub(&s);
    }
    // d[width-1] = −(current objective value).
    let mut pivots = 0;
    // Bland: smallest column index with negative reduced cost.
    while let Some(e) = (0..n + m).find(|&j| d[j].is_neg()) {
        // Ratio test; ties broken by the smallest basic variable index.
        let mut leave: Option<(usize, Q)> = None;
        for (r, row) in t.iter().enumerate() {
            if row[e].is_pos() {
                let ratio = row[width - 1].div(&row[e]);
                let better = match &leave {
                    None => true,
                    Some((lr, lq)) => ratio < *lq || (ratio == *lq && basis[r] < basis[*lr]),
                };
                if better {
                    leave = Some((r, ratio));
                }
            }
        }
        let Some((r, _)) = leave else { return Err(None) }; // unbounded: impossible in phase I
        // one pivot touches every row (charged to the goal, auto::meter)
        if !super::meter::spend((t.len() * width) as u64) {
            return Err(None);
        }
        pivot(&mut t, &mut d, r, e);
        basis[r] = e;
        pivots += 1;
        if pivots > MAX_PIVOTS {
            return Err(None);
        }
    }
    // Optimal: a certificate iff the objective is zero. Otherwise the dual
    // values y_r = 1 − d(artificial r) satisfy y·A_j ≤ 0 for every column
    // with y_const = the (positive) optimum, so y_atom / y_const is a point
    // satisfying every constraint.
    if !d[width - 1].is_zero() {
        let yc = Q::one().sub(&d[n + m - 1]);
        if !yc.is_pos() {
            return Err(None);
        }
        let mut point = vec![None; natoms];
        for (r, &a) in atom_rows.iter().enumerate() {
            point[a] = Some(Q::one().sub(&d[n + r]).div(&yc));
        }
        return Err(Some(point));
    }
    let mut y = vec![Q::zero(); n];
    for (r, &bv) in basis.iter().enumerate() {
        if bv < n {
            y[bv] = t[r][width - 1].clone();
        }
    }
    let mut cert = vec![Q::zero(); p.len()];
    for (j, (ci, sign)) in cols.iter().enumerate() {
        if !y[j].is_zero() {
            let v = if *sign > 0 { y[j].clone() } else { y[j].neg() };
            cert[*ci] = cert[*ci].add(&v);
        }
    }
    if verify(p, &cert) { Ok(cert) } else { Err(None) }
}

/// One pivot on `(r, e)`: normalize row `r`, eliminate column `e` elsewhere
/// (including the reduced-cost row).
fn pivot(t: &mut [Vec<Q>], d: &mut [Q], r: usize, e: usize) {
    let width = t[r].len();
    let pv = t[r][e].clone();
    if !(pv == Q::one()) {
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
}

/// Exact check of a certificate (the kernel's acceptance condition).
pub fn verify(p: &[Constraint], cert: &[Q]) -> bool {
    if cert.len() != p.len() {
        return false;
    }
    let mut sum: std::collections::BTreeMap<usize, Q> = std::collections::BTreeMap::new();
    let mut constant = Q::zero();
    for (c, m) in p.iter().zip(cert) {
        if c.kind == ConstraintKind::Le0 && m.is_neg() {
            return false;
        }
        if m.is_zero() {
            continue;
        }
        for (a, k) in &c.coeffs {
            let e = sum.entry(*a).or_insert_with(Q::zero);
            *e = e.add(&m.mul(&Q::int(k.clone())));
        }
        constant = constant.add(&m.mul(&Q::int(c.constant.clone())));
    }
    sum.values().all(Q::is_zero) && constant.is_pos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandblaster_kernel::linarith::ConstraintOrigin;

    fn le(coeffs: &[(usize, i64)], k: i64) -> Constraint {
        Constraint {
            coeffs: coeffs.iter().map(|(a, c)| (*a, BigInt::from(*c))).collect(),
            constant: BigInt::from(k),
            kind: ConstraintKind::Le0,
            origin: ConstraintOrigin::NegatedGoal,
        }
    }

    fn eq(coeffs: &[(usize, i64)], k: i64) -> Constraint {
        Constraint { kind: ConstraintKind::Eq0, ..le(coeffs, k) }
    }

    #[test]
    fn refutes_simple_systems() {
        // x ≤ 3, x ≥ 5  ⇒  x − 3 ≤ 0, 5 − x ≤ 0
        let p = vec![le(&[(0, 1)], -3), le(&[(0, -1)], 5)];
        let c = farkas(&p, 1).expect("refutable");
        assert!(verify(&p, &c));
        // x = 2y, x = 2y + 1 over the rationals is infeasible.
        let p = vec![eq(&[(0, 1), (1, -2)], 0), eq(&[(0, 1), (1, -2)], -1)];
        assert!(farkas(&p, 2).is_some());
        // x ≤ 3, x ≥ 2 is feasible.
        let p = vec![le(&[(0, 1)], -3), le(&[(0, -1)], 2)];
        assert!(farkas(&p, 1).is_none());
        // Trivial: 1 ≤ 0.
        let p = vec![le(&[], 1)];
        assert!(farkas(&p, 0).is_some());
    }

    #[test]
    fn needs_fractional_multipliers() {
        // 2x ≥ 1, 3x ≤ 1  ⇒  1 − 2x ≤ 0, 3x − 1 ≤ 0  (x ∈ [1/2, 1/3]: empty)
        let p = vec![le(&[(0, -2)], 1), le(&[(0, 3)], -1)];
        let c = farkas(&p, 1).expect("refutable");
        assert!(verify(&p, &c));
    }
}
