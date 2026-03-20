//! Sumcheck-based evaluation proofs for polynomial commitments.
//!
//! Proves P(z_k) = v_k for specific positions z_k in the committed polynomial.
//! Uses a batched sumcheck: Sigma_{x in {0,1}^n} P(x) * Q(x) = Sigma_k alpha_k * v_k
//! where Q(x) = Sigma_k alpha_k * eq(z_k, x).
//!
//! After n sumcheck rounds, the claim reduces to P(r) * Q(r) at a random
//! point r. The verifier computes Q(r) and extracts P(r).
//!
//! NOTE: The eval sumcheck alone does NOT bind to the committed polynomial.
//! A malicious prover could use a different polynomial for the sumcheck vs
//! the Merkle commitment. Full soundness requires an evaluation opening
//! that ties P(r) to the commitment (not yet implemented).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::field::BinaryFieldElement;

/// A single evaluation claim: the polynomial at position `index` equals `value`.
///
/// `index` is an integer whose binary representation gives the boolean
/// evaluation point.
#[derive(Clone, Debug)]
pub struct EvalClaim<T: BinaryFieldElement> {
    pub index: usize,
    pub value: T,
}

/// Round data from the evaluation sumcheck (degree-2 univariate).
///
/// g(X) = s0 + (s0+s1+s2)*X + s2*X^2
/// where s0 = g(0), s1 = g(1), s2 = coefficient of X^2.
#[derive(Clone, Debug)]
pub struct EvalSumcheckRound<U: BinaryFieldElement> {
    pub s0: U,
    pub s1: U,
    pub s2: U,
}

impl<U: BinaryFieldElement> EvalSumcheckRound<U> {
    /// Evaluate the degree-2 polynomial at point r.
    ///
    /// g(r) = s0 + (s0+s1+s2)*r + s2*r^2
    pub fn evaluate(&self, r: U) -> U {
        let b = self.s0.add(&self.s1).add(&self.s2);
        self.s0.add(&b.mul(&r)).add(&self.s2.mul(&r.mul(&r)))
    }
}

/// Compute the batched eq table: Q[j] = Sigma_k alpha_k * eq(z_k, j)
/// where j ranges over [0, N) and z_k is the binary representation of
/// claim indices.
///
/// eq(z, x) = Prod_i (z_i*x_i + (1+z_i)(1+x_i)) for binary field.
pub fn compute_batched_eq<T, U>(claims: &[EvalClaim<T>], alphas: &[U], n: usize) -> Vec<U>
where
    T: BinaryFieldElement,
    U: BinaryFieldElement + From<T>,
{
    let size = 1usize << n;
    let mut q = vec![U::zero(); size];

    for (claim, &alpha) in claims.iter().zip(alphas.iter()) {
        // Build eq(z_k, .) via tensor product expansion
        let mut eq_table = vec![U::zero(); size];
        eq_table[0] = U::one();
        let z = claim.index;

        for i in 0..n {
            let bit = (z >> i) & 1;
            let half = 1usize << i;
            // Process in reverse so j+half writes don't clobber unread entries
            for j in (0..half).rev() {
                let val = eq_table[j];
                if bit == 1 {
                    // eq_bit(1, 0) = 0, eq_bit(1, 1) = 1
                    eq_table[j + half] = val; // x_i = 1: keep
                    eq_table[j] = U::zero(); // x_i = 0: zero
                } else {
                    // eq_bit(0, 0) = 1, eq_bit(0, 1) = 0
                    eq_table[j + half] = U::zero(); // x_i = 1: zero
                                                     // eq_table[j] unchanged: x_i = 0: keep
                }
            }
        }

        // Accumulate: Q += alpha_k * eq_k
        for j in 0..size {
            q[j] = q[j].add(&alpha.mul(&eq_table[j]));
        }
    }

    q
}

/// Run the evaluation sumcheck prover.
///
/// Proves Sigma_{x in {0,1}^n} P(x)*Q(x) = target
/// where Q = Sigma_k alpha_k * eq(z_k, x) and target = Sigma_k alpha_k * v_k.
///
/// Returns (round_data, challenges, folded_P) where:
/// - round_data: sumcheck round coefficients for the verifier
/// - challenges: r_1,...,r_n produced by Fiat-Shamir
/// - folded_P: the fully-folded scalar P(r_1,...,r_n)
pub fn eval_sumcheck_prove<T, U>(
    poly: &[T],
    claims: &[EvalClaim<T>],
    alphas: &[U],
    n: usize,
    fs: &mut impl crate::Transcript,
) -> (Vec<EvalSumcheckRound<U>>, Vec<U>, U)
where
    T: BinaryFieldElement,
    U: BinaryFieldElement + From<T>,
{
    let mut p: Vec<U> = poly.iter().map(|&x| U::from(x)).collect();
    let mut q = compute_batched_eq::<T, U>(claims, alphas, n);

    let mut rounds = Vec::with_capacity(n);
    let mut challenges = Vec::with_capacity(n);

    for _round in 0..n {
        let half = p.len() / 2;

        // Compute round coefficients
        let mut s0 = U::zero();
        let mut s1 = U::zero();
        let mut s2 = U::zero();

        for j in 0..half {
            let p0 = p[2 * j];
            let p1 = p[2 * j + 1];
            let q0 = q[2 * j];
            let q1 = q[2 * j + 1];

            // s0 = Sigma P_even * Q_even (x_i = 0)
            s0 = s0.add(&p0.mul(&q0));
            // s1 = Sigma P_odd * Q_odd (x_i = 1)
            s1 = s1.add(&p1.mul(&q1));
            // s2 = Sigma (P_odd + P_even)(Q_odd + Q_even) = coeff of X^2
            let dp = p1.add(&p0);
            let dq = q1.add(&q0);
            s2 = s2.add(&dp.mul(&dq));
        }

        let round = EvalSumcheckRound { s0, s1, s2 };

        // Absorb round data into transcript
        fs.absorb_elem(s0);
        fs.absorb_elem(s1);
        fs.absorb_elem(s2);

        // Get challenge
        let r: U = fs.challenge();

        // Fold P and Q
        let mut p_new = Vec::with_capacity(half);
        let mut q_new = Vec::with_capacity(half);
        for j in 0..half {
            // p_new[j] = p[2j] + r*(p[2j+1] + p[2j])
            p_new.push(p[2 * j].add(&r.mul(&p[2 * j + 1].add(&p[2 * j]))));
            q_new.push(q[2 * j].add(&r.mul(&q[2 * j + 1].add(&q[2 * j]))));
        }

        rounds.push(round);
        challenges.push(r);
        p = p_new;
        q = q_new;
    }

    debug_assert_eq!(p.len(), 1);
    (rounds, challenges, p[0])
}

/// Verify the evaluation sumcheck.
///
/// Checks that the round coefficients are consistent, then derives
/// P(r) from the final claim and the verifier-computable Q(r).
///
/// Returns (challenges, claimed_p_at_r) if verification passes.
pub fn eval_sumcheck_verify<T, U>(
    rounds: &[EvalSumcheckRound<U>],
    claims: &[EvalClaim<T>],
    alphas: &[U],
    target: U,
    n: usize,
    fs: &mut impl crate::Transcript,
) -> Option<(Vec<U>, U)>
where
    T: BinaryFieldElement,
    U: BinaryFieldElement + From<T>,
{
    if rounds.len() != n {
        return None;
    }

    let mut claimed_sum = target;
    let mut challenges = Vec::with_capacity(n);

    for round in rounds {
        // Check: s0 + s1 = claimed_sum
        if round.s0.add(&round.s1) != claimed_sum {
            return None;
        }

        // Absorb and get challenge (must match prover's transcript)
        fs.absorb_elem(round.s0);
        fs.absorb_elem(round.s1);
        fs.absorb_elem(round.s2);
        let r: U = fs.challenge();

        // Next claimed sum = g(r)
        claimed_sum = round.evaluate(r);
        challenges.push(r);
    }

    // After n rounds: claimed_sum = P(r) * Q(r)
    // Compute Q(r) = Sigma_k alpha_k * eq(z_k, r)
    let q_at_r = compute_eq_at_r(claims, alphas, &challenges);

    if q_at_r == U::zero() {
        // Degenerate case: cannot derive P(r)
        return None;
    }

    // P(r) = claimed_sum / Q(r)
    // In binary fields, division = multiply by inverse
    let q_inv = q_at_r.inv();
    let p_at_r = claimed_sum.mul(&q_inv);

    Some((challenges, p_at_r))
}

/// Compute Q(r) = Sigma_k alpha_k * eq(z_k, r) where r = (r_1,...,r_n).
///
/// eq(z, r) = Prod_i (z_i*r_i + (1+z_i)(1+r_i))
fn compute_eq_at_r<T, U>(claims: &[EvalClaim<T>], alphas: &[U], challenges: &[U]) -> U
where
    T: BinaryFieldElement,
    U: BinaryFieldElement + From<T>,
{
    let mut result = U::zero();

    for (claim, &alpha) in claims.iter().zip(alphas.iter()) {
        let z = claim.index;
        let mut eq_val = U::one();

        for (i, &r_i) in challenges.iter().enumerate() {
            let z_bit = (z >> i) & 1;

            let factor = if z_bit == 1 {
                // eq_bit(1, r_i) = r_i
                r_i
            } else {
                // eq_bit(0, r_i) = 1 + r_i
                U::one().add(&r_i)
            };
            eq_val = eq_val.mul(&factor);
        }

        result = result.add(&alpha.mul(&eq_val));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{BinaryElem128, BinaryElem32};

    // NOTE: eval_sumcheck_prove/verify tests require a Transcript implementation.
    // These tests are disabled until the transcript module is ported.

    #[test]
    fn test_eq_table_single_claim() {
        // eq(z=0, x) should be 1 at x=0, 0 elsewhere (for n=1)
        let claims = vec![EvalClaim {
            index: 0,
            value: BinaryElem32::one(),
        }];
        let alphas = vec![BinaryElem128::one()];
        let q = compute_batched_eq::<BinaryElem32, BinaryElem128>(&claims, &alphas, 1);
        assert_eq!(q[0], BinaryElem128::one()); // eq(0, 0) = 1
        assert_eq!(q[1], BinaryElem128::zero()); // eq(0, 1) = 0
    }

    #[test]
    fn test_eq_table_identity() {
        // eq(z=3, x) for n=2: should be 1 at x=3, 0 elsewhere
        let claims = vec![EvalClaim {
            index: 3,
            value: BinaryElem32::one(),
        }];
        let alphas = vec![BinaryElem128::one()];
        let q = compute_batched_eq::<BinaryElem32, BinaryElem128>(&claims, &alphas, 2);
        assert_eq!(q[0], BinaryElem128::zero());
        assert_eq!(q[1], BinaryElem128::zero());
        assert_eq!(q[2], BinaryElem128::zero());
        assert_eq!(q[3], BinaryElem128::one());
    }
}
