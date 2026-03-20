//! Stateful sumcheck verifier instance.
//!
//! Maintains basis polynomials, challenges, and running state throughout
//! verification of the sumcheck protocol.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::field::BinaryFieldElement;
use crate::utils::partial_eval_multilinear;

/// Error type for sumcheck verifier operations.
#[derive(Debug, Clone, PartialEq)]
pub enum SumcheckError {
    /// Transcript exhausted before verification complete.
    TranscriptExhausted,
    /// Sumcheck coefficient sum does not match expected value.
    SumMismatch,
    /// Claim verification failed during introduce_new.
    ClaimMismatch,
    /// Missing running polynomial during glue operation.
    NoRunningPoly,
    /// Missing polynomial to glue.
    NoPolyToGlue,
    /// Basis polynomial did not fully evaluate.
    IncompleteEvaluation,
    /// Basis polynomial length mismatch during partial evaluation.
    LengthMismatch,
}

/// Linear polynomial structure for binary field sumcheck.
///
/// Represents f(x) = c + b*x.
#[derive(Debug, Clone)]
pub struct LinearPoly<F: BinaryFieldElement> {
    b: F, // coefficient of x
    c: F, // constant term
}

impl<F: BinaryFieldElement> LinearPoly<F> {
    pub const fn new(b: F, c: F) -> Self {
        Self { b, c }
    }

    /// Evaluate linear polynomial at point r: c + b*r.
    pub fn eval(&self, r: F) -> F {
        self.c.add(&self.b.mul(&r))
    }
}

/// Quadratic polynomial structure.
///
/// Represents f(x) = a*x^2 + b*x + c.
#[derive(Debug, Clone)]
pub struct QuadraticPoly<F: BinaryFieldElement> {
    a: F,
    b: F,
    c: F,
}

impl<F: BinaryFieldElement> QuadraticPoly<F> {
    pub const fn new(a: F, b: F, c: F) -> Self {
        Self { a, b, c }
    }

    /// Evaluate quadratic at point r: a*r^2 + b*r + c.
    pub fn eval_quadratic(&self, r: F) -> F {
        self.a.mul(&r).mul(&r).add(&self.b.mul(&r)).add(&self.c)
    }
}

/// Create linear polynomial from two evaluations.
///
/// For binary field sumcheck: g(x) = s0 + (s0 + s2)*x
/// where s0 = g(0) and s2 = g(1).
pub fn linear_from_evals<F: BinaryFieldElement>(s0: F, s2: F) -> LinearPoly<F> {
    // g(x) = s0 + (s0 + s2)*x
    // This gives g(0) = s0 and g(1) = s0 + (s0+s2) = s2 (in binary field)
    LinearPoly::new(s0.add(&s2), s0)
}

/// Create quadratic polynomial from three evaluations.
///
/// Given: f(0) = at0, f(1) = at1, f(x) = atx (default x=3).
/// Computes unique degree-2 polynomial through these points.
pub fn quadratic_from_evals<F: BinaryFieldElement>(at0: F, at1: F, atx: F) -> QuadraticPoly<F> {
    // Default x = 3
    let x = F::from_bits(3);

    // Standard Lagrange interpolation for quadratic
    // numerator = atx + at0 + x*(at1 + at0)
    let numerator = atx.add(&at0).add(&x.mul(&at1.add(&at0)));

    // denominator = x^2 + x
    let denominator = x.mul(&x).add(&x);

    // a = numerator / denominator
    let a = numerator.mul(&denominator.inv());

    // b = at1 + at0 + a
    let b = at1.add(&at0).add(&a);

    QuadraticPoly { a, b, c: at0 }
}

/// Fold two linear polynomials with separation challenge.
///
/// result = p1 + alpha * p2
pub fn fold_linear<F: BinaryFieldElement>(
    p1: LinearPoly<F>,
    p2: LinearPoly<F>,
    alpha: F,
) -> LinearPoly<F> {
    LinearPoly::new(p1.b.add(&alpha.mul(&p2.b)), p1.c.add(&alpha.mul(&p2.c)))
}

/// Fold two quadratic polynomials with separation challenge.
///
/// result = p1 + alpha * p2
pub fn fold_quadratic<F: BinaryFieldElement>(
    p1: QuadraticPoly<F>,
    p2: QuadraticPoly<F>,
    alpha: F,
) -> QuadraticPoly<F> {
    QuadraticPoly::new(
        p1.a.add(&alpha.mul(&p2.a)),
        p1.b.add(&alpha.mul(&p2.b)),
        p1.c.add(&alpha.mul(&p2.c)),
    )
}

/// Stateful sumcheck verifier instance.
///
/// Maintains basis polynomials, challenges, and running state throughout
/// verification.
pub struct SumcheckVerifierInstance<F: BinaryFieldElement> {
    /// Basis polynomials being tracked.
    basis_polys: Vec<Vec<F>>,
    /// Separation challenges for gluing.
    separation_challenges: Vec<F>,
    /// Current sum claim (public so verifier can absorb it).
    pub sum: F,
    /// Full sumcheck transcript.
    transcript: Vec<(F, F, F)>,
    /// Random challenges received so far.
    ris: Vec<F>,
    /// Current position in transcript.
    tr_reader: usize,
    /// Current running polynomial (linear for binary field sumcheck).
    running_poly: Option<LinearPoly<F>>,
    /// Polynomial to be glued next.
    to_glue: Option<LinearPoly<F>>,
}

impl<F: BinaryFieldElement> SumcheckVerifierInstance<F> {
    /// Create new verifier instance with first basis polynomial and initial sum.
    ///
    /// The first `fold()` call will read the first transcript entry.
    pub fn new(b1: Vec<F>, h1: F, transcript: Vec<(F, F, F)>) -> Self {
        Self {
            basis_polys: vec![b1],
            separation_challenges: vec![F::one()],
            sum: h1,
            transcript,
            ris: vec![],
            tr_reader: 0,
            running_poly: None,
            to_glue: None,
        }
    }

    /// Read next transcript entry.
    fn read_tr(&mut self) -> Result<(F, F, F), SumcheckError> {
        if self.tr_reader >= self.transcript.len() {
            return Err(SumcheckError::TranscriptExhausted);
        }
        let (g0, g1, g2) = self.transcript[self.tr_reader];
        self.tr_reader += 1;
        Ok((g0, g1, g2))
    }

    /// Fold the sumcheck with random challenge r.
    pub fn fold(&mut self, r: F) -> Result<(F, F, F), SumcheckError> {
        // Read transcript entry for this round
        let (s0, s_total, s2) = self.read_tr()?;

        // Verify the coefficients match current sum claim
        if s_total != self.sum {
            return Err(SumcheckError::SumMismatch);
        }

        // Construct linear polynomial from the coefficients
        let poly = linear_from_evals(s0, s2);

        // Evaluate at the challenge point to get new sum
        self.sum = poly.eval(r);

        // Update running polynomial for next round
        self.running_poly = Some(poly);

        // Store the challenge
        self.ris.push(r);

        Ok((s0, s_total, s2))
    }

    /// Introduce new basis polynomial to be glued.
    pub fn introduce_new(&mut self, bi: Vec<F>, h: F) -> Result<(F, F, F), SumcheckError> {
        let (s0, s_total, s2) = self.read_tr()?;

        // Verify the new polynomial's claim
        if s_total != h {
            return Err(SumcheckError::ClaimMismatch);
        }

        self.basis_polys.push(bi);

        // Construct linear polynomial from evaluations
        self.to_glue = Some(linear_from_evals(s0, s2));

        Ok((s0, s_total, s2))
    }

    /// Glue the pending polynomial with separation challenge alpha.
    pub fn glue(&mut self, alpha: F) -> Result<(), SumcheckError> {
        if self.running_poly.is_none() {
            return Err(SumcheckError::NoRunningPoly);
        }
        if self.to_glue.is_none() {
            return Err(SumcheckError::NoPolyToGlue);
        }

        self.separation_challenges.push(alpha);

        let running = self.running_poly.take().unwrap();
        let to_glue = self.to_glue.take().unwrap();

        self.running_poly = Some(fold_linear(running, to_glue, alpha));
        Ok(())
    }

    /// Evaluate basis polynomials at the current point (after all folds).
    ///
    /// This is used for the final check.
    fn evaluate_basis_polys(&mut self, r: F) -> Result<F, SumcheckError> {
        self.ris.push(r);

        // Evaluate first basis polynomial at all ris
        let mut b0_copy = self.basis_polys[0].clone();
        partial_eval_multilinear(&mut b0_copy, &self.ris);

        if b0_copy.len() != 1 {
            return Err(SumcheckError::IncompleteEvaluation);
        }
        let mut b_eval = b0_copy[0];

        // Evaluate other basis polynomials
        for i in 1..self.basis_polys.len() {
            let n = self.basis_polys[i].len().ilog2() as usize;
            let num_rs = self.ris.len();

            // Take the last n evaluation points for this basis polynomial
            let eval_pts = if num_rs >= n {
                &self.ris[num_rs - n..]
            } else {
                &self.ris[..]
            };

            let mut bi_copy = self.basis_polys[i].clone();
            partial_eval_multilinear(&mut bi_copy, eval_pts);

            if bi_copy.len() != 1 {
                return Err(SumcheckError::IncompleteEvaluation);
            }
            let bi_eval = bi_copy[0];

            // Add scaled contribution
            b_eval = b_eval.add(&self.separation_challenges[i].mul(&bi_eval));
        }

        Ok(b_eval)
    }

    /// Final verification check: f(r) * basis(r) == sum.
    pub fn verify(&mut self, r: F, f_eval: F) -> Result<bool, SumcheckError> {
        if self.running_poly.is_none() {
            return Ok(false);
        }

        let running_poly = self.running_poly.as_ref().unwrap().clone();
        self.sum = running_poly.eval(r);

        let basis_evals = self.evaluate_basis_polys(r)?;

        Ok(f_eval.mul(&basis_evals) == self.sum)
    }

    /// Evaluate basis polynomials partially (keeping k variables unevaluated).
    ///
    /// Returns a vector of length 2^k.
    fn evaluate_basis_polys_partially(&mut self, r: F, k: usize) -> Result<Vec<F>, SumcheckError> {
        self.ris.push(r);

        // Evaluate first basis polynomial
        let mut b0_copy = self.basis_polys[0].clone();
        partial_eval_multilinear(&mut b0_copy, &self.ris);
        let mut acc = b0_copy;

        // Evaluate and accumulate other basis polynomials
        for i in 1..self.basis_polys.len() {
            let n = self.basis_polys[i].len().ilog2() as usize;
            let num_rs = self.ris.len();

            // Take the last (n - k) evaluation points for this basis polynomial.
            // This leaves k variables unevaluated.
            let eval_len = n.saturating_sub(k);
            let eval_len = eval_len.min(num_rs);

            let eval_pts = if eval_len > 0 {
                &self.ris[num_rs - eval_len..]
            } else {
                &[]
            };

            let mut bi_copy = self.basis_polys[i].clone();
            if !eval_pts.is_empty() {
                partial_eval_multilinear(&mut bi_copy, eval_pts);
            }

            let alpha = self.separation_challenges[i];

            // Accumulate: acc[j] += alpha * bi_eval[j]
            if acc.len() != bi_copy.len() {
                return Err(SumcheckError::LengthMismatch);
            }

            for j in 0..acc.len() {
                acc[j] = acc[j].add(&alpha.mul(&bi_copy[j]));
            }
        }

        Ok(acc)
    }

    /// Final partial verification check: sum(f_partial_eval[i] * basis_evals[i]) == sum.
    ///
    /// Note: in current protocol, verify_ligero provides sufficient verification.
    /// This function is kept for completeness but may not be necessary.
    pub fn verify_partial(&mut self, r: F, f_partial_eval: &[F]) -> Result<bool, SumcheckError> {
        let k = f_partial_eval.len().ilog2() as usize;

        if self.running_poly.is_none() {
            return Ok(false);
        }

        // Evaluate running polynomial at r
        self.sum = self.running_poly.as_ref().unwrap().eval(r);

        // Evaluate basis polynomials partially
        let basis_evals = self.evaluate_basis_polys_partially(r, k)?;

        // Check lengths match
        if f_partial_eval.len() != basis_evals.len() {
            return Ok(false);
        }

        // Compute dot product: sum(f[i] * basis[i])
        let dot_product = f_partial_eval
            .iter()
            .zip(basis_evals.iter())
            .fold(F::zero(), |acc, (&f_i, &b_i)| acc.add(&f_i.mul(&b_i)));

        Ok(dot_product == self.sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BinaryElem128;

    #[test]
    fn test_quadratic_eval() {
        // Test f(x) = x^2 + 2x + 3 in binary field
        let poly = QuadraticPoly::new(
            BinaryElem128::one(),
            BinaryElem128::from_value(2),
            BinaryElem128::from_value(3),
        );

        let val_at_0 = poly.eval_quadratic(BinaryElem128::zero());
        assert_eq!(val_at_0, BinaryElem128::from_value(3));
    }

    #[test]
    fn test_quadratic_from_evals() {
        // Create quadratic from three points
        let at0 = BinaryElem128::from_value(1);
        let at1 = BinaryElem128::from_value(2);
        let at3 = BinaryElem128::from_value(4);

        let poly = quadratic_from_evals(at0, at1, at3);

        // Verify it passes through the points
        assert_eq!(poly.eval_quadratic(BinaryElem128::zero()), at0);
        assert_eq!(poly.eval_quadratic(BinaryElem128::one()), at1);
        assert_eq!(poly.eval_quadratic(BinaryElem128::from_value(3)), at3);
    }

    #[test]
    fn test_fold_quadratic() {
        let p1 = QuadraticPoly::new(
            BinaryElem128::one(),
            BinaryElem128::from_value(2),
            BinaryElem128::from_value(3),
        );
        let p2 = QuadraticPoly::new(
            BinaryElem128::from_value(4),
            BinaryElem128::from_value(5),
            BinaryElem128::from_value(6),
        );
        let alpha = BinaryElem128::from_value(7);

        let folded = fold_quadratic(p1.clone(), p2.clone(), alpha);

        // Check that folded(x) = p1(x) + alpha * p2(x)
        let x = BinaryElem128::from_value(11);
        let expected = p1.eval_quadratic(x).add(&alpha.mul(&p2.eval_quadratic(x)));
        let actual = folded.eval_quadratic(x);
        assert_eq!(actual, expected);
    }
}
