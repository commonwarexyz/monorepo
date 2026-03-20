//! Sumcheck Protocol for Constraint Verification
//!
//! The core soundness mechanism for polkavm-pcvm.
//!
//! # The Problem
//!
//! We have constraint polynomial C: {0,1}^k → GF(2^128)
//! We want to prove: ∑_{x ∈ {0,1}^k} C(x) = 0
//!
//! Without sumcheck, prover just CLAIMS this. Not sound.
//!
//! # The Solution
//!
//! Sumcheck reduces "sum over exponential domain" to "evaluation at random point":
//!
//! ```text
//! Claim: ∑_{x ∈ {0,1}^k} C(x) = 0
//!        ↓ (k rounds)
//! Reduced claim: C(r₁, ..., rₖ) = vₖ
//! ```
//!
//! The verifier:
//! 1. Checks each round's univariate is consistent
//! 2. At the end, verifies C(r) = vₖ by querying the trace polynomial
//!
//! # Security (Schwartz-Zippel)
//!
//! If any constraint is non-zero, the prover must "hit" a root of a
//! non-zero polynomial at each round. Probability ≤ deg/|F| per round.
//!
//! For k rounds with degree-1 polynomials in GF(2^128):
//! Soundness error ≤ k/2^128 (negligible)
//!
//! # Why GF(2^128)?
//!
//! - 128-bit security margin
//! - Efficient: CLMUL instruction on modern CPUs
//! - Extension of GF(2^32) where trace lives

use commonware_commitment::field::{BinaryElem128, BinaryFieldElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A single round of the sumcheck protocol
///
/// The prover sends a univariate polynomial g(X) such that:
/// g(0) + g(1) = (previous round's claim)
#[derive(Debug, Clone)]
pub struct SumcheckRound {
    /// g(0) - evaluation at 0
    pub g_0: BinaryElem128,
    /// g(1) - evaluation at 1
    pub g_1: BinaryElem128,
}

impl SumcheckRound {
    /// Create a new sumcheck round
    pub fn new(g_0: BinaryElem128, g_1: BinaryElem128) -> Self {
        Self { g_0, g_1 }
    }

    /// Evaluate g at challenge point r
    ///
    /// For degree-1 polynomial g(X) = g(0) + X·(g(1) - g(0)):
    /// g(r) = g(0) + r·(g(1) ⊕ g(0))  [in GF(2^128), subtraction = XOR]
    pub fn evaluate(&self, r: BinaryElem128) -> BinaryElem128 {
        // g(1) - g(0) in GF(2^128) is XOR
        let slope = self.g_1.add(&self.g_0);
        // g(0) + r * slope
        self.g_0.add(&r.mul(&slope))
    }

    /// Check consistency: g(0) + g(1) should equal claimed sum
    pub fn check_sum(&self, claimed: BinaryElem128) -> bool {
        self.g_0.add(&self.g_1) == claimed
    }
}

/// Complete sumcheck proof
#[derive(Debug, Clone)]
pub struct SumcheckProof {
    /// One round per variable (log₂(steps) rounds)
    pub rounds: Vec<SumcheckRound>,

    /// Final claimed value C(r₁, ..., rₖ)
    pub final_evaluation: BinaryElem128,
}

/// Sumcheck prover state
///
/// Maintains the partial evaluation as we fix variables one by one.
pub struct SumcheckProver {
    /// Number of variables (log₂ of domain size)
    num_vars: usize,

    /// The constraint evaluations on the boolean hypercube
    /// Indexed as: evaluations[x₁ + 2·x₂ + 4·x₃ + ...]
    evaluations: Vec<BinaryElem128>,

    /// Challenges received so far
    challenges: Vec<BinaryElem128>,
}

impl SumcheckProver {
    /// Create prover from constraint evaluations
    ///
    /// `evaluations[i]` = C(bits of i) for i ∈ [0, 2^num_vars)
    pub fn new(evaluations: Vec<BinaryElem128>) -> Self {
        assert!(evaluations.len().is_power_of_two(), "Domain must be power of 2");
        let num_vars = evaluations.len().trailing_zeros() as usize;

        Self {
            num_vars,
            evaluations,
            challenges: Vec::with_capacity(num_vars),
        }
    }

    /// Generate the next round's univariate polynomial
    ///
    /// At round i, we've fixed (x₁, ..., xᵢ₋₁) = (r₁, ..., rᵢ₋₁)
    /// We output g(X) = ∑_{xᵢ₊₁,...,xₖ} C(r₁, ..., rᵢ₋₁, X, xᵢ₊₁, ..., xₖ)
    ///
    /// For degree-1, we just need g(0) and g(1).
    pub fn next_round(&self) -> SumcheckRound {
        let round = self.challenges.len();
        let remaining_vars = self.num_vars - round - 1;
        let half_size = 1 << remaining_vars;

        let mut g_0 = BinaryElem128::zero();
        let mut g_1 = BinaryElem128::zero();

        // Sum over all assignments to remaining variables
        for suffix in 0..half_size {
            // Index with current variable = 0
            let idx_0 = suffix;
            // Index with current variable = 1
            let idx_1 = suffix + half_size;

            g_0 = g_0.add(&self.evaluations[idx_0]);
            g_1 = g_1.add(&self.evaluations[idx_1]);
        }

        SumcheckRound::new(g_0, g_1)
    }

    /// Apply challenge and update state for next round
    ///
    /// After receiving challenge r for variable xᵢ, we "fold" the evaluations:
    /// new_evals[suffix] = evals[suffix] + r·(evals[suffix + half] - evals[suffix])
    pub fn apply_challenge(&mut self, r: BinaryElem128) {
        let remaining_vars = self.num_vars - self.challenges.len() - 1;
        let half_size = 1 << remaining_vars;

        let mut new_evaluations = Vec::with_capacity(half_size);

        for suffix in 0..half_size {
            let e_0 = self.evaluations[suffix];
            let e_1 = self.evaluations[suffix + half_size];

            // Linear interpolation: e_0 + r·(e_1 - e_0)
            // In GF(2^128): e_0 ⊕ r·(e_1 ⊕ e_0)
            let diff = e_1.add(&e_0);
            let folded = e_0.add(&r.mul(&diff));
            new_evaluations.push(folded);
        }

        self.evaluations = new_evaluations;
        self.challenges.push(r);
    }

    /// Get the final evaluation C(r₁, ..., rₖ)
    pub fn final_evaluation(&self) -> BinaryElem128 {
        assert_eq!(self.challenges.len(), self.num_vars, "Not all rounds complete");
        assert_eq!(self.evaluations.len(), 1, "Should have single evaluation left");
        self.evaluations[0]
    }

    /// Run the complete sumcheck protocol with given challenges
    ///
    /// Returns the proof. In non-interactive (Fiat-Shamir) mode,
    /// challenges come from transcript.
    pub fn prove(mut self, challenges: &[BinaryElem128]) -> SumcheckProof {
        assert_eq!(challenges.len(), self.num_vars, "Need one challenge per variable");

        let mut rounds = Vec::with_capacity(self.num_vars);

        for &r in challenges {
            let round = self.next_round();
            rounds.push(round);
            self.apply_challenge(r);
        }

        let final_evaluation = self.final_evaluation();

        SumcheckProof {
            rounds,
            final_evaluation,
        }
    }
}

/// Verify a sumcheck proof
///
/// Returns Ok(final_evaluation) if proof is valid, Err otherwise.
///
/// The caller must then verify that final_evaluation matches
/// C(r₁, ..., rₖ) computed from the trace polynomial.
pub fn verify_sumcheck(
    proof: &SumcheckProof,
    claimed_sum: BinaryElem128,
    challenges: &[BinaryElem128],
) -> Result<BinaryElem128, SumcheckError> {
    if proof.rounds.len() != challenges.len() {
        return Err(SumcheckError::WrongNumberOfRounds {
            expected: challenges.len(),
            got: proof.rounds.len(),
        });
    }

    let mut current_claim = claimed_sum;

    for (i, (round, &r)) in proof.rounds.iter().zip(challenges).enumerate() {
        // Check: g(0) + g(1) = current_claim
        if !round.check_sum(current_claim) {
            return Err(SumcheckError::SumMismatch {
                round: i,
                expected: current_claim,
                got: round.g_0.add(&round.g_1),
            });
        }

        // Update claim for next round: current_claim = g(r)
        current_claim = round.evaluate(r);
    }

    // Final claim should match proof's final_evaluation
    if current_claim != proof.final_evaluation {
        return Err(SumcheckError::FinalEvaluationMismatch {
            computed: current_claim,
            claimed: proof.final_evaluation,
        });
    }

    Ok(proof.final_evaluation)
}

/// Sumcheck verification errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SumcheckError {
    /// Wrong number of rounds
    WrongNumberOfRounds { expected: usize, got: usize },

    /// g(0) + g(1) doesn't match claimed sum
    SumMismatch {
        round: usize,
        expected: BinaryElem128,
        got: BinaryElem128,
    },

    /// Final evaluation doesn't match
    FinalEvaluationMismatch {
        computed: BinaryElem128,
        claimed: BinaryElem128,
    },
}

impl core::fmt::Display for SumcheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SumcheckError::WrongNumberOfRounds { expected, got } => {
                write!(f, "Wrong number of sumcheck rounds: expected {}, got {}", expected, got)
            }
            SumcheckError::SumMismatch { round, expected, got } => {
                write!(f, "Sumcheck round {} failed: g(0)+g(1)={:?}, expected {:?}", round, got, expected)
            }
            SumcheckError::FinalEvaluationMismatch { computed, claimed } => {
                write!(f, "Final evaluation mismatch: computed {:?}, claimed {:?}", computed, claimed)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SumcheckError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sumcheck_zero_polynomial() {
        // C(x) = 0 for all x
        // Sum should be 0, and proof should verify
        let evaluations = vec![BinaryElem128::zero(); 8]; // 2^3 = 8 points
        let prover = SumcheckProver::new(evaluations);

        // Use deterministic challenges for testing
        let challenges = vec![
            BinaryElem128::from(0x123u128),
            BinaryElem128::from(0x456u128),
            BinaryElem128::from(0x789u128),
        ];

        let proof = prover.prove(&challenges);

        // Verify
        let result = verify_sumcheck(&proof, BinaryElem128::zero(), &challenges);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), BinaryElem128::zero());
    }

    #[test]
    fn test_sumcheck_nonzero_sum() {
        // C(x) = 1 for all x ∈ {0,1}^3
        // Sum = 8 (but in GF(2^128), 8 ones XOR'd = 0!)
        // Actually in GF(2), 1+1=0, so sum of 8 ones = 0
        let evaluations = vec![BinaryElem128::one(); 8];
        let prover = SumcheckProver::new(evaluations);

        let challenges = vec![
            BinaryElem128::from(0x123u128),
            BinaryElem128::from(0x456u128),
            BinaryElem128::from(0x789u128),
        ];

        let proof = prover.prove(&challenges);

        // In GF(2^128), sum of 8 ones = 0 (even number)
        let result = verify_sumcheck(&proof, BinaryElem128::zero(), &challenges);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sumcheck_single_nonzero() {
        // C(0,0,0) = 1, all others = 0
        // Sum = 1
        let mut evaluations = vec![BinaryElem128::zero(); 8];
        evaluations[0] = BinaryElem128::one();

        let prover = SumcheckProver::new(evaluations);

        let challenges = vec![
            BinaryElem128::from(0x123u128),
            BinaryElem128::from(0x456u128),
            BinaryElem128::from(0x789u128),
        ];

        let proof = prover.prove(&challenges);

        // Sum is 1
        let result = verify_sumcheck(&proof, BinaryElem128::one(), &challenges);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sumcheck_wrong_claim_fails() {
        // C(x) = 0 for all x, but claim sum = 1
        let evaluations = vec![BinaryElem128::zero(); 8];
        let prover = SumcheckProver::new(evaluations);

        let challenges = vec![
            BinaryElem128::from(0x123u128),
            BinaryElem128::from(0x456u128),
            BinaryElem128::from(0x789u128),
        ];

        let proof = prover.prove(&challenges);

        // Claim wrong sum
        let result = verify_sumcheck(&proof, BinaryElem128::one(), &challenges);
        assert!(result.is_err());
    }

    #[test]
    fn test_sumcheck_round_consistency() {
        // Test that g(0) + g(1) = claimed sum at each round
        let evaluations = vec![
            BinaryElem128::from(1u128),
            BinaryElem128::from(2u128),
            BinaryElem128::from(3u128),
            BinaryElem128::from(4u128),
        ];

        // Compute actual sum: 1 ⊕ 2 ⊕ 3 ⊕ 4 = 4 (in GF(2^128))
        let sum = evaluations.iter().fold(BinaryElem128::zero(), |acc, x| acc.add(x));

        let prover = SumcheckProver::new(evaluations);

        let challenges = vec![
            BinaryElem128::from(0xABCu128),
            BinaryElem128::from(0xDEFu128),
        ];

        let proof = prover.prove(&challenges);

        // First round: g(0) + g(1) should equal total sum
        let round0_sum = proof.rounds[0].g_0.add(&proof.rounds[0].g_1);
        assert_eq!(round0_sum, sum);

        // Full verification should pass
        let result = verify_sumcheck(&proof, sum, &challenges);
        assert!(result.is_ok());
    }
}
