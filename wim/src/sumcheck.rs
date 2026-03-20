//! Sumcheck Protocol for Constraint Verification

use commonware_commitment::field::{BinaryElem128, BinaryFieldElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct SumcheckRound {
    pub g_0: BinaryElem128,
    pub g_1: BinaryElem128,
}

impl SumcheckRound {
    pub fn new(g_0: BinaryElem128, g_1: BinaryElem128) -> Self { Self { g_0, g_1 } }

    pub fn evaluate(&self, r: BinaryElem128) -> BinaryElem128 {
        let slope = self.g_1.add(&self.g_0);
        self.g_0.add(&r.mul(&slope))
    }

    pub fn check_sum(&self, claimed: BinaryElem128) -> bool {
        self.g_0.add(&self.g_1) == claimed
    }
}

#[derive(Debug, Clone)]
pub struct SumcheckProof {
    pub rounds: Vec<SumcheckRound>,
    pub final_evaluation: BinaryElem128,
}

pub struct SumcheckProver {
    num_vars: usize,
    evaluations: Vec<BinaryElem128>,
    challenges: Vec<BinaryElem128>,
}

impl SumcheckProver {
    pub fn new(evaluations: Vec<BinaryElem128>) -> Self {
        assert!(evaluations.len().is_power_of_two());
        let num_vars = evaluations.len().trailing_zeros() as usize;
        Self { num_vars, evaluations, challenges: Vec::with_capacity(num_vars) }
    }

    pub fn next_round(&self) -> SumcheckRound {
        let remaining_vars = self.num_vars - self.challenges.len() - 1;
        let half_size = 1 << remaining_vars;
        let mut g_0 = BinaryElem128::zero();
        let mut g_1 = BinaryElem128::zero();
        for suffix in 0..half_size {
            g_0 = g_0.add(&self.evaluations[suffix]);
            g_1 = g_1.add(&self.evaluations[suffix + half_size]);
        }
        SumcheckRound::new(g_0, g_1)
    }

    pub fn apply_challenge(&mut self, r: BinaryElem128) {
        let remaining_vars = self.num_vars - self.challenges.len() - 1;
        let half_size = 1 << remaining_vars;
        let mut new_evaluations = Vec::with_capacity(half_size);
        for suffix in 0..half_size {
            let e_0 = self.evaluations[suffix];
            let e_1 = self.evaluations[suffix + half_size];
            let diff = e_1.add(&e_0);
            new_evaluations.push(e_0.add(&r.mul(&diff)));
        }
        self.evaluations = new_evaluations;
        self.challenges.push(r);
    }

    pub fn final_evaluation(&self) -> BinaryElem128 {
        assert_eq!(self.challenges.len(), self.num_vars);
        assert_eq!(self.evaluations.len(), 1);
        self.evaluations[0]
    }

    pub fn prove(mut self, challenges: &[BinaryElem128]) -> SumcheckProof {
        assert_eq!(challenges.len(), self.num_vars);
        let mut rounds = Vec::with_capacity(self.num_vars);
        for &r in challenges {
            rounds.push(self.next_round());
            self.apply_challenge(r);
        }
        SumcheckProof { rounds, final_evaluation: self.final_evaluation() }
    }
}

pub fn verify_sumcheck(
    proof: &SumcheckProof, claimed_sum: BinaryElem128, challenges: &[BinaryElem128],
) -> Result<BinaryElem128, SumcheckError> {
    if proof.rounds.len() != challenges.len() {
        return Err(SumcheckError::WrongNumberOfRounds {
            expected: challenges.len(), got: proof.rounds.len(),
        });
    }
    let mut current_claim = claimed_sum;
    for (i, (round, &r)) in proof.rounds.iter().zip(challenges).enumerate() {
        if !round.check_sum(current_claim) {
            return Err(SumcheckError::SumMismatch {
                round: i, expected: current_claim, got: round.g_0.add(&round.g_1),
            });
        }
        current_claim = round.evaluate(r);
    }
    if current_claim != proof.final_evaluation {
        return Err(SumcheckError::FinalEvaluationMismatch {
            computed: current_claim, claimed: proof.final_evaluation,
        });
    }
    Ok(proof.final_evaluation)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SumcheckError {
    WrongNumberOfRounds { expected: usize, got: usize },
    SumMismatch { round: usize, expected: BinaryElem128, got: BinaryElem128 },
    FinalEvaluationMismatch { computed: BinaryElem128, claimed: BinaryElem128 },
}

impl core::fmt::Display for SumcheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SumcheckError::WrongNumberOfRounds { expected, got } =>
                write!(f, "Wrong number of sumcheck rounds: expected {}, got {}", expected, got),
            SumcheckError::SumMismatch { round, expected, got } =>
                write!(f, "Sumcheck round {} failed: g(0)+g(1)={:?}, expected {:?}", round, got, expected),
            SumcheckError::FinalEvaluationMismatch { computed, claimed } =>
                write!(f, "Final evaluation mismatch: computed {:?}, claimed {:?}", computed, claimed),
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
        let evaluations = vec![BinaryElem128::zero(); 8];
        let prover = SumcheckProver::new(evaluations);
        let challenges = vec![
            BinaryElem128::from(0x123u128),
            BinaryElem128::from(0x456u128),
            BinaryElem128::from(0x789u128),
        ];
        let proof = prover.prove(&challenges);
        let result = verify_sumcheck(&proof, BinaryElem128::zero(), &challenges);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sumcheck_wrong_claim_fails() {
        let evaluations = vec![BinaryElem128::zero(); 8];
        let prover = SumcheckProver::new(evaluations);
        let challenges = vec![
            BinaryElem128::from(0x123u128),
            BinaryElem128::from(0x456u128),
            BinaryElem128::from(0x789u128),
        ];
        let proof = prover.prove(&challenges);
        let result = verify_sumcheck(&proof, BinaryElem128::one(), &challenges);
        assert!(result.is_err());
    }
}
