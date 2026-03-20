//! Evaluation Proof Integration

use commonware_commitment::field::{BinaryElem32, BinaryElem128, BinaryFieldElement};
use commonware_commitment::{Proof, VerifierConfig};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct TraceEvaluationProof {
    pub commitment_proof: Proof<BinaryElem32, BinaryElem128>,
    pub eval_point: Vec<BinaryElem128>,
    pub column_evaluations: Vec<BinaryElem128>,
}

pub fn verify_trace_evaluation(
    proof: &TraceEvaluationProof, config: &VerifierConfig,
) -> Result<bool, EvaluationError> {
    let mut transcript = commonware_commitment::transcript::Sha256Transcript::new(0);
    let valid = commonware_commitment::verify(config, &proof.commitment_proof, &mut transcript)
        .map_err(|e| EvaluationError::CommitmentError(format!("{:?}", e)))?;
    if !valid { return Err(EvaluationError::CommitmentVerificationFailed); }
    Ok(true)
}

pub fn compute_column_evaluation_from_openings(
    opened_rows: &[Vec<BinaryElem32>], _query_indices: &[usize],
    lagrange_coeffs: &[BinaryElem128], col: usize,
) -> BinaryElem128 {
    assert_eq!(opened_rows.len(), lagrange_coeffs.len());
    let mut result = BinaryElem128::zero();
    for (row, &coeff) in opened_rows.iter().zip(lagrange_coeffs.iter()) {
        if col < row.len() {
            let val = BinaryElem128::from(row[col]);
            result = result.add(&val.mul(&coeff));
        }
    }
    result
}

// create_evaluation_proof requires polkavm-integration feature (currently disabled)

#[derive(Debug, Clone)]
pub enum EvaluationError {
    CommitmentVerificationFailed,
    CommitmentError(String),
    #[allow(dead_code)]
    PointMismatch { claimed: BinaryElem128, expected: BinaryElem128 },
    #[allow(dead_code)]
    ColumnMismatch { col: usize, computed: BinaryElem128, claimed: BinaryElem128 },
    #[allow(dead_code)]
    ColumnCountMismatch { claimed: usize, available: usize },
    #[allow(dead_code)]
    ColumnEvaluationMismatch { column: usize, claimed: BinaryElem128, computed: BinaryElem128 },
    ProvingError(String),
}

impl core::fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EvaluationError::CommitmentVerificationFailed => write!(f, "Commitment verification failed"),
            EvaluationError::CommitmentError(e) => write!(f, "Commitment error: {}", e),
            EvaluationError::PointMismatch { claimed, expected } =>
                write!(f, "Point mismatch: claimed {:?}, expected {:?}", claimed, expected),
            EvaluationError::ColumnMismatch { col, computed, claimed } =>
                write!(f, "Column {} mismatch: computed {:?}, claimed {:?}", col, computed, claimed),
            EvaluationError::ColumnCountMismatch { claimed, available } =>
                write!(f, "Column count mismatch: claimed {}, available {}", claimed, available),
            EvaluationError::ColumnEvaluationMismatch { column, claimed, computed } =>
                write!(f, "Column {} evaluation mismatch: claimed {:?}, computed {:?}", column, claimed, computed),
            EvaluationError::ProvingError(e) => write!(f, "Proving error: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EvaluationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_column_evaluation_from_openings() {
        let opened_rows = vec![
            vec![BinaryElem32::from(1u32), BinaryElem32::from(2u32)],
            vec![BinaryElem32::from(3u32), BinaryElem32::from(4u32)],
        ];
        let query_indices = vec![0, 1];
        let lagrange_coeffs = vec![BinaryElem128::from(1u128), BinaryElem128::from(0u128)];
        let col0 = compute_column_evaluation_from_openings(&opened_rows, &query_indices, &lagrange_coeffs, 0);
        assert_eq!(col0, BinaryElem128::from(1u128));
        let col1 = compute_column_evaluation_from_openings(&opened_rows, &query_indices, &lagrange_coeffs, 1);
        assert_eq!(col1, BinaryElem128::from(2u128));
    }
}
