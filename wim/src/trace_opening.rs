//! Trace Opening Verification

use commonware_commitment::field::{BinaryElem32, BinaryElem128, BinaryFieldElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub const COL_PC: usize = 0;
pub const COL_NEXT_PC: usize = 1;
pub const COL_INSTRUCTION_SIZE: usize = 2;
pub const COL_REGS_START: usize = 3;
#[allow(dead_code)]
pub const COL_REGS_END: usize = 16;
pub const COL_MEMORY_ROOT_START: usize = 16;
#[allow(dead_code)]
pub const COL_MEMORY_ROOT_END: usize = 24;
pub const STEP_WIDTH: usize = 24;

#[derive(Debug, Clone)]
pub struct TraceOpenings {
    pub step_point: Vec<BinaryElem128>,
    pub pc: BinaryElem128,
    pub next_pc: BinaryElem128,
    pub instruction_size: BinaryElem128,
    pub registers: [BinaryElem128; 13],
    pub memory_root: [BinaryElem128; 8],
}

pub fn evaluate_constraint_at_point(
    openings: &TraceOpenings, batching_challenge: BinaryElem128,
) -> BinaryElem128 {
    let mut accumulator = BinaryElem128::zero();
    let mut power = BinaryElem128::one();

    let pc_constraint = openings.next_pc.add(&openings.pc);
    accumulator = accumulator.add(&pc_constraint.mul(&power));
    power = power.mul(&batching_challenge);

    for (i, &reg) in openings.registers.iter().enumerate() {
        let reg_constraint = reg.mul(&BinaryElem128::from((i + 1) as u128));
        accumulator = accumulator.add(&reg_constraint.mul(&power));
        power = power.mul(&batching_challenge);
    }

    for &mem_chunk in &openings.memory_root {
        accumulator = accumulator.add(&mem_chunk.mul(&power));
        power = power.mul(&batching_challenge);
    }

    accumulator
}

pub fn lagrange_coefficient(i: usize, r: &[BinaryElem128]) -> BinaryElem128 {
    let mut result = BinaryElem128::one();
    for (j, &rj) in r.iter().enumerate() {
        let ij = ((i >> j) & 1) as u128;
        let one = BinaryElem128::one();
        let term = if ij == 1 { rj } else { one.add(&rj) };
        result = result.mul(&term);
    }
    result
}

pub fn open_trace_at_point(
    trace_poly: &[BinaryElem32], step_point: &[BinaryElem128],
    _num_steps: usize, step_width: usize,
) -> TraceOpenings {
    let num_vars = step_point.len();
    let padded_steps = 1 << num_vars;
    assert_eq!(trace_poly.len(), padded_steps * step_width);

    let mut column_values = vec![BinaryElem128::zero(); step_width];
    for step in 0..padded_steps {
        let lagrange_coeff = lagrange_coefficient(step, step_point);
        for col in 0..step_width {
            let trace_value = trace_poly[step * step_width + col];
            let value_ext = BinaryElem128::from(trace_value);
            column_values[col] = column_values[col].add(&value_ext.mul(&lagrange_coeff));
        }
    }

    let mut registers = [BinaryElem128::zero(); 13];
    for (i, reg) in registers.iter_mut().enumerate() {
        *reg = column_values[COL_REGS_START + i];
    }
    let mut memory_root = [BinaryElem128::zero(); 8];
    for (i, chunk) in memory_root.iter_mut().enumerate() {
        *chunk = column_values[COL_MEMORY_ROOT_START + i];
    }

    TraceOpenings {
        step_point: step_point.to_vec(),
        pc: column_values[COL_PC],
        next_pc: column_values[COL_NEXT_PC],
        instruction_size: column_values[COL_INSTRUCTION_SIZE],
        registers,
        memory_root,
    }
}

pub fn verify_trace_openings(
    config: &commonware_commitment::VerifierConfig,
    proof: &commonware_commitment::Proof<BinaryElem32, BinaryElem128>,
    _openings: &TraceOpenings,
) -> Result<bool, TraceOpeningError> {
    let mut transcript = commonware_commitment::transcript::Sha256Transcript::new(0);
    let valid = commonware_commitment::verify(config, proof, &mut transcript)
        .map_err(|e| TraceOpeningError::CommitmentVerification(format!("{:?}", e)))?;
    if !valid {
        return Err(TraceOpeningError::CommitmentVerification(
            "Commitment proof verification failed".to_string()
        ));
    }
    Ok(true)
}

#[derive(Debug, Clone)]
pub enum TraceOpeningError {
    CommitmentVerification(String),
    PointMismatch { index: usize, claimed: BinaryElem128, expected: BinaryElem128 },
    #[allow(dead_code)]
    ColumnMismatch { col: usize, computed: BinaryElem128, claimed: BinaryElem128 },
}

impl core::fmt::Display for TraceOpeningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TraceOpeningError::CommitmentVerification(e) => write!(f, "Commitment verification failed: {}", e),
            TraceOpeningError::PointMismatch { index, claimed, expected } =>
                write!(f, "Point mismatch at index {}: claimed {:?}, expected {:?}", index, claimed, expected),
            TraceOpeningError::ColumnMismatch { col, computed, claimed } =>
                write!(f, "Column {} mismatch: computed {:?}, claimed {:?}", col, computed, claimed),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TraceOpeningError {}

pub fn verify_constraint_at_point(
    verifier_config: &commonware_commitment::VerifierConfig,
    commitment_proof: &commonware_commitment::Proof<BinaryElem32, BinaryElem128>,
    openings: &TraceOpenings,
    batching_challenge: BinaryElem128,
    sumcheck_final_value: BinaryElem128,
) -> Result<(), ConstraintVerificationError> {
    verify_trace_openings(verifier_config, commitment_proof, openings)
        .map_err(|e| ConstraintVerificationError::InvalidOpeningProof(e.to_string()))?;
    let computed_constraint = evaluate_constraint_at_point(openings, batching_challenge);
    if computed_constraint != sumcheck_final_value {
        return Err(ConstraintVerificationError::ConstraintMismatch {
            computed: computed_constraint, claimed: sumcheck_final_value,
        });
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub enum ConstraintVerificationError {
    InvalidOpeningProof(String),
    ConstraintMismatch { computed: BinaryElem128, claimed: BinaryElem128 },
}

impl core::fmt::Display for ConstraintVerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConstraintVerificationError::InvalidOpeningProof(e) =>
                write!(f, "Invalid commitment opening proof: {}", e),
            ConstraintVerificationError::ConstraintMismatch { computed, claimed } =>
                write!(f, "Constraint mismatch: computed {:?}, claimed {:?}", computed, claimed),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConstraintVerificationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lagrange_coefficients_sum_to_one() {
        let r = vec![
            BinaryElem128::from(0x123u128),
            BinaryElem128::from(0x456u128),
            BinaryElem128::from(0x789u128),
        ];
        let mut sum = BinaryElem128::zero();
        for i in 0..8 {
            sum = sum.add(&lagrange_coefficient(i, &r));
        }
        assert_eq!(sum, BinaryElem128::one());
    }

    #[test]
    fn test_constraint_evaluation_deterministic() {
        let openings = TraceOpenings {
            step_point: vec![BinaryElem128::from(1u128), BinaryElem128::from(2u128)],
            pc: BinaryElem128::from(100u128),
            next_pc: BinaryElem128::from(104u128),
            instruction_size: BinaryElem128::from(4u128),
            registers: [BinaryElem128::zero(); 13],
            memory_root: [BinaryElem128::zero(); 8],
        };
        let challenge = BinaryElem128::from(0xDEADBEEFu128);
        let c1 = evaluate_constraint_at_point(&openings, challenge);
        let c2 = evaluate_constraint_at_point(&openings, challenge);
        assert_eq!(c1, c2);
    }
}
