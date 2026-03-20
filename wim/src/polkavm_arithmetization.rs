//! PolkaVM Trace Arithmetization
//!
//! Convert PolkaVM execution traces into multilinear polynomials for Ligerito proving.
//!
//! # The Core Insight (Zhu Valley Vision)
//!
//! An execution trace is naturally a MATRIX:
//!
//! ```text
//!        | pc    | ra | sp | gp | ... | a7  | mem_root | ... |
//! -------|-------|----|----|----| ... |-----|----------|-----|
//! Step 0 | 0x100 | 0  | .  | .  | ... | 0   | [hash0]  | ... |
//! Step 1 | 0x103 | 0  | .  | .  | ... | 10  | [hash1]  | ... |
//! Step 2 | 0x106 | 0  | .  | .  | ... | 30  | [hash2]  | ... |
//! ```
//!
//! This matrix IS a multilinear polynomial M(x, y) where:
//! - x ∈ {0, 1}^log(steps) indexes the step (row)
//! - y ∈ {0, 1}^log(width) indexes the column (register/state)
//!
//! ## Multilinear Extension
//!
//! Given a matrix M[i][j], its multilinear extension M̃(x, y) is:
//!
//! ```text
//! M̃(x, y) = ∑ᵢ ∑ⱼ M[i][j] · Lᵢ(x) · Lⱼ(y)
//! ```
//!
//! where Lᵢ(x) is the Lagrange basis polynomial for point i.
//!
//! ## Why This Matters
//!
//! 1. **Ligerito commits to multilinear polynomials**
//! 2. **Constraints become polynomial identities**
//! 3. **Verification reduces to polynomial evaluation**
//!
//! Instead of checking N × M constraints individually, we:
//! 1. Commit to M̃(x, y) using Ligerito
//! 2. Prove polynomial identity: C(M̃(x, y)) = 0
//! 3. Verifier checks ONE polynomial evaluation
//!
//! This is **exponentially faster** than individual constraint checks.

use commonware_commitment::field::{BinaryElem32, BinaryElem128, BinaryFieldElement};

#[cfg(feature = "polkavm-integration")]
use super::polkavm_constraints::{ProvenTransition, generate_transition_constraints};

#[cfg(feature = "polkavm-integration")]
use polkavm::program::Instruction;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Arithmetized PolkaVM trace ready for Ligerito proving
#[derive(Debug, Clone)]
pub struct ArithmetizedPolkaVMTrace {
    /// Execution trace as multilinear polynomial (row-major flattened)
    ///
    /// Layout: [step0_col0, step0_col1, ..., step0_colN, step1_col0, ...]
    pub trace_polynomial: Vec<BinaryElem32>,

    /// Number of steps (rows) in the trace
    pub num_steps: usize,

    /// Width of each step (columns) - state vector size
    pub step_width: usize,

    /// Program commitment (Merkle root or hash)
    pub program_commitment: [u8; 32],

    /// Initial state root
    pub initial_state_root: [u8; 32],

    /// Final state root
    pub final_state_root: [u8; 32],

    /// Batched constraint accumulator (from Zhu Valley optimization)
    ///
    /// This is the result of: ∑ᵢ ∑ⱼ Cᵢⱼ · rⁱ⁺ʲ
    /// For valid execution, this MUST equal zero.
    /// Uses GF(2^128) for proper 128-bit security.
    pub constraint_accumulator: BinaryElem128,

    /// Challenge used for batched verification (from Fiat-Shamir)
    /// Uses GF(2^128) for proper 128-bit security.
    pub batching_challenge: BinaryElem128,
}

/// Column indices in the trace matrix
///
/// Each step is a row with these columns:
const COL_PC: usize = 0;
const COL_NEXT_PC: usize = 1;
const COL_INSTRUCTION_SIZE: usize = 2;
const COL_REGS_START: usize = 3;
const COL_REGS_END: usize = 3 + 13; // 13 registers
const COL_MEMORY_ROOT_START: usize = COL_REGS_END;
const COL_MEMORY_ROOT_END: usize = COL_MEMORY_ROOT_START + 8; // 32 bytes = 8 u32s

/// Width of each step in the trace (number of u32 columns)
pub const STEP_WIDTH: usize = COL_MEMORY_ROOT_END;

/// Arithmetize a PolkaVM execution trace
///
/// Converts the trace into a multilinear polynomial that Ligerito can commit to.
#[cfg(feature = "polkavm-integration")]
pub fn arithmetize_polkavm_trace(
    trace: &[(ProvenTransition, Instruction)],
    program_commitment: [u8; 32],
    batching_challenge: BinaryElem128,
) -> Result<ArithmetizedPolkaVMTrace, &'static str> {
    if trace.is_empty() {
        return Err("Cannot arithmetize empty trace");
    }

    let num_steps = trace.len();
    let step_width = STEP_WIDTH;

    // Allocate polynomial (row-major flattened matrix)
    let mut trace_polynomial = Vec::with_capacity(num_steps * step_width);

    // Extract initial and final states
    let initial_state_root = trace[0].0.memory_root_before;
    let final_state_root = trace[trace.len() - 1].0.memory_root_after;

    // Encode each step as a row
    for (transition, _instruction) in trace {
        encode_transition(&mut trace_polynomial, transition);
    }

    // Pad to next power of 2 (required by Ligerito multilinear polynomial)
    // Must be at least 2^20 = 1,048,576 for standard Ligerito configs
    // This is where the compression happens - even small traces get padded,
    // but Ligerito proof size is O(log²(N)) regardless!
    let total_size = trace_polynomial.len();
    let next_pow2 = total_size.next_power_of_two().max(1 << 20);  // 2^20
    trace_polynomial.resize(next_pow2, BinaryElem32::zero());

    // Compute batched constraint accumulator using Zhu Valley optimization
    let constraint_accumulator = compute_batched_constraints(trace, batching_challenge)?;

    Ok(ArithmetizedPolkaVMTrace {
        trace_polynomial,
        num_steps,
        step_width,
        program_commitment,
        initial_state_root,
        final_state_root,
        constraint_accumulator,
        batching_challenge,
    })
}

/// Encode a single transition as a row in the polynomial
fn encode_transition(poly: &mut Vec<BinaryElem32>, transition: &ProvenTransition) {
    // PC
    poly.push(BinaryElem32::from(transition.pc));

    // Next PC
    poly.push(BinaryElem32::from(transition.next_pc));

    // Instruction size
    poly.push(BinaryElem32::from(transition.instruction_size));

    // Registers (13 of them)
    let regs = transition.regs_after.to_array();
    for &reg_val in &regs {
        poly.push(BinaryElem32::from(reg_val));
    }

    // Memory root (32 bytes = 8 u32s)
    for chunk in transition.memory_root_after.chunks(4) {
        let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        poly.push(BinaryElem32::from(val));
    }
}

/// Compute batched constraint accumulator using random linear combination
///
/// This implements the Zhu Valley optimization: ∑ᵢ ∑ⱼ Cᵢⱼ · rⁱ⁺ʲ
///
/// Includes:
/// 1. Per-step instruction correctness constraints
/// 2. **State continuity constraints** (JAM/graypaper continuous execution model)
///
/// State continuity ensures execution forms a valid chain:
/// - step[i].regs_after == step[i+1].regs_before
/// - step[i].memory_root_after == step[i+1].memory_root_before
/// - step[i].next_pc == step[i+1].pc
#[cfg(feature = "polkavm-integration")]
fn compute_batched_constraints(
    trace: &[(ProvenTransition, Instruction)],
    challenge: BinaryElem128,
) -> Result<BinaryElem128, &'static str> {
    // Use GF(2^128) for 128-bit security
    let mut accumulator = BinaryElem128::zero();
    let mut power = BinaryElem128::one();

    // 1. Per-step instruction correctness
    for (transition, instruction) in trace {
        let constraints = generate_transition_constraints(transition, instruction)
            .map_err(|_| "Failed to generate constraints")?;

        for constraint in constraints {
            // Lift constraint from GF(2^32) to GF(2^128)
            let c_ext = BinaryElem128::from(constraint);
            let term = c_ext.mul(&power);
            accumulator = accumulator.add(&term);
            power = power.mul(&challenge);
        }
    }

    // 2. State continuity constraints (CRITICAL for continuous execution)
    //
    // JAM/graypaper model: service state must chain correctly between steps.
    // Without this, a prover could forge intermediate states!
    for i in 0..(trace.len() - 1) {
        let current = &trace[i].0;
        let next = &trace[i+1].0;

        // 2a. Register continuity (all 13 registers)
        let current_regs_after = current.regs_after.to_array();
        let next_regs_before = next.regs_before.to_array();

        for reg_idx in 0..13 {
            // In GF(2^32): a ⊕ b = 0 iff a == b
            let constraint = BinaryElem32::from(
                current_regs_after[reg_idx] ^ next_regs_before[reg_idx]
            );

            let c_ext = BinaryElem128::from(constraint);
            let term = c_ext.mul(&power);
            accumulator = accumulator.add(&term);
            power = power.mul(&challenge);
        }

        // 2b. Memory root continuity (like JAM service state commitment)
        for byte_idx in 0..32 {
            let byte_xor = current.memory_root_after[byte_idx] ^ next.memory_root_before[byte_idx];
            let constraint = BinaryElem32::from(byte_xor as u32);

            let c_ext = BinaryElem128::from(constraint);
            let term = c_ext.mul(&power);
            accumulator = accumulator.add(&term);
            power = power.mul(&challenge);
        }

        // 2c. PC continuity (control flow chain)
        let constraint = BinaryElem32::from(current.next_pc ^ next.pc);

        let c_ext = BinaryElem128::from(constraint);
        let term = c_ext.mul(&power);
        accumulator = accumulator.add(&term);
        power = power.mul(&challenge);
    }

    Ok(accumulator)
}

/// Evaluate the trace polynomial at a point (x, y)
///
/// This is the multilinear extension evaluation:
/// M̃(x, y) = ∑ᵢ ∑ⱼ M[i][j] · Lᵢ(x) · Lⱼ(y)
pub fn evaluate_trace_polynomial(
    arith: &ArithmetizedPolkaVMTrace,
    x: &[BinaryElem32],  // log(num_steps) bits
    y: &[BinaryElem32],  // log(step_width) bits
) -> BinaryElem32 {
    let mut result = BinaryElem32::zero();

    for i in 0..arith.num_steps {
        for j in 0..arith.step_width {
            let value = arith.trace_polynomial[i * arith.step_width + j];

            // Compute Lagrange basis: Lᵢ(x) · Lⱼ(y)
            let li_x = lagrange_basis(i, x);
            let lj_y = lagrange_basis(j, y);
            let basis = li_x.mul(&lj_y);

            // Add to result
            let term = value.mul(&basis);
            result = result.add(&term);
        }
    }

    result
}

/// Compute Lagrange basis polynomial Lᵢ(x)
///
/// For a boolean hypercube {0, 1}^k, the Lagrange basis for point i is:
/// Lᵢ(x) = ∏ₖ (xₖ · iₖ + (1 - xₖ) · (1 - iₖ))
///
/// where iₖ is the k-th bit of i.
fn lagrange_basis(i: usize, x: &[BinaryElem32]) -> BinaryElem32 {
    let mut result = BinaryElem32::one();

    for (k, &xk) in x.iter().enumerate() {
        let ik = ((i >> k) & 1) as u32;

        // Compute: xₖ · iₖ + (1 - xₖ) · (1 - iₖ)
        // In GF(2): this simplifies to: xₖ ⊕ iₖ ⊕ 1
        let term = if ik == 1 {
            xk
        } else {
            xk.add(&BinaryElem32::one())
        };

        result = result.mul(&term);
    }

    result
}

/// Verify an arithmetized trace
///
/// Checks that:
/// 1. Constraint accumulator equals zero (all constraints satisfied)
/// 2. Polynomial dimensions are consistent
pub fn verify_arithmetized_trace(arith: &ArithmetizedPolkaVMTrace) -> bool {
    // Check 1: Batched constraints must be satisfied
    if arith.constraint_accumulator != BinaryElem128::zero() {
        return false;
    }

    // Check 2: Polynomial size matches dimensions
    let expected_size = arith.num_steps * arith.step_width;
    if arith.trace_polynomial.len() != expected_size {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step_width() {
        // Verify our width calculation is correct
        // PC + next_PC + instr_size + 13 regs + 8 u32s for memory root
        assert_eq!(STEP_WIDTH, 3 + 13 + 8);
        assert_eq!(STEP_WIDTH, 24);
    }

    #[test]
    fn test_lagrange_basis_boolean_hypercube() {
        // For 2-bit hypercube: {0, 1}^2
        let x = vec![BinaryElem32::from(0), BinaryElem32::from(1)];

        // L₀(0, 1) should equal 0 (not at point 0 = (0, 0))
        let l0 = lagrange_basis(0, &x);
        assert_eq!(l0, BinaryElem32::zero());

        // L₂(0, 1) should equal 1 (at point 2 = (0, 1) in little-endian)
        let l2 = lagrange_basis(2, &x);
        assert_eq!(l2, BinaryElem32::one());
    }

    #[test]
    fn test_verify_empty_constraints() {
        // Create a minimal arithmetized trace with zero constraints
        let arith = ArithmetizedPolkaVMTrace {
            trace_polynomial: vec![BinaryElem32::zero(); 24], // 1 step
            num_steps: 1,
            step_width: 24,
            program_commitment: [0u8; 32],
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            constraint_accumulator: BinaryElem128::zero(), // All constraints satisfied
            batching_challenge: BinaryElem128::from(0x42u128),
        };

        assert!(verify_arithmetized_trace(&arith));
    }

    #[test]
    fn test_verify_fails_nonzero_constraints() {
        // Create trace with non-zero constraint accumulator (invalid!)
        let arith = ArithmetizedPolkaVMTrace {
            trace_polynomial: vec![BinaryElem32::zero(); 24],
            num_steps: 1,
            step_width: 24,
            program_commitment: [0u8; 32],
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            constraint_accumulator: BinaryElem128::from(0xdeadbeefu128), // NON-ZERO!
            batching_challenge: BinaryElem128::from(0x42u128),
        };

        assert!(!verify_arithmetized_trace(&arith));
    }
}
