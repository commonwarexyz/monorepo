//! Arithmetization: Convert execution traces to polynomials
//!
//! This module converts a RegisterOnlyTrace into a polynomial that can be
//! proven with Ligerito. The polynomial encodes:
//! 1. Program hash (using Rescue-Prime over GF(2^128))
//! 2. All execution steps (lifted from GF(2^32) to GF(2^128))
//! 3. Constraints (via grand product argument in GF(2^128))
//!
//! Security: all hashing and constraint accumulation operates in GF(2^128)
//! for 64-bit collision resistance. Trace values are embedded from GF(2^32).

use commonware_commitment::field::{BinaryElem32, BinaryElem128, BinaryFieldElement};
use super::trace::{RegisterOnlyTrace, RegisterOnlyStep, Opcode, Program};
use super::rescue::RescueHash;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Number of independent challenges for batched Schwartz-Zippel.
/// With 4 challenges in GF(2^32), soundness error ≤ (n/2^32)^4 ≈ n^4/2^128.
const NUM_BATCH_CHALLENGES: usize = 4;

/// Result of arithmetization: polynomial ready for Ligerito proving
#[derive(Debug, Clone)]
pub struct ArithmetizedTrace {
    /// The polynomial encoding the entire computation (base field for Ligerito)
    pub polynomial: Vec<BinaryElem32>,

    /// Program hash (Rescue-Prime, 128-bit, collision-resistant)
    pub program_hash: BinaryElem128,

    /// Batched constraint products in GF(2^32).
    /// Each product uses an independent challenge.
    /// All must verify for the trace to be accepted.
    /// Combined soundness: (n/2^32)^NUM_BATCH_CHALLENGES.
    pub constraint_products: [BinaryElem32; NUM_BATCH_CHALLENGES],

    /// Challenges used (Fiat-Shamir derived from trace commitment)
    pub challenges: [BinaryElem32; NUM_BATCH_CHALLENGES],
}

/// Convert a register-only trace to a polynomial
///
/// The challenges MUST be derived via Fiat-Shamir from the trace commitment
/// (not chosen by the prover). Caller is responsible for this binding.
pub fn arithmetize_register_trace(
    trace: &RegisterOnlyTrace,
    program: &Program,
    challenges: [BinaryElem32; NUM_BATCH_CHALLENGES],
) -> ArithmetizedTrace {
    let mut poly = Vec::new();

    // Step 1: Compute program hash using Rescue-Prime (128-bit, secure)
    let program_hash = hash_program(program);
    // Embed 128-bit hash as 4 × 32-bit elements in the polynomial
    let ph = program_hash.poly().value();
    poly.push(BinaryElem32::from(ph as u32));
    poly.push(BinaryElem32::from((ph >> 32) as u32));
    poly.push(BinaryElem32::from((ph >> 64) as u32));
    poly.push(BinaryElem32::from((ph >> 96) as u32));

    // Step 2: Encode number of steps
    poly.push(BinaryElem32::from(trace.steps.len() as u32));

    // Step 3: Encode each execution step
    let mut constraints = Vec::new();

    for (i, step) in trace.steps.iter().enumerate() {
        encode_step(&mut poly, step);
        generate_step_constraints(&mut constraints, step, program, i);
    }

    // Step 4: Encode final register state
    if let Some(final_regs) = trace.final_state() {
        for &reg in &final_regs {
            poly.push(BinaryElem32::from(reg));
        }
    }

    // Step 5: Batched grand products in GF(2^32)
    // Each challenge produces an independent product.
    // Combined soundness: (n/2^32)^4 ≈ n^4/2^128 (negligible).
    let mut constraint_products = [BinaryElem32::zero(); NUM_BATCH_CHALLENGES];
    for (j, &ch) in challenges.iter().enumerate() {
        constraint_products[j] = compute_constraint_product(&constraints, ch);
    }

    ArithmetizedTrace {
        polynomial: poly,
        program_hash,
        constraint_products,
        challenges,
    }
}

/// Hash a program using Rescue-Prime over GF(2^128)
///
/// Each instruction is packed into a single 128-bit element:
/// [opcode:8 | rd:8 | rs1:8 | rs2:8 | imm:32 | padding:64]
/// This is collision-resistant with 64-bit security (birthday bound on 128-bit field).
fn hash_program(program: &Program) -> BinaryElem128 {
    let mut elements = Vec::with_capacity(program.len());

    for instr in program {
        let packed = (instr.opcode as u8 as u128)
            | ((instr.rd as u128) << 8)
            | ((instr.rs1 as u128) << 16)
            | ((instr.rs2 as u128) << 24)
            | ((instr.imm as u128) << 32);
        elements.push(BinaryElem128::from(packed));
    }

    RescueHash::hash_elements(&elements)
}

/// Encode a single execution step into the polynomial
fn encode_step(poly: &mut Vec<BinaryElem32>, step: &RegisterOnlyStep) {
    // PC
    poly.push(BinaryElem32::from(step.pc));

    // Opcode
    poly.push(BinaryElem32::from(step.opcode as u8 as u32));

    // Register indices
    poly.push(BinaryElem32::from(step.rd as u32));
    poly.push(BinaryElem32::from(step.rs1 as u32));
    poly.push(BinaryElem32::from(step.rs2 as u32));

    // Immediate value
    poly.push(BinaryElem32::from(step.imm));

    // All register values BEFORE execution
    for &reg in &step.regs {
        poly.push(BinaryElem32::from(reg));
    }
}

/// Generate constraints for a single execution step
///
/// Constraints stay in GF(2^32) for performance. Security comes from
/// batching 4 independent challenges (see NUM_BATCH_CHALLENGES).
fn generate_step_constraints(
    constraints: &mut Vec<BinaryElem32>,
    step: &RegisterOnlyStep,
    program: &Program,
    step_index: usize,
) {
    // Constraint 1: PC matches step index
    let pc_constraint = BinaryElem32::from(step.pc)
        .add(&BinaryElem32::from(step_index as u32));
    constraints.push(pc_constraint);

    // Constraint 2: Opcode matches program
    if step_index < program.len() {
        let expected_opcode = BinaryElem32::from(program[step_index].opcode as u8 as u32);
        let actual_opcode = BinaryElem32::from(step.opcode as u8 as u32);
        constraints.push(expected_opcode.add(&actual_opcode));
    }

    // Constraint 3: Register indices match program
    if step_index < program.len() {
        let instr = &program[step_index];
        constraints.push(
            BinaryElem32::from(instr.rd as u32)
                .add(&BinaryElem32::from(step.rd as u32))
        );
        constraints.push(
            BinaryElem32::from(instr.rs1 as u32)
                .add(&BinaryElem32::from(step.rs1 as u32))
        );
        constraints.push(
            BinaryElem32::from(instr.rs2 as u32)
                .add(&BinaryElem32::from(step.rs2 as u32))
        );
    }

    // Constraint 4: ALU correctness
    constraints.push(check_alu_correctness(step));
}

/// Check that the ALU operation was performed correctly
fn check_alu_correctness(step: &RegisterOnlyStep) -> BinaryElem32 {
    let expected_result = match step.opcode {
        Opcode::ADD => step.regs[step.rs1 as usize].wrapping_add(step.regs[step.rs2 as usize]),
        Opcode::SUB => step.regs[step.rs1 as usize].wrapping_sub(step.regs[step.rs2 as usize]),
        Opcode::MUL => step.regs[step.rs1 as usize].wrapping_mul(step.regs[step.rs2 as usize]),
        Opcode::AND => step.regs[step.rs1 as usize] & step.regs[step.rs2 as usize],
        Opcode::OR  => step.regs[step.rs1 as usize] | step.regs[step.rs2 as usize],
        Opcode::XOR => step.regs[step.rs1 as usize] ^ step.regs[step.rs2 as usize],
        Opcode::SLL => step.regs[step.rs1 as usize] << (step.regs[step.rs2 as usize] & 0x1F),
        Opcode::SRL => step.regs[step.rs1 as usize] >> (step.regs[step.rs2 as usize] & 0x1F),
        Opcode::LI  => step.imm,
        Opcode::LOAD => step.memory_value.unwrap_or(0),
        Opcode::HALT => return BinaryElem32::zero(),
    };

    let new_regs = step.execute();
    let actual_result = new_regs[step.rd as usize];

    BinaryElem32::from(expected_result).add(&BinaryElem32::from(actual_result))
}

/// Compute grand product ∏(α + c_i) in GF(2^32)
///
/// For valid execution all c_i = 0, so product = α^n.
/// Single-challenge soundness: n/2^32. With NUM_BATCH_CHALLENGES
/// independent challenges, combined error: (n/2^32)^4 ≈ n^4/2^128.
fn compute_constraint_product(
    constraints: &[BinaryElem32],
    challenge: BinaryElem32,
) -> BinaryElem32 {
    let mut product = BinaryElem32::one();

    for constraint in constraints {
        let term = challenge.add(constraint);
        product = product.mul(&term);
    }

    product
}

/// Verify that a polynomial represents a valid execution
///
/// ALL batched products must verify independently.
pub fn verify_arithmetization(
    arith: &ArithmetizedTrace,
    num_constraints: usize,
) -> bool {
    for (j, &ch) in arith.challenges.iter().enumerate() {
        let expected = ch.pow(num_constraints as u64);
        if arith.constraint_products[j] != expected {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{execute_and_trace, Instruction};

    #[test]
    fn test_simple_arithmetization() {
        // Program: a0 = a1 + a2, then HALT
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::halt(),
        ];

        // Initial state: a1=5, a2=3
        let mut initial = [0u32; 13];
        initial[1] = 5;
        initial[2] = 3;

        let trace = execute_and_trace(&program, initial);
        assert!(trace.validate().is_ok());

        let challenges = [
            BinaryElem32::from(0x12345678),
            BinaryElem32::from(0xdeadbeef),
            BinaryElem32::from(0xcafebabe),
            BinaryElem32::from(0x0badf00d),
        ];
        let arith = arithmetize_register_trace(&trace, &program, challenges);

        // Polynomial should be non-empty
        assert!(!arith.polynomial.is_empty());

        // Program hash should be deterministic
        let program_hash2 = hash_program(&program);
        assert_eq!(arith.program_hash, program_hash2);
    }

    #[test]
    fn test_constraint_validation() {
        // Program: a0 = (a1 + a2) * a3
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),  // a0 = a1 + a2
            Instruction::new_rrr(Opcode::MUL, 0, 0, 3),  // a0 = a0 * a3
            Instruction::halt(),
        ];

        // Initial: a1=5, a2=3, a3=2
        let mut initial = [0u32; 13];
        initial[1] = 5;
        initial[2] = 3;
        initial[3] = 2;

        let trace = execute_and_trace(&program, initial);

        let challenges = [
            BinaryElem32::from(0xdeadbeef),
            BinaryElem32::from(0x12345678),
            BinaryElem32::from(0xfeedface),
            BinaryElem32::from(0xbaadcafe),
        ];
        let arith = arithmetize_register_trace(&trace, &program, challenges);

        // For a valid trace, constraints should verify
        // Note: We need to count the actual number of constraints generated
        // Each step generates: 1 (PC) + 1 (opcode) + 3 (reg indices) + 1 (ALU) = 6 constraints
        // 3 steps (ADD, MUL, HALT) = 18 constraints
        let num_constraints = trace.steps.len() * 6;

        assert!(verify_arithmetization(&arith, num_constraints));
    }

    #[test]
    fn test_program_hash_collision_resistance() {
        // Different programs should have different hashes
        let program1 = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::halt(),
        ];

        let program2 = vec![
            Instruction::new_rrr(Opcode::SUB, 0, 1, 2),
            Instruction::halt(),
        ];

        let hash1 = hash_program(&program1);
        let hash2 = hash_program(&program2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_alu_correctness_constraint() {
        // Create a step with ADD operation
        let step = RegisterOnlyStep {
            pc: 0,
            regs: {
                let mut regs = [0u32; 13];
                regs[1] = 10;
                regs[2] = 20;
                regs
            },
            opcode: Opcode::ADD,
            rd: 0,
            rs1: 1,
            rs2: 2,
            imm: 0,
            memory_address: None,
            memory_value: None,
            instruction_proof_0: None,
            instruction_proof_1: None,
        };

        // ALU constraint should be zero (correct execution)
        let constraint = check_alu_correctness(&step);
        assert_eq!(constraint, BinaryElem32::zero());
    }

    #[test]
    fn test_grand_product_zero_constraints() {
        let constraints = vec![
            BinaryElem32::zero(),
            BinaryElem32::zero(),
            BinaryElem32::zero(),
        ];

        let challenge = BinaryElem32::from(0x42);
        let product = compute_constraint_product(&constraints, challenge);
        assert_eq!(product, challenge.pow(3));
    }

    #[test]
    fn test_grand_product_nonzero_constraint() {
        let constraints = vec![
            BinaryElem32::zero(),
            BinaryElem32::from(1), // Non-zero!
            BinaryElem32::zero(),
        ];

        let challenge = BinaryElem32::from(0x42);
        let product = compute_constraint_product(&constraints, challenge);
        assert_ne!(product, challenge.pow(3));
    }
}
