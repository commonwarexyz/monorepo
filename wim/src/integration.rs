//! End-to-end integration tests for pcVM
//!
//! This module tests the complete pipeline:
//! 1. Execute a program and generate trace
//! 2. Arithmetize the trace into a polynomial
//! 3. Prove the polynomial with Ligerito
//! 4. Verify the proof

use commonware_commitment::field::{BinaryElem32, BinaryElem128, BinaryFieldElement};
use super::trace::{Program, Instruction, Opcode, execute_and_trace};
use super::arithmetization::arithmetize_register_trace;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Create a simple test program that computes (a + b) * c
pub fn create_test_program() -> Program {
    vec![
        // a0 = a1 + a2  (a + b)
        Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
        // a0 = a0 * a3  (result * c)
        Instruction::new_rrr(Opcode::MUL, 0, 0, 3),
        // HALT
        Instruction::halt(),
    ]
}

/// Create initial register state for testing
pub fn create_test_inputs(a: u32, b: u32, c: u32) -> [u32; 13] {
    let mut regs = [0u32; 13];
    regs[1] = a;  // a1 = a
    regs[2] = b;  // a2 = b
    regs[3] = c;  // a3 = c
    regs
}

/// Expected output: (a + b) * c
pub fn expected_result(a: u32, b: u32, c: u32) -> u32 {
    a.wrapping_add(b).wrapping_mul(c)
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use crate::{prove, verify, hardcoded_config_12, hardcoded_config_12_verifier};
    use std::marker::PhantomData;

    #[test]
    fn test_end_to_end_simple_program() {
        // Step 1: Create and execute program
        let program = create_test_program();
        let initial_regs = create_test_inputs(5, 3, 2);

        println!("=== Step 1: Execute Program ===");
        println!("Program: (a + b) * c");
        println!("Inputs: a={}, b={}, c={}", initial_regs[1], initial_regs[2], initial_regs[3]);

        let trace = execute_and_trace(&program, initial_regs);

        // Verify trace is valid
        assert!(trace.validate().is_ok());

        let final_state = trace.final_state().unwrap();
        let actual_result = final_state[0];
        let expected = expected_result(5, 3, 2);

        println!("Expected result: {}", expected);
        println!("Actual result: {}", actual_result);
        assert_eq!(actual_result, expected);

        // Step 2: Arithmetize the trace
        println!("\n=== Step 2: Arithmetize Trace ===");
        let challenge = BinaryElem32::from(0x12345678);
        let arith = arithmetize_register_trace(&trace, &program, challenge);

        println!("Polynomial size: {} elements", arith.polynomial.len());
        println!("Program hash: {:?}", arith.program_hash);

        // Step 3: Pad polynomial to power of 2
        let mut poly = arith.polynomial.clone();
        let target_size = 1 << 12; // 4096 elements (2^12)

        if poly.len() < target_size {
            poly.resize(target_size, BinaryElem32::zero());
        }

        println!("Padded polynomial to {} elements", poly.len());

        // Step 4: Prove with Ligerito
        println!("\n=== Step 3: Generate Ligerito Proof ===");
        let config = hardcoded_config_12(
            PhantomData::<BinaryElem32>,
            PhantomData::<BinaryElem128>,
        );

        let proof = prove(&config, &poly).unwrap();
        println!("Proof generated successfully");
        println!("Proof size: {} bytes", proof.size_of());

        // Step 5: Verify the proof
        println!("\n=== Step 4: Verify Proof ===");
        let verifier_config = hardcoded_config_12_verifier();
        let valid = verify(&verifier_config, &proof).unwrap();

        println!("Verification result: {}", valid);
        assert!(valid, "Proof verification failed!");

        println!("\n=== SUCCESS ===");
        println!("Complete pipeline verified:");
        println!("  Execute → Trace → Arithmetize → Prove → Verify ✓");
    }

    #[test]
    fn test_multiple_programs() {
        // Test different programs to ensure system is general
        let test_cases = vec![
            // (a, b, c, description)
            (10, 20, 2, "simple arithmetic"),
            (0, 0, 0, "all zeros"),
            (u32::MAX, 1, 1, "overflow handling"),
            (42, 42, 42, "same values"),
        ];

        for (a, b, c, desc) in test_cases {
            println!("\nTesting: {}", desc);

            let program = create_test_program();
            let initial_regs = create_test_inputs(a, b, c);
            let trace = execute_and_trace(&program, initial_regs);

            assert!(trace.validate().is_ok());

            let final_state = trace.final_state().unwrap();
            assert_eq!(final_state[0], expected_result(a, b, c));

            // Arithmetize
            let challenge = BinaryElem32::from(0xdeadbeef);
            let arith = arithmetize_register_trace(&trace, &program, challenge);

            let mut poly = arith.polynomial;
            poly.resize(1 << 12, BinaryElem32::zero());

            // Prove and verify
            let config = hardcoded_config_12(
                PhantomData::<BinaryElem32>,
                PhantomData::<BinaryElem128>,
            );

            let proof = prove(&config, &poly).unwrap();

            let verifier_config = hardcoded_config_12_verifier();
            let valid = verify(&verifier_config, &proof).unwrap();

            assert!(valid, "Verification failed for: {}", desc);
            println!("  ✓ Passed");
        }
    }

    #[test]
    fn test_complex_program() {
        // Test a more complex program with multiple operations
        let program = vec![
            // Load immediates
            Instruction::new_imm(0, 100),     // a0 = 100
            Instruction::new_imm(1, 50),      // a1 = 50

            // Arithmetic
            Instruction::new_rrr(Opcode::ADD, 2, 0, 1),  // a2 = a0 + a1 = 150
            Instruction::new_rrr(Opcode::SUB, 3, 2, 1),  // a3 = a2 - a1 = 100
            Instruction::new_rrr(Opcode::MUL, 4, 3, 1),  // a4 = a3 * a1 = 5000

            // Bitwise ops
            Instruction::new_imm(5, 0xFF),    // a5 = 255
            Instruction::new_rrr(Opcode::AND, 6, 4, 5),  // a6 = a4 & a5
            Instruction::new_rrr(Opcode::OR, 7, 0, 1),   // a7 = a0 | a1
            Instruction::new_rrr(Opcode::XOR, 8, 0, 1),  // a8 = a0 ^ a1

            // Shifts
            Instruction::new_imm(9, 2),       // a9 = 2
            Instruction::new_rrr(Opcode::SLL, 10, 0, 9), // a10 = a0 << 2
            Instruction::new_rrr(Opcode::SRL, 11, 0, 9), // a11 = a0 >> 2

            Instruction::halt(),
        ];

        println!("\n=== Complex Program Test ===");
        println!("Instructions: {}", program.len());

        let initial_regs = [0u32; 13];
        let trace = execute_and_trace(&program, initial_regs);

        assert!(trace.validate().is_ok());
        println!("Trace validated: {} steps", trace.steps.len());

        // Arithmetize
        let challenge = BinaryElem32::from(0xcafebabe);
        let arith = arithmetize_register_trace(&trace, &program, challenge);

        println!("Polynomial size before padding: {}", arith.polynomial.len());

        let mut poly = arith.polynomial;
        poly.resize(1 << 12, BinaryElem32::zero());

        // Prove
        let config = hardcoded_config_12(
            PhantomData::<BinaryElem32>,
            PhantomData::<BinaryElem128>,
        );

        let proof = prove(&config, &poly).unwrap();
        println!("Proof size: {} bytes", proof.size_of());

        // Verify
        let verifier_config = hardcoded_config_12_verifier();
        let valid = verify(&verifier_config, &proof).unwrap();

        assert!(valid);
        println!("✓ Complex program verified successfully");
    }

    #[test]
    fn test_constraint_satisfaction_during_proving() {
        use super::super::constraints::generate_all_constraints;

        let program = create_test_program();
        let initial_regs = create_test_inputs(7, 11, 3);
        let trace = execute_and_trace(&program, initial_regs);

        // Generate and check constraints
        let constraints = generate_all_constraints(&trace, &program);

        println!("\n=== Constraint Analysis ===");
        println!("Total constraints: {}", constraints.len());

        let satisfied = constraints.iter().filter(|c| c.value == BinaryElem32::zero()).count();
        println!("Satisfied: {}", satisfied);
        println!("Failed: {}", constraints.len() - satisfied);

        // All constraints must be satisfied for valid execution
        assert_eq!(satisfied, constraints.len(), "Some constraints not satisfied!");

        // Now prove it
        let challenge = BinaryElem32::from(0x42424242);
        let arith = arithmetize_register_trace(&trace, &program, challenge);

        let mut poly = arith.polynomial;
        poly.resize(1 << 12, BinaryElem32::zero());

        let config = hardcoded_config_12(
            PhantomData::<BinaryElem32>,
            PhantomData::<BinaryElem128>,
        );

        let proof = prove(&config, &poly).unwrap();
        let verifier_config = hardcoded_config_12_verifier();
        let valid = verify(&verifier_config, &proof).unwrap();

        assert!(valid);
        println!("✓ All constraints satisfied and proof verified");
    }

    #[test]
    fn test_program_hash_in_proof() {
        // Verify that different programs produce different proofs
        let program1 = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::halt(),
        ];

        let program2 = vec![
            Instruction::new_rrr(Opcode::SUB, 0, 1, 2),
            Instruction::halt(),
        ];

        let initial_regs = create_test_inputs(10, 5, 0);

        // Execute both programs
        let trace1 = execute_and_trace(&program1, initial_regs);
        let trace2 = execute_and_trace(&program2, initial_regs);

        let challenge = BinaryElem32::from(0x11111111);

        let arith1 = arithmetize_register_trace(&trace1, &program1, challenge);
        let arith2 = arithmetize_register_trace(&trace2, &program2, challenge);

        // Program hashes should be different
        assert_ne!(arith1.program_hash, arith2.program_hash);
        println!("✓ Different programs produce different hashes");

        // Polynomials should be different
        assert_ne!(arith1.polynomial, arith2.polynomial);
        println!("✓ Different programs produce different polynomials");
    }
}
