//! Arithmetization: Convert execution traces to polynomials

use commonware_commitment::field::{BinaryElem32, BinaryElem128, BinaryFieldElement};
use super::trace::{RegisterOnlyTrace, RegisterOnlyStep, Opcode, Program};
use super::rescue::RescueHash;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

const NUM_BATCH_CHALLENGES: usize = 4;

/// Result of arithmetization: polynomial ready for proving
#[derive(Debug, Clone)]
pub struct ArithmetizedTrace {
    pub polynomial: Vec<BinaryElem32>,
    pub program_hash: BinaryElem128,
    pub constraint_products: [BinaryElem32; NUM_BATCH_CHALLENGES],
    pub challenges: [BinaryElem32; NUM_BATCH_CHALLENGES],
}

/// Convert a register-only trace to a polynomial
pub fn arithmetize_register_trace(
    trace: &RegisterOnlyTrace,
    program: &Program,
    challenges: [BinaryElem32; NUM_BATCH_CHALLENGES],
) -> ArithmetizedTrace {
    let mut poly = Vec::new();

    let program_hash = hash_program(program);
    let ph = program_hash.poly().value();
    poly.push(BinaryElem32::from(ph as u32));
    poly.push(BinaryElem32::from((ph >> 32) as u32));
    poly.push(BinaryElem32::from((ph >> 64) as u32));
    poly.push(BinaryElem32::from((ph >> 96) as u32));
    poly.push(BinaryElem32::from(trace.steps.len() as u32));

    let mut constraints = Vec::new();
    for (i, step) in trace.steps.iter().enumerate() {
        encode_step(&mut poly, step);
        generate_step_constraints(&mut constraints, step, program, i);
    }

    if let Some(final_regs) = trace.final_state() {
        for &reg in &final_regs {
            poly.push(BinaryElem32::from(reg));
        }
    }

    let mut constraint_products = [BinaryElem32::zero(); NUM_BATCH_CHALLENGES];
    for (j, &ch) in challenges.iter().enumerate() {
        constraint_products[j] = compute_constraint_product(&constraints, ch);
    }

    ArithmetizedTrace { polynomial: poly, program_hash, constraint_products, challenges }
}

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

fn encode_step(poly: &mut Vec<BinaryElem32>, step: &RegisterOnlyStep) {
    poly.push(BinaryElem32::from(step.pc));
    poly.push(BinaryElem32::from(step.opcode as u8 as u32));
    poly.push(BinaryElem32::from(step.rd as u32));
    poly.push(BinaryElem32::from(step.rs1 as u32));
    poly.push(BinaryElem32::from(step.rs2 as u32));
    poly.push(BinaryElem32::from(step.imm));
    for &reg in &step.regs {
        poly.push(BinaryElem32::from(reg));
    }
}

fn generate_step_constraints(
    constraints: &mut Vec<BinaryElem32>, step: &RegisterOnlyStep,
    program: &Program, step_index: usize,
) {
    let pc_constraint = BinaryElem32::from(step.pc).add(&BinaryElem32::from(step_index as u32));
    constraints.push(pc_constraint);

    if step_index < program.len() {
        let expected_opcode = BinaryElem32::from(program[step_index].opcode as u8 as u32);
        let actual_opcode = BinaryElem32::from(step.opcode as u8 as u32);
        constraints.push(expected_opcode.add(&actual_opcode));
    }

    if step_index < program.len() {
        let instr = &program[step_index];
        constraints.push(BinaryElem32::from(instr.rd as u32).add(&BinaryElem32::from(step.rd as u32)));
        constraints.push(BinaryElem32::from(instr.rs1 as u32).add(&BinaryElem32::from(step.rs1 as u32)));
        constraints.push(BinaryElem32::from(instr.rs2 as u32).add(&BinaryElem32::from(step.rs2 as u32)));
    }

    constraints.push(check_alu_correctness(step));
}

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

fn compute_constraint_product(constraints: &[BinaryElem32], challenge: BinaryElem32) -> BinaryElem32 {
    let mut product = BinaryElem32::one();
    for constraint in constraints {
        let term = challenge.add(constraint);
        product = product.mul(&term);
    }
    product
}

/// Verify that a polynomial represents a valid execution
pub fn verify_arithmetization(arith: &ArithmetizedTrace, num_constraints: usize) -> bool {
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
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::halt(),
        ];
        let mut initial = [0u32; 13];
        initial[1] = 5;
        initial[2] = 3;
        let trace = execute_and_trace(&program, initial);
        let challenges = [
            BinaryElem32::from(0x12345678),
            BinaryElem32::from(0xdeadbeef),
            BinaryElem32::from(0xcafebabe),
            BinaryElem32::from(0x0badf00d),
        ];
        let arith = arithmetize_register_trace(&trace, &program, challenges);
        assert!(!arith.polynomial.is_empty());
    }
}
