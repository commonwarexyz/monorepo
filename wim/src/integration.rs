//! End-to-end integration tests for pcVM

use super::trace::{Program, Instruction, Opcode};

/// Create a simple test program that computes (a + b) * c
pub fn create_test_program() -> Program {
    vec![
        Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
        Instruction::new_rrr(Opcode::MUL, 0, 0, 3),
        Instruction::halt(),
    ]
}

pub fn create_test_inputs(a: u32, b: u32, c: u32) -> [u32; 13] {
    let mut regs = [0u32; 13];
    regs[1] = a; regs[2] = b; regs[3] = c;
    regs
}

pub fn expected_result(a: u32, b: u32, c: u32) -> u32 {
    a.wrapping_add(b).wrapping_mul(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_commitment::field::BinaryElem32;
    use crate::trace::execute_and_trace;
    use crate::arithmetization::arithmetize_register_trace;

    #[test]
    fn test_trace_and_arithmetize() {
        let program = create_test_program();
        let initial_regs = create_test_inputs(5, 3, 2);
        let trace = execute_and_trace(&program, initial_regs);
        assert!(trace.validate().is_ok());
        let final_state = trace.final_state().unwrap();
        assert_eq!(final_state[0], expected_result(5, 3, 2));

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
