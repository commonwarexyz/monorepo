//! Constraint system for register-only pcVM

use commonware_commitment::field::{BinaryElem32, BinaryFieldElement};
use super::trace::{RegisterOnlyTrace, Opcode, Program};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintType {
    PcContinuity, OpcodeCorrectness, RegisterIndices,
    AluCorrectness, RegisterPreservation, HaltTermination,
}

#[derive(Debug, Clone)]
pub struct Constraint {
    pub constraint_type: ConstraintType,
    pub step_index: usize,
    pub value: BinaryElem32,
    pub description: String,
}

/// Generate all constraints for a trace
pub fn generate_all_constraints(trace: &RegisterOnlyTrace, program: &Program) -> Vec<Constraint> {
    let mut constraints = Vec::new();
    generate_program_constraints(&mut constraints, trace, program);

    for (i, step) in trace.steps.iter().enumerate() {
        if i > 0 {
            let prev_pc = trace.steps[i - 1].pc;
            let expected_pc = prev_pc + 1;
            let value = BinaryElem32::from(expected_pc).add(&BinaryElem32::from(step.pc));
            constraints.push(Constraint {
                constraint_type: ConstraintType::PcContinuity, step_index: i, value,
                description: format!("PC at step {} should be {}", i, expected_pc),
            });
        }

        if i < program.len() {
            let value = BinaryElem32::from(program[i].opcode as u8 as u32)
                .add(&BinaryElem32::from(step.opcode as u8 as u32));
            constraints.push(Constraint {
                constraint_type: ConstraintType::OpcodeCorrectness, step_index: i, value,
                description: format!("Opcode at step {} matches program", i),
            });
        }

        if i < program.len() {
            let instr = &program[i];
            constraints.push(Constraint {
                constraint_type: ConstraintType::RegisterIndices, step_index: i,
                value: BinaryElem32::from(instr.rd as u32).add(&BinaryElem32::from(step.rd as u32)),
                description: format!("rd at step {} matches program", i),
            });
            constraints.push(Constraint {
                constraint_type: ConstraintType::RegisterIndices, step_index: i,
                value: BinaryElem32::from(instr.rs1 as u32).add(&BinaryElem32::from(step.rs1 as u32)),
                description: format!("rs1 at step {} matches program", i),
            });
            constraints.push(Constraint {
                constraint_type: ConstraintType::RegisterIndices, step_index: i,
                value: BinaryElem32::from(instr.rs2 as u32).add(&BinaryElem32::from(step.rs2 as u32)),
                description: format!("rs2 at step {} matches program", i),
            });
        }

        if step.opcode != Opcode::HALT {
            let alu_result = compute_expected_result(step);
            let actual_result = step.execute()[step.rd as usize];
            let alu_value = BinaryElem32::from(alu_result).add(&BinaryElem32::from(actual_result));
            constraints.push(Constraint {
                constraint_type: ConstraintType::AluCorrectness, step_index: i,
                value: alu_value,
                description: format!("ALU result at step {} is correct", i),
            });
        }

        if i > 0 {
            let prev_regs = trace.steps[i - 1].execute();
            let curr_regs = step.regs;
            for reg_idx in 0..13 {
                if reg_idx == trace.steps[i - 1].rd as usize { continue; }
                let value = BinaryElem32::from(prev_regs[reg_idx])
                    .add(&BinaryElem32::from(curr_regs[reg_idx]));
                if value != BinaryElem32::zero() {
                    constraints.push(Constraint {
                        constraint_type: ConstraintType::RegisterPreservation, step_index: i,
                        value,
                        description: format!("Register {} preserved at step {}", reg_idx, i),
                    });
                }
            }
        }
    }
    constraints
}

fn generate_program_constraints(
    constraints: &mut Vec<Constraint>, trace: &RegisterOnlyTrace, _program: &Program,
) {
    if let Some(last_step) = trace.steps.last() {
        let is_halt = if last_step.opcode == Opcode::HALT { 0u32 } else { 1u32 };
        constraints.push(Constraint {
            constraint_type: ConstraintType::HaltTermination,
            step_index: trace.steps.len() - 1,
            value: BinaryElem32::from(is_halt),
            description: "Trace ends with HALT".to_string(),
        });
    }
}

fn compute_expected_result(step: &super::trace::RegisterOnlyStep) -> u32 {
    match step.opcode {
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
        Opcode::HALT => 0,
    }
}

/// Check if all constraints are satisfied
pub fn validate_constraints(constraints: &[Constraint]) -> Result<(), Vec<Constraint>> {
    let failed: Vec<Constraint> = constraints.iter()
        .filter(|c| c.value != BinaryElem32::zero()).cloned().collect();
    if failed.is_empty() { Ok(()) } else { Err(failed) }
}

/// Compute constraint satisfaction statistics
pub fn constraint_stats(constraints: &[Constraint]) -> ConstraintStats {
    let total = constraints.len();
    let satisfied = constraints.iter().filter(|c| c.value == BinaryElem32::zero()).count();
    let mut by_type = std::collections::HashMap::new();
    for constraint in constraints {
        *by_type.entry(constraint.constraint_type).or_insert(0) += 1;
    }
    ConstraintStats { total, satisfied, failed: total - satisfied, by_type }
}

#[derive(Debug)]
pub struct ConstraintStats {
    pub total: usize,
    pub satisfied: usize,
    pub failed: usize,
    pub by_type: std::collections::HashMap<ConstraintType, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{execute_and_trace, Instruction};

    #[test]
    fn test_valid_trace_constraints() {
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::halt(),
        ];
        let mut initial = [0u32; 13];
        initial[1] = 5;
        initial[2] = 3;
        let trace = execute_and_trace(&program, initial);
        let constraints = generate_all_constraints(&trace, &program);
        assert!(validate_constraints(&constraints).is_ok());
    }
}
