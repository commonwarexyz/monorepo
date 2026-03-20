//! Constraint system for register-only pcVM
//!
//! This module defines the constraint system that ensures:
//! 1. Program integrity (correct binary is being proven)
//! 2. Execution correctness (each step follows the rules)
//! 3. State consistency (register values propagate correctly)

use commonware_commitment::field::{BinaryElem32, BinaryFieldElement};
use super::trace::{RegisterOnlyTrace, Opcode, Program};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Types of constraints in the pcVM
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintType {
    /// PC increments sequentially
    PcContinuity,

    /// Opcode matches program
    OpcodeCorrectness,

    /// Register indices match instruction
    RegisterIndices,

    /// ALU operation computed correctly
    AluCorrectness,

    /// Unchanged registers preserved
    RegisterPreservation,

    /// Final instruction is HALT
    HaltTermination,
}

/// A single constraint with metadata
#[derive(Debug, Clone)]
pub struct Constraint {
    /// Type of constraint
    pub constraint_type: ConstraintType,

    /// Step index this constraint applies to
    pub step_index: usize,

    /// The constraint value (should be zero for valid execution)
    pub value: BinaryElem32,

    /// Human-readable description
    pub description: String,
}

/// Generate all constraints for a trace
pub fn generate_all_constraints(
    trace: &RegisterOnlyTrace,
    program: &Program,
) -> Vec<Constraint> {
    let mut constraints = Vec::new();

    // Program-level constraints
    generate_program_constraints(&mut constraints, trace, program);

    // Step-level constraints
    for (i, step) in trace.steps.iter().enumerate() {
        // PC continuity
        if i > 0 {
            let prev_pc = trace.steps[i - 1].pc;
            let expected_pc = prev_pc + 1;
            let actual_pc = step.pc;

            let value = BinaryElem32::from(expected_pc).add(&BinaryElem32::from(actual_pc));

            constraints.push(Constraint {
                constraint_type: ConstraintType::PcContinuity,
                step_index: i,
                value,
                description: format!("PC at step {} should be {}", i, expected_pc),
            });
        }

        // Opcode correctness
        if i < program.len() {
            let expected_opcode = program[i].opcode as u8 as u32;
            let actual_opcode = step.opcode as u8 as u32;

            let value = BinaryElem32::from(expected_opcode).add(&BinaryElem32::from(actual_opcode));

            constraints.push(Constraint {
                constraint_type: ConstraintType::OpcodeCorrectness,
                step_index: i,
                value,
                description: format!("Opcode at step {} matches program", i),
            });
        }

        // Register indices
        if i < program.len() {
            let instr = &program[i];

            let rd_value = BinaryElem32::from(instr.rd as u32)
                .add(&BinaryElem32::from(step.rd as u32));
            constraints.push(Constraint {
                constraint_type: ConstraintType::RegisterIndices,
                step_index: i,
                value: rd_value,
                description: format!("rd at step {} matches program", i),
            });

            let rs1_value = BinaryElem32::from(instr.rs1 as u32)
                .add(&BinaryElem32::from(step.rs1 as u32));
            constraints.push(Constraint {
                constraint_type: ConstraintType::RegisterIndices,
                step_index: i,
                value: rs1_value,
                description: format!("rs1 at step {} matches program", i),
            });

            let rs2_value = BinaryElem32::from(instr.rs2 as u32)
                .add(&BinaryElem32::from(step.rs2 as u32));
            constraints.push(Constraint {
                constraint_type: ConstraintType::RegisterIndices,
                step_index: i,
                value: rs2_value,
                description: format!("rs2 at step {} matches program", i),
            });
        }

        // ALU correctness (skip for HALT which doesn't modify registers)
        if step.opcode != Opcode::HALT {
            let alu_result = compute_expected_result(step);
            let actual_result = step.execute()[step.rd as usize];
            let alu_value = BinaryElem32::from(alu_result).add(&BinaryElem32::from(actual_result));

            constraints.push(Constraint {
                constraint_type: ConstraintType::AluCorrectness,
                step_index: i,
                value: alu_value,
                description: format!("ALU result at step {} is correct", i),
            });
        }

        // Register preservation (unchanged registers stay the same)
        if i > 0 {
            let prev_regs = trace.steps[i - 1].execute();
            let curr_regs = step.regs;

            for reg_idx in 0..13 {
                // Skip the register that was written to in the previous step
                if reg_idx == trace.steps[i - 1].rd as usize {
                    continue;
                }

                let value = BinaryElem32::from(prev_regs[reg_idx])
                    .add(&BinaryElem32::from(curr_regs[reg_idx]));

                if value != BinaryElem32::zero() {
                    constraints.push(Constraint {
                        constraint_type: ConstraintType::RegisterPreservation,
                        step_index: i,
                        value,
                        description: format!("Register {} preserved at step {}", reg_idx, i),
                    });
                }
            }
        }
    }

    constraints
}

/// Generate program-level constraints
fn generate_program_constraints(
    constraints: &mut Vec<Constraint>,
    trace: &RegisterOnlyTrace,
    _program: &Program,
) {
    // Constraint: Last instruction must be HALT
    if let Some(last_step) = trace.steps.last() {
        let is_halt = if last_step.opcode == Opcode::HALT {
            0u32
        } else {
            1u32
        };

        constraints.push(Constraint {
            constraint_type: ConstraintType::HaltTermination,
            step_index: trace.steps.len() - 1,
            value: BinaryElem32::from(is_halt),
            description: "Trace ends with HALT".to_string(),
        });
    }
}

/// Compute the expected result of an ALU operation
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

/// Check if all constraints are satisfied (all values are zero)
pub fn validate_constraints(constraints: &[Constraint]) -> Result<(), Vec<Constraint>> {
    let failed: Vec<Constraint> = constraints
        .iter()
        .filter(|c| c.value != BinaryElem32::zero())
        .cloned()
        .collect();

    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed)
    }
}

/// Compute constraint satisfaction statistics
pub fn constraint_stats(constraints: &[Constraint]) -> ConstraintStats {
    let total = constraints.len();
    let satisfied = constraints.iter().filter(|c| c.value == BinaryElem32::zero()).count();
    let failed = total - satisfied;

    let mut by_type = std::collections::HashMap::new();
    for constraint in constraints {
        *by_type.entry(constraint.constraint_type).or_insert(0) += 1;
    }

    ConstraintStats {
        total,
        satisfied,
        failed,
        by_type,
    }
}

/// Statistics about constraint satisfaction
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
        // Program: a0 = a1 + a2, then HALT
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::halt(),
        ];

        let mut initial = [0u32; 13];
        initial[1] = 5;
        initial[2] = 3;

        let trace = execute_and_trace(&program, initial);
        let constraints = generate_all_constraints(&trace, &program);

        // Debug: Print failing constraints
        if let Err(failed) = validate_constraints(&constraints) {
            for c in &failed {
                eprintln!("Failed constraint: {:?} at step {}: {}", c.constraint_type, c.step_index, c.description);
                eprintln!("  Value: {:?}", c.value);
            }
        }

        // All constraints should be satisfied
        assert!(validate_constraints(&constraints).is_ok());
    }

    #[test]
    fn test_constraint_types() {
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::new_rrr(Opcode::MUL, 0, 0, 3),
            Instruction::halt(),
        ];

        let mut initial = [0u32; 13];
        initial[1] = 5;
        initial[2] = 3;
        initial[3] = 2;

        let trace = execute_and_trace(&program, initial);
        let constraints = generate_all_constraints(&trace, &program);

        // Should have multiple constraint types
        let stats = constraint_stats(&constraints);
        assert!(stats.by_type.contains_key(&ConstraintType::PcContinuity));
        assert!(stats.by_type.contains_key(&ConstraintType::OpcodeCorrectness));
        assert!(stats.by_type.contains_key(&ConstraintType::AluCorrectness));
        assert!(stats.by_type.contains_key(&ConstraintType::HaltTermination));
    }

    #[test]
    fn test_all_constraints_satisfied() {
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::halt(),
        ];

        let mut initial = [0u32; 13];
        initial[1] = 10;
        initial[2] = 20;

        let trace = execute_and_trace(&program, initial);
        let constraints = generate_all_constraints(&trace, &program);

        let stats = constraint_stats(&constraints);
        assert_eq!(stats.satisfied, stats.total);
        assert_eq!(stats.failed, 0);
    }
}
