//! Execution trace for pcVM programs (Phase 1 and Phase 2)

use super::memory::ReadOnlyMemory;
use super::merkle128::MerkleProof128;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Opcodes supported in Phase 1 and Phase 2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    ADD = 0x00, SUB = 0x01, MUL = 0x02, AND = 0x03,
    OR = 0x04, XOR = 0x05, SLL = 0x06, SRL = 0x07,
    LI = 0x08, LOAD = 0x09, HALT = 0xFF,
}

impl Opcode {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Opcode::ADD), 0x01 => Some(Opcode::SUB),
            0x02 => Some(Opcode::MUL), 0x03 => Some(Opcode::AND),
            0x04 => Some(Opcode::OR),  0x05 => Some(Opcode::XOR),
            0x06 => Some(Opcode::SLL), 0x07 => Some(Opcode::SRL),
            0x08 => Some(Opcode::LI),  0x09 => Some(Opcode::LOAD),
            0xFF => Some(Opcode::HALT), _ => None,
        }
    }
}

/// A single execution step in the trace
#[derive(Debug, Clone)]
pub struct RegisterOnlyStep {
    pub pc: u32,
    pub regs: [u32; 13],
    pub opcode: Opcode,
    pub rd: u8, pub rs1: u8, pub rs2: u8,
    pub imm: u32,
    pub memory_address: Option<u32>,
    pub memory_value: Option<u32>,
    pub instruction_proof_0: Option<MerkleProof128>,
    pub instruction_proof_1: Option<MerkleProof128>,
}

impl RegisterOnlyStep {
    /// Execute this instruction and return the new register state
    pub fn execute(&self) -> [u32; 13] {
        let mut new_regs = self.regs;
        let result = match self.opcode {
            Opcode::ADD => self.regs[self.rs1 as usize].wrapping_add(self.regs[self.rs2 as usize]),
            Opcode::SUB => self.regs[self.rs1 as usize].wrapping_sub(self.regs[self.rs2 as usize]),
            Opcode::MUL => self.regs[self.rs1 as usize].wrapping_mul(self.regs[self.rs2 as usize]),
            Opcode::AND => self.regs[self.rs1 as usize] & self.regs[self.rs2 as usize],
            Opcode::OR  => self.regs[self.rs1 as usize] | self.regs[self.rs2 as usize],
            Opcode::XOR => self.regs[self.rs1 as usize] ^ self.regs[self.rs2 as usize],
            Opcode::SLL => self.regs[self.rs1 as usize] << (self.regs[self.rs2 as usize] & 0x1F),
            Opcode::SRL => self.regs[self.rs1 as usize] >> (self.regs[self.rs2 as usize] & 0x1F),
            Opcode::LI  => self.imm,
            Opcode::LOAD => self.memory_value.unwrap_or(0),
            Opcode::HALT => 0,
        };
        if self.opcode != Opcode::HALT {
            new_regs[self.rd as usize] = result;
        }
        new_regs
    }
}

/// Complete execution trace of a register-only program
#[derive(Debug, Clone)]
pub struct RegisterOnlyTrace {
    pub steps: Vec<RegisterOnlyStep>,
}

impl RegisterOnlyTrace {
    pub fn new() -> Self { Self { steps: Vec::new() } }
    pub fn push(&mut self, step: RegisterOnlyStep) { self.steps.push(step); }
    pub fn initial_state(&self) -> Option<[u32; 13]> { self.steps.first().map(|s| s.regs) }

    pub fn final_state(&self) -> Option<[u32; 13]> {
        if self.steps.is_empty() { return None; }
        Some(self.steps.last().unwrap().execute())
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.steps.is_empty() { return Err("Empty trace"); }
        for i in 0..self.steps.len() - 1 {
            if self.steps[i + 1].pc != self.steps[i].pc + 1 {
                return Err("PC does not increment sequentially");
            }
        }
        for i in 0..self.steps.len() - 1 {
            if self.steps[i].execute() != self.steps[i + 1].regs {
                return Err("Register state mismatch between steps");
            }
        }
        if self.steps.last().unwrap().opcode != Opcode::HALT {
            return Err("Trace does not end with HALT");
        }
        Ok(())
    }
}

impl Default for RegisterOnlyTrace {
    fn default() -> Self { Self::new() }
}

/// Simple instruction encoding for our register-only VM
#[derive(Debug, Clone, Copy)]
pub struct Instruction {
    pub opcode: Opcode, pub rd: u8, pub rs1: u8, pub rs2: u8, pub imm: u32,
}

impl Instruction {
    pub fn new_rrr(opcode: Opcode, rd: u8, rs1: u8, rs2: u8) -> Self {
        Self { opcode, rd, rs1, rs2, imm: 0 }
    }
    pub fn new_imm(rd: u8, imm: u32) -> Self {
        Self { opcode: Opcode::LI, rd, rs1: 0, rs2: 0, imm }
    }
    pub fn new_load(rd: u8, rs1: u8, imm: u32) -> Self {
        Self { opcode: Opcode::LOAD, rd, rs1, rs2: 0, imm }
    }
    pub fn halt() -> Self {
        Self { opcode: Opcode::HALT, rd: 0, rs1: 0, rs2: 0, imm: 0 }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.opcode as u8;
        bytes[1] = (self.rd & 0x0F) | ((self.rs1 & 0x0F) << 4);
        bytes[2] = self.rs2 & 0x0F;
        bytes[3] = 0;
        bytes[4..8].copy_from_slice(&self.imm.to_le_bytes());
        bytes
    }

    pub fn to_words(&self) -> [u32; 2] {
        let bytes = self.to_bytes();
        [
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ]
    }

    pub fn from_words(words: [u32; 2]) -> Option<Self> {
        let w0_bytes = words[0].to_le_bytes();
        let opcode = Opcode::from_u8(w0_bytes[0])?;
        let rd = w0_bytes[1] & 0x0F;
        let rs1 = (w0_bytes[1] >> 4) & 0x0F;
        let rs2 = w0_bytes[2] & 0x0F;
        let imm = words[1];
        Some(Self { opcode, rd, rs1, rs2, imm })
    }
}

pub type Program = Vec<Instruction>;

/// Encode a program to bytes for loading into UnifiedMemory
pub fn program_to_bytes(program: &Program) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(program.len() * 8);
    for instr in program {
        bytes.extend_from_slice(&instr.to_bytes());
    }
    bytes
}

/// Execute a program and generate a trace (Phase 1: no memory)
pub fn execute_and_trace(program: &Program, initial_regs: [u32; 13]) -> RegisterOnlyTrace {
    execute_and_trace_with_memory(program, initial_regs, None)
}

/// Result of executing with instruction proofs
pub struct ProvenTrace {
    pub trace: RegisterOnlyTrace,
    pub program_root: commonware_commitment::field::BinaryElem32,
}

/// Execute a program and generate a trace with instruction fetch proofs (Phase 3)
pub fn execute_and_trace_with_proofs(
    program: &Program,
    initial_regs: [u32; 13],
) -> Result<ProvenTrace, &'static str> {
    use super::merkle128::MerkleTree128;

    let program_bytes = program_to_bytes(program);
    let mut words = Vec::new();
    for chunk in program_bytes.chunks(16) {
        let mut buf = [0u8; 16];
        buf[..chunk.len()].copy_from_slice(chunk);
        words.push(u128::from_le_bytes(buf));
    }

    let tree_size = words.len().max(1).next_power_of_two();
    words.resize(tree_size, 0u128);

    let tree = MerkleTree128::new(words)?;
    let program_root = commonware_commitment::field::BinaryElem32::from(0u32);

    let mut trace = RegisterOnlyTrace::new();
    let mut regs = initial_regs;

    for (pc, instr) in program.iter().enumerate() {
        let byte_pc = (pc * 8) as usize;
        let word_idx_0 = byte_pc / 16;
        let word_idx_1 = (byte_pc + 4) / 16;

        let proof_0 = tree.prove(word_idx_0)?;
        let proof_1 = tree.prove(word_idx_1)?;

        let (memory_address, memory_value) = if instr.opcode == Opcode::LOAD {
            let addr = regs[instr.rs1 as usize].wrapping_add(instr.imm);
            (Some(addr), Some(0))
        } else {
            (None, None)
        };

        let step = RegisterOnlyStep {
            pc: pc as u32, regs, opcode: instr.opcode,
            rd: instr.rd, rs1: instr.rs1, rs2: instr.rs2, imm: instr.imm,
            memory_address, memory_value,
            instruction_proof_0: Some(proof_0),
            instruction_proof_1: Some(proof_1),
        };

        regs = step.execute();
        trace.push(step);
        if instr.opcode == Opcode::HALT { break; }
    }

    Ok(ProvenTrace { trace, program_root })
}

/// Execute a program with optional memory and generate a trace (Phase 2)
pub fn execute_and_trace_with_memory(
    program: &Program, initial_regs: [u32; 13], memory: Option<&ReadOnlyMemory>,
) -> RegisterOnlyTrace {
    let mut trace = RegisterOnlyTrace::new();
    let mut regs = initial_regs;

    for (pc, instr) in program.iter().enumerate() {
        let (memory_address, memory_value) = if instr.opcode == Opcode::LOAD {
            let addr = regs[instr.rs1 as usize].wrapping_add(instr.imm);
            let value = memory.map(|m| m.read_unchecked(addr)).unwrap_or(0);
            (Some(addr), Some(value))
        } else {
            (None, None)
        };

        let step = RegisterOnlyStep {
            pc: pc as u32, regs, opcode: instr.opcode,
            rd: instr.rd, rs1: instr.rs1, rs2: instr.rs2, imm: instr.imm,
            memory_address, memory_value,
            instruction_proof_0: None, instruction_proof_1: None,
        };

        regs = step.execute();
        trace.push(step);
        if instr.opcode == Opcode::HALT { break; }
    }

    trace
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_addition() {
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::halt(),
        ];
        let mut initial = [0u32; 13];
        initial[1] = 5;
        initial[2] = 3;
        let trace = execute_and_trace(&program, initial);
        assert_eq!(trace.steps.len(), 2);
        assert_eq!(trace.final_state().unwrap()[0], 8);
        assert!(trace.validate().is_ok());
    }

    #[test]
    fn test_instruction_encoding_roundtrip() {
        let instructions = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::new_imm(3, 0xDEADBEEF),
            Instruction::halt(),
        ];
        for instr in &instructions {
            let words = instr.to_words();
            let decoded = Instruction::from_words(words).expect("decode failed");
            assert_eq!(decoded.opcode, instr.opcode);
            assert_eq!(decoded.rd, instr.rd);
            assert_eq!(decoded.imm, instr.imm);
        }
    }

    #[test]
    fn test_proven_trace() {
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::halt(),
        ];
        let mut initial = [0u32; 13];
        initial[1] = 5;
        initial[2] = 3;
        let proven = execute_and_trace_with_proofs(&program, initial)
            .expect("failed to generate proven trace");
        assert_eq!(proven.trace.steps.len(), 2);
        for step in &proven.trace.steps {
            assert!(step.instruction_proof_0.is_some());
            assert!(step.instruction_proof_1.is_some());
            assert!(step.instruction_proof_0.as_ref().unwrap().verify());
            assert!(step.instruction_proof_1.as_ref().unwrap().verify());
        }
    }
}
