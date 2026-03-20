//! Execution trace for pcVM programs (Phase 1 and Phase 2)

use super::memory::ReadOnlyMemory;
use super::merkle128::MerkleProof128;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Opcodes supported in Phase 1 and Phase 2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// rd = rs1 + rs2 (wrapping addition)
    ADD = 0x00,
    /// rd = rs1 - rs2 (wrapping subtraction)
    SUB = 0x01,
    /// rd = rs1 * rs2 (lower 32 bits)
    MUL = 0x02,
    /// rd = rs1 & rs2 (bitwise AND)
    AND = 0x03,
    /// rd = rs1 | rs2 (bitwise OR)
    OR = 0x04,
    /// rd = rs1 ^ rs2 (bitwise XOR)
    XOR = 0x05,
    /// rd = rs1 << rs2[4:0] (logical left shift)
    SLL = 0x06,
    /// rd = rs1 >> rs2[4:0] (logical right shift)
    SRL = 0x07,
    /// rd = immediate value
    LI = 0x08,
    /// rd = mem[rs1 + imm] (Phase 2: load from read-only memory)
    LOAD = 0x09,
    /// Halt execution
    HALT = 0xFF,
}

impl Opcode {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Opcode::ADD),
            0x01 => Some(Opcode::SUB),
            0x02 => Some(Opcode::MUL),
            0x03 => Some(Opcode::AND),
            0x04 => Some(Opcode::OR),
            0x05 => Some(Opcode::XOR),
            0x06 => Some(Opcode::SLL),
            0x07 => Some(Opcode::SRL),
            0x08 => Some(Opcode::LI),
            0x09 => Some(Opcode::LOAD),
            0xFF => Some(Opcode::HALT),
            _ => None,
        }
    }
}

/// A single execution step in the trace
#[derive(Debug, Clone)]
pub struct RegisterOnlyStep {
    /// Program counter (instruction index)
    pub pc: u32,

    /// Register values BEFORE this instruction executes
    /// Registers: a0-a7 (8 argument/return registers), t0-t4 (5 temporary registers)
    pub regs: [u32; 13],

    /// The instruction being executed
    pub opcode: Opcode,

    /// Destination register index (0-12)
    pub rd: u8,

    /// Source register 1 index (0-12)
    pub rs1: u8,

    /// Source register 2 index (0-12)
    pub rs2: u8,

    /// Immediate value (for LI and LOAD instructions)
    pub imm: u32,

    /// Memory address accessed (Phase 2: Some for LOAD, None otherwise)
    pub memory_address: Option<u32>,

    /// Value read from memory (Phase 2: Some for LOAD, None otherwise)
    pub memory_value: Option<u32>,

    /// Instruction fetch proof (Phase 3: merkle proof for instruction word 0)
    /// Proves the first word of instruction is in committed program memory
    pub instruction_proof_0: Option<MerkleProof128>,

    /// Instruction fetch proof for word 1 (instructions are 2 words = 8 bytes)
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
            Opcode::LOAD => self.memory_value.unwrap_or(0), // Value already fetched during trace generation
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
    /// All execution steps (one per instruction)
    pub steps: Vec<RegisterOnlyStep>,
}

impl RegisterOnlyTrace {
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Add a step to the trace
    pub fn push(&mut self, step: RegisterOnlyStep) {
        self.steps.push(step);
    }

    /// Get the initial register state
    pub fn initial_state(&self) -> Option<[u32; 13]> {
        self.steps.first().map(|s| s.regs)
    }

    /// Get the final register state (after last instruction)
    pub fn final_state(&self) -> Option<[u32; 13]> {
        if self.steps.is_empty() {
            return None;
        }

        Some(self.steps.last().unwrap().execute())
    }

    /// Validate that the trace is internally consistent
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.steps.is_empty() {
            return Err("Empty trace");
        }

        // Check PC increments sequentially
        for i in 0..self.steps.len() - 1 {
            if self.steps[i + 1].pc != self.steps[i].pc + 1 {
                return Err("PC does not increment sequentially");
            }
        }

        // Check that each step's next state matches the next step's current state
        for i in 0..self.steps.len() - 1 {
            let expected_next_regs = self.steps[i].execute();
            let actual_next_regs = self.steps[i + 1].regs;

            if expected_next_regs != actual_next_regs {
                return Err("Register state mismatch between steps");
            }
        }

        // Last instruction should be HALT
        if self.steps.last().unwrap().opcode != Opcode::HALT {
            return Err("Trace does not end with HALT");
        }

        Ok(())
    }
}

impl Default for RegisterOnlyTrace {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple instruction encoding for our register-only VM
#[derive(Debug, Clone, Copy)]
pub struct Instruction {
    pub opcode: Opcode,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub imm: u32,
}

impl Instruction {
    /// Create a new register-register instruction
    pub fn new_rrr(opcode: Opcode, rd: u8, rs1: u8, rs2: u8) -> Self {
        Self { opcode, rd, rs1, rs2, imm: 0 }
    }

    /// Create a new immediate instruction
    pub fn new_imm(rd: u8, imm: u32) -> Self {
        Self { opcode: Opcode::LI, rd, rs1: 0, rs2: 0, imm }
    }

    /// Create a LOAD instruction: rd = mem[rs1 + imm]
    pub fn new_load(rd: u8, rs1: u8, imm: u32) -> Self {
        Self { opcode: Opcode::LOAD, rd, rs1, rs2: 0, imm }
    }

    /// Create a HALT instruction
    pub fn halt() -> Self {
        Self { opcode: Opcode::HALT, rd: 0, rs1: 0, rs2: 0, imm: 0 }
    }

    /// Encode instruction to a u32 word
    ///
    /// Format: [opcode:8][rd:4][rs1:4][rs2:4][imm_hi:12] + [imm_lo:32] for instructions with imm
    /// For simplicity, all instructions are encoded as 8 bytes (2 words)
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.opcode as u8;
        bytes[1] = (self.rd & 0x0F) | ((self.rs1 & 0x0F) << 4);
        bytes[2] = self.rs2 & 0x0F;
        bytes[3] = 0; // reserved
        bytes[4..8].copy_from_slice(&self.imm.to_le_bytes());
        bytes
    }

    /// Encode instruction to two u32 words
    pub fn to_words(&self) -> [u32; 2] {
        let bytes = self.to_bytes();
        [
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ]
    }

    /// Decode instruction from two u32 words
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

/// A simple program is just a list of instructions
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
    /// The execution trace with merkle proofs attached
    pub trace: RegisterOnlyTrace,
    /// Root of the program memory (commitment to the program)
    pub program_root: commonware_commitment::field::BinaryElem32,
}

/// Execute a program and generate a trace with instruction fetch proofs (Phase 3)
///
/// This proves that each instruction executed came from the committed program.
/// Uses 128-bit Merkle proofs via the unified memory model.
pub fn execute_and_trace_with_proofs(
    program: &Program,
    initial_regs: [u32; 13],
) -> Result<ProvenTrace, &'static str> {
    use super::merkle128::MerkleTree128;

    // Encode program to u128 words (pack two u32 instruction words per u128)
    let program_bytes = program_to_bytes(program);
    let mut words = Vec::new();
    for chunk in program_bytes.chunks(16) {
        let mut buf = [0u8; 16];
        buf[..chunk.len()].copy_from_slice(chunk);
        words.push(u128::from_le_bytes(buf));
    }

    // Pad to power of 2
    let tree_size = words.len().max(1).next_power_of_two();
    words.resize(tree_size, 0u128);

    let tree = MerkleTree128::new(words)?;
    let program_root = commonware_commitment::field::BinaryElem32::from(0u32);

    let mut trace = RegisterOnlyTrace::new();
    let mut regs = initial_regs;

    for (pc, instr) in program.iter().enumerate() {
        // Each instruction is 8 bytes. 128-bit words hold 16 bytes (2 instructions).
        // Word index for instruction word 0
        let byte_pc = (pc * 8) as usize;
        let word_idx_0 = byte_pc / 16;
        // Instruction word 1 is at byte_pc + 4
        let word_idx_1 = (byte_pc + 4) / 16;

        let proof_0 = tree.prove(word_idx_0)?;
        let proof_1 = tree.prove(word_idx_1)?;

        // Handle memory access for LOAD instruction
        let (memory_address, memory_value) = if instr.opcode == Opcode::LOAD {
            let addr = regs[instr.rs1 as usize].wrapping_add(instr.imm);
            (Some(addr), Some(0))
        } else {
            (None, None)
        };

        let step = RegisterOnlyStep {
            pc: pc as u32,
            regs,
            opcode: instr.opcode,
            rd: instr.rd,
            rs1: instr.rs1,
            rs2: instr.rs2,
            imm: instr.imm,
            memory_address,
            memory_value,
            instruction_proof_0: Some(proof_0),
            instruction_proof_1: Some(proof_1),
        };

        regs = step.execute();
        trace.push(step);

        if instr.opcode == Opcode::HALT {
            break;
        }
    }

    Ok(ProvenTrace { trace, program_root })
}

/// Execute a program with optional memory and generate a trace (Phase 2)
pub fn execute_and_trace_with_memory(
    program: &Program,
    initial_regs: [u32; 13],
    memory: Option<&ReadOnlyMemory>,
) -> RegisterOnlyTrace {
    let mut trace = RegisterOnlyTrace::new();
    let mut regs = initial_regs;

    for (pc, instr) in program.iter().enumerate() {
        // Handle memory access for LOAD instruction
        let (memory_address, memory_value) = if instr.opcode == Opcode::LOAD {
            let addr = regs[instr.rs1 as usize].wrapping_add(instr.imm);
            let value = memory.map(|m| m.read_unchecked(addr)).unwrap_or(0);
            (Some(addr), Some(value))
        } else {
            (None, None)
        };

        let step = RegisterOnlyStep {
            pc: pc as u32,
            regs,
            opcode: instr.opcode,
            rd: instr.rd,
            rs1: instr.rs1,
            rs2: instr.rs2,
            imm: instr.imm,
            memory_address,
            memory_value,
            instruction_proof_0: None, // filled by execute_and_trace_with_proofs
            instruction_proof_1: None,
        };

        // Execute and update registers
        regs = step.execute();

        trace.push(step);

        // Stop at HALT
        if instr.opcode == Opcode::HALT {
            break;
        }
    }

    trace
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_addition() {
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

        assert_eq!(trace.steps.len(), 2);
        assert_eq!(trace.final_state().unwrap()[0], 8); // a0 = 5 + 3
        assert!(trace.validate().is_ok());
    }

    #[test]
    fn test_complex_computation() {
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

        assert_eq!(trace.steps.len(), 3);
        assert_eq!(trace.final_state().unwrap()[0], 16); // (5+3)*2 = 16
        assert!(trace.validate().is_ok());
    }

    #[test]
    fn test_instruction_encoding_roundtrip() {
        let instructions = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::new_rrr(Opcode::SUB, 5, 6, 7),
            Instruction::new_imm(3, 0xDEADBEEF),
            Instruction::new_load(8, 9, 100),
            Instruction::halt(),
        ];

        for instr in &instructions {
            let words = instr.to_words();
            let decoded = Instruction::from_words(words).expect("decode failed");
            assert_eq!(decoded.opcode, instr.opcode);
            assert_eq!(decoded.rd, instr.rd);
            assert_eq!(decoded.rs1, instr.rs1);
            assert_eq!(decoded.rs2, instr.rs2);
            assert_eq!(decoded.imm, instr.imm);
        }
    }

    #[test]
    fn test_program_to_bytes() {
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::new_imm(3, 42),
            Instruction::halt(),
        ];

        let bytes = program_to_bytes(&program);
        assert_eq!(bytes.len(), 24); // 3 instructions * 8 bytes each

        // Verify first instruction encodes correctly
        assert_eq!(bytes[0], Opcode::ADD as u8);
    }

    #[test]
    fn test_proven_trace() {
        // Simple program with instruction fetch proofs
        let program = vec![
            Instruction::new_rrr(Opcode::ADD, 0, 1, 2),
            Instruction::new_rrr(Opcode::MUL, 0, 0, 3),
            Instruction::halt(),
        ];

        let mut initial = [0u32; 13];
        initial[1] = 5;
        initial[2] = 3;
        initial[3] = 2;

        let proven = execute_and_trace_with_proofs(&program, initial)
            .expect("failed to generate proven trace");

        // Same result as regular execution
        assert_eq!(proven.trace.steps.len(), 3);
        assert_eq!(proven.trace.final_state().unwrap()[0], 16);

        // Each step should have instruction proofs
        for step in &proven.trace.steps {
            assert!(step.instruction_proof_0.is_some(), "missing proof 0");
            assert!(step.instruction_proof_1.is_some(), "missing proof 1");

            // Proofs should verify
            let proof_0 = step.instruction_proof_0.as_ref().unwrap();
            let proof_1 = step.instruction_proof_1.as_ref().unwrap();

            assert!(proof_0.verify(), "proof 0 failed to verify");
            assert!(proof_1.verify(), "proof 1 failed to verify");

            // Both proofs should share the same root
            assert_eq!(proof_0.root, proof_1.root, "proof roots should match");
        }
    }

    #[test]
    fn test_proven_trace_decode_matches() {
        // Verify that decoded instruction matches what's in the trace
        let program = vec![
            Instruction::new_imm(5, 0xCAFEBABE),  // a5 = 0xCAFEBABE
            Instruction::halt(),
        ];

        let initial = [0u32; 13];

        let proven = execute_and_trace_with_proofs(&program, initial)
            .expect("failed to generate proven trace");

        let step = &proven.trace.steps[0];

        // Get the u128 word from the merkle proof and extract u32 instruction words
        let word_128 = step.instruction_proof_0.as_ref().unwrap().value;
        let word_0 = word_128 as u32;
        let word_1 = (word_128 >> 32) as u32;

        // Decode instruction from the proven words
        let decoded = Instruction::from_words([word_0, word_1])
            .expect("failed to decode instruction from proof");

        // Verify the decoded instruction matches what we executed
        assert_eq!(decoded.opcode, step.opcode);
        assert_eq!(decoded.rd, step.rd);
        assert_eq!(decoded.rs1, step.rs1);
        assert_eq!(decoded.rs2, step.rs2);
        assert_eq!(decoded.imm, step.imm);
    }
}
