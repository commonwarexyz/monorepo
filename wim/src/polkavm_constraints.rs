//! Sound PolkaVM Constraint System (stub)
//! Full implementation requires the `polkavm-integration` feature.

use crate::polkavm_adapter::{PolkaVMRegisters, MemoryAccessSize};
use crate::merkle128::MerkleProof128;
use commonware_commitment::field::{BinaryElem32, BinaryElem128, BinaryFieldElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "polkavm-integration")]
use polkavm::program::Instruction;

#[derive(Debug, Clone)]
pub struct ProvenTransition {
    pub pc: u32,
    pub next_pc: u32,
    pub instruction_size: u32,
    pub regs_before: PolkaVMRegisters,
    pub regs_after: PolkaVMRegisters,
    pub memory_root_before: [u8; 32],
    pub memory_root_after: [u8; 32],
    pub memory_proof: Option<MemoryProof>,
    pub instruction_proof: InstructionProof,
}

#[derive(Debug, Clone)]
pub struct InstructionProof {
    pub merkle_path: Vec<[u8; 32]>,
    pub position: u64,
    pub opcode: u8,
    pub operands: [u32; 3],
}

#[derive(Debug, Clone)]
pub struct MemoryProof {
    pub merkle_proof: MerkleProof128,
    pub is_write: bool,
    pub size: MemoryAccessSize,
    pub root_after: BinaryElem128,
}

impl MemoryProof {
    pub fn verify(&self) -> bool { self.merkle_proof.verify() }
    pub fn address(&self) -> u32 { self.merkle_proof.index as u32 }
    pub fn value(&self) -> u32 { self.merkle_proof.value as u32 }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintError {
    UnimplementedInstruction { opcode: String },
    InvalidRegisterIndex { max_idx: usize },
    MissingMemoryProof,
    MemoryProofMismatch { expected_addr: u32, proof_addr: u32 },
    MemoryValueMismatch { expected: u32, actual: u32 },
    WrongMemoryOperation { expected_write: bool, actual_write: bool },
}

impl core::fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConstraintError::UnimplementedInstruction { opcode } =>
                write!(f, "Unimplemented instruction with opcode {}", opcode),
            ConstraintError::InvalidRegisterIndex { max_idx } =>
                write!(f, "Invalid register index {} (must be < 13)", max_idx),
            ConstraintError::MissingMemoryProof =>
                write!(f, "Memory access instruction missing Merkle proof"),
            ConstraintError::MemoryProofMismatch { expected_addr, proof_addr } =>
                write!(f, "Memory proof address mismatch: expected {:#x}, got {:#x}", expected_addr, proof_addr),
            ConstraintError::MemoryValueMismatch { expected, actual } =>
                write!(f, "Memory value mismatch: expected {:#x}, got {:#x}", expected, actual),
            ConstraintError::WrongMemoryOperation { expected_write, actual_write } =>
                write!(f, "Wrong memory operation: expected write={}, got write={}", expected_write, actual_write),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConstraintError {}

#[cfg(feature = "polkavm-integration")]
pub fn generate_transition_constraints(
    _transition: &ProvenTransition, _instruction: &Instruction,
) -> Result<Vec<BinaryElem32>, ConstraintError> {
    // Full implementation behind polkavm-integration feature
    Ok(vec![])
}
