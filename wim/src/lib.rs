//! PolkaVM Polynomial Commitment Verification
//!
//! This crate provides constraint system and proving infrastructure for PolkaVM execution traces
//! using the polynomial commitment scheme over binary fields.
//!
//! ## Features
//!
//! - **PolkaVM Integration**: Constraint generation for RISC-V instruction execution
//! - **State Continuity**: Cryptographic enforcement of execution chaining
//! - **Merkle Memory**: Authenticated memory via Merkle trees
//! - **Batched Constraints**: Schwartz-Zippel batching for efficient verification

pub mod trace;
pub mod arithmetization;
pub mod constraints;

// Secure cryptographic primitives (128-bit, 64-bit security)
pub mod rescue;
pub mod merkle128;
pub mod unified_memory128;

pub mod memory;
pub mod poker;
pub mod integration;
pub mod host_calls;
pub mod sumcheck;
pub mod trace_opening;
pub mod evaluation_proof;

// PolkaVM integration modules (require polkavm-integration feature, currently disabled)
// pub mod prover;
// pub mod polkavm_adapter;
// pub mod polkavm_tracer;
// pub mod polkavm_constraints;
// pub mod polkavm_arithmetization;

pub use trace::{
    RegisterOnlyTrace, RegisterOnlyStep, Opcode, Instruction, Program,
    execute_and_trace, ProvenTrace, program_to_bytes,
};
pub use arithmetization::arithmetize_register_trace;

// Export secure 128-bit versions as the default
pub use unified_memory128::{UnifiedMemory128, InstructionFetch128, InstructionFetchConstraint128};
pub use merkle128::{MerkleTree128, MerkleProof128};
