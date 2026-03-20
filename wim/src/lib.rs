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
//!
//! ## Architecture
//!
//! The library supports two execution models:
//!
//! ### 1. Register-only execution (Phase 1)
//! Simple register-based computations without memory
//!
//! ### 2. Full PolkaVM execution (Phase 2+)
//! Complete RISC-V instruction set with:
//! - 13 registers (a0-a7, t0-t2, sp, ra, zero)
//! - Merkle-authenticated memory
//! - State continuity constraints
//! - Windowed proving for continuous execution
//!
//! ## Security
//!
//! ### Secure (128-bit field, 64-bit security)
//! - [`rescue`]: Rescue-Prime hash with x^(-1) sbox, SHAKE-256 round constants, verified MDS
//! - [`merkle128`]: Merkle tree using Rescue-Prime over GF(2^128)
//! - [`unified_memory128`]: Authenticated memory with 128-bit merkle proofs
//!
//! Always use the 128-bit versions for production systems.
//!
//! ## Usage
//!
//! Enable the `polkavm-integration` feature for full PolkaVM support:
//!
//! ```toml
//! [dependencies]
//! commonware-pvm = { version = "0.1", features = ["polkavm-integration"] }
//! ```

pub mod trace;
pub mod arithmetization;
pub mod constraints;

// Secure cryptographic primitives (128-bit, 64-bit security)
pub mod rescue;
pub mod merkle128;
pub mod unified_memory128;

pub mod memory;
pub mod integration;
pub mod host_calls;
pub mod sumcheck;
pub mod trace_opening;
pub mod evaluation_proof;

#[cfg(feature = "polkavm-integration")]
pub mod prover;

#[cfg(feature = "polkavm-integration")]
pub mod polkavm_adapter;

#[cfg(feature = "polkavm-integration")]
pub mod polkavm_tracer;

#[cfg(feature = "polkavm-integration")]
pub mod polkavm_constraints;

#[cfg(feature = "polkavm-integration")]
pub mod polkavm_arithmetization;

pub use trace::{
    RegisterOnlyTrace, RegisterOnlyStep, Opcode, Instruction, Program,
    execute_and_trace, ProvenTrace, program_to_bytes,
};
pub use arithmetization::arithmetize_register_trace;

// Export secure 128-bit versions as the default
pub use unified_memory128::{UnifiedMemory128, InstructionFetch128, InstructionFetchConstraint128};
pub use merkle128::{MerkleTree128, MerkleProof128};
