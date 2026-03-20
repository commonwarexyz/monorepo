//! Circuit-based witness-indistinguishable proof infrastructure.
//!
//! Provides a constraint system that compiles circuits into polynomials
//! suitable for the commitment scheme. Supports AND, XOR, equality,
//! integer multiplication, and GF(2^32) field multiplication constraints.
//!
//! # Modules
//!
//! - [`constraint`]: Circuit builder, constraint types, and witness.
//! - [`witness`]: Witness polynomial encoding and constraint polynomial.
//! - [`wiproof`]: Prover and verifier bridging circuits to the commitment scheme.

pub mod constraint;
pub mod witness;
pub mod wiproof;

pub use constraint::{Circuit, CircuitBuilder, Constraint, Operand, ShiftOp, Witness, WireId};
pub use witness::{ConstraintPolynomial, LigeritoInstance, WitnessPolynomial};
pub use wiproof::{prove_and_verify, prove_from_block, ZkProof, ZkProver, ZkVerifier};
