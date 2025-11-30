//! Bulletproofs implementation for the Golden DKG protocol.
//!
//! This module provides the zero-knowledge proof infrastructure needed
//! for the eVRF construction in the Golden DKG.
//!
//! # Components
//!
//! - `transcript`: Fiat-Shamir transcript for non-interactive proofs
//! - `commitment`: Pedersen vector commitments
//! - `ipa`: Inner Product Argument (logarithmic-size proofs)
//! - `r1cs`: Rank-1 Constraint System for arithmetic circuits
//! - `gadgets`: Native circuit gadgets for eVRF on Jubjub curve
//!
//! # Two-Curve Architecture
//!
//! The gadgets use native arithmetic because Jubjub's base field equals
//! BLS12-381's scalar field, eliminating expensive non-native arithmetic.
//!
//! # References
//!
//! - Bulletproofs: Short Proofs for Confidential Transactions and More
//!   (Bunz et al., 2018) https://eprint.iacr.org/2017/1066

pub mod commitment;
pub mod gadgets;
pub mod ipa;
pub mod r1cs;
pub mod transcript;

pub use commitment::{hash_to_g1_with_label, Generators};
pub use gadgets::{
    get_jubjub_d, BitDecomposition, EVRFGadget, JubjubAddGadget, JubjubPointVar,
    JubjubScalarMulGadget, SCALAR_BITS,
};
pub use ipa::Proof as IpaProof;
pub use r1cs::{ConstraintSystem, LinearCombination, R1CSProof, R1CSProver, R1CSVerifier, Variable, Witness};
pub use transcript::Transcript;
