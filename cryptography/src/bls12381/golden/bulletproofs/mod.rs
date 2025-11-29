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
//! - `gadgets`: Circuit gadgets for eVRF (bit decomposition, exponentiation)
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
pub use gadgets::{BitDecomposition, EVRFGadget, ExponentiationGadget, PointVar, SCALAR_BITS};
pub use ipa::Proof as IpaProof;
pub use r1cs::{ConstraintSystem, LinearCombination, R1CSProof, R1CSProver, R1CSVerifier, Variable, Witness};
pub use transcript::Transcript;
