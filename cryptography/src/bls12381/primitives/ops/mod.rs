//! Digital signatures over the BLS12-381 curve.
//!
//! This module provides BLS12-381 signature operations organized into submodules:
//!
//! - [`core`]: Basic primitives (keypair generation, signing, verification, proof of possession)
//! - [`aggregate`]: Aggregation of public keys and signatures
//! - [`batch`]: Batch verification ensuring each individual signature is valid
//! - [`threshold`]: Threshold signature operations
//!
//! # Domain Separation Tag (DST)
//!
//! All signatures use the `POP` (Proof of Possession) scheme during signing. For Proof-of-Possession (POP) signatures,
//! the domain separation tag is `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. For signatures over other messages, the
//! domain separation tag is `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. You can read more about DSTs [here](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2).
//!
//! # Batch vs Aggregate Verification
//!
//! Use [`batch`] when you need to ensure each individual signature is valid. Use [`aggregate`]
//! when you only need to verify that the aggregate is valid (more efficient, but an attacker
//! could redistribute signature components between signers while keeping the aggregate unchanged).
//! Batch verification uses random scalar weights internally to prevent this attack.

pub mod aggregate;
pub use aggregate::{
    aggregate_public_keys, aggregate_signatures, aggregate_verify_multiple_messages,
    aggregate_verify_multiple_public_keys,
};
pub mod batch;
pub use batch::{verify_multiple_messages, verify_multiple_public_keys};
pub mod core;
pub use core::{
    compute_public, hash_message, hash_message_namespace, keypair, sign, sign_message,
    sign_proof_of_possession, verify, verify_message, verify_proof_of_possession,
};
pub mod threshold;
pub use threshold::{
    partial_aggregate_signatures, partial_sign_message, partial_sign_proof_of_possession,
    partial_verify_message, partial_verify_multiple_messages, partial_verify_multiple_public_keys,
    partial_verify_proof_of_possession, threshold_signature_recover,
    threshold_signature_recover_multiple, threshold_signature_recover_pair,
};

#[cfg(test)]
mod tests;
