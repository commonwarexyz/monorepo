//! Commit to polynomials with compact proofs and efficient verification.
//!
//! Implements the Ligerito polynomial commitment scheme over binary extension
//! fields. Commit to a polynomial of size 2^n and produce a proof of ~150 KB
//! that verifies in milliseconds.
//!
//! # Modules
//!
//! - [`field`]: Binary extension field arithmetic (GF(2^32), GF(2^128)).
//! - [`merkle`]: BLAKE3 Merkle tree with batched inclusion proofs.
//! - [`reed_solomon`]: Reed-Solomon encoding via binary field FFT.
//! - [`sumcheck`]: Sumcheck protocol for polynomial proximity testing.
//! - [`transcript`]: SHA-256 Fiat-Shamir transcript.
//!
//! # Status
//!
//! `ALPHA`: Breaking changes expected. No migration path provided.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub mod field;
pub mod merkle;
pub mod reed_solomon;
pub mod sumcheck;
pub mod transcript;

mod config;
mod encode;
mod error;
pub mod proof;
mod prover;
#[allow(dead_code)]
pub mod utils;
mod verifier;

pub use config::{
    log_size_for_len, prover_config_20, prover_config_for_log_size, prover_config_for_size,
    verifier_config_20, verifier_config_for_log_size, verifier_config_for_size, ProverConfig,
    VerifierConfig, MAX_LOG_SIZE, MIN_LOG_SIZE,
};
pub use error::Error;
pub use proof::Proof;
pub use prover::prove;
pub use verifier::verify;

/// Result type for commitment operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Fiat-Shamir transcript for non-interactive proofs.
///
/// Absorbs protocol messages and squeezes deterministic challenges.
/// Swap implementations (SHA-256, BLAKE2b) without changing protocol logic.
pub trait Transcript {
    /// Absorb a merkle root into the transcript.
    fn absorb_root(&mut self, root: &[u8]);

    /// Absorb a slice of raw bytes with a domain label.
    fn absorb_bytes(&mut self, label: &[u8], data: &[u8]);

    /// Absorb a single field element.
    fn absorb_elem<F: field::BinaryFieldElement>(&mut self, elem: F);

    /// Absorb multiple field elements.
    fn absorb_elems<F: field::BinaryFieldElement>(&mut self, elems: &[F]);

    /// Squeeze a field element challenge.
    fn challenge<F: field::BinaryFieldElement>(&mut self) -> F;

    /// Squeeze a query index in `[0, max)`.
    fn query(&mut self, max: usize) -> usize;

    /// Squeeze `count` distinct query indices in `[0, max)`, sorted.
    fn distinct_queries(&mut self, max: usize, count: usize) -> Vec<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use field::{BinaryElem128, BinaryElem32, BinaryFieldElement};
    use transcript::Sha256Transcript;

    #[test]
    fn test_prove_verify_roundtrip() {
        let prover_config = prover_config_20::<BinaryElem32, BinaryElem128>();
        let verifier_config = verifier_config_20();

        let poly = vec![BinaryElem32::one(); 1 << 20];

        let mut pt = Sha256Transcript::new(0);
        let proof = prove(&prover_config, &poly, &mut pt).expect("proof generation failed");

        let mut vt = Sha256Transcript::new(0);
        let valid = verify(&verifier_config, &proof, &mut vt).expect("verification failed");

        assert!(valid, "valid proof should verify");
    }

    #[test]
    fn test_zero_polynomial() {
        let prover_config = prover_config_20::<BinaryElem32, BinaryElem128>();
        let verifier_config = verifier_config_20();

        let poly = vec![BinaryElem32::zero(); 1 << 20];

        let mut pt = Sha256Transcript::new(42);
        let proof = prove(&prover_config, &poly, &mut pt).expect("proof failed");

        let mut vt = Sha256Transcript::new(42);
        let valid = verify(&verifier_config, &proof, &mut vt).expect("verify failed");

        assert!(valid);
    }

    #[test]
    fn test_random_polynomial() {
        use rand::{Rng, SeedableRng};

        let prover_config = prover_config_20::<BinaryElem32, BinaryElem128>();
        let verifier_config = verifier_config_20();

        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(123);
        let poly: Vec<BinaryElem32> = (0..1 << 20)
            .map(|_| BinaryElem32::from(rng.gen::<u32>()))
            .collect();

        let mut pt = Sha256Transcript::new(99);
        let proof = prove(&prover_config, &poly, &mut pt).expect("proof failed");

        let mut vt = Sha256Transcript::new(99);
        let valid = verify(&verifier_config, &proof, &mut vt).expect("verify failed");

        assert!(valid);
    }

    #[test]
    fn test_proof_size_compact() {
        let prover_config = prover_config_20::<BinaryElem32, BinaryElem128>();

        let poly = vec![BinaryElem32::one(); 1 << 20];

        let mut pt = Sha256Transcript::new(0);
        let proof = prove(&prover_config, &poly, &mut pt).expect("proof failed");

        let proof_size = proof.size_of();
        let poly_size = poly.len() * core::mem::size_of::<BinaryElem32>();

        // For 2^20 polynomials, proof should be much smaller than the polynomial
        assert!(
            proof_size < poly_size,
            "proof ({} bytes) should be smaller than polynomial ({} bytes)",
            proof_size,
            poly_size
        );
    }
}
