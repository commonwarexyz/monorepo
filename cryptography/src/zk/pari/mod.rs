//! Pari proofs for Square R1CS relations with committed inputs.
//!
//! Pari uses a circuit-specific structured reference string. Setup randomness is
//! toxic waste and must not be recoverable after [`setup()`] returns. The native
//! commitment key is relation-specific: commitments made for one relation cannot
//! be reused with another relation or setup.

mod circuit;
#[cfg(any(test, feature = "fuzz"))]
commonware_macros::stability_mod!(ALPHA, pub mod fuzz);
mod poly;
mod prover;
mod setup;
mod simulator;
#[cfg(test)]
mod tests;
mod types;
mod verifier;

use crate::bls12381::primitives::group::{Scalar, ScalarReadCfg};
pub use circuit::{InputLayout, Relation};
use commonware_codec::{Encode, Read};
use commonware_math::algebra::Additive;
pub use prover::{prove, prove_prebound};
use rand_core::CryptoRng;
pub use setup::{setup, setup_with_trapdoor};
pub use simulator::{simulate, simulate_prebound};
use thiserror::Error;
pub use types::{
    Claim, CommitmentKey, Opening, Proof, ProvingKey, Trapdoor, VerifyingKey, Witness,
};
pub use verifier::{
    BatchEntry, CommitmentTerm, batch_verify, batch_verify_prebound, verify, verify_prebound,
};
use zeroize::Zeroizing;

const TRANSCRIPT_MARKER: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_PARI_PROOF_V1";

/// Errors returned while constructing or proving a Pari relation.
#[derive(Debug, Error)]
pub enum Error {
    /// The generic arithmetic circuit could not be converted to Square R1CS.
    #[error("invalid circuit: {0}")]
    Circuit(String),
    /// A polynomial operation violated a required degree or divisibility bound.
    #[error("invalid polynomial: {0}")]
    Polynomial(String),
    /// The supplied object was generated for a different relation.
    #[error("relation does not match the key or witness")]
    RelationMismatch,
    /// The supplied public-input count does not match the relation.
    #[error("expected {expected} public inputs, got {actual}")]
    PublicInputCount { expected: usize, actual: usize },
    /// The supplied committed-input count does not match the commitment key.
    #[error("expected {expected} committed inputs, got {actual}")]
    CommittedInputCount { expected: usize, actual: usize },
    /// The supplied opening count does not match the committed-input blocks.
    #[error("expected {expected} openings, got {actual}")]
    OpeningCount { expected: usize, actual: usize },
    /// The claim does not match the witness and opening.
    #[error("claim does not match the witness")]
    ClaimMismatch,
    /// A commitment or proof point is the identity and cannot be encoded.
    #[error("{kind} must not be the group identity")]
    IdentityPoint { kind: &'static str },
    /// The supplied assignment does not satisfy the compiled relation.
    #[error("assignment does not satisfy the relation")]
    Unsatisfied,
    /// A polynomial expected to vanish at the evaluation point did not do so.
    #[error("internal polynomial opening is inconsistent")]
    InconsistentOpening,
    /// A checked dimension conversion or size calculation overflowed.
    #[error("relation is too large")]
    TooLarge,
}

impl From<circuit::Error> for Error {
    fn from(error: circuit::Error) -> Self {
        Self::Circuit(error.to_string())
    }
}

impl From<poly::Error> for Error {
    fn from(error: poly::Error) -> Self {
        Self::Polynomial(error.to_string())
    }
}

fn sample_scalar(rng: &mut impl CryptoRng) -> Scalar {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(bytes.as_mut());
        let mut encoded = bytes.as_slice();
        if let Ok(value) = Scalar::read_cfg(&mut encoded, &ScalarReadCfg::AllowZero) {
            return value;
        }
    }
}

/// Derive the evaluation challenge for a transcript that already binds the
/// statement (public inputs and block commitments, or their preimages).
///
/// The key digest covers the relation and commitment-key digests, so this
/// binds the challenge to the full verification context.
fn transcript_challenge_prebound(
    transcript: &mut crate::transcript::Transcript,
    domain: &poly::Domain,
    verifying_key: &VerifyingKey,
    t: &crate::bls12381::primitives::group::G1,
) -> Scalar {
    transcript.commit(TRANSCRIPT_MARKER);
    transcript.commit(verifying_key.digest().as_slice());
    transcript.commit(t.encode());

    let mut rng = transcript.noise(b"evaluation-point");
    loop {
        let value = sample_scalar(&mut rng);
        if domain.evaluate_vanishing(&value) != Scalar::zero() {
            return value;
        }
    }
}

fn transcript_challenge(
    transcript: &mut crate::transcript::Transcript,
    domain: &poly::Domain,
    verifying_key: &VerifyingKey,
    claim: &Claim,
    t: &crate::bls12381::primitives::group::G1,
) -> Scalar {
    transcript.commit(claim.encode());
    transcript_challenge_prebound(transcript, domain, verifying_key, t)
}
