//! Golden: Lightweight Non-Interactive Distributed Key Generation (DKG) for the BLS12-381 curve.
//!
//! This module implements the non-interactive DKG protocol from
//! "Golden: Lightweight Non-Interactive Distributed Key Generation" (Komlo, Bunz, Choi 2025).
//!
//! # Overview
//!
//! Golden achieves public verifiability using exponent Verifiable Random Functions (eVRF)
//! built on Bulletproofs. Each participant derives pairwise shared secrets via Diffie-Hellman
//! and uses these as one-time pads to encrypt shares. The correctness is proven in zero-knowledge
//! using Bulletproofs.
//!
//! # Two-Curve Architecture
//!
//! This implementation uses the paper's two-curve design:
//! - G_in = Jubjub: Used for identity keys and DH-based encryption
//! - G_out = BLS12-381 G1: Used for Feldman commitments and group keys
//!
//! The key insight is that Jubjub is embedded over BLS12-381's scalar field,
//! so Jubjub coordinates are directly usable in Bulletproofs without expensive
//! non-native field arithmetic. This reduces constraint count from ~16K+ to ~2.3K.
//!
//! # Protocol
//!
//! ## Setup
//!
//! Each participant `i` has a Jubjub key pair `(sk_i, PK_i = sk_i * G)` where
//! G is the Jubjub generator. These keys should be verified before starting the DKG.
//!
//! ## Round 0 (Contribution Phase)
//!
//! Each participant `i`:
//! 1. Samples random secret `omega_i` and creates Shamir shares with Feldman commitment
//! 2. Samples random message `msg_i`
//! 3. For each other participant `j`:
//!    - Computes DH shared secret: S = sk_i * PK_j
//!    - Extracts alpha = S.u (u-coordinate as BLS scalar)
//!    - Encrypts share: z_ij = alpha + share_ij
//! 4. Broadcasts `{msg_i, commitment, (z_ij, commitment_ij, proof_ij) for each j}`
//!
//! ## Round 1 (Verification and Recovery)
//!
//! Each participant `i`:
//! 1. For each contribution from `j`, verifies all eVRF proofs
//! 2. Verifies ciphertexts against commitments
//! 3. Decrypts own shares using DH symmetry
//! 4. Sums all decrypted shares to get final share
//! 5. Computes group public key from all commitments
//!
//! # Security Properties
//!
//! - **Public Verifiability**: Anyone can verify contributions without secret keys
//! - **Non-Interactive**: Only one broadcast round required
//! - **Zero-Knowledge**: Shared secrets are never revealed
//! - **DDH Security**: Security relies on the Decisional Diffie-Hellman assumption
//!
//! # Modules
//!
//! - `bulletproofs`: Zero-knowledge proof infrastructure (IPA, R1CS, gadgets)
//! - `jubjub`: Jubjub curve primitives for identity keys
//! - `evrf`: Exponent Verifiable Random Function using native Jubjub arithmetic
//! - `contributor`: DKG contribution generation
//! - `types`: Core types (Aggregator, Contribution, Output)
//!
//! # References
//!
//! - Golden Paper: https://eprint.iacr.org/2025/1924
//! - Bulletproofs: https://eprint.iacr.org/2017/1066
//! - Jubjub: https://z.cash/technology/jubjub/

pub mod batched;
pub mod bulletproofs;
pub mod contributor;
pub mod evrf;
pub mod jubjub;
pub mod types;

mod dleq;

pub use batched::{
    batch_verify_contributions, BatchedContribution, BatchedContributor, BatchedEncryptedShare,
};
pub use contributor::{Contribution, Contributor, EncryptedShare};
pub use dleq::{batch_verify as dleq_batch_verify, Proof as DleqProof};
pub use evrf::{evaluate as evrf_evaluate, verify as evrf_verify, BatchEVRF, EVRFOutput};
pub use jubjub::{IdentityKey, JubjubPoint, JubjubScalarWrapper};
pub use types::{Aggregator, Output};

use thiserror::Error;

/// Errors that can occur during the Golden DKG protocol.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// The participant index is out of range.
    #[error("participant index out of range")]
    ParticipantIndexOutOfRange,

    /// The contribution has an invalid commitment degree.
    #[error("commitment has wrong degree: expected {0}, got {1}")]
    CommitmentWrongDegree(u32, u32),

    /// An eVRF proof failed verification.
    #[error("eVRF proof verification failed for participant {0}")]
    EVRFProofInvalid(u32),

    /// The encrypted share failed verification against the commitment.
    #[error("encrypted share verification failed")]
    EncryptedShareInvalid,

    /// Not enough contributions to meet the threshold.
    #[error("insufficient contributions: need {0}, got {1}")]
    InsufficientContributions(usize, usize),

    /// Duplicate contribution from the same participant.
    #[error("duplicate contribution from participant {0}")]
    DuplicateContribution(u32),

    /// Invalid participant public key (e.g., identity element).
    #[error("invalid participant public key")]
    InvalidPublicKey,

    /// Share decryption produced an invalid share.
    #[error("share decryption failed")]
    ShareDecryptionFailed,

    /// The recovered share does not match the expected public key.
    #[error("share recovery mismatch")]
    ShareRecoveryMismatch,

    /// Too many participants for the protocol.
    #[error("too many participants: max {0}, got {1}")]
    TooManyParticipants(usize, usize),

    /// The number of encrypted shares does not match the number of participants.
    #[error("wrong number of encrypted shares: expected {0}, got {1}")]
    WrongNumberOfShares(usize, usize),

    /// Reshare source polynomial mismatch.
    #[error("reshare polynomial mismatch")]
    ResharePolynomialMismatch,

    /// Lagrange interpolation failed during resharing.
    #[error("interpolation failed")]
    InterpolationFailed,
}

/// Domain separation tag for DLEQ proof challenges.
pub(crate) const DST_DLEQ_CHALLENGE: &[u8] = b"GOLDEN_DKG_DLEQ_CHALLENGE_V1";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::{
        group::{Share, Scalar},
        ops::{partial_sign_proof_of_possession, threshold_signature_recover, verify_proof_of_possession},
        poly,
        variant::MinPk,
    };
    use commonware_utils::quorum;
    use rand::{rngs::StdRng, SeedableRng};

    /// Helper to create participant identities.
    fn create_identities(rng: &mut StdRng, n: usize) -> Vec<IdentityKey> {
        (0..n).map(|_| IdentityKey::generate(rng)).collect()
    }

    /// Run a complete DKG using the Aggregator.
    fn run_dkg_with_aggregator(
        seed: u64,
        n: usize,
    ) -> (poly::Public<MinPk>, Vec<Share>, Vec<IdentityKey>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = quorum(n as u32);

        // Create identities
        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Each participant creates a contribution
        let mut contributions = Vec::new();
        for (idx, identity) in identities.iter().enumerate() {
            let (_, contribution) = Contributor::<MinPk>::new(
                &mut rng,
                identity_keys.clone(),
                idx as u32,
                identity,
                None,
            );
            contributions.push((idx as u32, contribution));
        }

        // Use Aggregator to collect and verify contributions
        let mut aggregator = Aggregator::<MinPk>::new(identity_keys, threshold, 1);
        for (idx, contribution) in contributions {
            aggregator.add(idx, contribution).expect("failed to add contribution");
        }

        // Each participant finalizes and recovers their share
        let mut shares = Vec::new();
        let mut group_public = None;

        for (idx, identity) in identities.iter().enumerate() {
            let output = aggregator
                .finalize(idx as u32, identity)
                .expect("failed to finalize");

            shares.push(output.share);

            if let Some(ref expected) = group_public {
                assert_eq!(expected, &output.public, "group polynomial mismatch");
            } else {
                group_public = Some(output.public);
            }
        }

        (group_public.unwrap(), shares, identities)
    }

    /// Run a reshare using the Aggregator.
    fn run_reshare_with_aggregator(
        seed: u64,
        previous_public: &poly::Public<MinPk>,
        previous_shares: &[Share],
        identities: &[IdentityKey],
    ) -> (poly::Public<MinPk>, Vec<Share>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let n = identities.len() as u32;
        let threshold = quorum(n);

        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Each participant creates a contribution using their previous share
        let mut contributions = Vec::new();
        for (idx, identity) in identities.iter().enumerate() {
            let prev_share = previous_shares[idx].clone();
            let (_, contribution) = Contributor::<MinPk>::new(
                &mut rng,
                identity_keys.clone(),
                idx as u32,
                identity,
                Some(prev_share),
            );
            contributions.push((idx as u32, contribution));
        }

        // Use Aggregator for resharing
        let mut aggregator =
            Aggregator::<MinPk>::new_reshare(identity_keys, threshold, previous_public.clone(), 1);
        for (idx, contribution) in contributions {
            aggregator.add(idx, contribution).expect("failed to add contribution");
        }

        // Each participant finalizes
        let mut shares = Vec::new();
        let mut group_public = None;

        for (idx, identity) in identities.iter().enumerate() {
            let output = aggregator
                .finalize(idx as u32, identity)
                .expect("failed to finalize reshare");

            shares.push(output.share);

            if let Some(ref expected) = group_public {
                assert_eq!(expected, &output.public, "group polynomial mismatch in reshare");
            } else {
                group_public = Some(output.public);
            }
        }

        (group_public.unwrap(), shares)
    }

    #[test]
    fn test_basic_dkg() {
        let (public, shares, _) = run_dkg_with_aggregator(42, 5);

        // Verify by creating a threshold signature
        let threshold = quorum(5);
        let partials: Vec<_> = shares
            .iter()
            .map(|share| partial_sign_proof_of_possession::<MinPk>(&public, share))
            .collect();

        let signature = threshold_signature_recover::<MinPk, _>(threshold, &partials)
            .expect("failed to recover signature");

        let public_key = poly::public::<MinPk>(&public);
        verify_proof_of_possession::<MinPk>(public_key, &signature)
            .expect("proof of possession verification failed");
    }

    #[test]
    fn test_dkg_determinism() {
        let (public1, _, _) = run_dkg_with_aggregator(123, 5);
        let (public2, _, _) = run_dkg_with_aggregator(123, 5);
        assert_eq!(public1, public2, "DKG should be deterministic with same seed");

        let (public3, _, _) = run_dkg_with_aggregator(456, 5);
        assert_ne!(public1, public3, "different seeds should produce different results");
    }

    #[test]
    fn test_dkg_varying_sizes() {
        for n in [3, 4, 5, 7] {
            let (public, shares, _) = run_dkg_with_aggregator(n as u64, n);
            let threshold = quorum(n as u32);

            // Verify threshold signature works
            let partials: Vec<_> = shares
                .iter()
                .take(threshold as usize)
                .map(|share| partial_sign_proof_of_possession::<MinPk>(&public, share))
                .collect();

            let signature = threshold_signature_recover::<MinPk, _>(threshold, &partials)
                .expect("failed to recover signature");

            let public_key = poly::public::<MinPk>(&public);
            verify_proof_of_possession::<MinPk>(public_key, &signature)
                .expect("proof of possession verification failed");
        }
    }

    #[test]
    fn test_reshare_preserves_public_key() {
        // Run initial DKG
        let (public1, shares1, identities) = run_dkg_with_aggregator(42, 5);

        // Run reshare
        let (public2, shares2) =
            run_reshare_with_aggregator(100, &public1, &shares1, &identities);

        // The public key (constant term) should be the same
        assert_eq!(
            public1.constant(),
            public2.constant(),
            "reshare should preserve public key"
        );

        // Verify threshold signature works with new shares
        let threshold = quorum(5);
        let partials: Vec<_> = shares2
            .iter()
            .map(|share| partial_sign_proof_of_possession::<MinPk>(&public2, share))
            .collect();

        let signature = threshold_signature_recover::<MinPk, _>(threshold, &partials)
            .expect("failed to recover signature after reshare");

        let public_key = poly::public::<MinPk>(&public2);
        verify_proof_of_possession::<MinPk>(public_key, &signature)
            .expect("proof of possession verification failed after reshare");
    }

    #[test]
    fn test_multiple_reshares() {
        // Run initial DKG
        let (public1, shares1, identities) = run_dkg_with_aggregator(42, 5);
        let original_public_key = *public1.constant();

        // Run multiple reshares
        let (public2, shares2) =
            run_reshare_with_aggregator(100, &public1, &shares1, &identities);
        assert_eq!(*public2.constant(), original_public_key);

        let (public3, shares3) =
            run_reshare_with_aggregator(200, &public2, &shares2, &identities);
        assert_eq!(*public3.constant(), original_public_key);

        let (public4, _shares4) =
            run_reshare_with_aggregator(300, &public3, &shares3, &identities);
        assert_eq!(*public4.constant(), original_public_key);
    }

    #[test]
    fn test_dleq_proof_standalone() {
        use crate::bls12381::primitives::group::{Element, G1};

        let mut rng = StdRng::seed_from_u64(99);

        // Create a secret and two base points
        let secret = Scalar::from_rand(&mut rng);
        let g = G1::one();
        let mut h = G1::one();
        let h_scalar = Scalar::from_rand(&mut rng);
        h.mul(&h_scalar);

        // Compute public values
        let mut a = g;
        a.mul(&secret);
        let mut b = h;
        b.mul(&secret);

        // Generate proof
        let proof = dleq::Proof::create(&mut rng, &secret, &g, &h, &a, &b);

        // Verify proof
        assert!(proof.verify(&g, &h, &a, &b), "valid DLEQ proof should verify");

        // Wrong secret should fail
        let wrong_secret = Scalar::from_rand(&mut rng);
        let mut wrong_a = g;
        wrong_a.mul(&wrong_secret);
        assert!(!proof.verify(&g, &h, &wrong_a, &b), "wrong A should fail");
    }

    #[test]
    fn test_aggregator_duplicate_contribution() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;
        let threshold = quorum(n as u32);

        let identities = create_identities(&mut rng, n as usize);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Create a contribution
        let (_, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        // Create aggregator and add contribution
        let mut aggregator = Aggregator::<MinPk>::new(identity_keys, threshold, 1);
        aggregator.add(0, contribution.clone()).expect("first add should succeed");

        // Try to add duplicate
        let result = aggregator.add(0, contribution);
        assert!(
            matches!(result, Err(Error::DuplicateContribution(0))),
            "duplicate contribution should fail"
        );
    }

    #[test]
    fn test_aggregator_insufficient_contributions() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;
        let threshold = quorum(n as u32);

        let identities = create_identities(&mut rng, n as usize);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Create only one contribution
        let (_, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        // Create aggregator and add only one contribution
        let mut aggregator = Aggregator::<MinPk>::new(identity_keys, threshold, 1);
        aggregator.add(0, contribution).expect("add should succeed");

        // Try to finalize with insufficient contributions
        let result = aggregator.finalize(0, &identities[0]);
        assert!(
            matches!(result, Err(Error::InsufficientContributions(_, 1))),
            "should fail with insufficient contributions"
        );
    }
}
