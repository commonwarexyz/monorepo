//! Golden: Lightweight Non-Interactive Distributed Key Generation (DKG) for the BLS12-381 curve.
//!
//! This module implements a non-interactive DKG protocol based on the "Golden" construction
//! from "Golden: Lightweight Non-Interactive Distributed Key Generation" (Komlo, Bunz, Choi 2025).
//!
//! # Overview
//!
//! Golden achieves public verifiability in a lightweight manner using Non-Interactive Key Exchange
//! (NIKE) based on Diffie-Hellman. Each participant derives pairwise shared secrets with all other
//! participants and uses these as one-time pads to encrypt shares. The correctness of these
//! encrypted shares is publicly verifiable through Discrete Log Equality (DLEQ) proofs.
//!
//! # Protocol
//!
//! ## Setup
//!
//! Each participant `i` has a key pair `(sk_i, PK_i = sk_i * G)` where `G` is the generator.
//! These keys should be verified (e.g., via proof-of-possession) before starting the DKG.
//!
//! ## Contribution Phase
//!
//! Each participant `i`:
//! 1. Generates a random polynomial `p_i(x)` of degree `t-1`
//! 2. Computes Feldman commitment `C_i = [p_i(0)*G, p_i(1)*G, ..., p_i(t-1)*G]`
//! 3. For each other participant `j`:
//!    - Computes DH shared secret: `S_ij = sk_i * PK_j`
//!    - Derives encryption key: `k_ij = H(S_ij, i, j)`
//!    - Encrypts share: `e_ij = p_i(j) + k_ij`
//!    - Generates DLEQ proof proving `log_G(PK_i) = log_{PK_j}(S_ij)`
//! 4. Broadcasts `(C_i, {e_ij, proof_ij})` to all participants
//!
//! ## Verification Phase
//!
//! Any observer can verify a contribution by:
//! 1. Checking the DLEQ proofs for each encrypted share
//! 2. Verifying that the encrypted share, when decrypted with the derived key,
//!    yields a value consistent with the commitment
//!
//! ## Recovery Phase
//!
//! Each participant `j` recovers their share by:
//! 1. For each valid contribution `i`, computing the shared secret and decrypting their share
//! 2. Summing all decrypted shares to get their final share
//! 3. Summing all commitments to get the group public polynomial
//!
//! # Security Properties
//!
//! - **Public Verifiability**: Anyone can verify contributions without secret keys
//! - **Non-Interactive**: Only one broadcast round required
//! - **Discrete Log Security**: Security relies only on DL hardness (no pairings needed for verification)
//!
//! # Caveats
//!
//! ## Non-Uniform Distribution
//!
//! Like other Feldman-style DKGs, the generated secret is not uniformly random.
//! An adversary can introduce a small bias. For threshold signatures and encryption,
//! this does not affect security.
//!
//! # Example
//!
//! ```ignore
//! use commonware_cryptography::bls12381::golden::{Contributor, Aggregator, Output};
//! use commonware_cryptography::bls12381::primitives::variant::MinSig;
//!
//! // Setup: each participant has a key pair
//! let participants: Vec<G1> = /* public keys */;
//! let my_index = 0;
//! let my_secret_key = /* secret key */;
//!
//! // Generate contribution
//! let (contributor, contribution) = Contributor::<MinSig>::new(
//!     &mut rng,
//!     participants.clone(),
//!     my_index,
//!     &my_secret_key,
//! );
//!
//! // Broadcast contribution...
//!
//! // Aggregate all contributions
//! let mut aggregator = Aggregator::<MinSig>::new(participants.clone(), threshold);
//! for (idx, contribution) in contributions {
//!     aggregator.add(idx, contribution)?;
//! }
//!
//! // Finalize and recover share
//! let output = aggregator.finalize(my_index, &my_secret_key)?;
//! ```

mod contributor;
mod dleq;
mod types;

pub use contributor::Contributor;
pub use dleq::{Proof as DleqProof, batch_verify as dleq_batch_verify};
pub use types::{Aggregator, Contribution, EncryptedShare, Output};

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

    /// A DLEQ proof failed verification.
    #[error("DLEQ proof verification failed for participant {0}")]
    DleqProofInvalid(u32),

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

/// Domain separation tag for deriving encryption keys from DH shared secrets.
const DST_ENCRYPTION_KEY: &[u8] = b"GOLDEN_DKG_ENCRYPTION_KEY_V1";

/// Domain separation tag for DLEQ proof challenges.
pub(crate) const DST_DLEQ_CHALLENGE: &[u8] = b"GOLDEN_DKG_DLEQ_CHALLENGE_V1";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::{
        group::{Element, G1, Scalar, Share},
        ops::{partial_sign_proof_of_possession, threshold_signature_recover, verify_proof_of_possession},
        poly,
        variant::MinPk,
    };
    use commonware_utils::quorum;
    use rand::{rngs::StdRng, SeedableRng};

    /// Helper to create participant key pairs for MinPk variant.
    fn create_participants(rng: &mut StdRng, n: usize) -> Vec<(Scalar, G1)> {
        (0..n)
            .map(|_| {
                let sk = Scalar::from_rand(rng);
                let mut pk = G1::one();
                pk.mul(&sk);
                (sk, pk)
            })
            .collect()
    }

    /// Run a complete DKG using the Aggregator.
    fn run_dkg_with_aggregator(
        seed: u64,
        n: usize,
    ) -> (poly::Public<MinPk>, Vec<Share>, Vec<(Scalar, G1)>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = quorum(n as u32);

        // Create participants
        let participants = create_participants(&mut rng, n);
        let public_keys: Vec<G1> = participants.iter().map(|(_, pk)| *pk).collect();

        // Each participant creates a contribution
        let mut contributions = Vec::new();
        for (idx, (sk, _)) in participants.iter().enumerate() {
            let (_, contribution) = Contributor::<MinPk>::new(
                &mut rng,
                public_keys.clone(),
                idx as u32,
                sk,
                None,
            );
            contributions.push((idx as u32, contribution));
        }

        // Use Aggregator to collect and verify contributions
        let mut aggregator = Aggregator::<MinPk>::new(public_keys, threshold, 1);
        for (idx, contribution) in contributions {
            aggregator.add(idx, contribution).expect("failed to add contribution");
        }

        // Each participant finalizes and recovers their share
        let mut shares = Vec::new();
        let mut group_public = None;

        for (idx, (sk, _)) in participants.iter().enumerate() {
            let output = aggregator
                .finalize(idx as u32, sk)
                .expect("failed to finalize");

            shares.push(output.share);

            if let Some(ref expected) = group_public {
                assert_eq!(expected, &output.public, "group polynomial mismatch");
            } else {
                group_public = Some(output.public);
            }
        }

        (group_public.unwrap(), shares, participants)
    }

    /// Run a reshare using the Aggregator.
    fn run_reshare_with_aggregator(
        seed: u64,
        previous_public: &poly::Public<MinPk>,
        previous_shares: &[Share],
        participants: &[(Scalar, G1)],
    ) -> (poly::Public<MinPk>, Vec<Share>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let n = participants.len() as u32;
        let threshold = quorum(n);

        let public_keys: Vec<G1> = participants.iter().map(|(_, pk)| *pk).collect();

        // Each participant creates a contribution using their previous share
        let mut contributions = Vec::new();
        for (idx, (sk, _)) in participants.iter().enumerate() {
            let prev_share = previous_shares[idx].clone();
            let (_, contribution) = Contributor::<MinPk>::new(
                &mut rng,
                public_keys.clone(),
                idx as u32,
                sk,
                Some(prev_share),
            );
            contributions.push((idx as u32, contribution));
        }

        // Use Aggregator for resharing
        let mut aggregator =
            Aggregator::<MinPk>::new_reshare(public_keys, threshold, previous_public.clone(), 1);
        for (idx, contribution) in contributions {
            aggregator.add(idx, contribution).expect("failed to add contribution");
        }

        // Each participant finalizes
        let mut shares = Vec::new();
        let mut group_public = None;

        for (idx, (sk, _)) in participants.iter().enumerate() {
            let output = aggregator
                .finalize(idx as u32, sk)
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
        for n in [3, 4, 5, 7, 10] {
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
        let (public1, shares1, participants) = run_dkg_with_aggregator(42, 5);

        // Run reshare
        let (public2, shares2) =
            run_reshare_with_aggregator(100, &public1, &shares1, &participants);

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
        let (public1, shares1, participants) = run_dkg_with_aggregator(42, 5);
        let original_public_key = *public1.constant();

        // Run multiple reshares
        let (public2, shares2) =
            run_reshare_with_aggregator(100, &public1, &shares1, &participants);
        assert_eq!(*public2.constant(), original_public_key);

        let (public3, shares3) =
            run_reshare_with_aggregator(200, &public2, &shares2, &participants);
        assert_eq!(*public3.constant(), original_public_key);

        let (public4, _shares4) =
            run_reshare_with_aggregator(300, &public3, &shares3, &participants);
        assert_eq!(*public4.constant(), original_public_key);
    }

    #[test]
    fn test_dleq_proof_standalone() {
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

        let participants = create_participants(&mut rng, n as usize);
        let public_keys: Vec<G1> = participants.iter().map(|(_, pk)| *pk).collect();

        // Create a contribution
        let (_, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            public_keys.clone(),
            0,
            &participants[0].0,
            None,
        );

        // Create aggregator and add contribution
        let mut aggregator = Aggregator::<MinPk>::new(public_keys, threshold, 1);
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

        let participants = create_participants(&mut rng, n as usize);
        let public_keys: Vec<G1> = participants.iter().map(|(_, pk)| *pk).collect();

        // Create only one contribution
        let (_, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            public_keys.clone(),
            0,
            &participants[0].0,
            None,
        );

        // Create aggregator and add only one contribution
        let mut aggregator = Aggregator::<MinPk>::new(public_keys, threshold, 1);
        aggregator.add(0, contribution).expect("add should succeed");

        // Try to finalize with insufficient contributions
        let result = aggregator.finalize(0, &participants[0].0);
        assert!(
            matches!(result, Err(Error::InsufficientContributions(_, 1))),
            "should fail with insufficient contributions"
        );
    }
}
