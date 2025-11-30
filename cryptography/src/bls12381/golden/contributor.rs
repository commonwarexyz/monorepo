//! Contributor role for the Golden DKG protocol.
//!
//! A contributor generates a secret polynomial, creates a Feldman commitment,
//! encrypts shares for each participant using eVRF-derived keys, and provides
//! eVRF proofs for public verification.
//!
//! Per the Golden DKG paper:
//! - Each participant samples a random message `msg` for domain separation
//! - For each recipient j: `(alpha_ij, _, proof_ij) = eVRF.Evaluate(sk_i, (msg, PK_j))`
//! - Encrypts share: `z_ij = alpha_ij + share_ij`

use super::{
    evrf,
    types::{Contribution, EncryptedShare},
};
use crate::bls12381::primitives::{
    group::{Element, Scalar, Share, G1},
    poly,
    variant::Variant,
};
use commonware_codec::{DecodeExt, Encode, FixedSize};
use commonware_utils::quorum;
use rand_core::CryptoRngCore;

/// A contributor in the Golden DKG protocol.
///
/// The contributor generates shares for all participants and creates
/// eVRF proofs to allow public verification.
pub struct Contributor<V: Variant> {
    /// The contributor's index in the participant list.
    index: u32,
    /// The secret polynomial (kept for potential future use in resharing).
    #[allow(dead_code)]
    secret: poly::Private,
    /// The generated shares (one for each participant).
    shares: Vec<Share>,
    /// Marker for the variant.
    _variant: std::marker::PhantomData<V>,
}

impl<V: Variant> Contributor<V> {
    /// Creates a new contributor and generates their contribution.
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator
    /// * `public_keys` - Public keys of all participants (must be on G1 for MinPk variant)
    /// * `index` - This contributor's index in the participant list
    /// * `secret_key` - This contributor's secret key
    /// * `previous_share` - If resharing, the share from the previous DKG
    ///
    /// # Returns
    ///
    /// A tuple of `(Contributor, Contribution)` where the contribution should be broadcast.
    ///
    /// # Panics
    ///
    /// Panics if `index >= public_keys.len()` or if `public_keys` is empty.
    pub fn new<R: CryptoRngCore>(
        rng: &mut R,
        public_keys: Vec<V::Public>,
        index: u32,
        secret_key: &Scalar,
        previous_share: Option<Share>,
    ) -> (Self, Contribution<V>) {
        let n = public_keys.len() as u32;
        let threshold = quorum(n);

        assert!(
            index < n,
            "contributor index {} out of range for {} participants",
            index,
            n
        );

        // Generate secret polynomial
        let secret = if let Some(ref prev) = previous_share {
            // For resharing, set the constant term to the previous share
            poly::new_with_constant(threshold - 1, &mut *rng, prev.private.clone())
        } else {
            poly::new_from(threshold - 1, &mut *rng)
        };

        // Commit to the polynomial
        let commitment = poly::Public::<V>::commit(secret.clone());

        // Generate shares for all participants
        let shares: Vec<Share> = (0..n)
            .map(|i| {
                let eval = secret.evaluate(i);
                Share {
                    index: eval.index,
                    private: eval.value,
                }
            })
            .collect();

        // Generate random message for eVRF domain separation
        let mut msg = [0u8; 32];
        rng.fill_bytes(&mut msg);

        // Get my public key as G1
        let mut my_pk_g1 = G1::one();
        my_pk_g1.mul(secret_key);

        // Generate encrypted shares with eVRF proofs
        let mut encrypted_shares = Vec::with_capacity(n as usize);

        for (recipient_idx, share) in shares.iter().enumerate() {
            // Get recipient's public key and convert to G1
            let recipient_pk = &public_keys[recipient_idx];
            let recipient_pk_g1 = g1_from_public::<V>(recipient_pk);

            // Evaluate eVRF: (alpha, evrf_output) = eVRF.Evaluate(sk, (msg, recipient_pk))
            // alpha is the encryption key (kept secret), evrf_output is public
            let (alpha, evrf_output) = evrf::evaluate(secret_key, &my_pk_g1, &recipient_pk_g1, &msg);

            // Encrypt share: encrypted = share + alpha
            let mut encrypted_value = share.private.clone();
            encrypted_value.add(&alpha);

            encrypted_shares.push(EncryptedShare {
                value: encrypted_value,
                evrf_output,
            });
        }

        let contribution = Contribution {
            msg: msg.to_vec(),
            commitment,
            encrypted_shares,
        };

        let contributor = Self {
            index,
            secret,
            shares,
            _variant: std::marker::PhantomData,
        };

        (contributor, contribution)
    }

    /// Returns the contributor's index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Returns a reference to the generated shares.
    pub fn shares(&self) -> &[Share] {
        &self.shares
    }

    /// Consumes the contributor and returns the shares.
    pub fn into_shares(self) -> Vec<Share> {
        self.shares
    }
}

/// Convert a variant public key to G1.
///
/// For MinPk variant, public keys are on G1.
/// For MinSig variant, this would panic since eVRF requires G1 points.
fn g1_from_public<V: Variant>(pk: &V::Public) -> G1 {
    // Encode and decode as G1
    let encoded = pk.encode();
    if encoded.len() == G1::SIZE {
        G1::decode(encoded).expect("valid G1 encoding")
    } else {
        // MinSig variant has public keys on G2, which we don't support
        // since eVRF operates on G1 points
        panic!("Golden DKG currently only supports MinPk variant (G1 public keys)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::variant::MinPk;
    use rand::{rngs::StdRng, SeedableRng};

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

    #[test]
    fn test_contributor_creation() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let participants = create_participants(&mut rng, n);
        let public_keys: Vec<_> = participants.iter().map(|(_, pk)| *pk).collect();

        // Create contributor
        let (contributor, contribution) =
            Contributor::<MinPk>::new(&mut rng, public_keys.clone(), 0, &participants[0].0, None);

        // Check contribution structure
        let threshold = quorum(n as u32);
        assert_eq!(contribution.commitment.degree(), threshold - 1);
        assert_eq!(contribution.encrypted_shares.len(), n);
        assert!(!contribution.msg.is_empty(), "message should be set");

        // Check shares
        assert_eq!(contributor.shares().len(), n);
    }

    #[test]
    fn test_contribution_verification() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let participants = create_participants(&mut rng, n);
        let public_keys: Vec<_> = participants.iter().map(|(_, pk)| *pk).collect();

        // Create contribution
        let (_, contribution) =
            Contributor::<MinPk>::new(&mut rng, public_keys.clone(), 0, &participants[0].0, None);

        // Verify contribution (now uses eVRF verification)
        let threshold = quorum(n as u32);
        let result = contribution.verify(&public_keys, 0, threshold, None);
        assert!(result.is_ok(), "verification failed: {:?}", result);
    }

    #[test]
    fn test_share_decryption_with_evrf() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let participants = create_participants(&mut rng, n);
        let public_keys: Vec<_> = participants.iter().map(|(_, pk)| *pk).collect();

        // Create contribution from participant 0
        let (contributor, contribution) =
            Contributor::<MinPk>::new(&mut rng, public_keys.clone(), 0, &participants[0].0, None);

        // Each participant should be able to decrypt their share using eVRF symmetry
        for (recipient_idx, (recipient_sk, recipient_pk)) in participants.iter().enumerate() {
            let encrypted = &contribution.encrypted_shares[recipient_idx];

            // Use eVRF symmetry: recipient evaluates eVRF to get same alpha as dealer
            let dealer_pk = public_keys[0];
            let (alpha, _) = evrf::evaluate(recipient_sk, recipient_pk, &dealer_pk, &contribution.msg);

            // Decrypt: share = encrypted - alpha
            let mut decrypted = encrypted.value.clone();
            decrypted.sub(&alpha);

            // Verify decrypted share matches original
            let expected = &contributor.shares()[recipient_idx];
            assert_eq!(
                decrypted, expected.private,
                "decrypted share mismatch for recipient {recipient_idx}"
            );
        }
    }

    #[test]
    fn test_multiple_contributors() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let participants = create_participants(&mut rng, n);
        let public_keys: Vec<_> = participants.iter().map(|(_, pk)| *pk).collect();
        let threshold = quorum(n as u32);

        // Each participant creates a contribution
        let mut contributions = Vec::new();
        for (idx, (sk, _)) in participants.iter().enumerate() {
            let (_, contribution) =
                Contributor::<MinPk>::new(&mut rng, public_keys.clone(), idx as u32, sk, None);

            // Verify each contribution (now uses eVRF verification)
            let result = contribution.verify(&public_keys, idx as u32, threshold, None);
            assert!(
                result.is_ok(),
                "contribution {} verification failed: {:?}",
                idx,
                result
            );

            contributions.push(contribution);
        }

        // Aggregate contributions and recover shares
        let mut group_public = poly::Public::<MinPk>::zero();
        for contribution in &contributions {
            group_public.add(&contribution.commitment);
        }

        // Each participant recovers their share using eVRF symmetry
        for (recipient_idx, (recipient_sk, recipient_pk)) in participants.iter().enumerate() {
            let mut share_scalar = Scalar::zero();

            for (dealer_idx, contribution) in contributions.iter().enumerate() {
                let encrypted = &contribution.encrypted_shares[recipient_idx];

                // Use eVRF symmetry: recipient evaluates eVRF to get same alpha as dealer
                let dealer_pk = public_keys[dealer_idx];
                let (alpha, _) = evrf::evaluate(recipient_sk, recipient_pk, &dealer_pk, &contribution.msg);

                // Decrypt
                let mut decrypted = encrypted.value.clone();
                decrypted.sub(&alpha);

                share_scalar.add(&decrypted);
            }

            // Verify recovered share
            let share = Share {
                index: recipient_idx as u32,
                private: share_scalar,
            };
            let expected_public = group_public.evaluate(recipient_idx as u32).value;
            let actual_public = share.public::<MinPk>();
            assert_eq!(
                expected_public, actual_public,
                "share {} public key mismatch",
                recipient_idx
            );
        }
    }
}
