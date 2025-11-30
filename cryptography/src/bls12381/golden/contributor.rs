//! Contributor role for the Golden DKG protocol using two-curve architecture.
//!
//! This implements the Golden DKG paper's two-curve design:
//! - G_in = Jubjub: Used for identity keys and DH-based encryption
//! - G_out = BLS12-381 G1: Used for Feldman commitments
//!
//! The key insight is that Jubjub's base field equals BLS12-381's scalar field,
//! so the DH shared secret's u-coordinate can be directly used as a BLS scalar
//! for encrypting shares.

use super::{
    evrf::{self, EVRFOutput},
    jubjub::{IdentityKey, JubjubPoint},
};
use crate::bls12381::primitives::{
    group::{Element, Scalar, Share, G1},
    poly,
    variant::Variant,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_utils::quorum;
use core::num::NonZeroU32;
use rand_core::CryptoRngCore;

/// An encrypted share with eVRF proof.
///
/// Uses the two-curve architecture:
/// - alpha is derived from Jubjub DH (native arithmetic)
/// - commitment is on BLS12-381 G1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedShare {
    /// The encrypted share value: share + alpha.
    pub value: Scalar,
    /// The eVRF output (commitment and proof).
    pub evrf_output: EVRFOutput,
}

impl Write for EncryptedShare {
    fn write(&self, buf: &mut impl BufMut) {
        self.value.write(buf);
        self.evrf_output.write(buf);
    }
}

impl Read for EncryptedShare {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let value = Scalar::read(buf)?;
        let evrf_output = EVRFOutput::read(buf)?;
        Ok(Self { value, evrf_output })
    }
}

impl commonware_codec::EncodeSize for EncryptedShare {
    fn encode_size(&self) -> usize {
        self.value.encode_size() + self.evrf_output.encode_size()
    }
}

/// A contribution from a single participant in the Golden DKG.
///
/// This contains:
/// - A random message for domain separation
/// - A Feldman commitment on G_out (BLS12-381 G1)
/// - Encrypted shares with eVRF proofs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution<V: Variant> {
    /// Random message for eVRF domain separation.
    pub msg: Vec<u8>,
    /// The Feldman commitment to the secret polynomial (on G_out).
    pub commitment: poly::Public<V>,
    /// Encrypted shares for each participant.
    pub encrypted_shares: Vec<EncryptedShare>,
}

/// Maximum message size for eVRF (32 bytes is sufficient for random nonces).
const MAX_MSG_SIZE: usize = 64;

impl<V: Variant> Write for Contribution<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.msg.write(buf);
        self.commitment.write(buf);
        self.encrypted_shares.write(buf);
    }
}

impl<V: Variant> Read for Contribution<V> {
    type Cfg = (NonZeroU32, NonZeroU32); // (threshold, n_participants)

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let (threshold, n) = cfg;
        let n_usize = n.get() as usize;
        let msg = Vec::<u8>::read_cfg(buf, &(RangeCfg::from(0..=MAX_MSG_SIZE), ()))?;
        let commitment =
            poly::Public::<V>::read_cfg(buf, &RangeCfg::from(*threshold..=*threshold))?;
        let encrypted_shares = Vec::<EncryptedShare>::read_cfg(
            buf,
            &(RangeCfg::from(n_usize..=n_usize), ()),
        )?;
        Ok(Self {
            msg,
            commitment,
            encrypted_shares,
        })
    }
}

impl<V: Variant> commonware_codec::EncodeSize for Contribution<V> {
    fn encode_size(&self) -> usize {
        self.msg.encode_size() + self.commitment.encode_size() + self.encrypted_shares.encode_size()
    }
}

/// A contributor in the Golden DKG protocol using two-curve architecture.
///
/// Uses Jubjub for identity keys (G_in) and BLS12-381 G1 for commitments (G_out).
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
    /// * `identity_keys` - Jubjub public keys of all participants (G_in)
    /// * `index` - This contributor's index in the participant list
    /// * `identity` - This contributor's Jubjub identity key
    /// * `previous_share` - If resharing, the share from the previous DKG
    ///
    /// # Returns
    ///
    /// A tuple of `(Contributor, Contribution)`.
    ///
    /// # Panics
    ///
    /// Panics if `index >= identity_keys.len()` or if `identity_keys` is empty.
    pub fn new<R: CryptoRngCore>(
        rng: &mut R,
        identity_keys: Vec<JubjubPoint>,
        index: u32,
        identity: &IdentityKey,
        previous_share: Option<Share>,
    ) -> (Self, Contribution<V>) {
        let n = identity_keys.len() as u32;
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

        // Commit to the polynomial (on G_out = BLS12-381)
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

        // Generate encrypted shares with eVRF proofs
        let mut encrypted_shares = Vec::with_capacity(n as usize);

        for (recipient_idx, share) in shares.iter().enumerate() {
            // Get recipient's Jubjub public key
            let recipient_pk = &identity_keys[recipient_idx];

            // Evaluate eVRF: alpha from DH on Jubjub
            let (alpha, evrf_output) = evrf::evaluate(identity, recipient_pk, &msg);

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

impl<V: Variant> Contribution<V> {
    /// Verifies this contribution.
    ///
    /// # Arguments
    ///
    /// * `identity_keys` - The Jubjub public keys of all participants
    /// * `dealer_index` - The index of the dealer who created this contribution
    /// * `threshold` - The threshold for the DKG
    /// * `previous` - If resharing, the previous group polynomial
    ///
    /// # Returns
    ///
    /// `Ok(())` if the contribution is valid, `Err` otherwise.
    pub fn verify(
        &self,
        identity_keys: &[JubjubPoint],
        dealer_index: u32,
        threshold: u32,
        previous: Option<&poly::Public<V>>,
    ) -> Result<(), super::Error> {
        let n = identity_keys.len();
        let dealer_idx = dealer_index as usize;

        // Check dealer index is valid
        if dealer_idx >= n {
            return Err(super::Error::ParticipantIndexOutOfRange);
        }

        // Check commitment degree
        let expected_degree = threshold - 1;
        if self.commitment.degree() != expected_degree {
            return Err(super::Error::CommitmentWrongDegree(
                expected_degree,
                self.commitment.degree(),
            ));
        }

        // Check reshare constraint if applicable
        if let Some(prev) = previous {
            let expected_constant = prev.evaluate(dealer_index).value;
            if *self.commitment.constant() != expected_constant {
                return Err(super::Error::ResharePolynomialMismatch);
            }
        }

        // Check number of encrypted shares
        if self.encrypted_shares.len() != n {
            return Err(super::Error::WrongNumberOfShares(n, self.encrypted_shares.len()));
        }

        // Get dealer's Jubjub public key
        let dealer_pk = &identity_keys[dealer_idx];

        // Verify each encrypted share
        for (recipient_idx, encrypted) in self.encrypted_shares.iter().enumerate() {
            let recipient_idx = recipient_idx as u32;
            let recipient_pk = &identity_keys[recipient_idx as usize];

            // Verify eVRF proof
            if !evrf::verify(dealer_pk, recipient_pk, &self.msg, &encrypted.evrf_output) {
                return Err(super::Error::EVRFProofInvalid(recipient_idx));
            }

            // Verify encryption correctness:
            // Given: z = share + alpha (encrypted value)
            // We check: g^z == g^share * g^alpha == C * A
            // Where: C = commitment.evaluate(recipient) = g^share
            //        A = evrf_output.commitment = g^alpha

            // Compute g^z
            let mut g_z = V::Public::one();
            g_z.mul(&encrypted.value);

            // Get C = g^share from the Feldman commitment
            let commitment_eval = self.commitment.evaluate(recipient_idx).value;

            // Get A = g^alpha from the eVRF output
            // Both are on BLS12-381 G1, so direct conversion works for MinPk
            let alpha_commit = &encrypted.evrf_output.commitment;
            let alpha_commit_public = convert_g1_to_public::<V>(alpha_commit)?;

            // Compute expected: C * A = g^share * g^alpha
            let mut expected = commitment_eval;
            expected.add(&alpha_commit_public);

            // Check: g^z == C * A
            if g_z != expected {
                return Err(super::Error::EncryptedShareInvalid);
            }
        }

        Ok(())
    }
}

/// Convert G1 to the variant's public type.
fn convert_g1_to_public<V: Variant>(point: &G1) -> Result<V::Public, super::Error> {
    use commonware_codec::{DecodeExt, Encode};

    let encoded = point.encode();
    if encoded.len() == V::Public::SIZE {
        V::Public::decode(encoded).map_err(|_| super::Error::InvalidPublicKey)
    } else {
        // Size mismatch - this is MinSig variant which uses G2 for public keys
        Err(super::Error::InvalidPublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::variant::MinPk;
    use rand::{rngs::StdRng, SeedableRng};

    fn create_identities(rng: &mut StdRng, n: usize) -> Vec<IdentityKey> {
        (0..n).map(|_| IdentityKey::generate(rng)).collect()
    }

    #[test]
    fn test_contributor_creation() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Create contributor
        let (contributor, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        // Check contribution structure
        let threshold = quorum(n as u32);
        assert_eq!(contribution.commitment.degree(), threshold - 1);
        assert_eq!(contribution.encrypted_shares.len(), n);
        assert!(!contribution.msg.is_empty());
        assert_eq!(contributor.shares().len(), n);
    }

    #[test]
    fn test_contribution_verification() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Create contribution
        let (_, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        // Verify contribution
        let threshold = quorum(n as u32);
        let result = contribution.verify(&identity_keys, 0, threshold, None);
        assert!(result.is_ok(), "verification failed: {:?}", result);
    }

    #[test]
    fn test_share_decryption() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 5;

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Create contribution from participant 0
        let (contributor, contribution) = Contributor::<MinPk>::new(
            &mut rng,
            identity_keys.clone(),
            0,
            &identities[0],
            None,
        );

        // Each participant should be able to decrypt their share
        for (recipient_idx, recipient_identity) in identities.iter().enumerate() {
            let encrypted = &contribution.encrypted_shares[recipient_idx];

            // Compute alpha using DH symmetry
            let dealer_pk = &identity_keys[0];
            let alpha = recipient_identity.compute_alpha(dealer_pk);

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

        let identities = create_identities(&mut rng, n);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();
        let threshold = quorum(n as u32);

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

            // Verify each contribution
            let result = contribution.verify(&identity_keys, idx as u32, threshold, None);
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

        // Each participant recovers their share
        for (recipient_idx, recipient_identity) in identities.iter().enumerate() {
            let mut share_scalar = Scalar::zero();

            for (dealer_idx, contribution) in contributions.iter().enumerate() {
                let encrypted = &contribution.encrypted_shares[recipient_idx];

                // Compute alpha using DH symmetry
                let dealer_pk = &identity_keys[dealer_idx];
                let alpha = recipient_identity.compute_alpha(dealer_pk);

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
