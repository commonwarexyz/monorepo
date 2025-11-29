//! Types for the Golden DKG protocol.

use super::{dleq::Proof as DleqProof, Error, DST_ENCRYPTION_KEY};
use crate::bls12381::primitives::{
    group::{Element, Scalar, Share, G1},
    poly,
    variant::Variant,
};
use crate::Hasher;
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use core::num::NonZeroU32;
use std::collections::BTreeMap;

/// An encrypted share with its DLEQ proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedShare {
    /// The encrypted share value: `p(j) + H(S_ij, i, j)` where `S_ij` is the DH shared secret.
    pub value: Scalar,
    /// The DH shared secret `S_ij = sk_i * PK_j` (needed for public verification).
    pub shared_secret: G1,
    /// DLEQ proof that `log_G(PK_i) = log_{PK_j}(S_ij)`.
    pub proof: DleqProof,
}

impl Write for EncryptedShare {
    fn write(&self, buf: &mut impl BufMut) {
        self.value.write(buf);
        self.shared_secret.write(buf);
        self.proof.write(buf);
    }
}

impl Read for EncryptedShare {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let value = Scalar::read(buf)?;
        let shared_secret = G1::read(buf)?;
        let proof = DleqProof::read(buf)?;
        Ok(Self {
            value,
            shared_secret,
            proof,
        })
    }
}

impl FixedSize for EncryptedShare {
    const SIZE: usize = Scalar::SIZE + G1::SIZE + DleqProof::SIZE;
}

/// A contribution from a single participant in the Golden DKG.
///
/// This contains all the information needed for other participants to:
/// 1. Verify the contribution is valid
/// 2. Decrypt their share
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution<V: Variant> {
    /// The Feldman commitment to the secret polynomial.
    pub commitment: poly::Public<V>,
    /// Encrypted shares for each participant (indexed by participant index).
    pub encrypted_shares: Vec<EncryptedShare>,
}

impl<V: Variant> Contribution<V> {
    /// Verifies this contribution against the list of participant public keys.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - The public keys of all participants
    /// * `dealer_index` - The index of the dealer who created this contribution
    /// * `threshold` - The threshold for the DKG (number of shares needed to reconstruct)
    /// * `previous` - If resharing, the previous group polynomial
    ///
    /// # Returns
    ///
    /// `Ok(())` if the contribution is valid, `Err` otherwise.
    pub fn verify(
        &self,
        public_keys: &[V::Public],
        dealer_index: u32,
        threshold: u32,
        previous: Option<&poly::Public<V>>,
    ) -> Result<(), Error> {
        let n = public_keys.len();
        let dealer_idx = dealer_index as usize;

        // Check dealer index is valid
        if dealer_idx >= n {
            return Err(Error::ParticipantIndexOutOfRange);
        }

        // Check commitment degree
        let expected_degree = threshold - 1;
        if self.commitment.degree() != expected_degree {
            return Err(Error::CommitmentWrongDegree(
                expected_degree,
                self.commitment.degree(),
            ));
        }

        // Check reshare constraint if applicable
        if let Some(prev) = previous {
            let expected_constant = prev.evaluate(dealer_index).value;
            if *self.commitment.constant() != expected_constant {
                return Err(Error::ResharePolynomialMismatch);
            }
        }

        // Check number of encrypted shares
        if self.encrypted_shares.len() != n {
            return Err(Error::WrongNumberOfShares(n, self.encrypted_shares.len()));
        }

        // Get dealer's public key
        let dealer_pk = &public_keys[dealer_idx];
        let g = V::Public::one();

        // Verify each encrypted share
        for (recipient_idx, encrypted) in self.encrypted_shares.iter().enumerate() {
            let recipient_idx = recipient_idx as u32;

            // Get recipient's public key
            let recipient_pk = &public_keys[recipient_idx as usize];

            // Verify DLEQ proof: log_G(dealer_pk) = log_{recipient_pk}(shared_secret)
            // Note: We need to convert V::Public to G1 for the DLEQ proof
            // Since we're working with BLS12-381, the public key is either G1 or G2
            // depending on the variant. For now, we assume MinSig (public keys on G1).
            //
            // TODO: Make this work with both MinPk and MinSig variants
            let g_g1 = g1_from_public::<V>(&g)?;
            let dealer_pk_g1 = g1_from_public::<V>(dealer_pk)?;
            let recipient_pk_g1 = g1_from_public::<V>(recipient_pk)?;

            if !encrypted
                .proof
                .verify(&g_g1, &recipient_pk_g1, &dealer_pk_g1, &encrypted.shared_secret)
            {
                return Err(Error::DleqProofInvalid(recipient_idx));
            }

            // Derive encryption key from shared secret
            let key = derive_encryption_key(&encrypted.shared_secret, dealer_index, recipient_idx);

            // Compute expected encrypted value: commitment.evaluate(recipient) + key
            // Actually, we need to verify: encrypted.value - key ?= share
            // where share.public() should equal commitment.evaluate(recipient)
            //
            // Decrypted share: s = encrypted.value - key
            // Expected public: commitment.evaluate(recipient).value
            // Verify: s * G == commitment.evaluate(recipient).value

            let mut decrypted = encrypted.value.clone();
            decrypted.sub(&key);

            // Compute s * G
            let mut decrypted_public = V::Public::one();
            decrypted_public.mul(&decrypted);

            // Get expected public value from commitment
            let expected_public = self.commitment.evaluate(recipient_idx).value;

            if decrypted_public != expected_public {
                return Err(Error::EncryptedShareInvalid);
            }
        }

        Ok(())
    }
}

/// Convert a variant public key to G1 (for DLEQ proofs).
///
/// This only works for MinSig variant where public keys are on G1.
fn g1_from_public<V: Variant>(pk: &V::Public) -> Result<G1, Error> {
    // Encode and decode as G1
    let encoded = pk.encode();
    if encoded.len() != G1::SIZE {
        // This is G2 (MinPk variant), which we don't support for DLEQ proofs
        // on G1. In a full implementation, we'd need separate DLEQ proofs for G2.
        return Err(Error::InvalidPublicKey);
    }
    G1::decode(encoded).map_err(|_| Error::InvalidPublicKey)
}

impl<V: Variant> Write for Contribution<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.encrypted_shares.write(buf);
    }
}

impl<V: Variant> Read for Contribution<V> {
    type Cfg = (NonZeroU32, NonZeroU32); // (threshold, n_participants)

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let (threshold, n) = cfg;
        let n_usize = n.get() as usize;
        let commitment =
            poly::Public::<V>::read_cfg(buf, &RangeCfg::from(*threshold..=*threshold))?;
        let encrypted_shares = Vec::<EncryptedShare>::read_cfg(
            buf,
            &(RangeCfg::from(n_usize..=n_usize), ()),
        )?;
        Ok(Self {
            commitment,
            encrypted_shares,
        })
    }
}

impl<V: Variant> EncodeSize for Contribution<V> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.encrypted_shares.encode_size()
    }
}

/// Output of a successful Golden DKG for a participant.
#[derive(Debug, Clone)]
pub struct Output<V: Variant> {
    /// The group public polynomial.
    pub public: poly::Public<V>,
    /// This participant's share of the secret.
    pub share: Share,
}

impl<V: Variant> Output<V> {
    /// Returns the group public key.
    pub fn public_key(&self) -> &V::Public {
        poly::public::<V>(&self.public)
    }
}

/// Derives an encryption key from a DH shared secret.
///
/// The key is derived as: `H(DST || shared_secret || dealer || recipient)`
pub fn derive_encryption_key(shared_secret: &G1, dealer: u32, recipient: u32) -> Scalar {
    let mut hasher = crate::Sha256::new();
    hasher.update(DST_ENCRYPTION_KEY);
    hasher.update(&shared_secret.encode());
    hasher.update(&dealer.to_le_bytes());
    hasher.update(&recipient.to_le_bytes());
    let digest = hasher.finalize();

    // Map the hash to a scalar using a domain-separated hash-to-field
    Scalar::map(b"GOLDEN_DKG_KEY_SCALAR", digest.as_ref())
}

/// Aggregator for Golden DKG contributions.
///
/// Collects and verifies contributions, then allows participants to recover their shares.
#[derive(Debug, Clone)]
pub struct Aggregator<V: Variant> {
    /// Public keys of all participants.
    public_keys: Vec<V::Public>,
    /// Threshold for the DKG.
    threshold: u32,
    /// Previous group polynomial (for resharing).
    previous: Option<poly::Public<V>>,
    /// Collected contributions from dealers.
    contributions: BTreeMap<u32, Contribution<V>>,
}

impl<V: Variant> Aggregator<V> {
    /// Creates a new aggregator for a fresh DKG.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - Public keys of all participants (must be on G1 for MinPk)
    /// * `threshold` - The threshold for reconstruction
    pub fn new(public_keys: Vec<V::Public>, threshold: u32) -> Self {
        Self {
            public_keys,
            threshold,
            previous: None,
            contributions: BTreeMap::new(),
        }
    }

    /// Creates a new aggregator for resharing.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - Public keys of all participants in the new committee
    /// * `threshold` - The threshold for reconstruction
    /// * `previous` - The previous group polynomial
    pub fn new_reshare(
        public_keys: Vec<V::Public>,
        threshold: u32,
        previous: poly::Public<V>,
    ) -> Self {
        Self {
            public_keys,
            threshold,
            previous: Some(previous),
            contributions: BTreeMap::new(),
        }
    }

    /// Adds a contribution from a dealer.
    ///
    /// Verifies the contribution before adding it.
    ///
    /// # Arguments
    ///
    /// * `dealer_index` - The index of the dealer
    /// * `contribution` - The contribution to add
    ///
    /// # Returns
    ///
    /// `Ok(())` if the contribution was added, `Err` if verification failed.
    pub fn add(&mut self, dealer_index: u32, contribution: Contribution<V>) -> Result<(), Error> {
        // Check for duplicate
        if self.contributions.contains_key(&dealer_index) {
            return Err(Error::DuplicateContribution(dealer_index));
        }

        // Verify the contribution
        contribution.verify(
            &self.public_keys,
            dealer_index,
            self.threshold,
            self.previous.as_ref(),
        )?;

        // Add to collection
        self.contributions.insert(dealer_index, contribution);
        Ok(())
    }

    /// Returns the number of contributions collected.
    pub fn count(&self) -> usize {
        self.contributions.len()
    }

    /// Returns whether enough contributions have been collected.
    pub fn has_enough(&self) -> bool {
        self.contributions.len() >= self.threshold as usize
    }

    /// Finalizes the DKG and returns the output for a specific participant.
    ///
    /// # Arguments
    ///
    /// * `participant_index` - The index of the participant
    /// * `participant_sk` - The participant's secret key
    ///
    /// # Returns
    ///
    /// The output containing the group public polynomial and the participant's share.
    pub fn finalize(
        &self,
        participant_index: u32,
        participant_sk: &Scalar,
    ) -> Result<Output<V>, Error> {
        // Check we have enough contributions
        if !self.has_enough() {
            return Err(Error::InsufficientContributions(
                self.threshold as usize,
                self.contributions.len(),
            ));
        }

        // Select exactly threshold contributions (first by dealer index, already sorted by BTreeMap)
        let selected: Vec<_> = self
            .contributions
            .iter()
            .take(self.threshold as usize)
            .collect();

        // Compute public polynomial and shares differently based on whether we're resharing
        let (public, share_scalar) = if self.previous.is_some() {
            // Resharing: need to interpolate using Lagrange coefficients
            let dealer_indices: Vec<u32> = selected.iter().map(|(&idx, _)| idx).collect();
            let weights =
                poly::compute_weights(dealer_indices).map_err(|_| Error::InterpolationFailed)?;

            // Interpolate public polynomial coefficient-wise
            let degree = self.threshold - 1;
            let mut coefficients = Vec::with_capacity(self.threshold as usize);
            for coeff_idx in 0..=degree {
                let mut result = V::Public::zero();
                for (&dealer_idx, contribution) in &selected {
                    let weight = weights
                        .get(&dealer_idx)
                        .ok_or(Error::InterpolationFailed)?;
                    let mut term = contribution.commitment.get(coeff_idx);
                    term.mul(weight.as_scalar());
                    result.add(&term);
                }
                coefficients.push(result);
            }
            let public = poly::Public::<V>::from(coefficients);

            // Recover share with Lagrange weights
            let mut share_scalar = Scalar::zero();
            for (&dealer_idx, contribution) in &selected {
                let weight = weights
                    .get(&dealer_idx)
                    .ok_or(Error::InterpolationFailed)?;

                // Get the encrypted share for this participant
                let encrypted = &contribution.encrypted_shares[participant_index as usize];

                // Compute shared secret: my_sk * dealer_pk
                let dealer_pk = &self.public_keys[dealer_idx as usize];
                let dealer_pk_g1 = g1_from_public::<V>(dealer_pk)?;

                let mut shared_secret = dealer_pk_g1;
                shared_secret.mul(participant_sk);

                // Verify the shared secret matches
                if shared_secret != encrypted.shared_secret {
                    return Err(Error::ShareDecryptionFailed);
                }

                // Derive encryption key
                let key =
                    derive_encryption_key(&encrypted.shared_secret, dealer_idx, participant_index);

                // Decrypt: share = encrypted - key
                let mut decrypted = encrypted.value.clone();
                decrypted.sub(&key);

                // Multiply by Lagrange weight and add to accumulated share
                decrypted.mul(weight.as_scalar());
                share_scalar.add(&decrypted);
            }

            (public, share_scalar)
        } else {
            // Fresh DKG: sum all contributions
            let mut public = poly::Public::<V>::zero();
            for (_, contribution) in &selected {
                public.add(&contribution.commitment);
            }

            // Recover share
            let mut share_scalar = Scalar::zero();
            for (&dealer_idx, contribution) in &selected {
                // Get the encrypted share for this participant
                let encrypted = &contribution.encrypted_shares[participant_index as usize];

                // Compute shared secret: my_sk * dealer_pk
                let dealer_pk = &self.public_keys[dealer_idx as usize];
                let dealer_pk_g1 = g1_from_public::<V>(dealer_pk)?;

                let mut shared_secret = dealer_pk_g1;
                shared_secret.mul(participant_sk);

                // Verify the shared secret matches
                if shared_secret != encrypted.shared_secret {
                    return Err(Error::ShareDecryptionFailed);
                }

                // Derive encryption key
                let key =
                    derive_encryption_key(&encrypted.shared_secret, dealer_idx, participant_index);

                // Decrypt: share = encrypted - key
                let mut decrypted = encrypted.value.clone();
                decrypted.sub(&key);

                // Add to accumulated share
                share_scalar.add(&decrypted);
            }

            (public, share_scalar)
        };

        // Create share
        let share = Share {
            index: participant_index,
            private: share_scalar,
        };

        // Verify the share matches the public polynomial
        let expected_public = public.evaluate(participant_index).value;
        let actual_public = share.public::<V>();

        if expected_public != actual_public {
            return Err(Error::ShareRecoveryMismatch);
        }

        Ok(Output { public, share })
    }

    /// Returns the aggregated public polynomial without recovering any shares.
    pub fn public_polynomial(&self) -> Result<poly::Public<V>, Error> {
        if !self.has_enough() {
            return Err(Error::InsufficientContributions(
                self.threshold as usize,
                self.contributions.len(),
            ));
        }

        // Select exactly threshold contributions (first by dealer index)
        let selected: Vec<_> = self
            .contributions
            .iter()
            .take(self.threshold as usize)
            .collect();

        if self.previous.is_some() {
            // Resharing: interpolate coefficient-wise
            let dealer_indices: Vec<u32> = selected.iter().map(|(&idx, _)| idx).collect();
            let weights =
                poly::compute_weights(dealer_indices).map_err(|_| Error::InterpolationFailed)?;

            let degree = self.threshold - 1;
            let mut coefficients = Vec::with_capacity(self.threshold as usize);
            for coeff_idx in 0..=degree {
                let mut result = V::Public::zero();
                for (&dealer_idx, contribution) in &selected {
                    let weight = weights
                        .get(&dealer_idx)
                        .ok_or(Error::InterpolationFailed)?;
                    let mut term = contribution.commitment.get(coeff_idx);
                    term.mul(weight.as_scalar());
                    result.add(&term);
                }
                coefficients.push(result);
            }
            Ok(poly::Public::<V>::from(coefficients))
        } else {
            // Fresh DKG: sum all contributions
            let mut public = poly::Public::<V>::zero();
            for (_, contribution) in &selected {
                public.add(&contribution.commitment);
            }
            Ok(public)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_encrypted_share_codec() {
        let mut rng = StdRng::seed_from_u64(42);

        let value = Scalar::from_rand(&mut rng);
        let mut shared_secret = G1::one();
        shared_secret.mul(&Scalar::from_rand(&mut rng));

        let proof = DleqProof {
            challenge: Scalar::from_rand(&mut rng),
            response: Scalar::from_rand(&mut rng),
        };

        let share = EncryptedShare {
            value,
            shared_secret,
            proof,
        };

        let encoded = share.encode();
        assert_eq!(encoded.len(), EncryptedShare::SIZE);

        let decoded = EncryptedShare::decode(encoded).unwrap();
        assert_eq!(share, decoded);
    }

    #[test]
    fn test_derive_encryption_key_determinism() {
        let mut rng = StdRng::seed_from_u64(42);
        let mut shared_secret = G1::one();
        shared_secret.mul(&Scalar::from_rand(&mut rng));

        let key1 = derive_encryption_key(&shared_secret, 0, 1);
        let key2 = derive_encryption_key(&shared_secret, 0, 1);
        assert_eq!(key1, key2);

        // Different indices should give different keys
        let key3 = derive_encryption_key(&shared_secret, 0, 2);
        assert_ne!(key1, key3);

        let key4 = derive_encryption_key(&shared_secret, 1, 1);
        assert_ne!(key1, key4);
    }
}
