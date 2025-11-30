//! Types for the Golden DKG protocol.

use super::{evrf::EVRFOutput, Error};
use crate::bls12381::primitives::{
    group::{Element, Scalar, Share, G1},
    poly,
    variant::Variant,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use core::num::NonZeroU32;
use rayon::{prelude::*, ThreadPoolBuilder};
use std::collections::BTreeMap;

/// An encrypted share with its eVRF proof.
///
/// Per the Golden DKG paper, the encryption uses the eVRF output as a one-time pad:
/// - `(r_ij, R_ij, pi_ij) = eVRF.Evaluate(sk_i, (msg_i, PK_j))`
/// - `z_ij = r_ij + share_ij`
///
/// The eVRF proof provides public verifiability that the encryption key was
/// derived correctly without revealing the DH shared secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedShare {
    /// The encrypted share value: `share + alpha` where `alpha` is the eVRF output.
    pub value: Scalar,
    /// The eVRF output and proof for this share encryption.
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

impl EncodeSize for EncryptedShare {
    fn encode_size(&self) -> usize {
        self.value.encode_size() + self.evrf_output.encode_size()
    }
}

/// A contribution from a single participant in the Golden DKG.
///
/// This contains all the information needed for other participants to:
/// 1. Verify the contribution is valid
/// 2. Decrypt their share
///
/// Per the Golden DKG paper, each contribution includes:
/// - A random message `msg` for eVRF domain separation
/// - A Feldman commitment to the secret polynomial
/// - Encrypted shares with eVRF proofs for each participant
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution<V: Variant> {
    /// Random message for eVRF domain separation.
    pub msg: Vec<u8>,
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
        let dealer_pk_g1 = g1_from_public::<V>(dealer_pk)?;

        // Verify each encrypted share using eVRF
        for (recipient_idx, encrypted) in self.encrypted_shares.iter().enumerate() {
            let recipient_idx = recipient_idx as u32;

            // Get recipient's public key
            let recipient_pk = &public_keys[recipient_idx as usize];
            let recipient_pk_g1 = g1_from_public::<V>(recipient_pk)?;

            // Verify eVRF proof: proves the encryption key (alpha) was correctly derived
            // from the DH shared secret between dealer and recipient
            if !super::evrf::verify(
                &dealer_pk_g1,
                &recipient_pk_g1,
                &self.msg,
                &encrypted.evrf_output,
            ) {
                return Err(Error::EVRFProofInvalid(recipient_idx));
            }

            // The encryption key is the eVRF output alpha
            let key = &encrypted.evrf_output.alpha;

            // Verify: encrypted.value - alpha gives a share that matches the commitment
            // Decrypted share: s = encrypted.value - alpha
            // Expected public: commitment.evaluate(recipient).value
            // Verify: s * G == commitment.evaluate(recipient).value

            let mut decrypted = encrypted.value.clone();
            decrypted.sub(key);

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

/// Convert a variant public key to G1 (for eVRF evaluation).
///
/// This only works for MinPk variant where public keys are on G1.
fn g1_from_public<V: Variant>(pk: &V::Public) -> Result<G1, Error> {
    // Encode and decode as G1
    let encoded = pk.encode();
    if encoded.len() != G1::SIZE {
        // This is G2 (MinSig variant), which we don't support for eVRF
        // since eVRF operates on G1 points.
        return Err(Error::InvalidPublicKey);
    }
    G1::decode(encoded).map_err(|_| Error::InvalidPublicKey)
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

impl<V: Variant> EncodeSize for Contribution<V> {
    fn encode_size(&self) -> usize {
        self.msg.encode_size() + self.commitment.encode_size() + self.encrypted_shares.encode_size()
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
    /// Number of threads to use for parallel operations.
    concurrency: usize,
}

impl<V: Variant> Aggregator<V> {
    /// Creates a new aggregator for a fresh DKG.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - Public keys of all participants (must be on G1 for MinPk)
    /// * `threshold` - The threshold for reconstruction
    /// * `concurrency` - Number of threads to use for parallel operations
    pub fn new(public_keys: Vec<V::Public>, threshold: u32, concurrency: usize) -> Self {
        Self {
            public_keys,
            threshold,
            previous: None,
            contributions: BTreeMap::new(),
            concurrency,
        }
    }

    /// Creates a new aggregator for resharing.
    ///
    /// # Arguments
    ///
    /// * `public_keys` - Public keys of all participants in the new committee
    /// * `threshold` - The threshold for reconstruction
    /// * `previous` - The previous group polynomial
    /// * `concurrency` - Number of threads to use for parallel operations
    pub fn new_reshare(
        public_keys: Vec<V::Public>,
        threshold: u32,
        previous: poly::Public<V>,
        concurrency: usize,
    ) -> Self {
        Self {
            public_keys,
            threshold,
            previous: Some(previous),
            contributions: BTreeMap::new(),
            concurrency,
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

        // Build thread pool for parallel operations
        let pool = ThreadPoolBuilder::new()
            .num_threads(self.concurrency)
            .build()
            .expect("unable to build thread pool");

        // Compute public polynomial and shares differently based on whether we're resharing
        let (public, share_scalar) = if self.previous.is_some() {
            // Resharing: need to interpolate using Lagrange coefficients
            let dealer_indices: Vec<u32> = selected.iter().map(|(&idx, _)| idx).collect();
            let weights =
                poly::compute_weights(dealer_indices).map_err(|_| Error::InterpolationFailed)?;

            // Interpolate public polynomial coefficient-wise (parallel over coefficients)
            let degree = self.threshold - 1;
            let coefficients = pool.install(|| {
                (0..=degree)
                    .into_par_iter()
                    .map(|coeff_idx| {
                        let mut result = V::Public::zero();
                        for (&dealer_idx, contribution) in &selected {
                            if let Some(weight) = weights.get(&dealer_idx) {
                                let mut term = contribution.commitment.get(coeff_idx);
                                term.mul(weight.as_scalar());
                                result.add(&term);
                            }
                        }
                        result
                    })
                    .collect::<Vec<_>>()
            });
            let public = poly::Public::<V>::from(coefficients);

            // Recover share with Lagrange weights using eVRF symmetry
            let mut share_scalar = Scalar::zero();
            let my_pk_g1 = g1_from_public::<V>(&self.public_keys[participant_index as usize])?;

            for (&dealer_idx, contribution) in &selected {
                let weight = weights
                    .get(&dealer_idx)
                    .ok_or(Error::InterpolationFailed)?;

                // Get the encrypted share for this participant
                let encrypted = &contribution.encrypted_shares[participant_index as usize];

                // Get dealer's public key
                let dealer_pk = &self.public_keys[dealer_idx as usize];
                let dealer_pk_g1 = g1_from_public::<V>(dealer_pk)?;

                // Use eVRF symmetry: recipient evaluates eVRF to get same alpha as dealer
                // eVRF(dealer_sk, recipient_pk) = eVRF(recipient_sk, dealer_pk)
                let evrf_output =
                    super::evrf::evaluate(participant_sk, &my_pk_g1, &dealer_pk_g1, &contribution.msg);

                // The decryption key is the eVRF output alpha
                let key = &evrf_output.alpha;

                // Decrypt: share = encrypted - key
                let mut decrypted = encrypted.value.clone();
                decrypted.sub(key);

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

            // Recover share using eVRF symmetry
            let mut share_scalar = Scalar::zero();
            let my_pk_g1 = g1_from_public::<V>(&self.public_keys[participant_index as usize])?;

            for (&dealer_idx, contribution) in &selected {
                // Get the encrypted share for this participant
                let encrypted = &contribution.encrypted_shares[participant_index as usize];

                // Get dealer's public key
                let dealer_pk = &self.public_keys[dealer_idx as usize];
                let dealer_pk_g1 = g1_from_public::<V>(dealer_pk)?;

                // Use eVRF symmetry: recipient evaluates eVRF to get same alpha as dealer
                // eVRF(dealer_sk, recipient_pk) = eVRF(recipient_sk, dealer_pk)
                let evrf_output =
                    super::evrf::evaluate(participant_sk, &my_pk_g1, &dealer_pk_g1, &contribution.msg);

                // The decryption key is the eVRF output alpha
                let key = &evrf_output.alpha;

                // Decrypt: share = encrypted - key
                let mut decrypted = encrypted.value.clone();
                decrypted.sub(key);

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
            // Resharing: interpolate coefficient-wise (parallel)
            let dealer_indices: Vec<u32> = selected.iter().map(|(&idx, _)| idx).collect();
            let weights =
                poly::compute_weights(dealer_indices).map_err(|_| Error::InterpolationFailed)?;

            let pool = ThreadPoolBuilder::new()
                .num_threads(self.concurrency)
                .build()
                .expect("unable to build thread pool");

            let degree = self.threshold - 1;
            let coefficients = pool.install(|| {
                (0..=degree)
                    .into_par_iter()
                    .map(|coeff_idx| {
                        let mut result = V::Public::zero();
                        for (&dealer_idx, contribution) in &selected {
                            if let Some(weight) = weights.get(&dealer_idx) {
                                let mut term = contribution.commitment.get(coeff_idx);
                                term.mul(weight.as_scalar());
                                result.add(&term);
                            }
                        }
                        result
                    })
                    .collect::<Vec<_>>()
            });
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
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_encrypted_share_codec() {
        let mut rng = StdRng::seed_from_u64(42);

        // Create keypairs for eVRF evaluation
        let sk = Scalar::from_rand(&mut rng);
        let mut pk = G1::one();
        pk.mul(&sk);

        let sk_other = Scalar::from_rand(&mut rng);
        let mut pk_other = G1::one();
        pk_other.mul(&sk_other);

        // Generate eVRF output
        let evrf_output = super::super::evrf::evaluate(&sk, &pk, &pk_other, b"test_msg");

        let value = Scalar::from_rand(&mut rng);
        let share = EncryptedShare { value, evrf_output };

        let encoded = share.encode();
        let decoded = EncryptedShare::decode(encoded).unwrap();
        assert_eq!(share, decoded);
    }

    #[test]
    fn test_evrf_symmetry_for_decryption() {
        let mut rng = StdRng::seed_from_u64(42);

        // Create two keypairs
        let sk_a = Scalar::from_rand(&mut rng);
        let mut pk_a = G1::one();
        pk_a.mul(&sk_a);

        let sk_b = Scalar::from_rand(&mut rng);
        let mut pk_b = G1::one();
        pk_b.mul(&sk_b);

        let msg = b"test message for evrf";

        // A evaluates eVRF with B's public key
        let evrf_a = super::super::evrf::evaluate(&sk_a, &pk_a, &pk_b, msg);

        // B evaluates eVRF with A's public key (symmetric)
        let evrf_b = super::super::evrf::evaluate(&sk_b, &pk_b, &pk_a, msg);

        // The alpha values should be the same due to eVRF symmetry
        assert_eq!(evrf_a.alpha, evrf_b.alpha, "eVRF should be symmetric");
    }
}
