//! Types for the Golden DKG protocol using two-curve architecture.
//!
//! This implements the Golden DKG paper's two-curve design:
//! - G_in = Jubjub: Used for identity keys and DH-based encryption
//! - G_out = BLS12-381 G1: Used for Feldman commitments and group keys

use super::{
    contributor::Contribution,
    jubjub::{IdentityKey, JubjubPoint},
    Error,
};
use crate::bls12381::primitives::{
    group::{Element, Scalar, Share},
    poly,
    variant::Variant,
};
use rayon::{prelude::*, ThreadPoolBuilder};
use std::collections::BTreeMap;

/// Output of a successful Golden DKG for a participant.
#[derive(Debug, Clone)]
pub struct Output<V: Variant> {
    /// The group public polynomial (on G_out).
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

/// Aggregator for Golden DKG contributions using native two-curve architecture.
///
/// Collects and verifies contributions, then allows participants to recover
/// their shares using Jubjub DH.
#[derive(Debug, Clone)]
pub struct Aggregator<V: Variant> {
    /// Jubjub public keys of all participants (G_in).
    identity_keys: Vec<JubjubPoint>,
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
    /// * `identity_keys` - Jubjub public keys of all participants (G_in)
    /// * `threshold` - The threshold for reconstruction
    /// * `concurrency` - Number of threads to use for parallel operations
    pub fn new(identity_keys: Vec<JubjubPoint>, threshold: u32, concurrency: usize) -> Self {
        Self {
            identity_keys,
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
    /// * `identity_keys` - Jubjub public keys of all participants in the new committee
    /// * `threshold` - The threshold for reconstruction
    /// * `previous` - The previous group polynomial
    /// * `concurrency` - Number of threads to use for parallel operations
    pub fn new_reshare(
        identity_keys: Vec<JubjubPoint>,
        threshold: u32,
        previous: poly::Public<V>,
        concurrency: usize,
    ) -> Self {
        Self {
            identity_keys,
            threshold,
            previous: Some(previous),
            contributions: BTreeMap::new(),
            concurrency,
        }
    }

    /// Adds a contribution from a dealer.
    ///
    /// Verifies the contribution before adding it.
    pub fn add(
        &mut self,
        dealer_index: u32,
        contribution: Contribution<V>,
    ) -> Result<(), Error> {
        // Check for duplicate
        if self.contributions.contains_key(&dealer_index) {
            return Err(Error::DuplicateContribution(dealer_index));
        }

        // Verify the contribution
        contribution.verify(
            &self.identity_keys,
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
    /// * `participant_identity` - The participant's Jubjub identity key
    ///
    /// # Returns
    ///
    /// The output containing the group public polynomial and the participant's share.
    pub fn finalize(
        &self,
        participant_index: u32,
        participant_identity: &IdentityKey,
        previous_share: Option<&Share>,
    ) -> Result<Output<V>, Error> {
        // Check we have enough contributions
        if !self.has_enough() {
            return Err(Error::InsufficientContributions(
                self.threshold as usize,
                self.contributions.len(),
            ));
        }

        // Select all collected contributions to avoid cherry-picking
        let selected: Vec<_> = self.contributions.iter().collect();

        // Build thread pool for parallel operations
        let pool = ThreadPoolBuilder::new()
            .num_threads(self.concurrency)
            .build()
            .expect("unable to build thread pool");

        // Compute public polynomial and shares
        let (public, share_scalar) = if let Some(prev_public) = &self.previous {
            // Resharing: need to interpolate using Lagrange coefficients
            let dealer_indices: Vec<u32> = selected.iter().map(|(&idx, _)| idx).collect();
            let weights =
                poly::compute_weights(dealer_indices).map_err(|_| Error::InterpolationFailed)?;

            let prev_share = previous_share.ok_or(Error::MissingPreviousShare)?;

            // Interpolate public polynomial coefficient-wise
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
            let mut public = prev_public.clone();
            public.add(&poly::Public::<V>::from(coefficients));

            // Recover share with Lagrange weights
            let mut share_scalar = prev_share.private.clone();

            for (&dealer_idx, contribution) in &selected {
                let weight = weights
                    .get(&dealer_idx)
                    .ok_or(Error::InterpolationFailed)?;

                let encrypted = &contribution.encrypted_shares[participant_index as usize];

                // Compute alpha using DH symmetry on Jubjub
                let dealer_pk = &self.identity_keys[dealer_idx as usize];
                let alpha = participant_identity.compute_alpha(dealer_pk);

                // Decrypt: share = encrypted - alpha
                let mut decrypted = encrypted.value.clone();
                decrypted.sub(&alpha);

                // Multiply by Lagrange weight and add
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
                let encrypted = &contribution.encrypted_shares[participant_index as usize];

                // Compute alpha using DH symmetry on Jubjub
                let dealer_pk = &self.identity_keys[dealer_idx as usize];
                let alpha = participant_identity.compute_alpha(dealer_pk);

                // Decrypt: share = encrypted - alpha
                let mut decrypted = encrypted.value.clone();
                decrypted.sub(&alpha);

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

        let selected: Vec<_> = self.contributions.iter().collect();

        if let Some(prev_public) = &self.previous {
            // Resharing: interpolate coefficient-wise
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
            let mut public = prev_public.clone();
            public.add(&poly::Public::<V>::from(coefficients));
            Ok(public)
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
    use crate::bls12381::primitives::{
        ops::{partial_sign_proof_of_possession, threshold_signature_recover, verify_proof_of_possession},
        variant::MinPk,
    };
    use commonware_utils::quorum;
    use rand::{rngs::StdRng, SeedableRng};
    use super::super::contributor::Contributor;

    fn create_identities(rng: &mut StdRng, n: usize) -> Vec<IdentityKey> {
        (0..n).map(|_| IdentityKey::generate(rng)).collect()
    }

    /// Run a complete native DKG using the Aggregator.
    fn run_native_dkg(
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
                .finalize(idx as u32, identity, None)
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

    #[test]
    fn test_basic_dkg() {
        let (public, shares, _) = run_native_dkg(42, 2);

        // Verify by creating a threshold signature
        let threshold = quorum(2);
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
        let (public1, _, _) = run_native_dkg(123, 2);
        let (public2, _, _) = run_native_dkg(123, 2);
        assert_eq!(public1, public2, "DKG should be deterministic with same seed");

        let (public3, _, _) = run_native_dkg(456, 2);
        assert_ne!(public1, public3, "different seeds should produce different results");
    }

    #[test]
    fn test_dkg_varying_sizes() {
        for n in [2, 3] {
            let (public, shares, _) = run_native_dkg(n as u64, n);
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
        let (public1, shares1, identities) = run_native_dkg(42, 2);

        // Run reshare
        let mut rng = StdRng::seed_from_u64(100);
        let threshold = quorum(2);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        // Each participant creates a resharing contribution
        let mut contributions = Vec::new();
        for (idx, identity) in identities.iter().enumerate() {
            let prev_share = shares1[idx].clone();
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
        let mut aggregator = Aggregator::<MinPk>::new_reshare(
            identity_keys,
            threshold,
            public1.clone(),
            1,
        );
        for (idx, contribution) in contributions {
            aggregator.add(idx, contribution).expect("failed to add reshare contribution");
        }

        // Finalize and verify
        let mut shares2 = Vec::new();
        let mut group_public = None;

        for (idx, identity) in identities.iter().enumerate() {
            let output = aggregator
                .finalize(idx as u32, identity, Some(&shares1[idx]))
                .expect("failed to finalize reshare");

            shares2.push(output.share);

            if let Some(ref expected) = group_public {
                assert_eq!(expected, &output.public, "group polynomial mismatch in reshare");
            } else {
                group_public = Some(output.public);
            }
        }

        let public2 = group_public.unwrap();

        // The public key (constant term) should be the same
        assert_eq!(
            public1.constant(),
            public2.constant(),
            "reshare should preserve public key"
        );

        // Verify threshold signature works with new shares
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
        let n = 4;
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
        let result = aggregator.finalize(0, &identities[0], None);
        assert!(
            matches!(result, Err(Error::InsufficientContributions(_, 1))),
            "should fail with insufficient contributions"
        );
    }

    #[test]
    fn test_finalize_requires_all_contributions() {
        let mut rng = StdRng::seed_from_u64(77);
        let n = 4;
        let threshold = quorum(n as u32);

        let identities = create_identities(&mut rng, n as usize);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

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

        let mut aggregator = Aggregator::<MinPk>::new(identity_keys, threshold, 1);
        for (idx, contribution) in &contributions {
            aggregator.add(*idx, contribution.clone()).expect("add should succeed");
        }

        // Final public polynomial should include all contributions, not just threshold many.
        let expected_public = contributions.iter().fold(
            poly::Public::<MinPk>::zero(),
            |mut acc, (_, c)| {
                acc.add(&c.commitment);
                acc
            },
        );

        let output = aggregator
            .finalize(0, &identities[0], None)
            .expect("finalize should succeed");
        assert_eq!(output.public, expected_public);
    }

    #[test]
    fn test_finalize_requires_previous_share_for_reshare() {
        let mut rng = StdRng::seed_from_u64(88);
        let n = 4;
        let threshold = quorum(n as u32);

        let identities = create_identities(&mut rng, n as usize);
        let identity_keys: Vec<JubjubPoint> = identities.iter().map(|id| id.public).collect();

        let mut contributions = Vec::new();
        for (idx, identity) in identities.iter().enumerate() {
            let (_, contribution) = Contributor::<MinPk>::new(
                &mut rng,
                identity_keys.clone(),
                idx as u32,
                identity,
                Some(Share {
                    index: idx as u32,
                    private: Scalar::zero(),
                }),
            );
            contributions.push((idx as u32, contribution));
        }

        let mut aggregator = Aggregator::<MinPk>::new_reshare(
            identity_keys,
            threshold,
            poly::Public::<MinPk>::zero(),
            1,
        );
        for (idx, contribution) in contributions {
            aggregator.add(idx, contribution).expect("add should succeed");
        }

        let result = aggregator.finalize(0, &identities[0], None);
        assert!(
            matches!(result, Err(Error::MissingPreviousShare)),
            "finalize without previous share should fail for reshare"
        );
    }
}
