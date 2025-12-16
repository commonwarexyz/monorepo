//! Leader election strategies for simplex consensus.
//!
//! This module provides the [`Elector`] trait for customizing how leaders are selected
//! for each consensus round, along with built-in implementations.
//!
//! # Built-in Electors
//!
//! - [`RoundRobin`]: Simple deterministic rotation through participants based on view number.
//!   Works with any signing scheme.
//!
//! - [`ThresholdRandomness`]: Uses randomness derived from BLS threshold signatures for
//!   unpredictable leader selection. Only works with [`bls12381_threshold`].
//!
//! # Custom Electors
//!
//! Applications can implement [`Elector`] for custom leader selection logic such as
//! stake-weighted selection or other application-specific strategies.

use crate::{
    simplex::scheme::bls12381_threshold::{self, Seed},
    types::{Epoch, Round},
};
use commonware_codec::Encode;
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, certificate::Scheme, PublicKey,
};
use commonware_utils::ordered::Set;

/// Selects leaders for consensus rounds.
///
/// # Determinism Requirement
///
/// Implementations **must** be deterministic: given the same inputs (`participants`, `round`,
/// and `seed`), the [`elect`](Elector::elect) method must always return the same leader index.
/// This is critical for consensus correctness - all honest participants must agree on the
/// leader for each round.
///
/// Similarly, [`first`](Elector::first) must be deterministic given the same `participants`
/// and `epoch`, and [`seed`](Elector::seed) must produce the same seed given the same
/// `round` and `certificate`.
pub trait Elector<S: Scheme>: Send + 'static {
    /// The seed type used for leader election.
    ///
    /// For deterministic electors like [`RoundRobin`], this is `()`.
    /// For randomness-based electors, this contains the randomness source.
    type Seed;

    /// Selects the leader for the first view of an epoch (view 1, no previous certificate).
    ///
    /// This method **must** be a pure function.
    ///
    /// The default implementation selects `epoch % num_participants`.
    fn first(&self, participants: &Set<S::PublicKey>, epoch: Epoch) -> u32 {
        assert!(
            !participants.is_empty(),
            "no participants to select leader from"
        );
        (epoch.get() as usize % participants.len()) as u32
    }

    /// Extracts the seed from a certificate for the given round.
    fn seed(&self, round: Round, certificate: &S::Certificate) -> Self::Seed;

    /// Selects the leader for the given round using the provided seed.
    ///
    /// This method **must** be a pure function.
    ///
    /// Returns the index of the selected leader in the participants list.
    fn elect(&self, participants: &Set<S::PublicKey>, round: Round, seed: Self::Seed) -> u32;
}

/// Simple round-robin leader election.
///
/// Rotates through participants based on `(epoch + view) % num_participants`.
///
/// Works with any signing scheme.
#[derive(Debug, Clone, Copy, Default)]
pub struct RoundRobin;

impl<S: Scheme> Elector<S> for RoundRobin {
    type Seed = ();

    fn seed(&self, _round: Round, _certificate: &S::Certificate) {}

    fn elect(&self, participants: &Set<S::PublicKey>, round: Round, _seed: ()) -> u32 {
        assert!(
            !participants.is_empty(),
            "no participants to select leader from"
        );
        ((round.epoch().get().wrapping_add(round.view().get())) as usize % participants.len())
            as u32
    }
}

/// Leader election using threshold signature randomness.
///
/// Uses the seed signature from BLS threshold certificates to derive unpredictable
/// leader selection.
///
/// Only works with [`bls12381_threshold`] signing scheme.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThresholdRandomness;

impl<P, V> Elector<bls12381_threshold::Scheme<P, V>> for ThresholdRandomness
where
    P: PublicKey,
    V: Variant + Send + Sync,
{
    type Seed = Seed<V>;

    fn seed(&self, round: Round, certificate: &bls12381_threshold::Signature<V>) -> Self::Seed {
        Seed::new(round, certificate.seed_signature)
    }

    fn elect(&self, participants: &Set<P>, _round: Round, seed: Self::Seed) -> u32 {
        assert!(
            !participants.is_empty(),
            "no participants to select leader from"
        );

        // Encode seed and use modulo to select leader
        let encoded = seed.encode();
        commonware_utils::modulo(encoded.as_ref(), participants.len() as u64) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::{bls12381_threshold, ed25519},
            types::Subject,
        },
        types::View,
    };
    use commonware_cryptography::{
        bls12381::{self, primitives::variant::MinPk},
        certificate::mocks::Fixture,
        sha256::Digest as Sha256Digest,
    };
    use commonware_utils::{quorum_from_slice, TryFromIterator};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn round_robin_rotates_through_participants() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, 4);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len();
        let elector = RoundRobin;
        let epoch = Epoch::new(0);

        // Run through 3 * n views, record the sequence of leaders
        // RoundRobin uses () as seed, so we don't need certificates
        let mut leaders = Vec::new();
        for view in 1..=(3 * n as u64) {
            let round = Round::new(epoch, View::new(view));
            leaders.push(<RoundRobin as Elector<ed25519::Scheme>>::elect(
                &elector,
                &participants,
                round,
                (),
            ));
        }

        // Verify leaders cycle: consecutive leaders differ by 1 (mod n)
        for i in 0..leaders.len() - 1 {
            assert_eq!((leaders[i] + 1) % n as u32, leaders[i + 1]);
        }
    }

    #[test]
    fn round_robin_first_cycles_through_epochs() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len();
        let elector = RoundRobin;

        // Record first leader for epochs 0..n
        let leaders: Vec<_> = (0..n as u64)
            .map(|e| {
                <RoundRobin as Elector<ed25519::Scheme>>::first(
                    &elector,
                    &participants,
                    Epoch::new(e),
                )
            })
            .collect();

        // Each participant should be selected exactly once
        let mut seen = vec![false; n];
        for &leader in &leaders {
            assert!(!seen[leader as usize]);
            seen[leader as usize] = true;
        }
        assert!(seen.iter().all(|x| *x));
    }

    #[test]
    #[should_panic(expected = "no participants")]
    fn round_robin_first_panics_on_empty_participants() {
        let participants = Set::default();
        let elector = RoundRobin;
        <RoundRobin as Elector<ed25519::Scheme>>::first(&elector, &participants, Epoch::new(1));
    }

    #[test]
    #[should_panic(expected = "no participants")]
    fn round_robin_elect_panics_on_empty_participants() {
        let participants = Set::default();
        let elector = RoundRobin;
        let round = Round::new(Epoch::new(1), View::new(1));
        <RoundRobin as Elector<ed25519::Scheme>>::elect(&elector, &participants, round, ());
    }

    #[test]
    fn threshold_randomness_first_cycles_through_epochs() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { participants, .. } = bls12381_threshold::fixture::<MinPk, _>(&mut rng, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len();
        let elector = ThresholdRandomness;

        // Record first leader for epochs 0..n
        let leaders: Vec<_> = (0..n as u64)
            .map(|e| {
                <ThresholdRandomness as Elector<bls12381_threshold::Scheme<_, MinPk>>>::first(
                    &elector,
                    &participants,
                    Epoch::new(e),
                )
            })
            .collect();

        // Each participant should be selected exactly once
        let mut seen = vec![false; n];
        for &leader in &leaders {
            assert!(!seen[leader as usize]);
            seen[leader as usize] = true;
        }
        assert!(seen.iter().all(|x| *x));
    }

    #[test]
    fn threshold_randomness_elect() {
        type S = bls12381_threshold::Scheme<commonware_cryptography::ed25519::PublicKey, MinPk>;

        let mut rng = StdRng::seed_from_u64(42);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold::fixture::<MinPk, _>(&mut rng, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector = ThresholdRandomness;
        let quorum = quorum_from_slice(&schemes) as usize;

        // Create first certificate for round (1, 2)
        let round1 = Round::new(Epoch::new(1), View::new(2));
        let attestations1: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(b"test", Subject::Nullify { round: round1 })
                    .unwrap()
            })
            .collect();
        let cert1 = schemes[0].assemble(attestations1).unwrap();

        // Create second certificate for round (1, 3) (different round -> different seed signature)
        let round2 = Round::new(Epoch::new(1), View::new(3));
        let attestations2: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(b"test", Subject::Nullify { round: round2 })
                    .unwrap()
            })
            .collect();
        let cert2 = schemes[0].assemble(attestations2).unwrap();

        // Extract seeds from certificates
        let seed1 = <ThresholdRandomness as Elector<S>>::seed(&elector, round1, &cert1);
        let seed2 = <ThresholdRandomness as Elector<S>>::seed(&elector, round2, &cert2);

        // Same seed always gives same leader
        let leader1a = <ThresholdRandomness as Elector<S>>::elect(
            &elector,
            &participants,
            round1,
            seed1.clone(),
        );
        let leader1b =
            <ThresholdRandomness as Elector<S>>::elect(&elector, &participants, round1, seed1);
        assert_eq!(leader1a, leader1b);

        // Different seeds produce different leaders
        //
        // NOTE: In general, different seeds could produce the same leader by chance.
        // However, for our specific test inputs (rng seed 42, 5 participants), we've
        // verified these produce different results.
        let leader2 = <ThresholdRandomness as Elector<S>>::elect(
            &elector,
            &participants,
            round1,
            seed2.clone(),
        );
        assert_ne!(leader1a, leader2);

        // The output of the election is entirely determined by the seed, so using the same seed
        // across different rounds leads to the same result
        let leader3 =
            <ThresholdRandomness as Elector<S>>::elect(&elector, &participants, round2, seed2);
        assert_eq!(leader2, leader3);
    }

    #[test]
    #[should_panic(expected = "no participants")]
    fn threshold_randomness_first_panics_on_empty_participants() {
        type S = bls12381_threshold::Scheme<bls12381::PublicKey, MinPk>;

        let participants = Set::default();
        let elector = ThresholdRandomness;
        <ThresholdRandomness as Elector<S>>::first(&elector, &participants, Epoch::new(1));
    }

    #[test]
    #[should_panic(expected = "no participants")]
    fn threshold_randomness_elect_panics_on_empty_participants() {
        type S = bls12381_threshold::Scheme<commonware_cryptography::ed25519::PublicKey, MinPk>;

        // Create a real seed from fixture, but use empty participants
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { schemes, .. } = bls12381_threshold::fixture::<MinPk, _>(&mut rng, 3);
        let round = Round::new(Epoch::new(1), View::new(1));
        let quorum = quorum_from_slice(&schemes) as usize;
        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(b"test", Subject::Nullify { round })
                    .unwrap()
            })
            .collect();
        let cert = schemes[0].assemble(attestations).unwrap();

        let participants = Set::default();
        let elector = ThresholdRandomness;
        let seed = <ThresholdRandomness as Elector<S>>::seed(&elector, round, &cert);
        <ThresholdRandomness as Elector<S>>::elect(&elector, &participants, round, seed);
    }
}
