//! Leader election strategies for simplex consensus.
//!
//! This module provides the [`Config`] and [`Elector`] traits for customizing
//! how leaders are selected for each consensus round, along with built-in implementations.
//!
//! # Built-in Electors
//!
//! - [`RoundRobin`]/[`RoundRobinElector`]: Deterministic rotation through participants
//!   based on view number. Optionally shuffled using a seed. Works with any signing scheme.
//!
//! - [`Random`]/[`RandomElector`]: Uses randomness derived from BLS threshold VRF signatures
//!   for unpredictable leader selection. Falls back to round-robin for the first view
//!   (no certificate available). Requires [`super::scheme::bls12381_threshold::vrf`]
//!   (implements [`super::scheme::bls12381_threshold::vrf::Seedable`]).
//!
//! # Custom Electors
//!
//! Applications can implement [`Config`] and [`Elector`] for custom leader
//! selection logic such as stake-weighted selection or other application-specific strategies.
//!
//! # Usage
//!
//! Users configure leader election with an elector [`Config`] (for example,
//! [`RoundRobin`]) and pass it to the consensus configuration. Consensus builds
//! the initialized [`Elector`] with the scheme participants before starting.

pub use crate::elector::{Config, Elector, RoundRobin, RoundRobinElector, Terms};
use crate::{
    simplex::scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
    types::{Participant, Round, View},
};
use commonware_codec::Encode;
use commonware_cryptography::{
    PublicKey,
    bls12381::primitives::variant::Variant,
    certificate::{Scheme, Verifier},
};
use commonware_utils::{modulo, ordered::Set};
use std::{fmt, marker::PhantomData};

/// The certificate a VRF elector consumes as evidence.
type VrfCertificate<P, V> = <bls12381_threshold_vrf::Scheme<P, V> as Verifier>::Certificate;

/// Configuration for leader election using threshold signature randomness.
///
/// Uses the seed signature from BLS threshold certificates to derive unpredictable
/// leader selection. Falls back to standard round-robin for view 1 when no
/// certificate is available.
///
/// This elector does not support stable leaders: it has no term-length
/// configuration and [`Elector::terms`] always returns [`Terms::rotating`].
///
/// Only works with [`super::scheme::bls12381_threshold::vrf`]
/// (implements [`super::scheme::bls12381_threshold::vrf::Seedable`]).
pub struct Random<V: Variant>(PhantomData<V>);

impl<V: Variant> Clone for Random<V> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<V: Variant> fmt::Debug for Random<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Random").finish()
    }
}

impl<V: Variant> Default for Random<V> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<V: Variant> Random<V> {
    /// Returns the selected leader index for the given round and seed signature.
    pub fn select_leader(
        round: Round,
        n: u32,
        seed_signature: Option<V::Signature>,
    ) -> Participant {
        assert!(seed_signature.is_some() || round.view() == View::new(1));

        let Some(seed_signature) = seed_signature else {
            // Standard round-robin for view 1
            let idx = round.epoch().get().wrapping_add(round.view().get()) % u64::from(n);
            return Participant::new(u32::try_from(idx).expect("leader index fits in u32"));
        };

        // Use the seed signature as a source of randomness
        Participant::new(modulo(seed_signature.encode().as_ref(), n as u64) as u32)
    }
}

impl<P, V> Config<P, VrfCertificate<P, V>> for Random<V>
where
    P: PublicKey,
    V: Variant,
{
    type Elector = RandomElector<bls12381_threshold_vrf::Scheme<P, V>>;

    fn build(self, participants: &Set<P>) -> RandomElector<bls12381_threshold_vrf::Scheme<P, V>> {
        assert!(!participants.is_empty(), "no participants");
        RandomElector {
            n: participants.len() as u32,
            _phantom: PhantomData,
        }
    }
}

/// Initialized random leader elector using threshold signature randomness.
///
/// Created via [`Random::build`].
#[derive(Clone, Debug)]
pub struct RandomElector<S: Scheme> {
    n: u32,
    _phantom: PhantomData<S>,
}

impl<P, V> Elector<VrfCertificate<P, V>> for RandomElector<bls12381_threshold_vrf::Scheme<P, V>>
where
    P: PublicKey,
    V: Variant,
{
    fn terms(&self) -> Terms {
        Terms::rotating()
    }

    fn elect(
        &self,
        round: Round,
        certificate: Option<&bls12381_threshold_vrf::Certificate<V>>,
    ) -> Participant {
        Random::<V>::select_leader(
            round,
            self.n,
            certificate.map(|c| {
                c.get()
                    .expect("verified certificate must decode")
                    .seed_signature
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::{bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519},
            types::Subject,
        },
        types::{Epoch, TermLength, View, ViewDelta},
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, certificate::mocks::Fixture,
        sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{Faults, N3f1, NZU32, TryFromIterator, test_rng};
    use std::time::Duration;

    const NAMESPACE: &[u8] = b"test";

    type ThresholdScheme =
        bls12381_threshold_vrf::Scheme<commonware_cryptography::ed25519::PublicKey, MinPk>;

    #[test]
    fn stable_terms_preserve_optimistic_views() {
        let stall = Duration::from_secs(1);
        let length = TermLength::new(NZU32!(5));

        // The configured lookahead is stored verbatim, including values wider
        // than the term (bounded by the issuance window, not by config) and
        // zero (optimistic validation disabled).
        for requested in [0, 3, 4, 5, 6, u64::MAX] {
            let terms = Terms::stable(length, stall, ViewDelta::new(requested));
            assert_eq!(terms.optimistic_views(), ViewDelta::new(requested));
        }
    }

    #[test]
    fn round_robin_rotates_through_participants() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 4);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len() as u32;
        let elector: RoundRobinElector =
            RoundRobin::<Sha256>::default().rotation(participants.len());
        let epoch = Epoch::new(0);

        // Run through 3 * n views, record the sequence of leaders
        let mut leaders = Vec::new();
        for view in 1..=(3 * n as u64) {
            let round = Round::new(epoch, View::new(view));
            leaders.push(elector.leader(round));
        }

        // Verify leaders cycle: consecutive leaders differ by 1 (mod n)
        for i in 0..leaders.len() - 1 {
            assert_eq!(Participant::new((leaders[i].get() + 1) % n), leaders[i + 1]);
        }
    }

    #[test]
    fn round_robin_cycles_through_epochs() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len();
        let elector: RoundRobinElector =
            RoundRobin::<Sha256>::default().rotation(participants.len());

        // Record leader for view 1 of epochs 0..n
        let leaders: Vec<_> = (0..n as u64)
            .map(|e| {
                let round = Round::new(Epoch::new(e), View::new(1));
                elector.leader(round)
            })
            .collect();

        // Each participant should be selected exactly once
        let mut seen = vec![false; n];
        for leader in &leaders {
            assert!(!seen[usize::from(*leader)]);
            seen[usize::from(*leader)] = true;
        }
        assert!(seen.iter().all(|x| *x));
    }

    #[test]
    fn round_robin_handles_wrapping_epoch_plus_term_index() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RoundRobinElector = RoundRobin::<Sha256>::default()
            .with_term(
                TermLength::new(NZU32!(5)),
                Duration::from_secs(10),
                ViewDelta::zero(),
            )
            .rotation(participants.len());

        let round = Round::new(Epoch::new(u64::MAX - 1), View::new(6));
        let term_idx = round.view().term_index(TermLength::new(NZU32!(5)));
        let expected = round.epoch().get().wrapping_add(term_idx) % 5;

        assert_eq!(elector.leader(round), Participant::new(expected as u32));
    }

    #[test]
    fn round_robin_uses_stable_leaders_within_terms() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 4);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RoundRobinElector = RoundRobin::<Sha256>::default()
            .with_term(
                TermLength::new(NZU32!(3)),
                Duration::from_secs(10),
                ViewDelta::zero(),
            )
            .rotation(participants.len());
        let epoch = Epoch::new(0);

        let leader_v1 = elector.leader(Round::new(epoch, View::new(1)));
        let leader_v2 = elector.leader(Round::new(epoch, View::new(2)));
        let leader_v3 = elector.leader(Round::new(epoch, View::new(3)));
        let leader_v4 = elector.leader(Round::new(epoch, View::new(4)));
        let leader_v5 = elector.leader(Round::new(epoch, View::new(5)));
        let leader_v6 = elector.leader(Round::new(epoch, View::new(6)));

        assert_eq!(leader_v1, leader_v2);
        assert_eq!(leader_v1, leader_v3);
        assert_eq!(leader_v4, leader_v5);
        assert_eq!(leader_v4, leader_v6);
        assert_ne!(leader_v1, leader_v4);
    }

    #[test]
    fn round_robin_epoch_transition_shifts_stable_term_leader() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 4);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RoundRobinElector = RoundRobin::<Sha256>::default()
            .with_term(
                TermLength::new(NZU32!(3)),
                Duration::from_secs(10),
                ViewDelta::zero(),
            )
            .rotation(participants.len());

        let leader_epoch_0 = elector.leader(Round::new(Epoch::new(0), View::new(1)));
        let leader_epoch_0_v2 = elector.leader(Round::new(Epoch::new(0), View::new(2)));
        let leader_epoch_1 = elector.leader(Round::new(Epoch::new(1), View::new(1)));
        let leader_epoch_1_v3 = elector.leader(Round::new(Epoch::new(1), View::new(3)));
        let leader_epoch_2 = elector.leader(Round::new(Epoch::new(2), View::new(1)));
        let leader_epoch_2_v2 = elector.leader(Round::new(Epoch::new(2), View::new(2)));

        assert_eq!(leader_epoch_0, Participant::new(1));
        assert_eq!(leader_epoch_0_v2, leader_epoch_0);
        assert_eq!(leader_epoch_1, Participant::new(2));
        assert_eq!(leader_epoch_1_v3, leader_epoch_1);
        assert_eq!(leader_epoch_2, Participant::new(3));
        assert_eq!(leader_epoch_2_v2, leader_epoch_2);
    }

    #[test]
    fn round_robin_shuffled_changes_order() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();

        let elector_no_seed: RoundRobinElector =
            RoundRobin::<Sha256>::default().rotation(participants.len());
        let elector_seed_1: RoundRobinElector =
            RoundRobin::<Sha256>::shuffled(b"seed1").rotation(participants.len());
        let elector_seed_2: RoundRobinElector =
            RoundRobin::<Sha256>::shuffled(b"seed2").rotation(participants.len());

        // Collect first 5 leaders from each
        let epoch = Epoch::new(0);
        let leaders_no_seed: Vec<_> = (1..=5)
            .map(|v| elector_no_seed.leader(Round::new(epoch, View::new(v))))
            .collect();
        let leaders_seed_1: Vec<_> = (1..=5)
            .map(|v| elector_seed_1.leader(Round::new(epoch, View::new(v))))
            .collect();
        let leaders_seed_2: Vec<_> = (1..=5)
            .map(|v| elector_seed_2.leader(Round::new(epoch, View::new(v))))
            .collect();

        // No seed should be identity permutation
        assert_eq!(
            leaders_no_seed,
            vec![
                Participant::new(1),
                Participant::new(2),
                Participant::new(3),
                Participant::new(4),
                Participant::new(0)
            ]
        );

        // Different seeds should produce different permutations
        assert_ne!(leaders_seed_1, leaders_no_seed);
        assert_ne!(leaders_seed_2, leaders_no_seed);
        assert_ne!(leaders_seed_1, leaders_seed_2);

        // Each permutation should still cover all participants
        for leaders in [&leaders_seed_1, &leaders_seed_2] {
            let mut sorted = leaders.clone();
            sorted.sort();
            assert_eq!(
                sorted,
                vec![
                    Participant::new(0),
                    Participant::new(1),
                    Participant::new(2),
                    Participant::new(3),
                    Participant::new(4)
                ]
            );
        }
    }

    #[test]
    fn round_robin_same_seed_is_deterministic() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();

        let elector1: RoundRobinElector =
            RoundRobin::<Sha256>::shuffled(b"same_seed").rotation(participants.len());
        let elector2: RoundRobinElector =
            RoundRobin::<Sha256>::shuffled(b"same_seed").rotation(participants.len());

        let epoch = Epoch::new(0);
        for view in 1..=10 {
            let round = Round::new(epoch, View::new(view));
            assert_eq!(elector1.leader(round), elector2.leader(round));
        }
    }

    #[test]
    #[should_panic(expected = "no participants")]
    fn round_robin_build_panics_on_empty_participants() {
        let participants: Set<commonware_cryptography::ed25519::PublicKey> = Set::default();
        let _: RoundRobinElector = RoundRobin::<Sha256>::default().rotation(participants.len());
    }

    #[test]
    fn random_falls_back_to_round_robin_for_view_1() {
        let mut rng = test_rng();
        let Fixture { participants, .. } =
            bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len();
        let elector: RandomElector<ThresholdScheme> =
            Random::<MinPk>::default().build(&participants);

        // For view 1 (no certificate), Random should behave like RoundRobin
        let leaders: Vec<_> = (0..n as u64)
            .map(|e| {
                let round = Round::new(Epoch::new(e), View::new(1));
                elector.elect(round, None)
            })
            .collect();

        // Each participant should be selected exactly once (same as RoundRobin)
        let mut seen = vec![false; n];
        for leader in &leaders {
            assert!(!seen[usize::from(*leader)]);
            seen[usize::from(*leader)] = true;
        }
        assert!(seen.iter().all(|x| *x));
    }

    #[test]
    fn random_fallback_does_not_truncate_before_modulo() {
        // Five participants make truncation observable:
        // 2^32 % 5 is 1, while (2^32 as u32) % 5 is 0
        let mut rng = test_rng();
        let Fixture { participants, .. } =
            bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let random: RandomElector<ThresholdScheme> =
            Random::<MinPk>::default().build(&participants);
        let round_robin: RoundRobinElector =
            RoundRobin::<Sha256>::default().rotation(participants.len());

        // View 1 exercises Random's round-robin fallback
        let round = Round::new(Epoch::new(u64::from(u32::MAX)), View::new(1));

        // Both electors must preserve the full u64 sum through the modulo
        assert_eq!(round_robin.leader(round), Participant::new(1));
        assert_eq!(random.elect(round, None), Participant::new(1));
    }

    #[test]
    fn random_uses_certificate_randomness() {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RandomElector<ThresholdScheme> =
            Random::<MinPk>::default().build(&participants);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        // Create certificate for round (1, 2)
        let round1 = Round::new(Epoch::new(1), View::new(2));
        let attestations1: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(Subject::Nullify { round: round1 })
                    .unwrap()
            })
            .collect();
        let cert1 = schemes[0].assemble(attestations1, &Sequential).unwrap();

        // Create certificate for round (1, 3) (different round -> different seed signature)
        let round2 = Round::new(Epoch::new(1), View::new(3));
        let attestations2: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(Subject::Nullify { round: round2 })
                    .unwrap()
            })
            .collect();
        let cert2 = schemes[0].assemble(attestations2, &Sequential).unwrap();

        // Same certificate always gives same leader
        let leader1a = elector.elect(round1, Some(&cert1));
        let leader1b = elector.elect(round1, Some(&cert1));
        assert_eq!(leader1a, leader1b);

        // Different certificates produce different leaders
        //
        // NOTE: In general, different certificates could produce the same leader by chance.
        // However, for our specific test inputs (rng seed 42, 5 participants), we've
        // verified these produce different results.
        let leader2 = elector.elect(round1, Some(&cert2));
        assert_ne!(leader1a, leader2);
    }

    #[test]
    #[should_panic(expected = "no participants")]
    fn random_build_panics_on_empty_participants() {
        let participants: Set<commonware_cryptography::ed25519::PublicKey> = Set::default();
        let _: RandomElector<ThresholdScheme> = Random::<MinPk>::default().build(&participants);
    }

    #[test]
    #[should_panic]
    fn random_panics_on_none_certificate_after_view_1() {
        let mut rng = test_rng();
        let Fixture { participants, .. } =
            bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RandomElector<ThresholdScheme> =
            Random::<MinPk>::default().build(&participants);

        // View 2 requires a certificate
        let round = Round::new(Epoch::new(1), View::new(2));
        elector.elect(round, None);
    }

    mod conformance {
        use super::*;
        use commonware_codec::{Encode, Write};
        use commonware_conformance::Conformance;
        use commonware_cryptography::Sha256;
        use rand::{RngExt as _, SeedableRng};
        use rand_chacha::ChaCha8Rng;

        /// Conformance test for shuffled RoundRobin leader election.
        ///
        /// Verifies that the permutation generated by `RoundRobin::shuffled`
        /// remains deterministic across versions. This is critical because
        /// changing the shuffle algorithm would cause consensus failures.
        struct RoundRobinShuffleConformance;

        impl Conformance for RoundRobinShuffleConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let mut rng = ChaCha8Rng::seed_from_u64(seed);

                // Generate deterministic participants (using ed25519 fixture)
                let n = rng.random_range(1..=100);
                let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, n);
                let participants = Set::try_from_iter(participants).unwrap();

                // Generate a random seed for shuffling
                let shuffle_seed: [u8; 32] = rng.random();

                // Build the shuffled elector
                let elector: RoundRobinElector =
                    RoundRobin::<Sha256>::shuffled(&shuffle_seed).rotation(participants.len());

                // Encode the permutation as the commitment
                elector.permutation().encode().to_vec()
            }
        }

        /// Conformance test for Random leader election.
        ///
        /// Verifies that `Random::select_leader` produces deterministic results
        /// given the same inputs. This tests the `modulo` function usage and
        /// threshold signature encoding for leader selection.
        struct RandomSelectLeaderConformance;

        impl Conformance for RandomSelectLeaderConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let mut rng = ChaCha8Rng::seed_from_u64(seed);

                // Generate deterministic BLS threshold fixture (4-10 participants)
                let n = rng.random_range(4..=10);
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, n);
                let participants = Set::try_from_iter(participants).unwrap();
                let elector: RandomElector<ThresholdScheme> =
                    Random::<MinPk>::default().build(&participants);
                let quorum = N3f1::quorum(schemes.len()) as usize;

                // Generate deterministic round parameters
                let epoch = rng.random_range(0..1000);
                let view = rng.random_range(2..=101);

                let round = Round::new(Epoch::new(epoch), View::new(view));

                // Create a valid threshold certificate
                let attestations: Vec<_> = schemes
                    .iter()
                    .take(quorum)
                    .map(|s| s.sign::<Sha256Digest>(Subject::Nullify { round }).unwrap())
                    .collect();
                let cert = schemes[0].assemble(attestations, &Sequential).unwrap();

                // Elect leader using the certificate
                let leader = elector.elect(round, Some(&cert));

                // Also test view 1 fallback (no certificate, round-robin)
                let round_v1 = Round::new(Epoch::new(epoch), View::new(1));
                let leader_v1 = elector.elect(round_v1, None);

                // Commit both results
                let mut result = leader.encode_mut();
                leader_v1.write(&mut result);
                result.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            RoundRobinShuffleConformance => 512,
            RandomSelectLeaderConformance => 512,
        }
    }
}
