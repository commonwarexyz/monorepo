//! Leader election strategies for simplex consensus.
//!
//! This module provides the [`Elector`] trait for customizing how leaders are selected
//! for each consensus round, along with built-in implementations.
//!
//! # Built-in Electors
//!
//! - [`RoundRobin`]: Deterministic rotation through participants based on view number.
//!   Optionally shuffled using a seed. Works with any signing scheme.
//!
//! - [`Random`]: Uses randomness derived from BLS threshold signatures for unpredictable
//!   leader selection. Falls back to round-robin for the first view (no certificate available).
//!   Only works with [`bls12381_threshold`].
//!
//! # Custom Electors
//!
//! Applications can implement [`Elector`] for custom leader selection logic such as
//! stake-weighted selection or other application-specific strategies.

use crate::{
    simplex::scheme::bls12381_threshold,
    types::{Round, View},
};
use commonware_codec::Encode;
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, certificate::Scheme, Blake3, Hasher, PublicKey,
};
use commonware_utils::{modulo, ordered::Set};
use std::marker::PhantomData;

/// Selects leaders for consensus rounds.
///
/// Electors are created externally (with optional configuration like a seed), then
/// initialized by consensus with the participant set.
///
/// # Lifecycle
///
/// 1. Create elector externally via `Default::default()` or a custom constructor
/// 2. Pass to simplex configuration
/// 3. Consensus calls [`initialize`](Elector::initialize) with participants
/// 4. Consensus calls [`elect`](Elector::elect) for each round
///
/// # Determinism Requirement
///
/// Implementations **must** be deterministic: given the same construction parameters
/// and the same inputs to [`elect`](Elector::elect), the method must always return
/// the same leader index. This is critical for consensus correctness - all honest
/// participants must agree on the leader for each round.
///
/// # Certificate Handling
///
/// The `certificate` parameter is `None` only for view 1 (the first view after genesis).
/// For all subsequent views, a certificate from the previous view is provided. Implementations
/// can use the certificate to derive randomness (like [`Random`]) or ignore it entirely
/// (like [`RoundRobin`]).
pub trait Elector<S: Scheme>: Clone + Default + Send + 'static {
    /// Initializes the elector with the participant set.
    ///
    /// Called by consensus before any [`elect`](Elector::elect) calls.
    ///
    /// # Panics
    ///
    /// Implementations should panic if `participants` is empty.
    fn initialize(&mut self, participants: &Set<S::PublicKey>);

    /// Selects the leader for the given round.
    ///
    /// Must be called after [`initialize`](Elector::initialize). This method
    /// **must** be a pure function given the elector's construction and
    /// initialization state.
    ///
    /// The `certificate` is expected to be `None` only for view 1.
    ///
    /// # Panics
    ///
    /// Implementations should panic if called before [`initialize`](Elector::initialize).
    ///
    /// Returns the index of the selected leader in the participants list.
    fn elect(&self, round: Round, certificate: Option<&S::Certificate>) -> u32;
}

/// Simple round-robin leader election.
///
/// Rotates through participants based on `(epoch + view) % num_participants`.
/// The rotation order can be shuffled at construction using a seed.
///
/// Works with any signing scheme.
#[derive(Clone, Debug)]
pub struct RoundRobin<S: Scheme, H: Hasher = Blake3> {
    seed: Option<Vec<u8>>,
    permutation: Vec<u32>,
    _phantom: PhantomData<(S, H)>,
}

impl<S: Scheme, H: Hasher> Default for RoundRobin<S, H> {
    fn default() -> Self {
        Self {
            seed: None,
            permutation: Vec::new(),
            _phantom: PhantomData,
        }
    }
}

impl<S: Scheme, H: Hasher> RoundRobin<S, H> {
    /// Creates a round-robin elector that will shuffle the rotation order based on seed.
    ///
    /// The seed is stored and used during [`initialize`](Elector::initialize) to
    /// deterministically shuffle the permutation.
    pub fn shuffled(seed: &[u8]) -> Self {
        Self {
            seed: Some(seed.to_vec()),
            permutation: Vec::new(),
            _phantom: PhantomData,
        }
    }
}

impl<S: Scheme, H: Hasher> Elector<S> for RoundRobin<S, H> {
    fn initialize(&mut self, participants: &Set<S::PublicKey>) {
        assert!(!participants.is_empty(), "no participants");

        self.permutation = (0..participants.len() as u32).collect();

        if let Some(seed) = &self.seed {
            let mut hasher = H::new();
            self.permutation.sort_by_key(|&index| {
                hasher.update(seed);
                hasher.update(&index.encode());
                hasher.finalize()
            });
        }
    }

    fn elect(&self, round: Round, _certificate: Option<&S::Certificate>) -> u32 {
        assert!(!self.permutation.is_empty(), "elector not initialized");

        let n = self.permutation.len();
        let idx = (round.epoch().get().wrapping_add(round.view().get())) as usize % n;
        self.permutation[idx]
    }
}

/// Leader election using threshold signature randomness.
///
/// Uses the seed signature from BLS threshold certificates to derive unpredictable
/// leader selection. Falls back to standard round-robin for view 1 when no
/// certificate is available.
///
/// Only works with [`bls12381_threshold`] signing scheme.
#[derive(Clone, Debug)]
pub struct Random<P: PublicKey, V: Variant> {
    n: usize,
    _phantom: PhantomData<(P, V)>,
}

impl<P: PublicKey, V: Variant> Default for Random<P, V> {
    fn default() -> Self {
        Self {
            n: 0,
            _phantom: PhantomData,
        }
    }
}

impl<P, V> Elector<bls12381_threshold::Scheme<P, V>> for Random<P, V>
where
    P: PublicKey,
    V: Variant + Send + Sync + 'static,
{
    fn initialize(&mut self, participants: &Set<P>) {
        assert!(!participants.is_empty(), "no participants");
        self.n = participants.len();
    }

    fn elect(&self, round: Round, certificate: Option<&bls12381_threshold::Signature<V>>) -> u32 {
        assert!(self.n > 0, "elector not initialized");
        assert!(certificate.is_some() || round.view() == View::new(1));

        let Some(certificate) = certificate else {
            // Standard round-robin for view 1
            return (round.epoch().get().wrapping_add(round.view().get()) as usize % self.n) as u32;
        };

        // Use the seed signature as a source of randomness
        let seed = certificate.seed_signature.encode();
        modulo(seed.as_ref(), self.n as u64) as u32
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
        types::{Epoch, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, certificate::mocks::Fixture,
        sha256::Digest as Sha256Digest, Blake3,
    };
    use commonware_utils::{quorum_from_slice, TryFromIterator};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn round_robin_rotates_through_participants() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, 4);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len();
        let mut elector = RoundRobin::<ed25519::Scheme>::default();
        elector.initialize(&participants);
        let epoch = Epoch::new(0);

        // Run through 3 * n views, record the sequence of leaders
        let mut leaders = Vec::new();
        for view in 1..=(3 * n as u64) {
            let round = Round::new(epoch, View::new(view));
            leaders.push(elector.elect(round, None));
        }

        // Verify leaders cycle: consecutive leaders differ by 1 (mod n)
        for i in 0..leaders.len() - 1 {
            assert_eq!((leaders[i] + 1) % n as u32, leaders[i + 1]);
        }
    }

    #[test]
    fn round_robin_cycles_through_epochs() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len();
        let mut elector = RoundRobin::<ed25519::Scheme>::default();
        elector.initialize(&participants);

        // Record leader for view 1 of epochs 0..n
        let leaders: Vec<_> = (0..n as u64)
            .map(|e| {
                let round = Round::new(Epoch::new(e), View::new(1));
                elector.elect(round, None)
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
    fn round_robin_shuffled_changes_order() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, 5);
        let participants = Set::try_from_iter(participants).unwrap();

        let mut elector_no_seed = RoundRobin::<ed25519::Scheme>::default();
        elector_no_seed.initialize(&participants);
        let mut elector_seed_1 = RoundRobin::<ed25519::Scheme, Blake3>::shuffled(b"seed1");
        elector_seed_1.initialize(&participants);
        let mut elector_seed_2 = RoundRobin::<ed25519::Scheme, Blake3>::shuffled(b"seed2");
        elector_seed_2.initialize(&participants);

        // Collect first 5 leaders from each
        let epoch = Epoch::new(0);
        let leaders_no_seed: Vec<_> = (1..=5)
            .map(|v| elector_no_seed.elect(Round::new(epoch, View::new(v)), None))
            .collect();
        let leaders_seed_1: Vec<_> = (1..=5)
            .map(|v| elector_seed_1.elect(Round::new(epoch, View::new(v)), None))
            .collect();
        let leaders_seed_2: Vec<_> = (1..=5)
            .map(|v| elector_seed_2.elect(Round::new(epoch, View::new(v)), None))
            .collect();

        // No seed should be identity permutation
        assert_eq!(leaders_no_seed, vec![1, 2, 3, 4, 0]);

        // Different seeds should produce different permutations
        assert_ne!(leaders_seed_1, leaders_no_seed);
        assert_ne!(leaders_seed_2, leaders_no_seed);
        assert_ne!(leaders_seed_1, leaders_seed_2);

        // Each permutation should still cover all participants
        for leaders in [&leaders_seed_1, &leaders_seed_2] {
            let mut sorted = leaders.clone();
            sorted.sort();
            assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
        }
    }

    #[test]
    fn round_robin_same_seed_is_deterministic() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, 5);
        let participants = Set::try_from_iter(participants).unwrap();

        let mut elector1 = RoundRobin::<ed25519::Scheme, Blake3>::shuffled(b"same_seed");
        elector1.initialize(&participants);
        let mut elector2 = RoundRobin::<ed25519::Scheme, Blake3>::shuffled(b"same_seed");
        elector2.initialize(&participants);

        let epoch = Epoch::new(0);
        for view in 1..=10 {
            let round = Round::new(epoch, View::new(view));
            assert_eq!(elector1.elect(round, None), elector2.elect(round, None));
        }
    }

    #[test]
    #[should_panic(expected = "no participants")]
    fn round_robin_initialize_panics_on_empty_participants() {
        let participants: Set<commonware_cryptography::ed25519::PublicKey> = Set::default();
        let mut elector = RoundRobin::<ed25519::Scheme>::default();
        elector.initialize(&participants);
    }

    #[test]
    #[should_panic(expected = "elector not initialized")]
    fn round_robin_elect_panics_when_not_initialized() {
        let elector = RoundRobin::<ed25519::Scheme>::default();
        let round = Round::new(Epoch::new(0), View::new(1));
        elector.elect(round, None);
    }

    #[test]
    fn random_falls_back_to_round_robin_for_view_1() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { participants, .. } = bls12381_threshold::fixture::<MinPk, _>(&mut rng, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len();
        let mut elector = Random::<_, MinPk>::default();
        elector.initialize(&participants);

        // For view 1 (no certificate), Random should behave like RoundRobin
        let leaders: Vec<_> = (0..n as u64)
            .map(|e| {
                let round = Round::new(Epoch::new(e), View::new(1));
                elector.elect(round, None)
            })
            .collect();

        // Each participant should be selected exactly once (same as RoundRobin)
        let mut seen = vec![false; n];
        for &leader in &leaders {
            assert!(!seen[leader as usize]);
            seen[leader as usize] = true;
        }
        assert!(seen.iter().all(|x| *x));
    }

    #[test]
    fn random_uses_certificate_randomness() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold::fixture::<MinPk, _>(&mut rng, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let mut elector = Random::<_, MinPk>::default();
        elector.initialize(&participants);
        let quorum = quorum_from_slice(&schemes) as usize;

        // Create certificate for round (1, 2)
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

        // Create certificate for round (1, 3) (different round -> different seed signature)
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
    fn random_initialize_panics_on_empty_participants() {
        let participants: Set<commonware_cryptography::ed25519::PublicKey> = Set::default();
        let mut elector = Random::<_, MinPk>::default();
        elector.initialize(&participants);
    }

    #[test]
    #[should_panic]
    fn random_panics_on_none_certificate_after_view_1() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { participants, .. } = bls12381_threshold::fixture::<MinPk, _>(&mut rng, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let mut elector = Random::<_, MinPk>::default();
        elector.initialize(&participants);

        // View 2 requires a certificate
        let round = Round::new(Epoch::new(1), View::new(2));
        elector.elect(round, None);
    }

    #[test]
    #[should_panic(expected = "elector not initialized")]
    fn random_elect_panics_when_not_initialized() {
        let elector = Random::<commonware_cryptography::ed25519::PublicKey, MinPk>::default();
        let round = Round::new(Epoch::new(0), View::new(1));
        elector.elect(round, None);
    }
}
