//! The leader of a round, as the shards engine learns it before consensus names the round's
//! commitment.

use crate::{
    simplex::elector::{Config as ElectorConfig, Elector, Scheduled},
    types::{Epoch, Round},
};
use commonware_cryptography::certificate::{Provider, Scheme as _, Verifier};
use commonware_utils::{ordered::Quorum as _, sync::Mutex};
use std::sync::Arc;

/// Returns the leader of a round, or `None` while it is not known.
pub type RoundLeader<P> = Arc<dyn Fn(Round) -> Option<P> + Send + Sync>;

/// Returns a [`RoundLeader`] that elects each round's leader with `elector`, built over the
/// participants of the scheme `provider` returns for the round's epoch. The electors of the two
/// most recently asked epochs are kept, so the shards engine, which asks about rounds of the
/// current and the next epoch, builds each epoch's elector once.
///
/// `elector` must be configured as the consensus engine's elector is, so both name the same
/// leader. Only a [`Scheduled`] elector can name a leader before the round starts. A
/// [`Dynamic`](crate::simplex::elector::Dynamic) elector derives each leader from the certificate
/// that unlocks the round. The consensus engine holds that certificate, so a caller using such an
/// elector supplies a [`RoundLeader`] that answers `None` until it learns the leader.
pub fn scheduled_leader<L, Z>(
    elector: L,
    provider: Z,
) -> RoundLeader<<Z::Scheme as Verifier>::PublicKey>
where
    Z: Provider<Scope = Epoch>,
    L: ElectorConfig<Z::Scheme> + Sync,
    L::Elector: Elector<Z::Scheme, Mode = Scheduled>,
{
    // The electors of the two most recently asked epochs, the most recent first.
    let built = Mutex::new([None::<(Epoch, L::Elector)>, None]);
    Arc::new(move |round| {
        let epoch = round.epoch();
        let scheme = provider.scheme(epoch)?;
        let participants = scheme.participants();
        let mut built = built.lock();
        let position = built
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|(kept, _)| *kept == epoch));
        if position != Some(0) {
            built.swap(0, 1);
        }
        if position.is_none() {
            built[0] = Some((epoch, elector.clone().build(participants)));
        }
        let (_, scheduled) = built[0]
            .as_ref()
            .expect("the asked epoch's elector must be built");
        participants.key(scheduled.elect(round, ())).cloned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{elector::RoundRobin, scheme::ed25519},
        types::View,
    };
    use commonware_cryptography::{
        Sha256, Signer as _,
        certificate::ConstantProvider,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::ordered::Set;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A [`RoundRobin`] configuration that counts the electors built from it.
    #[derive(Clone)]
    struct Counting {
        inner: RoundRobin<Sha256>,
        builds: Arc<AtomicUsize>,
    }

    impl ElectorConfig<ed25519::Scheme> for Counting {
        type Elector = <RoundRobin<Sha256> as ElectorConfig<ed25519::Scheme>>::Elector;

        fn build(self, participants: &Set<PublicKey>) -> Self::Elector {
            self.builds.fetch_add(1, Ordering::Relaxed);
            ElectorConfig::<ed25519::Scheme>::build(self.inner, participants)
        }
    }

    /// The helper names the leader the elector names for every round, across epochs, and keeps the
    /// electors of the two most recently asked epochs, so rounds that alternate between two epochs
    /// build each epoch's elector once.
    #[test]
    fn scheduled_leader_matches_elector() {
        // A five-member committee signs every epoch.
        let keys: Vec<_> = (0..5).map(PrivateKey::from_seed).collect();
        let participants = Set::from_iter_dedup(keys.iter().map(|key| key.public_key()));
        let scheme = ed25519::Scheme::signer(
            b"_COMMONWARE_CONSENSUS_SHARDS_LEADER_TEST",
            participants.clone(),
            keys[0].clone(),
        )
        .expect("the signer must be a participant");

        // The helper and a directly built elector share one round-robin configuration.
        let elector = RoundRobin::<Sha256>::default();
        let builds = Arc::new(AtomicUsize::new(0));
        let counting = Counting {
            inner: elector.clone(),
            builds: builds.clone(),
        };
        let leader = scheduled_leader(counting, ConstantProvider::<_, Epoch>::new(scheme));
        let built = ElectorConfig::<ed25519::Scheme>::build(elector, &participants);

        // Both name the same leader for every round of three epochs. Rounds alternate between
        // epochs 0 and 1 and then between epochs 0 and 2, and each epoch's elector is built once.
        for epoch in [0, 1, 0, 1, 0, 2, 0] {
            for view in 1..8 {
                let round = Round::new(Epoch::new(epoch), View::new(view));
                let expected = participants.key(built.elect(round, ())).cloned();
                assert!(expected.is_some());
                assert_eq!(leader(round), expected);
            }
        }
        assert_eq!(builds.load(Ordering::Relaxed), 3);
    }
}
