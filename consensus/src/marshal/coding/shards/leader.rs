//! The leader of a round, as the shards engine learns it before the round's proposal.

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
/// participants of the scheme `provider` returns for the round's epoch.
///
/// `elector` must be configured as the consensus engine's elector is, so both name the same
/// leader. Only a [`Scheduled`] elector can name a leader before the round starts. A
/// [`Dynamic`](crate::simplex::elector::Dynamic) elector derives each leader from the certificate
/// that unlocks the round, which the consensus engine holds, so a caller using one supplies a
/// [`RoundLeader`] that answers `None` until it learns the leader.
pub fn scheduled_leader<L, Z>(
    elector: L,
    provider: Z,
) -> RoundLeader<<Z::Scheme as Verifier>::PublicKey>
where
    Z: Provider<Scope = Epoch>,
    L: ElectorConfig<Z::Scheme> + Sync,
    L::Elector: Elector<Z::Scheme, Mode = Scheduled>,
{
    // Building an elector can cost a pass over the participants, so the elector of the latest
    // epoch asked about is kept.
    let built: Mutex<Option<(Epoch, L::Elector)>> = Mutex::new(None);
    Arc::new(move |round| {
        let scheme = provider.scheme(round.epoch())?;
        let participants = scheme.participants();
        let mut built = built.lock();
        if built
            .as_ref()
            .is_none_or(|(epoch, _)| *epoch != round.epoch())
        {
            *built = Some((round.epoch(), elector.clone().build(participants)));
        }
        let (_, elector) = built.as_ref().expect("elector was built for the epoch");
        participants.key(elector.elect(round, ())).cloned()
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
        Sha256, Signer as _, certificate::ConstantProvider, ed25519::PrivateKey,
    };
    use commonware_utils::ordered::Set;

    /// The helper names the leader the elector names for every round, across epochs.
    #[test]
    fn scheduled_leader_matches_elector() {
        let keys: Vec<_> = (0..5).map(PrivateKey::from_seed).collect();
        let participants = Set::from_iter_dedup(keys.iter().map(|key| key.public_key()));
        let scheme = ed25519::Scheme::signer(
            b"_COMMONWARE_CONSENSUS_SHARDS_LEADER_TEST",
            participants.clone(),
            keys[0].clone(),
        )
        .expect("signer must be a participant");
        let elector = RoundRobin::<Sha256>::default();
        let leader = scheduled_leader(elector.clone(), ConstantProvider::<_, Epoch>::new(scheme));
        let built = ElectorConfig::<ed25519::Scheme>::build(elector, &participants);
        for epoch in 0..3 {
            for view in 1..8 {
                let round = Round::new(Epoch::new(epoch), View::new(view));
                let expected = participants.key(built.elect(round, ())).cloned();
                assert!(expected.is_some());
                assert_eq!(leader(round), expected);
            }
        }
    }
}
