//! Shared floor-sampling primitives.
//!
//! [`stateful::probe`](crate::stateful::probe) and
//! [`dkg::probe`](crate::dkg::probe) both discover a floor by soliciting a
//! committee's latest finalizations and selecting the highest after replies
//! exceed the fault budget. [`Sample`] owns the bookkeeping of that protocol:
//! per-peer reply dedup, reply-mass accounting, and max-selection. Each
//! probe keeps its own wire format, committee source, minimum-epoch filter,
//! verification, and peer blocking.

use commonware_consensus::{
    marshal::{
        Identifier,
        core::{Mailbox as MarshalMailbox, Variant},
    },
    simplex::{scheme::Scheme, types::Finalization},
    types::Epoch,
};
use commonware_cryptography::Digest;
use std::collections::BTreeMap;

/// A fault-budget sample of a committee's latest finalizations.
///
/// The sample counts at most one reply per peer and resolves to the highest
/// reply once the mass of contributed replies exceeds the caller's fault
/// budget. Waiting for that threshold guarantees at least one reply comes from
/// an honest, current committee member, so the selected floor is at least as
/// recent as that member's latest finalization.
///
/// Callers verify replies and enforce committee membership before recording
/// them, and judge which recorded replies are currently usable at selection
/// time (a reply may become unjudgeable if its epoch's scheme is forgotten).
pub(crate) struct Sample<S, D>
where
    S: Scheme<D>,
    D: Digest,
{
    minimum_epoch: Epoch,
    replies: BTreeMap<S::PublicKey, Finalization<S, D>>,
    floor: Option<Finalization<S, D>>,
}

impl<S, D> Sample<S, D>
where
    S: Scheme<D>,
    D: Digest,
{
    /// Creates an empty sample that ignores replies below `minimum_epoch`.
    pub(crate) const fn new(minimum_epoch: Epoch) -> Self {
        Self {
            minimum_epoch,
            replies: BTreeMap::new(),
            floor: None,
        }
    }

    /// Returns the lower bound on accepted reply epochs.
    pub(crate) const fn minimum_epoch(&self) -> Epoch {
        self.minimum_epoch
    }

    /// Returns the selected floor, if the sample has resolved.
    pub(crate) const fn floor(&self) -> Option<&Finalization<S, D>> {
        self.floor.as_ref()
    }

    /// Returns whether a reply from `peer` is still awaited.
    ///
    /// A reply is not awaited once the floor is selected or after the peer has
    /// already contributed this request round; callers skip such replies
    /// before decoding or verifying them, so a duplicate can neither inflate
    /// the sample nor be treated as a fault.
    pub(crate) fn pending(&self, peer: &S::PublicKey) -> bool {
        self.floor.is_none() && !self.replies.contains_key(peer)
    }

    /// Records a verified reply from `peer`.
    ///
    /// Callers filter replies below [`Sample::minimum_epoch`] before decoding
    /// or verifying them: such replies are stale by definition (the chain
    /// reached the minimum epoch, so any current committee member holds a
    /// finalization at or above its boundary) but not proof of misbehavior.
    pub(crate) fn record(&mut self, peer: S::PublicKey, finalization: Finalization<S, D>) {
        self.replies.entry(peer).or_insert(finalization);
    }

    /// Clears collected replies for a new request round.
    pub(crate) fn reset(&mut self) {
        self.replies.clear();
    }

    /// Attempts to select the highest reply from a sample of distinct peers.
    ///
    /// Only replies for which `judgeable` returns true are counted or
    /// eligible: a recorded reply whose epoch can no longer be judged must not
    /// contribute to the sample. Selection requires judgeable replies whose
    /// total `mass` is at least `required_mass`. Returns the floor exactly
    /// once, when it is first selected.
    pub(crate) fn select(
        &mut self,
        required_mass: u64,
        mass: impl Fn(&S::PublicKey) -> u64,
        judgeable: impl Fn(&Finalization<S, D>) -> bool,
    ) -> Option<Finalization<S, D>> {
        if self.floor.is_some() {
            return None;
        }

        let (floor, reply_mass) =
            self.replies
                .iter()
                .fold((None, 0u64), |(floor, reply_mass), (peer, finalization)| {
                    if !judgeable(finalization) {
                        return (floor, reply_mass);
                    }
                    let floor = floor
                        .is_none_or(|candidate: &Finalization<S, D>| {
                            finalization.round() > candidate.round()
                        })
                        .then_some(finalization)
                        .or(floor);
                    (
                        floor,
                        reply_mass
                            .checked_add(mass(peer))
                            .expect("reply mass exceeds u64::MAX"),
                    )
                });
        let floor = floor?;
        if reply_mass < required_mass {
            return None;
        }

        self.floor = Some(floor.clone());
        self.floor.clone()
    }
}

/// Fetches the latest finalization from marshal, if available.
///
/// Both probes answer solicitations with this lookup while serving.
pub(crate) async fn latest_finalization<S, V>(
    marshal: &MarshalMailbox<S, V>,
) -> Option<Finalization<S, V::Commitment>>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    let (latest_height, _) = marshal.get_info(Identifier::Latest).await?;
    marshal.get_finalization(latest_height).await
}
