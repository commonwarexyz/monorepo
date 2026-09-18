//! Shared floor-sampling primitives.
//!
//! [`stateful::probe`](crate::stateful::probe) and
//! [`dkg::probe`](crate::dkg::probe) both discover a floor by soliciting a
//! committee's latest finalizations and selecting the highest from `f + 1`
//! distinct replies. [`Sample`] owns the bookkeeping of that protocol:
//! per-peer reply dedup, the fault-budget threshold, and max-selection. Each
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
use commonware_utils::{Faults, N3f1};
use std::collections::BTreeMap;

/// An `f + 1` sample of a committee's latest finalizations.
///
/// The sample counts at most one reply per peer and resolves to the highest
/// reply once `f + 1` distinct peers have contributed, where `f` is the
/// maximum fault count of the solicited committee under the `3f + 1` model.
/// Waiting for `f + 1` replies guarantees at least one comes from an honest,
/// current committee member, so the selected floor is at least as recent as
/// that member's latest finalization.
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
    /// contribute to the sample. Selection requires `f + 1` judgeable replies,
    /// where `f` is derived from `committee_size`. Returns the floor exactly
    /// once, when it is first selected.
    pub(crate) fn select(
        &mut self,
        committee_size: usize,
        judgeable: impl Fn(&Finalization<S, D>) -> bool,
    ) -> Option<Finalization<S, D>> {
        if self.floor.is_some() {
            return None;
        }

        let (floor, replies) =
            self.replies
                .values()
                .fold((None, 0usize), |(floor, replies), finalization| {
                    if !judgeable(finalization) {
                        return (floor, replies);
                    }
                    let floor = floor
                        .is_none_or(|candidate: &Finalization<S, D>| {
                            finalization.round() > candidate.round()
                        })
                        .then_some(finalization)
                        .or(floor);
                    (floor, replies + 1)
                });
        let floor = floor?;
        if replies < N3f1::max_faults(committee_size) as usize + 1 {
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
