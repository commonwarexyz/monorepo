//! Floor sampling shared by the stateful and DKG probes.
//!
//! [`stateful::probe`](crate::stateful::probe) and
//! [`dkg::probe`](crate::dkg::probe) both discover a floor by soliciting a
//! committee's latest finalizations and selecting the highest from `f + 1`
//! distinct replies. [`Sample`] owns the bookkeeping of that protocol: one
//! reply per peer, the fault-budget threshold, and selection of the highest
//! reply. Each probe keeps its own wire format, committee source,
//! minimum-epoch filter, verification, and peer blocking.

use commonware_consensus::{
    simplex::{
        marshal::{
            Identifier,
            core::{Mailbox as MarshalMailbox, Variant},
        },
        scheme::Scheme,
        types::Finalization,
    },
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
/// If at most `f` members of that committee are faulty, `f + 1` replies
/// include one from an honest member, so the selected floor is at least as
/// recent as that member's reply.
///
/// Callers must verify replies and enforce committee membership before
/// recording them, and judge at selection time which recorded replies are
/// usable (a reply becomes unjudgeable if its epoch's scheme is forgotten).
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

    /// Returns whether a reply from `peer` is still awaited: `false` once the
    /// floor is selected or after `peer` has contributed to the current request
    /// round.
    ///
    /// Callers should check this before decoding or verifying a reply, so a
    /// duplicate costs no verification and is never treated as a fault.
    pub(crate) fn awaits(&self, peer: &S::PublicKey) -> bool {
        self.floor.is_none() && !self.replies.contains_key(peer)
    }

    /// Records `finalization` as the reply of `peer`, keeping only the first
    /// reply from each peer in a request round.
    ///
    /// Callers must verify the reply and check that `peer` belongs to the
    /// solicited committee first. Callers should discard replies below
    /// [`Sample::minimum_epoch`] without treating them as faults: the chain has
    /// reached the minimum epoch, so such replies are stale rather than
    /// evidence of misbehavior.
    pub(crate) fn record(&mut self, peer: S::PublicKey, finalization: Finalization<S, D>) {
        self.replies.entry(peer).or_insert(finalization);
    }

    /// Discards the selected floor and all collected replies, starting a new
    /// request round.
    pub(crate) fn reset(&mut self) {
        self.replies.clear();
        self.floor = None;
    }

    /// Selects the highest judgeable reply once `f + 1` replies are judgeable,
    /// where `f` is derived from `committee_size`.
    ///
    /// Only replies for which `judgeable` returns `true` are counted or
    /// eligible. Returns the floor exactly once, when it is first selected, and
    /// `None` otherwise.
    pub(crate) fn select(
        &mut self,
        committee_size: usize,
        judgeable: impl Fn(&Finalization<S, D>) -> bool,
    ) -> Option<Finalization<S, D>> {
        if self.floor.is_some() {
            return None;
        }

        let (floor, count) =
            self.replies
                .values()
                .fold((None, 0usize), |(floor, count), finalization| {
                    if !judgeable(finalization) {
                        return (floor, count);
                    }
                    let floor = floor
                        .is_none_or(|candidate: &Finalization<S, D>| {
                            finalization.round() > candidate.round()
                        })
                        .then_some(finalization)
                        .or(floor);
                    (floor, count + 1)
                });
        let floor = floor?;
        if count < N3f1::max_faults(committee_size) as usize + 1 {
            return None;
        }

        self.floor = Some(floor.clone());
        self.floor.clone()
    }
}

/// Returns marshal's latest finalization, if any.
pub(crate) async fn latest_finalization<S, V>(
    marshal: &MarshalMailbox<S, V>,
) -> Option<Finalization<S, V::Commitment>>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    let (height, _) = marshal.get_info(Identifier::Latest).await?;
    marshal.get_finalization(height).await
}
