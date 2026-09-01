//! Objective equivocation detection over authenticated protocol claims.
//!
//! Each newly proven participant is reported once and quarantined through
//! [`Capability::Quarantine`](super::Capability::Quarantine), which the voter executes by blocking
//! the participant at the network layer.

use super::util::retire_prefix;
use crate::{
    Viewable as _,
    multimmit::{
        algebra::CertificateDerivations,
        types::{Artifact, BlockRef, ChainId, TransactionBlockHeader, VoteBody},
    },
    types::{Attributable as _, Height, Participant, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// The first authenticated claims of one signer in one view.
#[derive(Clone, Debug)]
struct ViewClaims<D: Digest> {
    /// The digest of the leader block the signer proposed.
    leader: Option<D>,
    /// The vote body the signer signed.
    vote: Option<VoteBody<D>>,
    /// Whether the signer signed a no-vote.
    novote: bool,
}

impl<D: Digest> Default for ViewClaims<D> {
    fn default() -> Self {
        Self {
            leader: None,
            vote: None,
            novote: false,
        }
    }
}

/// Bounded evidence retained only long enough to compare live authenticated claims.
///
/// Faults are proven by two authenticated claims of one signer that cannot both be honest: two
/// leader blocks, two votes, or a vote and a novote for one view, and two headers for one producer
/// height or a header that does not extend its neighbor. Each newly proven participant is reported
/// once, for the network blocker.
pub(super) struct AccountabilityState<D: Digest> {
    views: BTreeMap<(View, Participant), ViewClaims<D>>,
    producer: BTreeMap<(ChainId, Height), TransactionBlockHeader<D>>,
    producer_order: VecDeque<(ChainId, Height)>,
    /// The most producer headers retained; the oldest is evicted first.
    producer_capacity: usize,
    faulted: BTreeSet<Participant>,
}

impl<D: Digest> AccountabilityState<D> {
    /// Creates empty state retaining at most `producer_capacity` producer headers.
    pub(super) const fn new(producer_capacity: usize) -> Self {
        Self {
            views: BTreeMap::new(),
            producer: BTreeMap::new(),
            producer_order: VecDeque::new(),
            producer_capacity,
            faulted: BTreeSet::new(),
        }
    }

    /// Records one verified artifact and any complete vote transcript authenticated with it.
    pub(super) fn observe<H: Hasher<Digest = D>, V: Variant>(
        &mut self,
        artifact: &Artifact<V, D>,
        derivations: Option<&CertificateDerivations<V, D>>,
    ) -> Vec<Participant> {
        let mut proven = BTreeSet::new();
        match artifact {
            Artifact::TransactionBlock(block) => {
                self.observe_producer_header::<H>(block.signer(), block.header(), &mut proven);
            }
            Artifact::LeaderBlock(block) => {
                let signer = block.signer();
                let digest = block.block().digest::<H>();
                let claims = self.views.entry((block.view(), signer)).or_default();
                if claims.leader.is_some_and(|prior| prior != digest) {
                    proven.insert(signer);
                }
                claims.leader.get_or_insert(digest);
            }
            Artifact::Vote(vote) => {
                self.observe_vote(vote.signer(), vote.body(), &mut proven);
            }
            Artifact::NoVote(novote) => {
                self.observe_novote(novote.signer(), novote.view(), &mut proven);
            }
            Artifact::Vqc(certificate) => {
                for signer in certificate.novoters().iter() {
                    self.observe_novote(signer, certificate.view(), &mut proven);
                }
            }
            Artifact::DaVote(_)
            | Artifact::DaCertificate(_)
            | Artifact::Nullify(_)
            | Artifact::Nullification(_)
            | Artifact::Lqc(_) => {}
        }
        if let Some(derivations) = derivations {
            for vote in derivations.votes() {
                self.observe_vote(vote.signer, &vote.body, &mut proven);
            }
        }
        proven
            .into_iter()
            .filter(|participant| self.faulted.insert(*participant))
            .collect()
    }

    /// Records a proven fault found elsewhere, such as two DA shares verified off-thread, and
    /// returns whether it is new.
    pub(super) fn record_fault(&mut self, participant: Participant) -> bool {
        self.faulted.insert(participant)
    }

    /// Drops view claims at or below `view` and producer headers more than one height below each
    /// chain's certified tip in `floors`.
    ///
    /// The header just below a tip is kept so a conflicting header at the tip's height can still
    /// be checked against the parent it must extend.
    pub(super) fn retire(&mut self, view: View, floors: &[BlockRef<D>]) {
        retire_prefix(&mut self.views, |(claim_view, _)| *claim_view <= view);
        let retained = self.producer.len();
        for floor in floors {
            let chain = floor.chain();
            let first = floor.height().previous().unwrap_or_else(Height::zero);
            self.producer
                .extract_if((chain, Height::zero())..(chain, first), |_, _| true)
                .for_each(drop);
        }
        if self.producer.len() != retained {
            self.producer_order
                .retain(|slot| self.producer.contains_key(slot));
        }
    }

    fn observe_producer_header<H: Hasher<Digest = D>>(
        &mut self,
        signer: Participant,
        header: &TransactionBlockHeader<D>,
        proven: &mut BTreeSet<Participant>,
    ) {
        let slot = (header.chain(), header.height());
        if self
            .producer
            .get(&slot)
            .is_some_and(|prior| prior != header)
        {
            proven.insert(signer);
        }
        if let Some(previous) = header.height().previous()
            && self
                .producer
                .get(&(header.chain(), previous))
                .is_some_and(|parent| parent.digest::<H>() != header.parent())
        {
            proven.insert(signer);
        }
        if let Some(next) = header.height().get().checked_add(1).map(Height::new)
            && let Some(child) = self.producer.get(&(header.chain(), next))
            && child.parent() != header.digest::<H>()
        {
            proven.insert(signer);
        }
        if !self.producer.contains_key(&slot) {
            if self.producer.len() >= self.producer_capacity
                && let Some(evicted) = self.producer_order.pop_front()
            {
                self.producer.remove(&evicted);
            }
            self.producer.insert(slot, header.clone());
            self.producer_order.push_back(slot);
        }
    }

    fn observe_vote(
        &mut self,
        signer: Participant,
        body: &VoteBody<D>,
        proven: &mut BTreeSet<Participant>,
    ) {
        let claims = self.views.entry((body.view(), signer)).or_default();
        if claims.novote || claims.vote.as_ref().is_some_and(|prior| prior != body) {
            proven.insert(signer);
        }
        claims.vote.get_or_insert_with(|| body.clone());
    }

    fn observe_novote(
        &mut self,
        signer: Participant,
        view: View,
        proven: &mut BTreeSet<Participant>,
    ) {
        let claims = self.views.entry((view, signer)).or_default();
        if claims.vote.is_some() {
            proven.insert(signer);
        }
        claims.novote = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Epoch;
    use commonware_cryptography::{Sha256, sha256};

    #[test]
    fn retirement_preserves_live_claims_and_producer_order() {
        let digest = Sha256::hash(&[b"claim"]);
        let mut state = AccountabilityState::<sha256::Digest>::new(usize::MAX);
        for view in [0, 1, 2, u64::MAX] {
            state.views.insert(
                (View::new(view), Participant::new(0)),
                ViewClaims::default(),
            );
        }
        let mut insertion_order = VecDeque::new();
        for height in (1..=7).rev() {
            for chain in 0..3 {
                let slot = (ChainId::new(chain), Height::new(height));
                let header =
                    TransactionBlockHeader::new(Epoch::zero(), slot.0, slot.1, digest, digest)
                        .unwrap();
                state.producer.insert(slot, header);
                insertion_order.push_back(slot);
            }
        }
        state.producer_order = insertion_order.clone();
        let floors = [0, 3, 6].map(Height::new);
        let tips: Vec<_> = floors
            .iter()
            .enumerate()
            .map(|(chain, height)| BlockRef::new(ChainId::new(chain as u32), *height, digest))
            .collect();
        let expected: VecDeque<_> = insertion_order
            .into_iter()
            .filter(|(chain, height)| height.get() >= [0, 2, 5][chain.index()])
            .collect();
        for _ in 0..2 {
            state.retire(View::new(1), &tips);
            assert_eq!(
                state
                    .views
                    .keys()
                    .map(|(view, _)| view.get())
                    .collect::<Vec<_>>(),
                [2, u64::MAX]
            );
            assert_eq!(state.producer_order, expected);
            assert_eq!(
                state.producer.keys().copied().collect::<BTreeSet<_>>(),
                expected.iter().copied().collect()
            );
        }
        state
            .views
            .insert((View::zero(), Participant::new(0)), ViewClaims::default());
        state.retire(View::new(1), &tips);
        assert_eq!(state.views.len(), 2);
        state.retire(View::new(u64::MAX), &tips);
        assert!(state.views.is_empty());
    }
}
