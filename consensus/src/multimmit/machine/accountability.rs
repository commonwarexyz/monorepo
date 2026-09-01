//! Objective equivocation detection over authenticated protocol claims.

use super::{Artifact, finality::CertificateDerivations};
use crate::{
    Viewable as _,
    multimmit::types::{ChainId, Height, TransactionBlockHeader, VoteBody},
    types::{Attributable as _, Participant, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug)]
struct ViewClaims<D: Digest> {
    leader: Option<D>,
    vote: Option<VoteBody<D>>,
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
pub(super) struct AccountabilityState<D: Digest> {
    views: BTreeMap<(View, Participant), ViewClaims<D>>,
    producer: BTreeMap<(ChainId, Height), TransactionBlockHeader<D>>,
    producer_order: VecDeque<(ChainId, Height)>,
    faulted: BTreeSet<Participant>,
}

impl<D: Digest> AccountabilityState<D> {
    pub(super) const fn new() -> Self {
        Self {
            views: BTreeMap::new(),
            producer: BTreeMap::new(),
            producer_order: VecDeque::new(),
            faulted: BTreeSet::new(),
        }
    }

    /// Records one verified artifact and any complete vote transcript authenticated with it.
    pub(super) fn observe<H: Hasher<Digest = D>, V: Variant>(
        &mut self,
        artifact: &Artifact<V, D>,
        derivations: Option<&CertificateDerivations<V, D>>,
        producer_capacity: usize,
    ) -> Vec<Participant> {
        let mut proven = BTreeSet::new();
        match artifact {
            Artifact::TransactionBlock(block) => {
                let signer = block.signer();
                let header = block.header();
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
                    if self.producer.len() >= producer_capacity
                        && let Some(evicted) = self.producer_order.pop_front()
                    {
                        self.producer.remove(&evicted);
                    }
                    self.producer.insert(slot, header.clone());
                    self.producer_order.push_back(slot);
                }
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
            .filter(|participant| self.mark_fault(*participant))
            .collect()
    }

    /// Records a signer whose two DA shares were individually verified off-thread.
    pub(super) fn observe_da_equivocator(&mut self, participant: Participant) -> bool {
        self.mark_fault(participant)
    }

    pub(super) fn retire(&mut self, view: View, floors: &[crate::multimmit::types::BlockRef<D>]) {
        self.views.retain(|(claim_view, _), _| *claim_view > view);
        self.producer.retain(|(chain, height), _| {
            let floor = floors[chain.get() as usize].height();
            *height >= floor.previous().unwrap_or_else(Height::zero)
        });
        self.producer_order
            .retain(|slot| self.producer.contains_key(slot));
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

    fn mark_fault(&mut self, participant: Participant) -> bool {
        self.faulted.insert(participant)
    }
}
