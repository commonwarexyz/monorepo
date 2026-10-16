//! Leader blocks: this node's proposal as a view's leader, and the proposals it votes for.
//!
//! The leader of view `v` proposes once, on entering `v`: the leader block `(v, H(Q'), C(Q'))`
//! naming the V-QC `Q'` of view `v - 1` it entered on and that V-QC's tips-history commitment.
//! The block's signature goes through a durable signing reservation, which records the view's
//! leader-block slot, so a leader never signs two blocks for one view.
//!
//! A received leader block of view `u` is valid when it is the only one this node holds from
//! `lead(u)` for `u`, names a V-QC of view `u - 1` held with its whole parent chain, and carries
//! that V-QC's commitment. A wrong commitment is a faulty leader: nothing is voted for, and the
//! view ends on count or on the grace without a leader. Two different blocks from the leader of one
//! view make neither valid.
//!
//! Leader blocks are read for views `[v - 1, v + 1]` around the current view `v`. A block of the
//! next view waits for its parent V-QC, the one this node will enter on; a block of the current
//! view is voted for until the view's V-QC arrives; a block of the previous view is only evidence
//! that this node's leaderless final vote for it was too early, which widens the grace.

use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::Role,
        machine::{
            capability::Capability,
            chain::is_capacity,
            durability::{DurableEffect, ProposalParent, ProposalRequest, SignRequest},
            input::{Rejection, StepError},
            reducer::{
                components::{Precheck, WorkResult, WorkStatus},
                machine::Machine,
            },
            resolution::RetrievalKey,
            scheduler::ProtocolComponent,
        },
        types::{Artifact, BlockRef, CertificateId, EpochGenesis, LeaderBlock, SignedLeaderBlock},
    },
    types::{Attributable as _, Round, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// The tips of a V-QC, one per chain: the base of a leader block naming it.
pub(crate) type Tips<D> = Arc<[BlockRef<D>]>;

/// A V-QC this node holds with its whole parent chain, as a leader block names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeldVqc<D: Digest> {
    /// The V-QC's view; zero for the genesis V-QC.
    pub(crate) view: View,
    /// The V-QC's identifier `H(Q)`.
    pub(crate) id: CertificateId<D>,
    /// The tips-history commitment `C(Q)` of the V-QC's chain.
    pub(crate) history: D,
    /// The V-QC's tips `Tips(Q)`.
    pub(crate) tips: Tips<D>,
}

impl<D: Digest> HeldVqc<D> {
    /// Returns the epoch's genesis V-QC, which every validator holds.
    pub(crate) fn genesis(genesis: &EpochGenesis<D>) -> Self {
        Self {
            view: View::zero(),
            id: genesis.vqc(),
            history: genesis.history(),
            tips: genesis.tips().into(),
        }
    }
}

/// What this node holds of the leader blocks of one view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Proposal<D: Digest> {
    /// One leader block, valid, with its digest, its parent `Q'`, and its base `Tips(Q')`.
    Valid {
        block: D,
        parent: CertificateId<D>,
        base: Tips<D>,
    },
    /// One leader block, invalid: its parent is not of the previous view, or its commitment is
    /// not its parent's.
    Invalid(D),
    /// Two different leader blocks: the leader equivocated, and neither is valid.
    Conflicting,
}

impl<D: Digest> Proposal<D> {
    /// Returns the proposal after receiving the leader block `block`, valid with the held parent
    /// and base `valid` when given.
    fn with(slot: Option<&Self>, block: D, valid: Option<(CertificateId<D>, Tips<D>)>) -> Self {
        match slot {
            None => valid.map_or(Self::Invalid(block), |(parent, base)| Self::Valid {
                block,
                parent,
                base,
            }),
            Some(held @ (Self::Valid { block: digest, .. } | Self::Invalid(digest)))
                if *digest == block =>
            {
                held.clone()
            }
            Some(_) => Self::Conflicting,
        }
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the V-QC `id` if this node holds it with its whole parent chain: the genesis V-QC,
    /// a V-QC of the store, or the retention root, whose chain retention dropped.
    pub(in crate::multimmit::machine) fn held_vqc(
        &self,
        id: &CertificateId<H::Digest>,
    ) -> Option<HeldVqc<H::Digest>> {
        let genesis = self.profile.protocol().genesis();
        if *id == genesis.vqc() {
            return Some(HeldVqc::genesis(genesis));
        }
        if let Some(stored) = self.stored_vqc(id) {
            return Some(stored.held.clone());
        }
        let state = &self.durable.state;
        let root = state.root.as_ref().filter(|root| root.vqc == *id)?;
        Some(HeldVqc {
            view: state.retired_view,
            id: *id,
            history: root.record.commitment::<H>(),
            tips: root.record.tips().into(),
        })
    }

    /// Checks that a received leader block is of a view this node reads, signed by that view's
    /// leader, and not of a view whose leader already equivocated.
    pub(in crate::multimmit::machine) fn precheck_leader_block(
        &self,
        block: &SignedLeaderBlock<V, H::Digest>,
    ) -> Result<Precheck<H::Digest>, Rejection> {
        let view = block.view();
        let current = self.durable.state.view;
        if view.next() < current || view > current.next() {
            return Err(Rejection::TagWindow);
        }
        if block.signer() != self.profile.protocol().leader(view) {
            return Err(Rejection::Participant);
        }
        if matches!(
            self.components.view.proposals.get(&view),
            Some(Proposal::Conflicting)
        ) {
            return Err(Rejection::Superseded);
        }
        Ok(Precheck::Verify(None))
    }

    /// Returns the V-QC an authenticated leader block names when this node does not hold it with
    /// its chain.
    pub(in crate::multimmit::machine) fn leader_block_dependency(
        &self,
        block: &SignedLeaderBlock<V, H::Digest>,
    ) -> Option<RetrievalKey<H::Digest>> {
        let parent = block.block().parent();
        self.held_vqc(&parent)
            .is_none()
            .then_some(RetrievalKey::Vqc(parent))
    }

    /// Records an authenticated leader block whose parent this node holds, unless its view fell
    /// behind the views leader blocks are read for while it waited for that parent.
    pub(in crate::multimmit::machine) fn admit_leader_block(
        &mut self,
        block: &SignedLeaderBlock<V, H::Digest>,
    ) {
        let view = block.view();
        if view.next() < self.durable.state.view {
            return;
        }
        self.record_proposal(block.block());
    }

    /// Records the leader block `block`, signed by its view's leader and received or signed by
    /// this node, and wakes the view layer and the V-QC assembly, which may need it as the
    /// designated block.
    ///
    /// A valid block of a view this node already ended with a leaderless final vote widens the
    /// grace once per view. Recording the valid block this node voted for restores its base when
    /// the base is unknown, as after a restart. A second, different block of the view proves its
    /// leader faulty.
    pub(in crate::multimmit::machine) fn record_proposal(
        &mut self,
        block: &LeaderBlock<H::Digest>,
    ) {
        let view = block.view();
        let digest = block.digest::<H>();
        let valid = self
            .held_vqc(&block.parent())
            .filter(|parent| parent.view.next() == view && parent.history == block.history())
            .map(|parent| (parent.id, parent.tips));
        let layer = &mut self.components.view;
        let previous = layer.proposals.get(&view);
        let proposal = Proposal::with(previous, digest, valid);
        let equivocated = matches!(proposal, Proposal::Conflicting)
            && !matches!(previous, Some(Proposal::Conflicting));
        let base = match &proposal {
            Proposal::Valid { base, .. } => Some(Arc::clone(base)),
            Proposal::Invalid(_) | Proposal::Conflicting => None,
        };
        let valid = base.is_some();
        layer.proposals.insert(view, proposal);
        if equivocated {
            self.account_equivocation(self.profile.protocol().leader(view));
        }
        if let Some(base) = base
            && self.notarised(view) == Some(digest)
            && self.notarised_base(view).is_none()
        {
            self.set_notarised_base(view, base);
        }
        let layer = &mut self.components.view;
        let ended_leaderless = self
            .durable
            .state
            .watermark
            .get(&view)
            .and_then(|watermark| watermark.final_content.as_ref())
            .is_some_and(|content| content.leader().is_none());
        if valid && ended_leaderless && layer.widened < view {
            layer.widened = view;
            layer.timing.widen();
        }
        self.wake(ProtocolComponent::View);
        self.wake(ProtocolComponent::Forwarding);
    }

    /// Requests the leader block of the current view when this node voted for it but no longer
    /// knows its base, which a restart loses; recording the block again restores the base.
    pub(in crate::multimmit::machine) fn request_notarised_proposal(
        &mut self,
    ) -> Result<Option<Capability<V, H::Digest>>, StepError> {
        let view = self.durable.state.view;
        if self.notarised(view).is_none() || self.notarised_base(view).is_some() {
            return Ok(None);
        }
        self.request(RetrievalKey::LeaderBlock(view))
    }

    /// Returns the digest and base of the valid leader block of `view`, if this node holds one.
    pub(in crate::multimmit::machine) fn valid_proposal(
        &self,
        view: View,
    ) -> Option<(H::Digest, Tips<H::Digest>)> {
        match self.components.view.proposals.get(&view)? {
            Proposal::Valid { block, base, .. } => Some((*block, Arc::clone(base))),
            Proposal::Invalid(_) | Proposal::Conflicting => None,
        }
    }

    /// Reserves this node's leader block for the current view when it leads the view, has not
    /// proposed, and holds the V-QC it entered the view on.
    ///
    /// Returns `None` when there is nothing to propose.
    pub(in crate::multimmit::machine) fn propose(&mut self) -> Option<WorkResult<V, H::Digest>> {
        let Role::Validator(own) = self.profile.role() else {
            return None;
        };
        let protocol = self.profile.protocol();
        let view = self.durable.state.view;
        if protocol.leader(view) != own || self.proposed(view) {
            return None;
        }
        let parent = self
            .components
            .view
            .state
            .parent
            .as_ref()
            .filter(|parent| parent.view.next() == view)?;
        let block = LeaderBlock::new(
            Round::new(protocol.epoch(), view),
            parent.id,
            parent.history,
        )
        .ok()?;
        let request = if parent.id == protocol.genesis().vqc() {
            ProposalRequest::new(block, ProposalParent::Genesis, false)
        } else {
            // A leader block carries its parent V-QC. A parent held only as the retention root has
            // no certificate to carry, so there is nothing to propose.
            let Artifact::Vqc(vqc) = self.stored_vqc(&parent.id)?.artifact.as_ref() else {
                return None;
            };
            ProposalRequest::new(block, ProposalParent::Exact(Arc::new(vqc.clone())), true)
        };
        Some(
            match self.reserve_effect(DurableEffect::sign(SignRequest::LeaderBlock(request))) {
                Ok(capabilities) => Ok((WorkStatus::Requeue, capabilities)),
                Err(error) if is_capacity(&error) => Ok((WorkStatus::Blocked, Vec::new())),
                Err(error) => Err(error),
            },
        )
    }
}
