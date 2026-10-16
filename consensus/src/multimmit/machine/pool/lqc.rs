//! L-QC assembly: `n - f` signed votes for one leader block.
//!
//! Once `n - f` validators voted for the leader block `l` of view `v` (any version, final or not)
//! and the V-QC `Q'` that `l` names is held with its chain, `l` is finalized (case (a) of
//! emission). The L-QC certifying it aggregates, per signer, the latest signed vote for `l` read,
//! preferring signers whose final vote was read: a correct signer's final vote for `l` is its last
//! statement of the tag, so finals of one view tend to agree and identical contents verify with one
//! pairing. Votes read only through a V-QC carry no individual signature and cannot be aggregated
//! again.
//!
//! The aggregation runs on the crypto pool; its completion is staged by the emission drive as a
//! created certificate and then held like an L-QC received from a peer. View one's leader block
//! names the genesis V-QC, which opens no history record, so it gets no L-QC.

use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        machine::{
            capability::{
                AggregateId, AttestedVote, Capabilities, Capability, CryptoJob, LqcAggregateJob,
            },
            input::{Aggregated, StepError},
            job::{IdSequence, Issued},
            reducer::{components::WorkStatus, machine::Machine},
            scheduler::ProtocolComponent,
            view::vqc::Identified,
        },
        types::{Artifact, Attestation, LeaderBlock, Lqc, VoteContent, VoteUpdate},
    },
    types::{Attributable as _, Participant, Round, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, sync::Arc};

/// A vote's full content and its signer's signature.
type SignedVote<V, D> = (Arc<VoteContent<D>>, Attestation<V>);

/// The state of this node's L-QC assembly.
pub(crate) struct LqcAssembly<V: Variant, D: Digest> {
    /// Per view and sender, the latest signed vote for a leader block read; a final vote is never
    /// replaced.
    votes: BTreeMap<(View, Participant), SignedVote<V, D>>,
    /// The aggregation in flight and the view it is for.
    pending: Option<(Issued<AggregateId>, View)>,
    ids: IdSequence<AggregateId>,
    /// An assembled L-QC waiting to be staged, with its artifact identifier.
    created: Option<Identified<V, D>>,
}

impl<V: Variant, D: Digest> LqcAssembly<V, D> {
    pub(crate) const fn new() -> Self {
        Self {
            votes: BTreeMap::new(),
            pending: None,
            ids: IdSequence::new(),
            created: None,
        }
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Records the signature of a vote for a leader block read with full content `content`, which
    /// an L-QC this node assembles may aggregate.
    pub(in crate::multimmit::machine) fn note_leader_vote(
        &mut self,
        content: &Arc<VoteContent<H::Digest>>,
        attestation: &Attestation<V>,
    ) {
        let view = content.view();
        if content.leader().is_none() || view <= self.components.emitter.finalized {
            return;
        }
        self.components
            .lqc_assembly
            .votes
            .entry((view, attestation.signer()))
            .and_modify(|(recorded, signature)| {
                if !recorded.is_final() {
                    *recorded = Arc::clone(content);
                    *signature = attestation.clone();
                }
            })
            .or_insert_with(|| (Arc::clone(content), attestation.clone()));
    }

    /// Records the signature of this node's own `update`, staged with its record, when it votes for
    /// a leader block. Its content is the one the pool read when the update was reserved.
    pub(in crate::multimmit::machine) fn note_own_vote(
        &mut self,
        update: &VoteUpdate<V, H::Digest>,
    ) {
        if update.leader().is_none() {
            return;
        }
        let content = self
            .components
            .pool
            .reader(update.view(), update.signer())
            .and_then(|reader| reader.last.content(update.seq()))
            .cloned();
        if let Some(content) = content {
            self.note_leader_vote(&content, update.attestation());
        }
    }

    /// Forgets the signatures of votes tagged `view` or earlier.
    pub(in crate::multimmit::machine) fn retire_leader_votes_through(&mut self, view: View) {
        let assembly = &mut self.components.lqc_assembly;
        assembly.votes = assembly
            .votes
            .split_off(&(view.next(), Participant::new(0)));
    }

    /// Resets the assembly at a start or restart: aggregations of earlier generations are stale and
    /// signatures return with the votes they sign.
    pub(in crate::multimmit::machine) fn restore_lqc_assembly(&mut self) {
        self.components.lqc_assembly = LqcAssembly::new();
    }

    /// Issues the aggregation of an L-QC for the first leader block of a view above the last
    /// finalized one that `n - f` validators voted for, whose parent V-QC is held, and for which no
    /// L-QC is held, unless an aggregation is in flight or waits to be staged.
    pub(in crate::multimmit::machine) fn assemble_lqc(
        &mut self,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        let assembly = &self.components.lqc_assembly;
        if assembly.pending.is_some() || assembly.created.is_some() {
            return Ok(Capabilities::new());
        }
        let quorum = self.profile.codec().view_quorum();
        let floor = self.components.emitter.finalized.next();
        let finalized = self
            .components
            .pool
            .tags
            .range(floor..)
            .filter(|(view, _)| self.lqc(**view).is_none())
            .flat_map(|(view, tag)| {
                tag.leaders
                    .iter()
                    .filter(move |(_, voters)| voters.count_ones() as usize >= quorum)
                    .map(move |(leader, _)| (*view, *leader))
            })
            .collect::<Vec<_>>();
        for (view, leader) in finalized {
            let Some(block) = self.leader_block_of(view, &leader) else {
                continue;
            };
            let Some(votes) = self.select_leader_votes(view, &leader) else {
                continue;
            };
            let assembly = &mut self.components.lqc_assembly;
            let id = assembly.ids.issue().ok_or(StepError::IdentifierExhausted)?;
            let issued = Issued::new(id, self.durable.state.generation);
            assembly.pending = Some((issued, view));
            return Ok(vec![Capability::Crypto(CryptoJob::AggregateLqc(
                LqcAggregateJob::new(issued, block, votes),
            ))]);
        }
        Ok(Capabilities::new())
    }

    /// Returns the leader block of `view` with digest `leader` when the V-QC it names is held: it
    /// names one held V-QC of the previous view and that V-QC's commitment.
    fn leader_block_of(&self, view: View, leader: &H::Digest) -> Option<LeaderBlock<H::Digest>> {
        let round = Round::new(self.profile.protocol().epoch(), view);
        let previous = view.previous()?;
        self.components.vqcs.held_in(previous).find_map(|stored| {
            let block = LeaderBlock::new(round, stored.held.id, stored.held.history).ok()?;
            (block.digest::<H>() == *leader).then_some(block)
        })
    }

    /// Chooses `n - f` signed votes for `leader` in `view`, signers whose final vote was read
    /// first, each in signer order, and returns them in signer order; `None` while fewer are held.
    fn select_leader_votes(
        &self,
        view: View,
        leader: &H::Digest,
    ) -> Option<Vec<AttestedVote<V, H::Digest>>> {
        let quorum = self.profile.codec().view_quorum();
        let mut votes = self
            .components
            .lqc_assembly
            .votes
            .range((view, Participant::new(0))..)
            .take_while(|((tag, _), _)| *tag == view)
            .filter(|(_, (content, _))| content.leader() == Some(*leader))
            .map(|(_, vote)| vote)
            .collect::<Vec<_>>();
        if votes.len() < quorum {
            return None;
        }
        votes.sort_by_key(|(content, attestation)| (!content.is_final(), attestation.signer()));
        votes.truncate(quorum);
        votes.sort_by_key(|(_, attestation)| attestation.signer());
        Some(
            votes
                .into_iter()
                .map(|(content, attestation)| (content.as_ref().clone(), attestation.clone()))
                .collect(),
        )
    }

    /// Parks an assembled L-QC for staging if it completes the aggregation in flight.
    pub(in crate::multimmit::machine) fn complete_lqc(
        &mut self,
        completion: Aggregated<Lqc<V, H::Digest>>,
    ) {
        let assembly = &mut self.components.lqc_assembly;
        if assembly
            .pending
            .is_none_or(|(issued, _)| issued != completion.issued())
        {
            return;
        }
        assembly.pending = None;
        let artifact = Arc::new(Artifact::Lqc(completion.into_certificate()));
        assembly.created = Some((artifact.id::<H>(), artifact));
        self.wake(ProtocolComponent::Emission);
    }

    /// Stages the assembled L-QC waiting to be created and holds it as its view's, unless its view
    /// already holds one or was finalized meanwhile. Returns `None` when none waits, and
    /// [`WorkStatus::Blocked`] when persistence or the artifact cache lacks room.
    pub(in crate::multimmit::machine) fn create_assembled_lqc(
        &mut self,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<Option<WorkStatus>, StepError> {
        let Some((id, artifact)) = self.components.lqc_assembly.created.take() else {
            return Ok(None);
        };
        let Artifact::Lqc(lqc) = artifact.as_ref() else {
            return Err(StepError::ViewInvariant);
        };
        let view = lqc.view();
        if view <= self.components.emitter.finalized || self.lqc(view).is_some() {
            return Ok(Some(WorkStatus::Requeue));
        }
        if !self.retain_certificate(id, &artifact, capabilities)? {
            self.components.lqc_assembly.created = Some((id, artifact));
            return Ok(Some(WorkStatus::Blocked));
        }
        self.admit_lqc(id, &artifact);
        Ok(Some(WorkStatus::Requeue))
    }
}
