//! Verified view records: proposals, leaders, view messages, nullify shares, and parents.

use super::{
    claims::{Claim, ClaimKind},
    state::{ViewError, ViewState},
};
use crate::{
    Viewable,
    multimmit::{
        algebra::{Tips, ValidatedVqc, ValidatedVqcParts, validate_vqc},
        machine::{
            artifact::{
                ArtifactKind, DesignatingKind, Held, LeaderBlockKind, NullificationKind,
                NullifyKind, VqcKind,
            },
            util::{Observed, ObservedList},
            verification::Observation,
        },
        types::{
            Artifact, ArtifactId, CertificateId, DigestedLeader, LeaderBlock, NoVote,
            SelectedCommitments, TipRecord, Vote, VoteBody,
        },
    },
    types::{Attributable, Height, Participant, View},
};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeSet, btree_map::Entry},
    sync::Arc,
};

/// The earliest proposal or certificate that designated one leader block.
pub(super) type LeaderRecord<V, D> = Observed<Held<DesignatingKind, V, D>>;

/// A view's verified proposals by artifact.
pub(super) type ProposalRecords<V, D> = ObservedList<ArtifactId<D>, Held<LeaderBlockKind, V, D>>;

/// A verified vote or novote at its earliest observation.
type MessageRecord<V, D> = Observed<Held<ViewMessageKind, V, D>>;

/// One signer's verified votes and novotes for a view, by artifact.
pub(super) type MessageRecords<V, D> = ObservedList<ArtifactId<D>, Held<ViewMessageKind, V, D>>;

/// The view message settled for one signer, with its artifact id.
pub(super) type StickyMessage<V, D> = (ArtifactId<D>, MessageRecord<V, D>);

/// A verified nullify share at its earliest observation.
pub(super) type NullifyRecord<V, D> = Observed<Held<NullifyKind, V, D>>;

/// A view's verified nullifications by artifact.
pub(super) type NullificationRecords<V, D> =
    ObservedList<ArtifactId<D>, Held<NullificationKind, V, D>>;

/// A view's verified V-QCs by certificate and artifact, so equal observations order by
/// certificate.
pub(super) type VqcRecords<V, D> =
    ObservedList<(CertificateId<D>, ArtifactId<D>), Held<VqcKind, V, D>>;

/// What proves a proposal parent.
#[derive(Clone, Debug)]
pub(super) enum ParentProof<V: Variant, D: Digest> {
    /// The epoch's genesis anchor, which no certificate proves.
    Genesis,
    /// The V-QC that certified the parent.
    Vqc(Held<VqcKind, V, D>),
}

/// A certified block later proposals may build on, with the tips and commitments it fixes.
#[derive(Clone, Debug)]
pub(super) struct ParentRecord<V: Variant, D: Digest> {
    pub(super) id: CertificateId<D>,
    pub(super) view: View,
    pub(super) history: D,
    pub(super) canonical: Bytes,
    pub(super) proof: ParentProof<V, D>,
    pub(super) tips: Arc<Tips<D>>,
    pub(super) commitments: SelectedCommitments<D>,
    /// Each chain's proposed tip height in the view this record's V-QC certified.
    pub(super) proposed: Vec<Height>,
    /// The commitment of [`Self::tip_record`], which a child leader block names as its history.
    /// Validation computes it once because every proposal validity check compares against it;
    /// `None` when the tips and proposed heights do not form a tip record.
    pub(super) child_history: Option<D>,
    pub(super) messages: usize,
}

impl<V: Variant, D: Digest> ParentRecord<V, D> {
    /// Returns the safe-tip opening a child leader block commits to as its history.
    pub(super) fn tip_record(&self) -> Result<TipRecord<D>, ViewError> {
        TipRecord::new(
            self.history,
            self.tips.blocks().to_vec(),
            self.proposed.clone(),
        )
        .map_err(|_| ViewError::Proposal)
    }

    /// Returns the history commitment a child leader block names.
    pub(super) fn child_history(&self) -> Result<D, ViewError> {
        self.child_history.ok_or(ViewError::Proposal)
    }
}

/// A borrowed view message.
pub(super) enum MessageRef<'a, V: Variant, D: Digest> {
    Vote(&'a Vote<V, D>),
    NoVote(&'a NoVote<V>),
}

/// A complete vote or signed abstention.
pub(super) enum ViewMessageKind {}

impl<V: Variant, D: Digest> ArtifactKind<V, D> for ViewMessageKind {
    type Target<'a> = MessageRef<'a, V, D>;

    fn project(artifact: &Artifact<V, D>) -> Option<Self::Target<'_>> {
        match artifact {
            Artifact::Vote(vote) => Some(MessageRef::Vote(vote)),
            Artifact::NoVote(novote) => Some(MessageRef::NoVote(novote)),
            _ => None,
        }
    }
}

/// How a view message counts toward a V-QC for one target.
#[derive(Copy, Clone)]
pub(super) enum VqcEligibility {
    Target,
    Other,
}

impl<V: Variant, D: Digest> Held<ViewMessageKind, V, D> {
    /// Returns the message's view and signer.
    pub(super) fn author(&self) -> (View, Participant) {
        match self.get() {
            MessageRef::Vote(vote) => (vote.view(), vote.signer()),
            MessageRef::NoVote(novote) => (novote.view(), novote.signer()),
        }
    }

    /// Returns how the message counts toward a V-QC for `target`, or `None` if it votes for
    /// `target` with a body invalid for `leader`.
    pub(super) fn vqc_eligibility(
        &self,
        target: D,
        leader: &LeaderBlock<V, D>,
    ) -> Option<VqcEligibility> {
        match self.get() {
            MessageRef::Vote(vote) if vote.body().leader() == target => vote
                .body()
                .valid_for(DigestedLeader::with_digest(leader, target))
                .then_some(VqcEligibility::Target),
            MessageRef::Vote(_) | MessageRef::NoVote(_) => Some(VqcEligibility::Other),
        }
    }
}

fn message_opposes<V: Variant, D: Digest>(
    message: MessageRef<'_, V, D>,
    voted: &VoteBody<D>,
) -> bool {
    match message {
        MessageRef::NoVote(_) => true,
        MessageRef::Vote(vote) => vote.body().leader() != voted.leader(),
    }
}

impl<V: Variant, D: Digest> ViewState<V, D> {
    /// Returns every verified vote and novote retained for `view`, in participant order.
    pub(crate) fn verified_messages(&self, view: View) -> Vec<Arc<Artifact<V, D>>> {
        self.entry(view).map_or_else(Vec::new, |entry| {
            entry
                .messages
                .values()
                .flat_map(ObservedList::iter)
                .map(|(_, record)| Arc::clone(record.value.arc()))
                .collect()
        })
    }

    /// Records a verified proposal and the leader block it designates.
    pub(super) fn observe_proposal<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        block: Held<LeaderBlockKind, V, D>,
    ) {
        let leader = block.get().block();
        let key = (leader.view(), leader.digest::<H>());
        self.record_leader(observation, block.widen(), key);
        self.entry_mut(key.0)
            .proposals
            .upsert_min(id, observation, || block);
    }

    /// Records the earliest `source` designating the leader block `key` names.
    fn record_leader(
        &mut self,
        observation: Observation,
        source: Held<DesignatingKind, V, D>,
        (view, digest): (View, D),
    ) {
        match self.entry_mut(view).leaders.entry(digest) {
            Entry::Vacant(entry) => {
                entry.insert(Observed {
                    observation,
                    value: source,
                });
            }
            Entry::Occupied(mut entry) => {
                if observation < entry.get().observation {
                    entry.insert(Observed {
                        observation,
                        value: source,
                    });
                }
            }
        }
    }

    /// Records a verified view message at its earliest observation.
    pub(super) fn observe_message(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        message: Held<ViewMessageKind, V, D>,
    ) {
        let (view, signer) = message.author();
        if let Some(location) = self.message_locations.get(&id).copied() {
            debug_assert_eq!(location, (view, signer));
            self.views
                .get_mut(&view)
                .expect("indexed view exists")
                .messages
                .get_mut(&signer)
                .expect("indexed signer exists")
                .upsert_min(id, observation, || message);
            return;
        }

        let entry = self.entry_mut(view);
        let opposes_local_vote = entry
            .slot
            .vote()
            .is_some_and(|voted| message_opposes(message.get(), voted));
        entry
            .messages
            .entry(signer)
            .or_default()
            .upsert_min(id, observation, || message);
        if opposes_local_vote {
            entry.post_vote_evidence.insert(signer);
        }
        self.message_locations.insert(id, (view, signer));
    }

    /// Removes a view message from the records of `view` and `signer`.
    pub(super) fn remove_message(&mut self, id: ArtifactId<D>, view: View, signer: Participant) {
        let Some(location) = self.message_locations.remove(&id) else {
            return;
        };
        debug_assert_eq!(location, (view, signer));

        let Some(entry) = self.views.get_mut(&view) else {
            return;
        };
        if entry.messages.get_mut(&signer).is_some_and(|records| {
            records.remove(id);
            records.is_empty()
        }) {
            entry.messages.remove(&signer);
        }
        if entry
            .sticky
            .get(&signer)
            .is_some_and(|(held, _)| *held == id)
        {
            entry.sticky.remove(&signer);
        }
    }

    /// Makes the earliest view message of `participant` sticky once no earlier claim can
    /// displace it.
    pub(super) fn settle_message(&mut self, view: View, participant: Participant) {
        if self
            .entry(view)
            .is_some_and(|entry| entry.sticky.contains_key(&participant))
        {
            return;
        }
        let Some((id, record)) = self
            .entry(view)
            .and_then(|entry| entry.messages.get(&participant))
            .and_then(ObservedList::first)
            .map(|(id, record)| (id, record.clone()))
        else {
            return;
        };
        if self
            .claims
            .first_cohort(Claim::new(view, ClaimKind::ViewMessage(participant)))
            .is_some_and(|cohort| cohort <= record.observation.cohort())
        {
            return;
        }
        self.entry_mut(view)
            .sticky
            .insert(participant, (id, record));
    }

    /// Records a verified nullify share, keeping the earliest per signer.
    pub(super) fn observe_nullify(
        &mut self,
        observation: Observation,
        share: Held<NullifyKind, V, D>,
    ) {
        let view = share.get().view();
        let signer = share.get().signer();
        let has_voted = self.has_voted(view);
        let entry = self.entry_mut(view);
        match entry.nullifies.get(&signer) {
            Some(existing) if existing.observation <= observation => {}
            _ => {
                entry.nullifies.insert(
                    signer,
                    Observed {
                        observation,
                        value: share,
                    },
                );
            }
        }
        if has_voted {
            entry.post_vote_evidence.insert(signer);
        }
    }

    /// Records a verified nullification at its earliest observation.
    pub(super) fn observe_nullification(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        certificate: Held<NullificationKind, V, D>,
    ) {
        self.entry_mut(certificate.get().view())
            .nullification
            .records
            .upsert_min(id, observation, || certificate);
    }

    /// Records a verified V-QC and retains its block as a proposal parent.
    pub(super) fn observe_vqc<H: Hasher<Digest = D>>(
        &mut self,
        artifact_id: ArtifactId<D>,
        observation: Observation,
        certificate: Held<VqcKind, V, D>,
        validated: Option<ValidatedVqc<D>>,
    ) -> Result<(), ViewError> {
        let validated = match validated {
            Some(validated) => validated,
            None => validate_vqc::<H, V, D>(certificate.get(), self.config)
                .map_err(|_| ViewError::Certificate)?,
        };
        let leader = validated.leader();
        let id = self.retain_parent(&certificate, validated)?;
        let view = certificate.get().view();
        if view <= self.retired_transitions && self.vqc_forwarded(view) {
            return Ok(());
        }
        self.record_leader(observation, certificate.widen(), (view, leader));
        self.entry_mut(view)
            .vqc
            .records
            .upsert_min((id, artifact_id), observation, || certificate);
        Ok(())
    }

    /// Retains a V-QC as a proposal parent without scheduling standalone forwarding.
    pub(crate) fn retain_vqc_parent<H: Hasher<Digest = D>>(
        &mut self,
        artifact: &Arc<Artifact<V, D>>,
    ) -> Result<CertificateId<D>, ViewError> {
        let Some(certificate) = Held::<VqcKind, V, D>::try_new(artifact) else {
            return Err(ViewError::Certificate);
        };
        // A retained Arc owns the validation of this immutable certificate. Other
        // allocations, including decoded copies, must establish their own validity.
        if let Some(ids) = self.parents_by_view.get(&certificate.get().view()) {
            for id in ids {
                if matches!(
                    &self.parents[id].proof,
                    ParentProof::Vqc(retained) if Arc::ptr_eq(retained.arc(), artifact)
                ) {
                    return Ok(*id);
                }
            }
        }
        let validated = validate_vqc::<H, V, D>(certificate.get(), self.config)
            .map_err(|_| ViewError::Certificate)?;
        self.retain_parent(&certificate, validated)
    }

    /// Retains the block a validated V-QC certifies as a proposal parent.
    pub(crate) fn retain_validated_vqc_parent(
        &mut self,
        artifact: &Arc<Artifact<V, D>>,
        validated: ValidatedVqc<D>,
    ) -> Result<CertificateId<D>, ViewError> {
        let certificate = Held::<VqcKind, V, D>::try_new(artifact).ok_or(ViewError::Certificate)?;
        self.retain_parent(&certificate, validated)
    }

    fn retain_parent(
        &mut self,
        held: &Held<VqcKind, V, D>,
        validated: ValidatedVqc<D>,
    ) -> Result<CertificateId<D>, ViewError> {
        let certificate = held.get();
        let ValidatedVqcParts {
            id,
            canonical,
            tips,
            commitments,
            child_history,
        } = validated.into_parts();
        let record = ParentRecord {
            id,
            view: certificate.view(),
            history: certificate.leader().history(),
            canonical,
            proof: ParentProof::Vqc(held.clone()),
            proposed: certificate.leader().proposed_heights(),
            tips,
            commitments,
            child_history,
            messages: certificate.tally().signers().count()
                + certificate.novoters().count()
                + certificate.conflicting_votes().len(),
        };
        if let Some(existing) = self.parents.get(&id) {
            return (existing.canonical == record.canonical)
                .then_some(id)
                .ok_or(ViewError::Certificate);
        }

        self.parents.insert(id, record);
        let ids = self.parents_by_view.entry(certificate.view()).or_default();
        let index = ids.binary_search(&id).unwrap_or_else(|index| index);
        ids.insert(index, id);
        Ok(id)
    }

    /// Recomputes the signers whose messages or nullify shares oppose this node's vote in `view`.
    pub(super) fn rebuild_post_vote_evidence(&mut self, view: View) {
        let Some(entry) = self.views.get_mut(&view) else {
            return;
        };
        let Some(voted) = entry.slot.vote() else {
            return;
        };
        let mut evidence = entry.nullifies.keys().copied().collect::<BTreeSet<_>>();
        for (participant, records) in &entry.messages {
            if records
                .iter()
                .any(|(_, record)| message_opposes(record.value.get(), voted))
            {
                evidence.insert(*participant);
            }
        }
        entry.post_vote_evidence = evidence;
    }
}

#[cfg(test)]
mod tests {
    use super::{Held, MessageRef, ViewMessageKind};
    use crate::{
        multimmit::{
            machine::{
                artifact::{DesignatingKind, LeaderBlockKind, NullifyKind},
                testing::fixtures::Harness,
                tests::fixtures::{leader, leader_artifact, no_vote, view_vote},
            },
            types::Artifact,
        },
        types::{Participant, View},
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use std::sync::Arc;

    #[test]
    fn held_handles_check_their_kind_at_construction() {
        let (machine, _) = Harness::observer().participants(6).start();
        let block = leader(&machine, 1);
        let vote = Arc::new(Artifact::Vote(view_vote(&machine, &block, 2)));
        let novote = Arc::new(Artifact::<_, Digest>::NoVote(no_vote(
            &machine,
            View::new(1),
            3,
        )));
        let proposal = Arc::new(leader_artifact(&machine, 1));

        let message = Held::<ViewMessageKind, _, _>::try_new(&vote).expect("votes are messages");
        let MessageRef::Vote(held) = message.get() else {
            panic!("a vote projects as a vote");
        };
        assert_eq!(held.body().leader(), block.digest::<Sha256>());
        assert_eq!(message.author(), (View::new(1), Participant::new(2)));
        let message =
            Held::<ViewMessageKind, _, _>::try_new(&novote).expect("novotes are messages");
        assert_eq!(message.author(), (View::new(1), Participant::new(3)));
        assert!(Held::<ViewMessageKind, _, _>::try_new(&proposal).is_none());
        assert!(Held::<LeaderBlockKind, _, _>::try_new(&vote).is_none());
        assert!(Held::<NullifyKind, _, _>::try_new(&vote).is_none());

        let held = Held::<LeaderBlockKind, _, _>::try_new(&proposal).expect("a leader block");
        assert!(Arc::ptr_eq(held.arc(), &proposal));
        let designating: Held<DesignatingKind, _, _> = held.widen();
        assert_eq!(designating.get(), &block);
        assert!(Arc::ptr_eq(designating.arc(), &proposal));
    }
}
