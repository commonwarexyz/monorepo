//! Checkpoint snapshots and the checks a restored snapshot must pass.

use super::{Cursor, DurableState, EffectId, OutboxEntry, ReplayError};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::{Profile, Role},
        types::{Artifact, Resolution},
    },
    types::{Attributable as _, Epoch, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// A projection of the last acknowledged durable cursor.
///
/// Verification jobs, unsynced reservations, and other volatile work are intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot<V: Variant, D: Digest> {
    pub(super) epoch: Epoch,
    pub(super) role: Role,
    pub(super) state: DurableState<V, D>,
}

impl<V: Variant, D: Digest> Snapshot<V, D> {
    pub(crate) const fn new(epoch: Epoch, role: Role, state: DurableState<V, D>) -> Self {
        Self { epoch, role, state }
    }

    /// Returns the acknowledged journal cursor.
    pub(crate) const fn cursor(&self) -> Cursor {
        self.state.cursor
    }

    /// Returns this snapshot relabelled at `cursor`, so storage tests can hold distinct snapshots.
    #[cfg(test)]
    pub(crate) const fn at_cursor_for_test(mut self, cursor: Cursor) -> Self {
        self.state.cursor = cursor;
        self
    }

    /// Returns the highest view whose state the snapshot no longer retains.
    pub(crate) const fn retired_view(&self) -> View {
        self.state.retired_view
    }

    /// Returns the bound epoch.
    pub(crate) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns every artifact durably retained by this snapshot, once per holder.
    ///
    /// Locally created artifacts are only part of the set: accepted headers, the proofs views were
    /// exited with, the artifacts the outbox publishes (including a proposal's block and parent),
    /// and the parents signing reservations reference are equally relevant to recovery.
    pub(crate) fn retained_artifacts(&self) -> impl Iterator<Item = Arc<Artifact<V, D>>> {
        let mut artifacts = Vec::new();
        self.state
            .visit_retained(|_, retained| artifacts.push(retained.to_artifact()));
        artifacts.into_iter()
    }

    pub(crate) fn into_state(self) -> DurableState<V, D> {
        self.state
    }

    /// Checks the snapshot against `profile`: its context, the bounds of every durable field,
    /// and the invariants that relate them, naming the first failed check.
    pub(crate) fn validate<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H::Digest>,
    ) -> Result<(), ReplayError> {
        if self.epoch != profile.protocol().epoch() || self.role != profile.role() {
            return Err(ReplayError::Context);
        }
        self.check_bounds::<H>(profile)?;
        self.check_local_artifacts::<H>(profile)?;
        self.check_accepted::<H>(profile)?;
        self.check_signing_slots(profile)?;
        self.check_emission::<H>(profile)?;
        self.check_effects::<H>(profile)?;
        self.check_forwarded(profile)?;
        self.check_exits()?;
        self.check_ancestors::<H>(profile)
    }

    /// Checks entry counts, effect ownership, artifact occupancy, and the produced height.
    fn check_bounds<H: Hasher<Digest = D>>(&self, profile: &Profile<D>) -> Result<(), ReplayError> {
        let resources = profile.resources();
        let chains = profile.codec().chains();
        let state = &self.state;
        let observer_produced = matches!(self.role, Role::Observer) && !state.produced.is_zero();
        if state.local.len() > resources.max_cached_artifacts()
            || state.effect_count() > resources.max_outbox_effects()
            || state
                .signing_reservations
                .keys()
                .any(|id| state.outbox.contains_key(id))
            || state.artifact_occupancy::<H>() > resources.max_cached_artifacts()
            || observer_produced
            || state.accepted.len() != chains
            || state.origin.len() != chains
            || state.last_final.1.len() != chains
            || state
                .last_final
                .1
                .iter()
                .enumerate()
                .any(|(index, tip)| tip.chain().index() != index)
        {
            return Err(invalid(SnapshotReason::Bounds));
        }
        Ok(())
    }

    /// Checks that every locally held artifact is in bounds, identified by its key, and one this
    /// role could have created: a certificate, or an artifact this validator signed.
    fn check_local_artifacts<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<D>,
    ) -> Result<(), ReplayError> {
        let protocol = profile.protocol();
        for (id, artifact) in &self.state.local {
            let constructible = match (self.role, artifact.as_ref()) {
                (_, Artifact::Vqc(_) | Artifact::Lqc(_)) => true,
                (Role::Validator(signer), Artifact::TransactionBlock(block)) => {
                    protocol.producer(block.header().chain()) == Some(signer)
                        && block.signer() == signer
                        && block.header().height() <= self.state.produced
                }
                (Role::Validator(signer), _) => artifact.signer() == Some(signer),
                (Role::Observer, _) => false,
            };
            if !constructible
                || artifact.epoch() != self.epoch
                || artifact.encoded_len() > profile.resources().max_artifact_bytes()
                || artifact
                    .view()
                    .is_some_and(|view| view <= self.state.retired_view)
                || artifact.id::<H>() != *id
            {
                return Err(invalid(SnapshotReason::LocalArtifact));
            }
        }
        Ok(())
    }

    /// Checks that each chain's origin and accepted headers are of that chain, and that the
    /// accepted headers form one path that starts at or extends the origin, or extends their
    /// oldest retained header, every header accepted in full signed by its producer.
    fn check_accepted<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<D>,
    ) -> Result<(), ReplayError> {
        let protocol = profile.protocol();
        let state = &self.state;
        for (index, (accepted, origin)) in state.accepted.iter().zip(&state.origin).enumerate() {
            if origin.chain().index() != index {
                return Err(invalid(SnapshotReason::Accepted));
            }
            let mut tip = None;
            for (height, acceptance) in accepted {
                let header = acceptance.header();
                let first = tip.is_none();
                let parent = tip.unwrap_or_else(|| {
                    if header.height().get() == origin.height().get() + 1 {
                        *origin
                    } else {
                        header.parent_ref()
                    }
                });
                if header.chain().index() != index
                    || header.height() != *height
                    || header.epoch() != self.epoch
                    || first && header.height() < origin.height()
                    || first
                        && header.height() == origin.height()
                        && header.block_ref::<H>() != *origin
                    || acceptance.signed().is_some_and(|block| {
                        protocol.producer(header.chain()) != Some(block.signer())
                    })
                    || header.parent_ref() != parent
                {
                    return Err(invalid(SnapshotReason::Accepted));
                }
                tip = Some(header.block_ref::<H>());
            }
        }
        Ok(())
    }

    /// Checks that every signing slot and the anchored tag lie above the retired view, the anchored
    /// tag at or below the current view, and that each watermark is internally consistent.
    fn check_signing_slots(&self, profile: &Profile<D>) -> Result<(), ReplayError> {
        let state = &self.state;
        let chains = profile.codec().chains();
        let retired = |view: &View| *view <= state.retired_view;
        let watermark_valid = state.watermark.iter().all(|(view, watermark)| {
            watermark.seq != 0
                && watermark.tips.len() == chains
                && watermark.declared.chains() == chains
                && watermark.declared.len() == watermark.declared_at.len()
                && watermark.final_content.as_ref().is_none_or(|content| {
                    content.view() == *view
                        && content.is_final()
                        && content.tips() == watermark.tips.as_slice()
                        && content.declared() == &watermark.declared
                })
        });
        let anchored_valid = state
            .anchored_tag
            .is_none_or(|tag| tag > state.retired_view && tag <= state.view);
        if !watermark_valid
            || !anchored_valid
            || state.leader_blocks.keys().any(retired)
            || state.notarised.keys().any(retired)
            || state.watermark.keys().any(retired)
            || matches!(self.role, Role::Observer)
                && !(state.leader_blocks.is_empty()
                    && state.notarised.is_empty()
                    && state.watermark.is_empty())
        {
            return Err(invalid(SnapshotReason::SigningSlot));
        }
        Ok(())
    }

    /// Checks that the emissions lie above the retired view in consecutive views, each naming one
    /// tip per chain and extending the previous one's commitment (view two extends the genesis
    /// history), and that a retired view has a root and the emission of the view after it.
    fn check_emission<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<D>,
    ) -> Result<(), ReplayError> {
        let state = &self.state;
        let genesis = profile.protocol().genesis();
        let rooted = state.root.as_ref().map_or_else(
            || state.retired_view.is_zero(),
            |root| {
                !state.retired_view.is_zero()
                    && root.record.tips().len() == profile.codec().chains()
                    && state.emission.contains_key(&state.retired_view.next())
            },
        );
        if !rooted {
            return Err(invalid(SnapshotReason::Emission));
        }
        let mut previous: Option<(View, D)> = None;
        for (view, emission) in &state.emission {
            let commitment = match previous {
                Some((last, commitment)) if *view == last.next() => Some(commitment),
                Some(_) => return Err(invalid(SnapshotReason::Emission)),
                None => (*view == View::new(2)).then(|| genesis.history()),
            };
            let valid = *view > state.retired_view
                && emission.base().len() == profile.codec().chains()
                && commitment.is_none_or(|commitment| emission.record.parent() == commitment)
                && match emission.by {
                    Resolution::Determined => true,
                    Resolution::Pinned { view: pinned, .. } => pinned >= *view,
                };
            if !valid {
                return Err(invalid(SnapshotReason::Emission));
            }
            previous = Some((*view, emission.record.commitment::<H>()));
        }
        Ok(())
    }

    /// Checks that every durable effect was minted at or before the cursor and is authorized, and
    /// that every queued publication's discharges match its items.
    fn check_effects<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<D>,
    ) -> Result<(), ReplayError> {
        let state = &self.state;
        let minted = |id: &EffectId| id.get() != 0 && id.get() <= state.cursor.get();
        if state
            .signing_reservations
            .iter()
            .any(|(id, effect)| !minted(id) || !effect.authorized::<H>(profile))
            || state
                .outbox
                .iter()
                .any(|(id, entry)| !minted(id) || !entry.publication().authorized::<H>(profile))
        {
            return Err(invalid(SnapshotReason::Effect));
        }
        if !state.outbox.values().all(OutboxEntry::consistent) {
            return Err(invalid(SnapshotReason::Obligation));
        }
        Ok(())
    }

    /// Checks the forwarding history bound.
    fn check_forwarded(&self, profile: &Profile<D>) -> Result<(), ReplayError> {
        let state = &self.state;
        if state.forwarded_vqcs.keys().any(|view| view.is_zero())
            || state
                .forwarded_vqcs
                .values()
                .any(|forwarded| forwarded.is_empty())
            || state.forwarded_count() > profile.resources().max_forwarded_certificates()
        {
            return Err(invalid(SnapshotReason::Forwarded));
        }
        Ok(())
    }

    /// Checks that the retired view lies below the current one and that exits cover every
    /// retained view below it, each with a certificate of its own view.
    ///
    /// The retired view is not checked against the profile's retention: a snapshot written under
    /// a larger retention retains more views.
    fn check_exits(&self) -> Result<(), ReplayError> {
        let state = &self.state;
        let first = state.retired_view.get().checked_add(1);
        let contiguous = !state.view.is_zero()
            && state.retired_view < state.view
            && first.is_some_and(|first| {
                state
                    .exits
                    .keys()
                    .map(|view| view.get())
                    .eq(first..state.view.get())
            });
        if !contiguous
            || state.exits.iter().any(|(view, proof)| {
                proof.view() != Some(*view)
                    || !matches!(proof.as_ref(), Artifact::Vqc(_) | Artifact::Lqc(_))
            })
        {
            return Err(invalid(SnapshotReason::Exits));
        }
        Ok(())
    }

    /// Checks that every entry-chain ancestor is an in-bounds V-QC of this epoch, identified by its
    /// key, of a retained view below the parent of the current one.
    fn check_ancestors<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<D>,
    ) -> Result<(), ReplayError> {
        let state = &self.state;
        let valid = state.ancestors.iter().all(|(id, artifact)| {
            let Artifact::Vqc(vqc) = artifact.as_ref() else {
                return false;
            };
            vqc.epoch() == self.epoch
                && artifact.encoded_len() <= profile.resources().max_artifact_bytes()
                && vqc.view() > state.retired_view
                && vqc.view().get().saturating_add(1) < state.view.get()
                && vqc.id::<H>() == *id
        });
        if !valid {
            return Err(invalid(SnapshotReason::Ancestors));
        }
        Ok(())
    }
}

/// Returns a snapshot failure naming `reason`.
const fn invalid(reason: SnapshotReason) -> ReplayError {
    ReplayError::Snapshot(reason)
}

/// The snapshot check a restored state failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotReason {
    /// Entry counts, effect ownership, artifact occupancy, or the produced height exceed their
    /// bounds.
    #[error("state exceeds its bounds")]
    Bounds,
    /// A locally held artifact is out of bounds, misidentified, or not locally constructible.
    #[error("local artifact is invalid")]
    LocalArtifact,
    /// An accepted header is out of bounds or does not extend its chain's accepted path.
    #[error("accepted header is invalid")]
    Accepted,
    /// A signing slot (leader block, notarised leader, or vote watermark) is inconsistent.
    #[error("signing slot is invalid")]
    SigningSlot,
    /// An emission is malformed or lies outside the retained views, or a retired view lacks its
    /// root or the emission of the view after it.
    #[error("emission is invalid")]
    Emission,
    /// A durable effect is unminted or unauthorized.
    #[error("durable effect is invalid")]
    Effect,
    /// A queued publication's discharges do not match its items.
    #[error("publication obligation is invalid")]
    Obligation,
    /// A forwarded certificate record is invalid or the forwarding history exceeds its bound.
    #[error("forwarded certificate is invalid")]
    Forwarded,
    /// The exits do not cover the retained views with retained exit proofs.
    #[error("view exits are invalid")]
    Exits,
    /// An entry-chain ancestor is not an in-bounds V-QC of a retained view below the current
    /// view's parent, or is misidentified.
    #[error("entry chain ancestor is invalid")]
    Ancestors,
}
