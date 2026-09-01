//! Retention floors, view compaction, and retired-artifact sweeps.

use super::{
    machine::Machine,
    store::{ArtifactEntry, ArtifactState, FloorPosition},
};
use crate::{
    Viewable,
    multimmit::{
        algebra::ValidatedVqc,
        machine::{
            artifact::Dependency,
            durability::{ReplayError, TransitionReason},
            input::StepError,
            util::{drain_prefix, retire_prefix},
            view::RetireFloors,
        },
        types::{Artifact, ArtifactId},
    },
    types::View,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use core::mem::take;
use std::sync::Arc;

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the greatest view whose state the machine has stopped retaining.
    ///
    /// The machine can never act in a view it has already left, so retirement is measured from the
    /// current view rather than from finality. Memory therefore stays bounded while finality
    /// stalls.
    pub(crate) const fn retention_floor(&self) -> View {
        self.retention_floor_at(self.durable.state.view)
    }

    /// Returns the greatest view the machine stops retaining once `view` is current.
    pub(crate) const fn retention_floor_at(&self, view: View) -> View {
        self.profile.retention_floor(view)
    }

    /// Returns the retention floor, never below the durably retired view.
    pub(crate) fn effective_retention_floor(&self) -> View {
        self.retention_floor().max(self.durable.state.retired_view)
    }

    /// Applies durable transition and consensus signing floors to volatile state.
    pub(crate) fn retire_view_history(&mut self) -> Result<(), ReplayError> {
        let transition_floor = self.durable.state.retired_view;
        let finality_floor = self.signing_floor_view();
        let (anchor_view, anchor) = self.proposal_anchor();
        // Retiring finality can release a queued L-QC whose derived leader keeps its proposal
        // parent alive, so it runs before the views retire parents.
        self.retire_finality_through(self.retention_floor())
            .map_err(|_| ReplayError::Transition(TransitionReason::FinalityState))?;
        self.retract_unneeded_resolutions();
        self.dependencies.available.retain(|dependency| {
            !matches!(dependency, Dependency::Leader { round, .. }
                if !round.view().is_zero() && round.view() <= transition_floor)
        });
        let retired_parents = self.views.retire(RetireFloors {
            transitions: transition_floor,
            parents: finality_floor.max(anchor_view),
            anchor,
        });
        self.finality.retire_proofs_through(finality_floor);
        for id in retired_parents {
            self.dependencies.forget(&Dependency::Vqc(id));
        }
        Ok(())
    }

    pub(crate) fn advance_proposal_anchor(
        &mut self,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), ReplayError> {
        let Artifact::Vqc(certificate) = artifact.as_ref() else {
            return Err(ReplayError::Transition(TransitionReason::ArtifactKind));
        };
        let current = self.durable.state.proposal_anchor_view();
        if certificate.view() <= current || certificate.view() > self.durable.state.view {
            return Ok(());
        }

        self.set_proposal_anchor(artifact, None)
    }

    /// Installs a proposal parent, including a finality-backed same-view replacement.
    pub(crate) fn set_proposal_anchor(
        &mut self,
        artifact: &Arc<Artifact<V, H::Digest>>,
        validated: Option<ValidatedVqc<H::Digest>>,
    ) -> Result<(), ReplayError> {
        let Artifact::Vqc(certificate) = artifact.as_ref() else {
            return Err(ReplayError::Transition(TransitionReason::ArtifactKind));
        };
        if certificate.view() > self.durable.state.view {
            return Err(ReplayError::Transition(TransitionReason::ProposalParent));
        }

        match validated {
            Some(validated) => self.views.retain_validated_vqc_parent(artifact, validated),
            None => self.views.retain_vqc_parent::<H>(artifact),
        }
        .map_err(|_| ReplayError::Transition(TransitionReason::ViewState))?;

        let id = artifact.id::<H>();
        self.retain_durable_artifact(id)?;
        if let Some(previous) = self
            .durable
            .state
            .proposal_anchor
            .replace(Arc::clone(artifact))
        {
            self.release_durable_artifact(previous.id::<H>())?;
        }
        self.durable.state.proposal_nullified_through = self
            .durable
            .state
            .proposal_nullified_through
            .max(certificate.view());
        self.views.restore_proposal_frontier(
            certificate.view(),
            self.durable.state.proposal_nullified_through,
        );
        Ok(())
    }

    /// Retires every view at or below `floor`, which becomes the durably retired view.
    ///
    /// A view the machine has left can never be acted in again, so this runs whether or not
    /// finality advanced; the retired views' certificates, local artifacts, and exit proofs
    /// are only reachable by resolution afterwards.
    pub(crate) fn compact_view_history(&mut self, floor: View) -> Result<(), ReplayError> {
        self.durable.state.retired_view = floor;

        // Retention makes views at or below the floor unactionable, so their pending consensus
        // signing authority retires with the same durable transition regardless of which path
        // advanced the floor. A completion that arrives afterwards reconciles as a stale
        // observation instead of exposing a signature for a retired view.
        for id in self.obsolete_consensus_signing_effects(floor) {
            self.retire_signing(id)?;
        }

        let local = self
            .durable
            .state
            .local
            .iter()
            .filter_map(|(id, artifact)| {
                artifact
                    .view()
                    .is_some_and(|view| view <= floor)
                    .then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in local {
            self.durable.state.local.remove(&id);
            self.release_durable_artifact(id)?;
        }

        let forwarded = drain_prefix(&mut self.durable.state.forwarded_vqcs, |view| {
            *view <= floor
        })
        .chain(drain_prefix(
            &mut self.durable.state.forwarded_nullifications,
            |view| *view <= floor,
        ))
        .map(|(_, artifact)| artifact.id::<H>())
        .collect::<Vec<_>>();
        for id in forwarded {
            self.release_durable_artifact(id)?;
        }
        retire_prefix(&mut self.durable.state.exits, |view| *view <= floor);

        self.retire_view_history()?;
        self.forget_retired_artifacts()
            .map_err(|_| ReplayError::Transition(TransitionReason::References))?;
        Ok(())
    }

    /// Whether `artifact` sits at or below a retention floor: its view is retired or its chain
    /// position is certified.
    pub(super) fn retired(&self, artifact: &Artifact<V, H::Digest>) -> bool {
        artifact
            .view()
            .is_some_and(|view| view <= self.durable.state.retired_view)
            || artifact.chain_position().is_some_and(|(chain, height)| {
                self.durable
                    .state
                    .certified_tips
                    .get(chain.get() as usize)
                    .is_some_and(|tip| height <= tip.height())
            })
    }

    /// Returns where `artifact` sits against the retention floors.
    pub(super) fn floor_position(&self, artifact: &Artifact<V, H::Digest>) -> FloorPosition {
        if self.retired(artifact) {
            FloorPosition::Retired
        } else {
            FloorPosition::Above
        }
    }

    /// Queues a retained artifact for re-examination if it sits at or below a retention floor.
    pub(crate) fn note_retirement_candidate(&mut self, id: ArtifactId<H::Digest>) {
        if self
            .store
            .artifacts
            .get(&id)
            .is_some_and(|entry| self.retired(&entry.artifact))
        {
            self.store.retirement_pending.push(id);
        }
    }

    /// Returns whether retirement may forget a retained artifact once its state allows.
    ///
    /// Future-view artifacts and artifacts pinned by durable state stay retained.
    pub(super) fn forgettable(
        &self,
        id: &ArtifactId<H::Digest>,
        entry: &ArtifactEntry<V, H::Digest>,
    ) -> bool {
        !entry.future && !self.durable.artifact_references.contains_key(id)
    }

    /// Forgets the retired, ready, unreferenced artifacts among `candidates`.
    pub(crate) fn forget_ready(&mut self, candidates: impl Iterator<Item = ArtifactId<H::Digest>>) {
        let ids = candidates
            .filter(|id| {
                self.store.artifacts.get(id).is_some_and(|entry| {
                    self.forgettable(id, entry)
                        && matches!(entry.state, ArtifactState::Ready)
                        && self.retired(&entry.artifact)
                })
            })
            .collect::<Vec<_>>();
        for id in ids {
            // Candidates may repeat: a queued artifact can also sit in a freshly swept range.
            let Some(entry) = self.remove_entry(id) else {
                continue;
            };
            self.store.forget_vqcs(id, &entry.provisions);
            for provision in entry.provisions.iter() {
                if self.dependencies.remove_provider(provision, &id)
                    && matches!(provision, Dependency::Leader { round, .. }
                        if !round.view().is_zero() && round.view() <= self.durable.state.retired_view)
                {
                    self.dependencies.available.remove(provision);
                }
            }
        }
    }

    /// Forgets retained artifacts that retirement no longer needs.
    ///
    /// Each newly retired view and certified height is examined once. An artifact that stays
    /// retained past that examination (still verifying, durably referenced, or a future artifact)
    /// returns through the pending queue when its own state changes, so the work tracks state
    /// changes rather than the retained population.
    pub(super) fn forget_retired_artifacts(&mut self) -> Result<(), StepError> {
        let retired = self.durable.state.retired_view;
        let accountability_floor = self.retention_floor();
        self.accountability
            .retire(accountability_floor, &self.durable.state.certified_tips);
        let mut candidates = take(&mut self.store.retirement_pending);
        self.store.sweep_retired_views(retired, &mut candidates);
        self.store
            .sweep_retired_floors(&self.durable.state.certified_tips, &mut candidates);
        let waiting = candidates
            .iter()
            .filter(|id| {
                self.store.artifacts.get(id).is_some_and(|entry| {
                    self.forgettable(id, entry)
                        && matches!(entry.state, ArtifactState::Waiting(_))
                        && entry.artifact.view().is_some_and(|view| view <= retired)
                })
            })
            .copied()
            .collect::<Vec<_>>();
        for id in waiting {
            self.remove_terminal_artifact(id)?;
        }
        self.forget_ready(candidates.into_iter());
        Ok(())
    }
}
