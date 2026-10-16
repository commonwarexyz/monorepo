//! Finality anchoring: how a node further behind than its peers' retention catches up.
//!
//! Peers retain the views above their own retention floor only, so a node whose current view lies
//! below it can never again hold a V-QC of its next view, which needs the whole parent chain. Such
//! a node asks a peer for its newest finalization certificate ([`RetrievalKey::LatestFloor`]): an
//! L-QC of view `v` with the record opening its leader block's history commitment. That certificate
//! fixes the facts of the V-QC `Q'` every V-QC of `v` and later descends from, so it is a retention
//! root authenticated by `n - f` votes rather than by the node's own chain.
//!
//! The node asks when its restart could not hold the V-QC its current view was entered on (the
//! durable state predates its peers' retention), and when a V-QC or L-QC beyond the future-view
//! window verifies: its `n - f` signers include a correct validator that far ahead. Such a
//! certificate is refused, but its signature is checked first, one certificate at a time and only
//! while no request is outstanding. A signed artifact there is refused unchecked: the signer it
//! names proves nothing. At most one request is outstanding. A verified floor of view `v` anchors
//! the node when `v > view + J` ([`Tuning::anchor_lag`]); a nearer one is dropped and the node
//! catches up view by view. Of several, the highest is kept, and a later one beyond the lag anchors
//! the node again.
//!
//! Anchoring stages [`Change::Anchored`] and restarts the machine in process
//! ([`Machine::restart_in_process`]): a new generation fences the work issued before, and every
//! component is rebuilt from the new durable state. The node then enters `v` on `Q'`, reports the
//! certificate finalized, and votes only in tags from `v` on.
//!
//! [`Tuning::anchor_lag`]: crate::multimmit::config::Tuning::anchor_lag
//! [`Change::Anchored`]: crate::multimmit::machine::durability::Change::Anchored

use super::vqc::Identified;
use crate::{
    Viewable as _,
    multimmit::{
        machine::{
            capability::{Capabilities, Capability},
            input::{Now, Rejection, StepError},
            reducer::{
                components::{Precheck, WorkStatus},
                machine::Machine,
            },
            resolution::RetrievalKey,
            scheduler::ProtocolComponent,
            verification::{VerificationItem, VerificationTicket},
        },
        types::{Artifact, ArtifactId, ArtifactKind, Floor},
    },
    types::View,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// The anchoring component's volatile state.
pub(crate) struct Anchor<V: Variant, D: Digest> {
    /// The signature check of a certificate refused for lying beyond the future-view window, while
    /// one is in flight.
    probe: Option<VerificationTicket<D>>,
    /// The highest verified floor this node can anchor on.
    floor: Option<Identified<V, D>>,
}

impl<V: Variant, D: Digest> Anchor<V, D> {
    pub(crate) const fn new() -> Self {
        Self {
            probe: None,
            floor: None,
        }
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns whether a floor of `view` lies beyond the anchor lag above the current view.
    const fn beyond_lag(&self, view: View) -> bool {
        view.get()
            > self
                .durable
                .state
                .view
                .get()
                .saturating_add(self.profile.tuning().anchor_lag.get())
    }

    /// Returns the view of the floor held for anchoring, if any.
    fn held_floor(&self) -> Option<View> {
        self.components
            .anchor
            .floor
            .as_ref()
            .and_then(|(_, artifact)| artifact.view())
    }

    /// Checks the signature of `artifact`, refused for lying beyond the future-view window, under
    /// `ticket` when it is a certificate of a later view, no check or floor request is
    /// outstanding, and a verification job fits. Returns the item to verify, if any.
    pub(in crate::multimmit::machine) fn probe_ahead(
        &mut self,
        ticket: VerificationTicket<H::Digest>,
        artifact: Artifact<V, H::Digest>,
    ) -> Option<VerificationItem<V, H::Digest>> {
        if !matches!(artifact, Artifact::Vqc(_) | Artifact::Lqc(_))
            || artifact
                .view()
                .is_none_or(|view| view <= self.durable.state.view)
            || self.components.anchor.probe.is_some()
            || self.resolution.contains(&RetrievalKey::LatestFloor)
            || self.completions.verification_jobs.len()
                >= self.profile.resources().max_inflight_verifications()
        {
            return None;
        }
        self.components.anchor.probe = Some(ticket);
        Some(VerificationItem::new(ticket, Arc::new(artifact)))
    }

    /// Settles the verdict `valid` on the certificate checked under `ticket`, requesting a peer's
    /// newest floor when it holds. Returns whether `ticket` was that check.
    pub(in crate::multimmit::machine) fn settle_probe(
        &mut self,
        ticket: VerificationTicket<H::Digest>,
        valid: bool,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<bool, StepError> {
        if self.components.anchor.probe != Some(ticket) {
            return Ok(false);
        }
        self.components.anchor.probe = None;
        if valid {
            capabilities.extend(self.request(RetrievalKey::LatestFloor)?);
        }
        Ok(true)
    }

    /// Refuses a floor this node would not anchor on: one within the anchor lag, or one no higher
    /// than the floor it holds.
    pub(in crate::multimmit::machine) fn precheck_floor(
        &self,
        floor: &Floor<V, H::Digest>,
    ) -> Result<Precheck<H::Digest>, Rejection> {
        let view = floor.lqc().view();
        if !self.beyond_lag(view) {
            return Err(Rejection::TagWindow);
        }
        if self.held_floor().is_some_and(|held| held >= view) {
            return Err(Rejection::Superseded);
        }
        Ok(Precheck::Verify(None))
    }

    /// Holds an authenticated floor for anchoring when this node can anchor on it and it is higher
    /// than the one held, and drops it otherwise.
    pub(in crate::multimmit::machine) fn admit_floor(
        &mut self,
        id: ArtifactId<H::Digest>,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) {
        let Artifact::Floor(floor) = artifact.as_ref() else {
            return;
        };
        let view = floor.lqc().view();
        if !self.beyond_lag(view)
            || !self.anchors(floor)
            || self.held_floor().is_some_and(|held| held >= view)
        {
            self.store.remove(&id);
            return;
        }
        if let Some((replaced, _)) = self
            .components
            .anchor
            .floor
            .replace((id, Arc::clone(artifact)))
        {
            self.store.remove(&replaced);
        }
        self.wake(ProtocolComponent::Forwarding);
    }

    /// Anchors on the floor held, unless the current view caught up within the anchor lag: stages
    /// the anchor, then restarts the machine in process at `now`. Returns `None` when no floor is
    /// held, and [`WorkStatus::Blocked`] until the artifact cache holds the anchoring L-QC and two
    /// batches (the anchor and the generation) can be staged.
    pub(in crate::multimmit::machine) fn anchor(
        &mut self,
        capabilities: &mut Capabilities<V, H::Digest>,
        now: Now,
    ) -> Result<Option<WorkStatus>, StepError> {
        let Some((id, artifact)) = self.components.anchor.floor.take() else {
            return Ok(None);
        };
        let Artifact::Floor(floor) = artifact.as_ref() else {
            return Err(StepError::ViewInvariant);
        };
        if !self.beyond_lag(floor.lqc().view()) || !self.anchors(floor) {
            self.store.remove(&id);
            return Ok(None);
        }
        let lqc = Artifact::<V, H::Digest>::id_of::<H, _>(ArtifactKind::Lqc, floor.lqc());
        if !self.fits(&[lqc])
            || !self.has_batch_room(2)
            || !self.stage(self.anchoring(Arc::clone(&artifact)), capabilities)?
        {
            self.components.anchor.floor = Some((id, artifact));
            return Ok(Some(WorkStatus::Blocked));
        }
        capabilities.extend(self.restart_in_process(now)?);
        Ok(Some(WorkStatus::Requeue))
    }

    /// Resets the anchoring component at a start, a restart, or an anchor, and requests a peer's
    /// newest floor when the V-QC the current view was entered on is not held.
    pub(in crate::multimmit::machine) fn restore_anchor(
        &mut self,
    ) -> Result<Option<Capability<V, H::Digest>>, StepError> {
        self.components.anchor = Anchor::new();
        if self.components.view.state.parent.is_some() {
            return Ok(None);
        }
        self.request(RetrievalKey::LatestFloor)
    }
}
