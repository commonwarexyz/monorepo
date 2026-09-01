//! Publication discharges: the protocol facts that retire queued publications.

use super::{
    durability::{
        Discharge, DischargeKind, DurableEffect, EffectId, OutboxEntry, Publication, ReplayError,
        TransitionReason,
    },
    reducer::machine::Machine,
};
use crate::{
    Viewable,
    multimmit::types::{Artifact, ChainId},
    types::{Height, View},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};

/// Outstanding data-availability publications per chain and pipeline slot: a block, a DA vote,
/// and a DA certificate.
const DA_PUBLICATIONS_PER_SLOT: usize = 3;

/// Outstanding own-message publications per retained view: a leader block, a vote or no-vote, a
/// nullify share, and an L-QC.
const OWN_MESSAGES_PER_VIEW: usize = 4;

/// Outstanding discharges per bounded family, or the bound on them.
#[derive(Default)]
pub(crate) struct ObligationCounts {
    pub(crate) da: usize,
    pub(crate) own_messages: usize,
}

/// A durable protocol fact evaluated against queued discharges.
#[derive(Copy, Clone)]
enum Successor {
    /// No new fact: discharges are evaluated against the durable state alone.
    Current,
    /// A DA certificate at this height on this chain.
    Da(ChainId, Height),
    /// A durable exit from this view.
    Exit(View),
    /// A retention floor raised to this view.
    Floor(View),
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the most outstanding discharges each bounded family may hold.
    ///
    /// Own messages are counted from the durable retired view, so the retained window is the
    /// larger of this profile's view retention and the views the durable state still holds below
    /// the current one. The two agree in steady state; the durable window is larger after a
    /// restart with a smaller view retention, until the next exit compacts it.
    pub(crate) fn obligation_family_bounds(&self) -> ObligationCounts {
        let protocol = self.profile.codec();
        let da = protocol
            .chains()
            .checked_mul(protocol.pipeline_depth())
            .and_then(|slots| slots.checked_mul(DA_PUBLICATIONS_PER_SLOT))
            .unwrap_or(usize::MAX);
        let durable_window = self
            .durable
            .state
            .view
            .get()
            .saturating_sub(self.durable.state.retired_view.get())
            .saturating_sub(1);
        let retained_views =
            usize::try_from(self.profile.view_retention().get().max(durable_window))
                .ok()
                .and_then(|retention| retention.checked_add(1))
                .unwrap_or(usize::MAX);
        let own_messages = retained_views.saturating_mul(OWN_MESSAGES_PER_VIEW);
        ObligationCounts { da, own_messages }
    }

    /// Returns whether queuing `discharges` keeps every family within its bound.
    fn discharges_fit(&self, discharges: &[Discharge]) -> bool {
        let mut counts = ObligationCounts::default();
        // A batch can outlive its certified items. Family limits count outstanding duties;
        // the artifact cache independently bounds every payload retained by the whole batch.
        for discharge in self
            .durable
            .state
            .outbox
            .values()
            .flat_map(OutboxEntry::discharges)
            .chain(discharges)
            .filter(|discharge| !self.discharge_satisfied(discharge.until(), Successor::Current))
        {
            match discharge.until() {
                DischargeKind::BlockCertifiedAtLeast { .. }
                | DischargeKind::VoteCertifiedAtLeast { .. }
                | DischargeKind::CertificateSupersededAbove { .. } => {
                    counts.da = counts.da.saturating_add(1);
                }
                // Exit publications are already bounded by the durable outbox. Their proofs may
                // outlive compacted forwarding history until a higher exit replaces them.
                DischargeKind::ExitReplacedAfter { .. } => {}
                DischargeKind::ViewRetired { .. } => {
                    counts.own_messages = counts.own_messages.saturating_add(1);
                }
            }
        }
        let bounds = self.obligation_family_bounds();
        counts.da <= bounds.da && counts.own_messages <= bounds.own_messages
    }

    /// Returns the fact that ends the publication of `artifact`, or `None` when it already holds.
    fn discharge_kind(&self, artifact: &Artifact<V, H::Digest>) -> Option<DischargeKind> {
        let certified = |chain| {
            self.durable
                .state
                .certified_height(chain)
                .unwrap_or_default()
        };
        match artifact {
            Artifact::TransactionBlock(block) => {
                let (chain, height) = (block.header().chain(), block.header().height());
                (certified(chain) < height)
                    .then_some(DischargeKind::BlockCertifiedAtLeast { chain, height })
            }
            Artifact::DaVote(vote) => {
                let (chain, height) = (vote.header().chain(), vote.header().height());
                (certified(chain) < height)
                    .then_some(DischargeKind::VoteCertifiedAtLeast { chain, height })
            }
            Artifact::DaCertificate(certificate) => {
                let (chain, height) = (certificate.header().chain(), certificate.header().height());
                (certified(chain) <= height)
                    .then_some(DischargeKind::CertificateSupersededAbove { chain, height })
            }
            Artifact::Vqc(certificate) => Some(DischargeKind::ExitReplacedAfter {
                view: certificate.view(),
            }),
            Artifact::Nullification(certificate) => Some(DischargeKind::ExitReplacedAfter {
                view: certificate.view(),
            }),
            Artifact::LeaderBlock(block) => self.own_message_discharge(block.view()),
            Artifact::Vote(vote) => self.own_message_discharge(vote.view()),
            Artifact::NoVote(vote) => self.own_message_discharge(vote.view()),
            Artifact::Nullify(vote) => self.own_message_discharge(vote.view()),
            Artifact::Lqc(certificate) => self.own_message_discharge(certificate.view()),
        }
    }

    /// Returns the discharge of an own message in `view`, or `None` once the durably retired
    /// view covers it.
    ///
    /// The durable floor rather than the profile's is used, so replay reaches the same decision
    /// after the view retention changes across a restart.
    fn own_message_discharge(&self, view: View) -> Option<DischargeKind> {
        (self.durable.state.retired_view <= view).then_some(DischargeKind::ViewRetired { view })
    }

    /// Returns the discharges of `publication`'s outstanding items, in item order, or `None`
    /// when no item is outstanding.
    pub(super) fn discharges(
        &self,
        publication: &Publication<V, H::Digest>,
    ) -> Option<Vec<Discharge>> {
        let discharges = match publication {
            Publication::Propose(proposal) => self
                .own_message_discharge(proposal.block().view())
                .map(|until| Discharge::new(0, until))
                .into_iter()
                .collect(),
            Publication::Broadcast(_) | Publication::Send(_) => publication
                .artifacts()
                .enumerate()
                .filter_map(|(item, artifact)| {
                    let item = u32::try_from(item).ok()?;
                    let until = self.discharge_kind(artifact)?;
                    Some(Discharge::new(item, until))
                })
                .collect::<Vec<_>>(),
        };
        (!discharges.is_empty()).then_some(discharges)
    }

    fn discharge_satisfied(&self, until: DischargeKind, successor: Successor) -> bool {
        let certified = |chain: ChainId| match successor {
            Successor::Da(successor, height) if successor == chain => height,
            _ => self
                .durable
                .state
                .certified_height(chain)
                .unwrap_or_default(),
        };
        match until {
            DischargeKind::BlockCertifiedAtLeast { chain, height }
            | DischargeKind::VoteCertifiedAtLeast { chain, height } => certified(chain) >= height,
            DischargeKind::CertificateSupersededAbove { chain, height } => {
                certified(chain) > height
            }
            DischargeKind::ExitReplacedAfter { view } => {
                matches!(successor, Successor::Exit(exit) if exit > view)
            }
            DischargeKind::ViewRetired { view } => {
                let floor = match successor {
                    Successor::Floor(floor) => floor,
                    _ => self.durable.state.retired_view,
                };
                floor > view
            }
        }
    }

    fn obligations_satisfied(&self, successor: Successor) -> Vec<EffectId> {
        self.durable
            .state
            .outbox
            .iter()
            .filter_map(|(id, entry)| {
                entry
                    .discharges()
                    .iter()
                    .all(|discharge| self.discharge_satisfied(discharge.until(), successor))
                    .then_some(*id)
            })
            .collect()
    }

    pub(super) fn obligations_retired_by_da(
        &self,
        chain: ChainId,
        height: Height,
    ) -> Vec<EffectId> {
        self.obligations_satisfied(Successor::Da(chain, height))
    }

    pub(super) fn obligations_retired_by_exit(&self, view: View) -> Vec<EffectId> {
        self.obligations_satisfied(Successor::Exit(view))
    }

    pub(super) fn obligations_retired_by_floor(&self, floor: View) -> Vec<EffectId> {
        self.obligations_satisfied(Successor::Floor(floor))
    }

    /// Queues `publication` with its outstanding discharges when they fit their family bounds.
    pub(super) fn install_publication(
        &mut self,
        id: EffectId,
        publication: Publication<V, H::Digest>,
    ) -> bool {
        let Some(discharges) = self.discharges(&publication) else {
            return false;
        };
        if !self.discharges_fit(&discharges) {
            return false;
        }
        self.durable
            .state
            .outbox
            .insert(id, OutboxEntry::new(publication, discharges))
            .is_none()
    }

    pub(super) fn retire_publication_obligations(
        &mut self,
        retired: &[EffectId],
    ) -> Result<(), ReplayError> {
        if retired.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ReplayError::Transition(TransitionReason::Obligation));
        }
        for id in retired {
            let entry = self
                .durable
                .state
                .outbox
                .remove(id)
                .ok_or(ReplayError::Transition(TransitionReason::Obligation))?;
            self.release_durable_effect(*id, &DurableEffect::Publish(entry.into_publication()))?;
        }
        Ok(())
    }
}
