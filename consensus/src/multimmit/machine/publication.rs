//! Durable family-typed publication obligations.

use super::{
    Artifact, DurableEffect, EffectId, Machine, ObligationId, PublicationDischarge,
    PublicationKind, PublicationObligation,
};
use crate::{
    Viewable,
    multimmit::types::{ChainId, Height},
    types::View,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};

pub(crate) struct ObligationFamilyBounds {
    pub(crate) da: usize,
    pub(crate) own_messages: usize,
}

#[derive(Default)]
struct ObligationFamilyCounts {
    da: usize,
    own_messages: usize,
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    pub(crate) fn obligation_family_bounds(&self) -> ObligationFamilyBounds {
        let protocol = self.profile.protocol().codec_config();
        let da = protocol
            .chains()
            .checked_mul(protocol.pipeline_depth())
            .and_then(|slots| slots.checked_mul(3))
            .unwrap_or(usize::MAX);
        let retained_views = usize::try_from(self.profile.view_retention().get())
            .ok()
            .and_then(|retention| retention.checked_add(1))
            .unwrap_or(usize::MAX);
        let own_messages = retained_views.saturating_mul(4);
        ObligationFamilyBounds { da, own_messages }
    }

    pub(super) fn publication_obligation_fits(&self, candidate: &PublicationObligation) -> bool {
        let mut counts = ObligationFamilyCounts::default();
        for discharge in self
            .durable
            .obligations
            .values()
            .flat_map(PublicationObligation::discharges)
            .chain(candidate.discharges())
        {
            match discharge {
                PublicationDischarge::BlockCertifiedAtLeast { .. }
                | PublicationDischarge::VoteCertifiedAtLeast { .. }
                | PublicationDischarge::CertificateSupersededAbove { .. } => {
                    counts.da = counts.da.saturating_add(1);
                }
                // Exit publications are already bounded by the durable outbox. Their proofs may
                // outlive compacted forwarding history until a higher exit replaces them.
                PublicationDischarge::ExitReplacedAfter { .. } => {}
                PublicationDischarge::ViewRetired { .. } => {
                    counts.own_messages = counts.own_messages.saturating_add(1);
                }
            }
        }
        let bounds = self.obligation_family_bounds();
        counts.da <= bounds.da && counts.own_messages <= bounds.own_messages
    }

    const fn publication_kind(effect: &DurableEffect<V, H::Digest>) -> Option<PublicationKind> {
        match effect {
            DurableEffect::Broadcast(_) => Some(PublicationKind::Broadcast),
            DurableEffect::BroadcastBatch(_) => Some(PublicationKind::BroadcastBatch),
            DurableEffect::Propose(_) => Some(PublicationKind::Propose),
            DurableEffect::Send(_) => Some(PublicationKind::Send),
            DurableEffect::SendBatch(_) => Some(PublicationKind::SendBatch),
            DurableEffect::Sign(_) | DurableEffect::SignBatch(_) => None,
        }
    }

    fn publication_artifacts(effect: &DurableEffect<V, H::Digest>) -> Vec<&Artifact<V, H::Digest>> {
        match effect {
            DurableEffect::Broadcast(artifact) => vec![artifact.as_ref()],
            DurableEffect::BroadcastBatch(artifacts) => {
                artifacts.iter().map(|artifact| artifact.as_ref()).collect()
            }
            DurableEffect::Send(request) => vec![request.artifact().as_ref()],
            DurableEffect::SendBatch(requests) => requests
                .iter()
                .map(|request| request.artifact().as_ref())
                .collect(),
            DurableEffect::Sign(_) | DurableEffect::SignBatch(_) | DurableEffect::Propose(_) => {
                Vec::new()
            }
        }
    }

    fn typed_discharge(
        &self,
        effect: EffectId,
        item: u32,
        artifact: &Artifact<V, H::Digest>,
    ) -> Option<PublicationDischarge> {
        match artifact {
            Artifact::TransactionBlock(block) => {
                let chain = block.header().chain();
                let height = block.header().height();
                (self.certified_height(chain) < height).then_some(
                    PublicationDischarge::BlockCertifiedAtLeast {
                        id: ObligationId::new(effect, item),
                        chain,
                        height,
                    },
                )
            }
            Artifact::DaVote(vote) => {
                let chain = vote.header().chain();
                let height = vote.header().height();
                (self.certified_height(chain) < height).then_some(
                    PublicationDischarge::VoteCertifiedAtLeast {
                        id: ObligationId::new(effect, item),
                        chain,
                        height,
                    },
                )
            }
            Artifact::DaCertificate(certificate) => {
                let chain = certificate.header().chain();
                let height = certificate.header().height();
                (self.certified_height(chain) <= height).then_some(
                    PublicationDischarge::CertificateSupersededAbove {
                        id: ObligationId::new(effect, item),
                        chain,
                        height,
                    },
                )
            }
            Artifact::Vqc(certificate) => Some(PublicationDischarge::ExitReplacedAfter {
                id: ObligationId::new(effect, item),
                view: certificate.view(),
            }),
            Artifact::Nullification(certificate) => Some(PublicationDischarge::ExitReplacedAfter {
                id: ObligationId::new(effect, item),
                view: certificate.view(),
            }),
            Artifact::LeaderBlock(block) => self.own_message_discharge(effect, item, block.view()),
            Artifact::Vote(vote) => self.own_message_discharge(effect, item, vote.view()),
            Artifact::NoVote(vote) => self.own_message_discharge(effect, item, vote.view()),
            Artifact::Nullify(vote) => self.own_message_discharge(effect, item, vote.view()),
            Artifact::Lqc(certificate) => {
                self.own_message_discharge(effect, item, certificate.view())
            }
        }
    }

    fn own_message_discharge(
        &self,
        effect: EffectId,
        item: u32,
        view: View,
    ) -> Option<PublicationDischarge> {
        let floor = self.retention_floor().max(self.durable.retired_view);
        (floor <= view).then_some(PublicationDischarge::ViewRetired {
            id: ObligationId::new(effect, item),
            view,
        })
    }

    fn certified_height(&self, chain: ChainId) -> Height {
        self.durable
            .certified_tips
            .get(chain.get() as usize)
            .map_or(Height::zero(), |tip| tip.height())
    }

    pub(super) fn publication_obligation(
        &self,
        id: EffectId,
        effect: &DurableEffect<V, H::Digest>,
    ) -> Option<PublicationObligation> {
        let kind = Self::publication_kind(effect)?;
        let mut discharges = match effect {
            DurableEffect::Propose(proposal) => self
                .own_message_discharge(id, 0, proposal.block().view())
                .into_iter()
                .collect(),
            _ => Self::publication_artifacts(effect)
                .into_iter()
                .enumerate()
                .filter_map(|(item, artifact)| {
                    let item = u32::try_from(item).ok()?;
                    self.typed_discharge(id, item, artifact)
                })
                .collect::<Vec<_>>(),
        };
        if discharges.is_empty() {
            return None;
        }
        discharges.sort_unstable_by_key(|discharge| discharge.item());
        Some(PublicationObligation::new(id, kind, discharges))
    }

    fn discharge_satisfied(
        &self,
        discharge: PublicationDischarge,
        da: Option<(ChainId, Height)>,
        exit: Option<View>,
        floor: Option<View>,
    ) -> bool {
        match discharge {
            PublicationDischarge::BlockCertifiedAtLeast { chain, height, .. }
            | PublicationDischarge::VoteCertifiedAtLeast { chain, height, .. } => {
                let certified = da
                    .filter(|(successor_chain, _)| *successor_chain == chain)
                    .map_or_else(|| self.certified_height(chain), |(_, height)| height);
                certified >= height
            }
            PublicationDischarge::CertificateSupersededAbove { chain, height, .. } => {
                let certified = da
                    .filter(|(successor_chain, _)| *successor_chain == chain)
                    .map_or_else(|| self.certified_height(chain), |(_, height)| height);
                certified > height
            }
            PublicationDischarge::ExitReplacedAfter { view, .. } => {
                exit.is_some_and(|successor| successor > view)
            }
            PublicationDischarge::ViewRetired { view, .. } => {
                floor.unwrap_or_else(|| self.retention_floor().max(self.durable.retired_view))
                    > view
            }
        }
    }

    fn obligations_satisfied(
        &self,
        da: Option<(ChainId, Height)>,
        exit: Option<View>,
        floor: Option<View>,
    ) -> Vec<EffectId> {
        self.durable
            .obligations
            .iter()
            .filter_map(|(id, obligation)| {
                obligation
                    .discharges()
                    .iter()
                    .all(|discharge| self.discharge_satisfied(*discharge, da, exit, floor))
                    .then_some(*id)
            })
            .collect()
    }

    pub(super) fn obligations_retired_by_da(
        &self,
        chain: ChainId,
        height: Height,
    ) -> Vec<EffectId> {
        self.obligations_satisfied(Some((chain, height)), None, None)
    }

    pub(super) fn obligations_retired_by_exit(&self, view: View) -> Vec<EffectId> {
        self.obligations_satisfied(None, Some(view), None)
    }

    pub(super) fn obligations_retired_by_floor(&self, floor: View) -> Vec<EffectId> {
        self.obligations_satisfied(None, None, Some(floor))
    }

    pub(super) fn install_publication_obligation(
        &mut self,
        id: EffectId,
        effect: &DurableEffect<V, H::Digest>,
    ) -> bool {
        let Some(obligation) = self.publication_obligation(id, effect) else {
            return false;
        };
        if !self.publication_obligation_fits(&obligation) {
            return false;
        }
        self.durable.obligations.insert(id, obligation).is_none()
    }

    pub(super) fn retire_publication_obligations(
        &mut self,
        retired: &[EffectId],
    ) -> Result<(), super::ReplayError> {
        if retired.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(super::ReplayError::Transition);
        }
        for id in retired {
            if self.durable.obligations.remove(id).is_none() {
                return Err(super::ReplayError::Transition);
            }
            let effect = self
                .durable
                .outbox
                .remove(id)
                .ok_or(super::ReplayError::Transition)?;
            self.release_durable_effect(*id, &effect)?;
        }
        Ok(())
    }
}
