//! Queued publications and the protocol facts that end them.

use super::Publication;
use crate::{
    Viewable,
    multimmit::types::{Artifact, ChainId},
    types::{Height, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// The protocol fact that ends the duty to publish one item.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum DischargeKind {
    /// A certificate at or above the block height substitutes for the window fact.
    BlockCertifiedAtLeast {
        /// Producer chain.
        chain: ChainId,
        /// Published block height.
        height: Height,
    },
    /// A certificate at or above the vote height makes the share redundant.
    VoteCertifiedAtLeast {
        /// Producer chain.
        chain: ChainId,
        /// Voted height.
        height: Height,
    },
    /// Only a strictly higher certificate supersedes a certificate publication.
    CertificateSupersededAbove {
        /// Producer chain.
        chain: ChainId,
        /// Published certificate height.
        height: Height,
    },
    /// A newer durable exit ends an older exit publication.
    ExitReplacedAfter {
        /// Published exit view.
        view: View,
    },
    /// The acknowledged retention floor ends an own-message publication.
    ViewRetired {
        /// Published message view.
        view: View,
    },
}

impl DischargeKind {
    /// Returns whether this fact can end the publication of `artifact`.
    fn matches<V: Variant, D: Digest>(self, artifact: &Artifact<V, D>) -> bool {
        match (self, artifact) {
            (Self::BlockCertifiedAtLeast { chain, height }, Artifact::TransactionBlock(block)) => {
                block.header().chain() == chain && block.header().height() == height
            }
            (Self::VoteCertifiedAtLeast { chain, height }, Artifact::DaVote(vote)) => {
                vote.header().chain() == chain && vote.header().height() == height
            }
            (
                Self::CertificateSupersededAbove { chain, height },
                Artifact::DaCertificate(certificate),
            ) => certificate.header().chain() == chain && certificate.header().height() == height,
            (Self::ExitReplacedAfter { view }, Artifact::Vqc(_) | Artifact::Nullification(_))
            | (
                Self::ViewRetired { view },
                Artifact::LeaderBlock(_)
                | Artifact::Vote(_)
                | Artifact::NoVote(_)
                | Artifact::Nullify(_)
                | Artifact::Lqc(_),
            ) => artifact.view() == Some(view),
            _ => false,
        }
    }
}

/// The end condition for one item of a queued publication.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Discharge {
    pub(super) item: u32,
    pub(super) until: DischargeKind,
}

impl Discharge {
    pub(crate) const fn new(item: u32, until: DischargeKind) -> Self {
        Self { item, until }
    }

    /// Returns the item's ordinal within its publication.
    pub(crate) const fn item(self) -> u32 {
        self.item
    }

    /// Returns the protocol fact that ends the item's publication.
    pub(crate) const fn until(self) -> DischargeKind {
        self.until
    }
}

/// One queued publication and the end conditions of its items.
///
/// The publication retires once every discharge holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboxEntry<V: Variant, D: Digest> {
    pub(super) publication: Publication<V, D>,
    pub(super) discharges: Arc<[Discharge]>,
}

impl<V: Variant, D: Digest> OutboxEntry<V, D> {
    pub(crate) fn new(publication: Publication<V, D>, discharges: Vec<Discharge>) -> Self {
        Self {
            publication,
            discharges: discharges.into(),
        }
    }

    /// Returns the queued publication.
    pub(crate) const fn publication(&self) -> &Publication<V, D> {
        &self.publication
    }

    /// Consumes the entry and returns its publication.
    pub(crate) fn into_publication(self) -> Publication<V, D> {
        self.publication
    }

    /// Returns the end condition of every outstanding item, in item order.
    pub(crate) fn discharges(&self) -> &[Discharge] {
        &self.discharges
    }

    /// Returns whether the discharges name distinct items, in order, each ended by its fact.
    pub(crate) fn consistent(&self) -> bool {
        !self.discharges.is_empty()
            && self
                .discharges
                .windows(2)
                .all(|pair| pair[0].item() < pair[1].item())
            && self.discharges.iter().all(|discharge| {
                if let Publication::Propose(proposal) = &self.publication {
                    return discharge.item() == 0
                        && discharge.until()
                            == DischargeKind::ViewRetired {
                                view: proposal.block().view(),
                            };
                }
                usize::try_from(discharge.item())
                    .ok()
                    .and_then(|item| self.publication.artifact(item))
                    .is_some_and(|artifact| discharge.until().matches(artifact.as_ref()))
            })
    }
}
