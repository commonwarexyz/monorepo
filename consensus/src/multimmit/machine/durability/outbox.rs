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
    /// An own header stays published until its chain's height quorum `h*` reached its height, as
    /// the durable produced height shows (see
    /// [`DischargeFacts::endorsed_headers`](super::DischargeFacts::endorsed_headers)).
    HeaderBelowHstar {
        /// Producer chain.
        chain: ChainId,
        /// Published header height.
        height: Height,
    },
    /// A vote update stays published until the update two sequence numbers later is durable, or
    /// until its tag is unread: below the vote window of the current view, or retired.
    UpdateSuperseded {
        /// The view tagging the update.
        view: View,
        /// The update's sequence number.
        seq: u32,
    },
    /// A newer durable exit ends an older exit certificate's publication.
    ExitReplacedAfter {
        /// Published exit view.
        view: View,
    },
    /// An own leader block stays published until its view is unread: below the vote window of
    /// the current view, or retired.
    ViewUnread {
        /// Published message view.
        view: View,
    },
}

impl DischargeKind {
    /// Returns the fact that ends the publication of `artifact`.
    pub(crate) fn of<V: Variant, D: Digest>(artifact: &Artifact<V, D>) -> Self {
        match artifact {
            Artifact::TransactionBlock(block) => Self::HeaderBelowHstar {
                chain: block.header().chain(),
                height: block.header().height(),
            },
            Artifact::Update(update) => Self::UpdateSuperseded {
                view: update.view(),
                seq: update.seq(),
            },
            Artifact::Vqc(certificate) => Self::ExitReplacedAfter {
                view: certificate.view(),
            },
            Artifact::LeaderBlock(block) => Self::ViewUnread { view: block.view() },
            Artifact::Lqc(certificate) => Self::ViewUnread {
                view: certificate.view(),
            },
            Artifact::Floor(floor) => Self::ViewUnread {
                view: floor.lqc().view(),
            },
        }
    }

    /// Returns whether this fact can end the publication of `artifact`.
    pub(crate) fn matches<V: Variant, D: Digest>(self, artifact: &Artifact<V, D>) -> bool {
        match (self, artifact) {
            (Self::HeaderBelowHstar { chain, height }, Artifact::TransactionBlock(block)) => {
                block.header().chain() == chain && block.header().height() == height
            }
            (Self::UpdateSuperseded { view, seq }, Artifact::Update(update)) => {
                update.view() == view && update.seq() == seq
            }
            (Self::ExitReplacedAfter { view }, Artifact::Vqc(_))
            | (
                Self::ViewUnread { view },
                Artifact::LeaderBlock(_) | Artifact::Lqc(_) | Artifact::Floor(_),
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

    /// Returns `publication` queued until each of its items is ended by its own fact.
    pub(crate) fn of(publication: Publication<V, D>) -> Self {
        let discharges = match &publication {
            Publication::Propose(proposal) => vec![Discharge::new(
                0,
                DischargeKind::ViewUnread {
                    view: proposal.block().view(),
                },
            )],
            Publication::Broadcast(artifacts) => (0u32..)
                .zip(artifacts.iter())
                .map(|(item, artifact)| Discharge::new(item, DischargeKind::of(artifact)))
                .collect(),
        };
        Self::new(publication, discharges)
    }

    /// Returns the queued publication.
    pub(crate) const fn publication(&self) -> &Publication<V, D> {
        &self.publication
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
                            == DischargeKind::ViewUnread {
                                view: proposal.block().view(),
                            };
                }
                usize::try_from(discharge.item())
                    .ok()
                    .and_then(|item| self.publication.artifacts().get(item))
                    .is_some_and(|artifact| discharge.until().matches(artifact.as_ref()))
            })
    }
}
