//! The synchronizer mailbox, its messages, and its error.

use crate::{
    Viewable as _,
    multimmit::{
        actors::util::ask,
        marshal::{
            actors::{backfill, catalog},
            protocol::{ancestry, floor, order},
            storage,
            types::{self, Floor},
        },
        types::{CertificateId, FinalityFact, Lqc, SelectedCommitments, TransactionBlockHeader},
    },
    types::View,
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, VecDeque},
    error::Error as StdError,
    sync::Arc,
};
use tracing::Span;

/// A synchronization operation failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The synchronizer has stopped accepting commands.
    #[error("synchronizer mailbox is closed")]
    Closed,
    /// A catalog request failed.
    #[error("catalog request failed: {0}")]
    Catalog(#[from] catalog::Error),
    /// A backfill fetch failed.
    #[error("exact fetch failed: {0}")]
    Fetch(#[from] backfill::Error),
    /// A history or block scratch stack operation failed.
    #[error("scratch stack failed: {0}")]
    Scratch(#[from] storage::Error),
    /// A floor anchor failed L-QC verification.
    #[error("LQC verification failed: {0}")]
    Verify(#[source] Box<dyn StdError + Send + Sync>),
    /// An input or a local response violated a synchronization invariant.
    #[error("invalid synchronization input: {0}")]
    Invalid(&'static str),
    /// The dense output index space is exhausted.
    #[error("dense output coordinate is exhausted")]
    OutputExhausted,
    /// The floor generation counter is exhausted.
    #[error("floor generation is exhausted")]
    GenerationExhausted,
    /// The tip-history index is exhausted.
    #[error("history index is exhausted")]
    HistoryIndexExhausted,
    /// An ordering input is malformed or non-monotone.
    #[error(transparent)]
    Order(#[from] order::Error),
    /// A producer ancestry response is inconsistent with its request.
    #[error(transparent)]
    Ancestry(#[from] ancestry::Error),
    /// A floor checkpoint does not match the state it would replace.
    #[error(transparent)]
    Floor(#[from] floor::Error),
}

/// The reply for a floor installation.
pub(super) type Reply = types::Reply<(), Error>;

/// Distinct same-view L-QCs, keyed by certificate identifier.
pub(super) type FinalityProofs<V, D> = BTreeMap<CertificateId<D>, Arc<Lqc<V, D>>>;

/// Finalized L-QCs of the highest view reported so far, coalesced into one synchronization pass.
pub(super) struct FinalityBatch<V: Variant, D: Digest> {
    /// View shared by every proof in the batch.
    pub view: View,
    /// Distinct same-view proofs, keyed by certificate identifier.
    pub proofs: FinalityProofs<V, D>,
    /// Maximum number of distinct proofs retained.
    max_proofs: usize,
}

impl<V: Variant, D: Digest> FinalityBatch<V, D> {
    pub(super) fn new(id: CertificateId<D>, proof: Arc<Lqc<V, D>>, max_proofs: usize) -> Self {
        debug_assert!(max_proofs > 0);
        let view = proof.view();
        let mut proofs = BTreeMap::new();
        proofs.insert(id, proof);
        Self {
            view,
            proofs,
            max_proofs,
        }
    }

    /// Merges `next`, keeping only the proofs of the higher view.
    pub(super) fn merge(&mut self, next: Self) {
        match next.view.cmp(&self.view) {
            Ordering::Greater => {
                self.view = next.view;
                self.proofs = next.proofs;
            }
            Ordering::Equal => {
                for (id, proof) in next.proofs {
                    // Valid same-view LQCs are equivalent under the protocol fault assumption.
                    // Cap same-view proofs so a peer cannot grow the batch.
                    if self.proofs.len() == self.max_proofs && !self.proofs.contains_key(&id) {
                        break;
                    }
                    self.proofs.insert(id, proof);
                }
            }
            Ordering::Less => {}
        }
    }
}

/// A command for the synchronization actor.
pub(super) enum Message<V: Variant, D: Digest> {
    /// An authenticated producer header, used as an ancestry hint.
    Header {
        span: Span,
        header: TransactionBlockHeader<D>,
    },
    /// Authenticated forward producer paths, used as ancestry hints.
    Commitments { commitments: SelectedCommitments<D> },
    /// Finalized L-QCs to synchronize to.
    Synchronize {
        span: Span,
        batch: FinalityBatch<V, D>,
    },
    /// A locally derived direct-pool finality fact.
    Finality { span: Span, fact: FinalityFact<D> },
    /// A verified floor checkpoint to install, with the reply for its result.
    InstallFloor {
        span: Span,
        checkpoint: Floor<V, D>,
        reply: Reply,
    },
}

impl<V: Variant, D: Digest> Policy for Message<V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.retain(
            |message| !matches!(message, Self::InstallFloor { reply, .. } if reply.is_closed()),
        );
        match message {
            // Header and direct-pool hints are optional acceleration. Dropping them under mailbox
            // pressure preserves space for LQC finality and floor obligations with exact fallback.
            Self::Header { .. } | Self::Commitments { .. } | Self::Finality { .. } => {}
            Self::Synchronize { span, batch } => match overflow.back_mut() {
                Some(Self::Synchronize { batch: pending, .. }) => pending.merge(batch),
                _ => overflow.push_back(Self::Synchronize { span, batch }),
            },
            Self::InstallFloor {
                span,
                checkpoint,
                reply,
            } => {
                if !reply.is_closed() {
                    overflow.push_back(Self::InstallFloor {
                        span,
                        checkpoint,
                        reply,
                    });
                }
            }
        }
    }
}

/// Mailbox for the synchronization actor.
pub(crate) struct Mailbox<V: Variant, D: Digest> {
    commands: mailbox::Sender<Message<V, D>>,
    /// Maximum number of distinct same-view proofs one synchronization pass retains.
    max_proofs: usize,
}

impl<V: Variant, D: Digest> Clone for Mailbox<V, D> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            max_proofs: self.max_proofs,
        }
    }
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    pub(super) const fn new(commands: mailbox::Sender<Message<V, D>>, max_proofs: usize) -> Self {
        Self {
            commands,
            max_proofs,
        }
    }

    /// Enqueues a finalized target without waiting for resolution or durable publication.
    pub(crate) fn trigger(&self, id: CertificateId<D>, proof: Arc<Lqc<V, D>>) -> Result<(), Error> {
        match self.commands.enqueue(Message::Synchronize {
            span: Span::current(),
            batch: FinalityBatch::new(id, proof, self.max_proofs),
        }) {
            Feedback::Closed => Err(Error::Closed),
            Feedback::Ok | Feedback::Backoff => Ok(()),
        }
    }

    /// Offers one authenticated producer header as a non-authoritative ancestry hint.
    pub(crate) fn header(&self, header: TransactionBlockHeader<D>) -> Feedback {
        self.commands.enqueue(Message::Header {
            span: Span::current(),
            header,
        })
    }

    /// Offers authenticated forward producer paths without waiting for synchronization.
    pub(crate) fn commitments(&self, commitments: SelectedCommitments<D>) -> Feedback {
        self.commands.enqueue(Message::Commitments { commitments })
    }

    /// Offers one locally derived direct-pool finality projection.
    pub(crate) fn finality(&self, fact: FinalityFact<D>) -> Feedback {
        self.commands.enqueue(Message::Finality {
            span: Span::current(),
            fact,
        })
    }

    /// Verifies `checkpoint` and installs it as the durable floor.
    ///
    /// Returns once the catalog has installed the floor, or an error if the checkpoint is invalid
    /// or does not advance the current floor.
    pub(crate) async fn install_floor(&self, checkpoint: Floor<V, D>) -> Result<(), Error> {
        ask(
            |message| self.commands.enqueue(message),
            |reply| Message::InstallFloor {
                span: Span::current(),
                checkpoint,
                reply,
            },
            Error::Closed,
        )
        .await
    }
}
