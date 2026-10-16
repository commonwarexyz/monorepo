//! The synchronizer mailbox, its messages, and its error.

use crate::{
    multimmit::{
        actors::util::ask,
        marshal::{
            actors::{backfill, catalog},
            protocol::{
                ancestry,
                floor::{self, pinned_view},
                order,
            },
            storage,
            types::{self, Floor},
        },
        types::{BlockRef, CertificateId, ChainSet, HistoryRecord, Lqc, TransactionBlockHeader},
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
    mem,
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
    /// A floor L-QC failed verification.
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
    /// The tips-history index is exhausted.
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
    /// A floor install arrived while a pass or another floor install waited, which stopped it.
    ///
    /// The synchronizer recovers and runs the arriving floor install next. A floor install it
    /// stopped is answered with this error.
    #[error("a floor install interrupted the synchronization pass")]
    Preempted,
}

/// The reply for a floor installation.
pub(super) type Reply = types::Reply<(), Error>;

/// Distinct L-QCs pinning one view, keyed by certificate identifier.
pub(super) type FinalityProofs<V, D> = BTreeMap<CertificateId<D>, Arc<Lqc<V, D>>>;

/// A resolved view to synchronize through, coalesced into one synchronization pass.
///
/// Targets merge: the higher view wins, targets of one view pool their opening, and the L-QCs of
/// every merged target are kept, so a pass through a higher view still selects an L-QC pinning
/// an earlier view it opens.
pub(super) struct Target<V: Variant, D: Digest> {
    /// The resolved view.
    pub view: View,
    /// The tips-history commitment of `view`.
    pub commitment: D,
    /// The record opening `commitment`, when it came with the target.
    pub record: Option<Arc<HistoryRecord<D>>>,
    /// Distinct L-QCs pinning `view` or an earlier view.
    pub proofs: FinalityProofs<V, D>,
    /// Whether merged targets named different commitments for `view`.
    pub conflict: bool,
    /// Maximum number of distinct proofs retained.
    max_proofs: usize,
}

impl<V: Variant, D: Digest> Clone for Target<V, D> {
    fn clone(&self) -> Self {
        Self {
            view: self.view,
            commitment: self.commitment,
            record: self.record.clone(),
            proofs: self.proofs.clone(),
            conflict: self.conflict,
            max_proofs: self.max_proofs,
        }
    }
}

impl<V: Variant, D: Digest> Target<V, D> {
    /// Returns the target of resolved `view`, whose tips-history commitment `commitment` local
    /// consensus opened as `record`.
    pub(super) const fn resolved(
        view: View,
        commitment: D,
        record: Arc<HistoryRecord<D>>,
        max_proofs: usize,
    ) -> Self {
        Self {
            view,
            commitment,
            record: Some(record),
            proofs: BTreeMap::new(),
            conflict: false,
            max_proofs,
        }
    }

    /// Returns the target of the view `proof` pins, with the record opening it, if known.
    pub(super) fn finalized(
        id: CertificateId<D>,
        proof: Arc<Lqc<V, D>>,
        record: Option<Arc<HistoryRecord<D>>>,
        max_proofs: usize,
    ) -> Self {
        debug_assert!(max_proofs > 0);
        Self {
            view: pinned_view(&proof),
            commitment: proof.leader().history(),
            record,
            proofs: BTreeMap::from([(id, proof)]),
            conflict: false,
            max_proofs,
        }
    }

    /// Merges `next` into the target of the higher view, keeping the L-QCs of both.
    pub(super) fn merge(&mut self, next: Self) {
        let proofs = match next.view.cmp(&self.view) {
            Ordering::Greater => {
                let lower = mem::replace(self, next);
                self.conflict |= lower.conflict;
                lower.proofs
            }
            Ordering::Equal if next.commitment != self.commitment || next.conflict => {
                self.conflict = true;
                return;
            }
            Ordering::Equal => {
                if self.record.is_none() {
                    self.record = next.record;
                }
                next.proofs
            }
            Ordering::Less => next.proofs,
        };
        for (id, proof) in proofs {
            // Cap the proofs so a peer cannot grow the target; the higher target's come first.
            if self.proofs.len() == self.max_proofs && !self.proofs.contains_key(&id) {
                break;
            }
            self.proofs.entry(id).or_insert(proof);
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
    /// A resolved view to synchronize through.
    Synchronize { span: Span, target: Target<V, D> },
    /// The sweep of the open view, reported by local consensus.
    Sweep {
        view: View,
        finals: Arc<[BlockRef<D>]>,
        settled: ChainSet,
    },
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
            // Header and sweep hints are optional acceleration. Dropping them under mailbox
            // pressure preserves space for resolution and floor obligations with exact fallback.
            Self::Header { .. } | Self::Sweep { .. } => {}
            Self::Synchronize { span, target } => match overflow.back_mut() {
                Some(Self::Synchronize {
                    target: pending, ..
                }) => pending.merge(target),
                _ => overflow.push_back(Self::Synchronize { span, target }),
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
    /// Maximum number of distinct L-QCs one synchronization pass retains.
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

    /// Enqueues synchronization through the view the L-QC `proof` pins, without waiting for
    /// durable publication. `record`, when known, opens the proof's history commitment.
    pub(crate) fn trigger(
        &self,
        id: CertificateId<D>,
        proof: Arc<Lqc<V, D>>,
        record: Option<Arc<HistoryRecord<D>>>,
    ) -> Result<(), Error> {
        self.synchronize(Target::finalized(id, proof, record, self.max_proofs))
    }

    /// Enqueues synchronization through `view`, which local consensus resolved with the
    /// tips-history opening `record` of `commitment`, without waiting for durable publication.
    pub(crate) fn resolve(
        &self,
        view: View,
        commitment: D,
        record: Arc<HistoryRecord<D>>,
    ) -> Result<(), Error> {
        self.synchronize(Target::resolved(view, commitment, record, self.max_proofs))
    }

    fn synchronize(&self, target: Target<V, D>) -> Result<(), Error> {
        match self.commands.enqueue(Message::Synchronize {
            span: Span::current(),
            target,
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

    /// Offers the sweep of the open view: per chain, the highest block every correct log will
    /// contain, and the chains that gain nothing more in the view.
    pub(crate) fn sweep(
        &self,
        view: View,
        finals: Arc<[BlockRef<D>]>,
        settled: ChainSet,
    ) -> Feedback {
        self.commands.enqueue(Message::Sweep {
            view,
            finals,
            settled,
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
