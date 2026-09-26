//! The running synchronizer's mailbox receiver and the commands it defers during a pass.

use super::mailbox::{Error, FinalityBatch, Message, Reply};
use crate::multimmit::{
    marshal::types::Floor,
    types::{FinalityFact, SelectedCommitments, TransactionBlockHeader},
};
use commonware_actor::mailbox;
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::future::{Future, pending};
use tracing::Span;

/// An optional hint taken in while a synchronization pass runs.
pub(super) enum Absorbed<D: Digest> {
    /// An authenticated producer header.
    Header(TransactionBlockHeader<D>),
    /// Authenticated forward producer paths.
    Commitments(SelectedCommitments<D>),
    /// A direct-pool finality fact.
    Finality(FinalityFact<D>),
}

/// A synchronization target merged from the messages a pass took in.
pub(super) struct DeferredSync<V: Variant, D: Digest> {
    pub span: Span,
    pub batch: FinalityBatch<V, D>,
}

impl<V: Variant, D: Digest> DeferredSync<V, D> {
    /// Merges the target `batch`, requested under `span`.
    fn merge(&mut self, span: Span, batch: FinalityBatch<V, D>) {
        // Multiple hints from one router batch share their origin span.
        if self.span.id() != span.id() {
            self.span.follows_from(span.id());
        }
        self.batch.merge(batch);
    }
}

/// A floor installation waiting for the current pass to finish.
pub(super) struct DeferredFloor<V: Variant, D: Digest> {
    pub span: Span,
    pub checkpoint: Floor<V, D>,
    pub reply: Reply,
}

/// Input a synchronization pass takes in while it waits for storage or peers.
pub(super) trait Absorb<V: Variant, D: Digest>: Send {
    /// Takes one message: defers a command, or returns a hint for the pass to apply.
    ///
    /// Resolves to `None` when the message was deferred or the mailbox closed, and pends while
    /// no message may be taken.
    fn absorb(&mut self) -> impl Future<Output = Result<Option<Absorbed<D>>, Error>> + Send;
}

/// The input of recovery, which takes nothing in.
pub(super) struct Idle;

impl<V: Variant, D: Digest> Absorb<V, D> for Idle {
    async fn absorb(&mut self) -> Result<Option<Absorbed<D>>, Error> {
        pending().await
    }
}

/// The running synchronizer's mailbox receiver, with the commands deferred behind a pass.
///
/// A pass takes in messages as they arrive: hints apply at once, synchronization targets merge
/// into one deferred batch, and a floor install is deferred and stops further intake, so no later
/// command overtakes it. After the pass, deferred commands run in mailbox order: the
/// synchronization first, then the floor install.
pub(super) struct Inbox<V: Variant, D: Digest> {
    receiver: mailbox::Receiver<Message<V, D>>,
    synchronize: Option<DeferredSync<V, D>>,
    floor: Option<DeferredFloor<V, D>>,
    closed: bool,
}

impl<V: Variant, D: Digest> Inbox<V, D> {
    pub(super) const fn new(receiver: mailbox::Receiver<Message<V, D>>) -> Self {
        Self {
            receiver,
            synchronize: None,
            floor: None,
            closed: false,
        }
    }

    /// Returns whether the mailbox closed and no deferred command remains.
    pub(super) const fn is_done(&self) -> bool {
        self.closed && self.synchronize.is_none() && self.floor.is_none()
    }

    /// Takes the next deferred command: the synchronization, then the floor install.
    pub(super) fn next_deferred(&mut self) -> Option<Message<V, D>> {
        if let Some(DeferredSync { span, batch }) = self.synchronize.take() {
            return Some(Message::Synchronize { span, batch });
        }
        self.floor.take().map(|floor| Message::InstallFloor {
            span: floor.span,
            checkpoint: floor.checkpoint,
            reply: floor.reply,
        })
    }

    /// Receives the next message, or `None` once the mailbox closed.
    pub(super) async fn recv(&mut self) -> Option<Message<V, D>> {
        let message = self.receiver.recv().await;
        if message.is_none() {
            self.closed = true;
        }
        message
    }

    /// Returns whether a message may be taken now: the mailbox is open and no floor install is
    /// deferred.
    pub(super) const fn can_receive(&self) -> bool {
        !self.closed && self.floor.is_none()
    }

    /// Takes an already queued message, unless it would cross a deferred floor install.
    pub(super) fn try_recv(&mut self) -> Option<Message<V, D>> {
        if !self.can_receive() {
            return None;
        }
        self.receiver.try_recv().ok()
    }

    /// Takes the queued messages that may be taken now, merging synchronization targets into
    /// `sync` and deferring a floor install. Returns the next hint for the caller to apply, or
    /// `None` once nothing more may be taken.
    pub(super) fn drain(
        &mut self,
        sync: &mut DeferredSync<V, D>,
    ) -> Result<Option<Absorbed<D>>, Error> {
        while let Some(message) = self.try_recv() {
            match message {
                Message::Synchronize { span, batch } => sync.merge(span, batch),
                message => {
                    if let Some(hint) = self.defer(message)? {
                        return Ok(Some(hint));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Defers a command behind the current pass, or returns a hint.
    pub(super) fn defer(&mut self, message: Message<V, D>) -> Result<Option<Absorbed<D>>, Error> {
        Ok(match message {
            Message::Header { header, .. } => Some(Absorbed::Header(header)),
            Message::Commitments { commitments } => Some(Absorbed::Commitments(commitments)),
            Message::Finality { fact, .. } => Some(Absorbed::Finality(fact)),
            Message::Synchronize { span, batch } => {
                match &mut self.synchronize {
                    Some(pending) => pending.merge(span, batch),
                    None => self.synchronize = Some(DeferredSync { span, batch }),
                }
                None
            }
            Message::InstallFloor {
                span,
                checkpoint,
                reply,
            } => {
                let floor = DeferredFloor {
                    span,
                    checkpoint,
                    reply,
                };
                if self.floor.replace(floor).is_some() {
                    return Err(Error::Invalid("multiple floor barriers were deferred"));
                }
                None
            }
        })
    }
}

impl<V: Variant, D: Digest> Absorb<V, D> for Inbox<V, D> {
    async fn absorb(&mut self) -> Result<Option<Absorbed<D>>, Error> {
        if !self.can_receive() {
            return pending().await;
        }
        let Some(message) = self.recv().await else {
            return Ok(None);
        };
        self.defer(message)
    }
}
