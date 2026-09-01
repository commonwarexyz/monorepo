//! Control and query messages accepted by the resolver.

use super::custody::{Change, Custody};
use crate::{
    multimmit::{machine::ResolutionJob, types::ViewProof},
    types::{Round, View},
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Overflow, Policy, UnreliablePolicy},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, sync::Arc};
use tracing::Span;

/// One machine-issued resolver request.
pub(crate) struct ResolveRequest {
    /// The root span that owns terminal failures from this request.
    pub(crate) root: Span,
    /// The issuing tracing span.
    pub(crate) span: Span,
    /// The round that issued the request.
    pub(crate) round: Round,
    /// The machine-issued job.
    pub(crate) job: ResolutionJob,
}

/// Reliable local control accepted by the resolver.
pub(crate) enum Message<V: Variant, D: Digest> {
    /// Resolve one machine-issued view request.
    Resolve(ResolveRequest),
    /// Retract one machine-owned request.
    ///
    /// Peer deliveries still awaiting the machine's verdict on this job settle as valid.
    Cancel { job: ResolutionJob },
    /// Reject content returned by the queried peer.
    Reject { job: ResolutionJob },
    /// Retain one machine-verified view proof for peers.
    Retain { proof: ViewProof<V, D> },
    /// Retire view evidence no longer retained by the machine.
    Prune { through: View },
}

/// Coalesced Retain/Prune messages queued between two job messages.
///
/// Job messages delimit the deltas because moving retention across a resolve or cancellation can
/// change whether that job is served locally. Within one delta, the [`Custody`] rules make
/// retention monotone, so only the final projection is forwarded.
pub(super) type RetentionDelta<V, D> = Custody<V, D, ViewProof<V, D>>;

impl<V: Variant, D: Digest> RetentionDelta<V, D> {
    /// Forwards the delta as a Prune followed by Retains, stopping at the first message `push`
    /// hands back.
    ///
    /// Returns `false`, keeping the unsent remainder, when `push` hands a message back.
    fn forward<F>(&mut self, push: &mut F) -> bool
    where
        F: FnMut(Message<V, D>) -> Option<Message<V, D>>,
    {
        self.drain(|change| {
            let message = match change {
                Change::Prune(through) => Message::Prune { through },
                Change::Retain(proof) => Message::Retain { proof },
            };
            match push(message)? {
                Message::Prune { through } => Some(Change::Prune(through)),
                Message::Retain { proof } => Some(Change::Retain(proof)),
                _ => None,
            }
        })
    }
}

/// One job message, or the coalesced Retain/Prune messages queued before it.
pub(super) enum OverflowChunk<V: Variant, D: Digest> {
    Job(Message<V, D>),
    Retention(RetentionDelta<V, D>),
}

/// Reliable overflow that keeps every job message and coalesces the Retain/Prune messages queued
/// between two job messages.
pub(crate) struct ControlOverflow<V: Variant, D: Digest> {
    /// Job messages and the retention deltas between them, in arrival order.
    pub(super) chunks: VecDeque<OverflowChunk<V, D>>,
    /// Retain/Prune messages queued after the last job message.
    tail: Option<RetentionDelta<V, D>>,
}

impl<V: Variant, D: Digest> ControlOverflow<V, D> {
    /// Returns the delta that coalesces Retain/Prune messages queued after the last job message.
    fn back_delta(&mut self) -> &mut RetentionDelta<V, D> {
        self.tail.get_or_insert_with(RetentionDelta::empty)
    }
}

impl<V: Variant, D: Digest> Default for ControlOverflow<V, D> {
    fn default() -> Self {
        Self {
            chunks: VecDeque::new(),
            tail: None,
        }
    }
}

impl<V: Variant, D: Digest> Overflow<Message<V, D>> for ControlOverflow<V, D> {
    fn is_empty(&self) -> bool {
        self.chunks.is_empty() && self.tail.is_none()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<V, D>) -> Option<Message<V, D>>,
    {
        while let Some(chunk) = self.chunks.pop_front() {
            match chunk {
                OverflowChunk::Job(message) => {
                    if let Some(message) = push(message) {
                        self.chunks.push_front(OverflowChunk::Job(message));
                        return;
                    }
                }
                OverflowChunk::Retention(mut delta) => {
                    if !delta.forward(&mut push) {
                        self.chunks.push_front(OverflowChunk::Retention(delta));
                        return;
                    }
                }
            }
        }
        if let Some(mut delta) = self.tail.take()
            && !delta.forward(&mut push)
        {
            self.tail = Some(delta);
        }
    }
}

impl<V: Variant, D: Digest> Policy for Message<V, D> {
    type Overflow = ControlOverflow<V, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        match message {
            Self::Resolve(_) | Self::Cancel { .. } | Self::Reject { .. } => {
                if let Some(delta) = overflow.tail.take() {
                    overflow.chunks.push_back(OverflowChunk::Retention(delta));
                }
                overflow.chunks.push_back(OverflowChunk::Job(message));
            }
            Self::Retain { proof } => overflow.back_delta().retain(proof),
            Self::Prune { through } => overflow.back_delta().prune(through),
        }
    }
}

/// A best-effort request for one locally retained view proof.
pub(crate) struct Serve<V: Variant, D: Digest> {
    /// The requested view.
    pub(crate) view: View,
    /// Receives the retained proof covering `view`, if any.
    pub(crate) responder: oneshot::Sender<Option<Arc<ViewProof<V, D>>>>,
}

impl<V: Variant, D: Digest> UnreliablePolicy for Serve<V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

/// Typed control endpoint of the resolver.
pub(crate) struct Mailbox<V: Variant, D: Digest> {
    control: mailbox::Sender<Message<V, D>>,
    #[cfg_attr(
        not(any(test, feature = "mocks")),
        expect(
            dead_code,
            reason = "only tests and mocks query retained proofs locally"
        )
    )]
    server: Server<V, D>,
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    /// Wraps the sending halves of the resolver's control and query queues.
    pub(crate) const fn new(
        control: mailbox::Sender<Message<V, D>>,
        queries: mailbox::UnreliableSender<Serve<V, D>>,
    ) -> Self {
        Self {
            control,
            server: Server { queries },
        }
    }

    /// Resolves one machine-issued view request.
    pub(crate) fn resolve(&self, request: ResolveRequest) -> Feedback {
        self.control.enqueue(Message::Resolve(request))
    }

    /// Retracts one machine-owned request; see [`Message::Cancel`].
    pub(crate) fn cancel(&self, job: ResolutionJob) -> Feedback {
        self.control.enqueue(Message::Cancel { job })
    }

    /// Rejects the content a peer returned for one request.
    pub(crate) fn reject(&self, job: ResolutionJob) -> Feedback {
        self.control.enqueue(Message::Reject { job })
    }

    /// Retains one machine-verified view proof for peers.
    pub(crate) fn retain(&self, proof: ViewProof<V, D>) -> Feedback {
        self.control.enqueue(Message::Retain { proof })
    }

    /// Retires the retained exits at or below `through`.
    pub(crate) fn prune(&self, through: View) -> Feedback {
        self.control.enqueue(Message::Prune { through })
    }

    /// Returns a handle that only serves retained proofs.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn server(&self) -> Server<V, D> {
        self.server.clone()
    }
}

/// A cloneable handle that reads the view proofs the resolver retains.
pub(crate) struct Server<V: Variant, D: Digest> {
    queries: mailbox::UnreliableSender<Serve<V, D>>,
}

impl<V: Variant, D: Digest> Clone for Server<V, D> {
    fn clone(&self) -> Self {
        Self {
            queries: self.queries.clone(),
        }
    }
}

#[cfg(any(test, feature = "mocks"))]
impl<V: Variant, D: Digest> Server<V, D> {
    /// Requests the retained proof covering `view`.
    ///
    /// The receiver resolves to `None` when nothing covers `view`, and closes when the resolver is
    /// stopped or its query queue is full.
    pub(crate) fn serve(&self, view: View) -> oneshot::Receiver<Option<Arc<ViewProof<V, D>>>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.queries.enqueue(Serve { view, responder });
        receiver
    }
}
