//! Control and query messages accepted by the resolver.

use super::custody::{Change, Custody};
use crate::{
    multimmit::{
        machine::{CertificateJob, ResolutionJob},
        scheme::Scheme,
        types::{ChainId, DaCertificate, ViewProof},
    },
    types::{Round, View},
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Overflow, Policy, UnreliablePolicy},
};
use commonware_cryptography::Digest;
use commonware_utils::channel::oneshot;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
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

/// One machine-issued DA-certificate request.
pub(crate) struct CertificateRequest {
    /// The root span that owns terminal failures from this request.
    pub(crate) root: Span,
    /// The issuing tracing span.
    pub(crate) span: Span,
    /// The machine-issued job.
    pub(crate) job: CertificateJob,
}

/// Reliable local control accepted by the resolver.
pub(crate) enum Message<S: Scheme, D: Digest> {
    /// Resolve one machine-issued view request.
    Resolve(ResolveRequest),
    /// Retract one machine-owned request.
    ///
    /// Peer deliveries still awaiting the machine's verdict on this job settle as valid.
    Cancel { job: ResolutionJob },
    /// Reject content returned by the queried peer.
    Reject { job: ResolutionJob },
    /// Retain one machine-verified view proof for peers.
    Retain { proof: ViewProof<S, D> },
    /// Retire view evidence no longer retained by the machine.
    Prune { through: View },
    /// Resolve one machine-issued DA-certificate request.
    ResolveCertificate(CertificateRequest),
    /// Retract one machine-owned DA-certificate request; see [`Message::Cancel`].
    CancelCertificate { job: CertificateJob },
    /// Reject a DA certificate returned by the queried peer.
    RejectCertificate { job: CertificateJob },
    /// Serve one durable DA certificate to peers, replacing any lower one of its chain.
    RetainCertificate { certificate: DaCertificate<S, D> },
}

/// Coalesced Retain/Prune messages queued between two job messages.
///
/// Job messages delimit the deltas because moving retention across a resolve or cancellation can
/// change whether that job is served locally. Within one delta, the [`Custody`] rules make
/// retention monotone, so only the final projection is forwarded.
pub(super) type RetentionDelta<S, D> = Custody<S, D, ViewProof<S, D>>;

impl<S: Scheme, D: Digest> RetentionDelta<S, D> {
    /// Forwards the delta as a Prune followed by Retains, stopping at the first message `push`
    /// hands back.
    ///
    /// Returns `false`, keeping the unsent remainder, when `push` hands a message back.
    fn forward<F>(&mut self, push: &mut F) -> bool
    where
        F: FnMut(Message<S, D>) -> Option<Message<S, D>>,
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
pub(super) enum OverflowChunk<S: Scheme, D: Digest> {
    Job(Message<S, D>),
    Retention(RetentionDelta<S, D>),
}

/// Reliable overflow that keeps every job message and coalesces the Retain/Prune messages queued
/// between two job messages.
pub(crate) struct ControlOverflow<S: Scheme, D: Digest> {
    /// Job messages and the retention deltas between them, in arrival order.
    pub(super) chunks: VecDeque<OverflowChunk<S, D>>,
    /// Retain/Prune messages queued after the last job message.
    tail: Option<RetentionDelta<S, D>>,
    /// The highest queued DA certificate to retain per chain.
    ///
    /// A certificate request is never served from local retention, so certificates need no
    /// ordering against job messages, and a higher one replaces a lower one of its chain.
    certificates: BTreeMap<ChainId, DaCertificate<S, D>>,
}

impl<S: Scheme, D: Digest> ControlOverflow<S, D> {
    /// Returns the delta that coalesces Retain/Prune messages queued after the last job message.
    fn back_delta(&mut self) -> &mut RetentionDelta<S, D> {
        self.tail.get_or_insert_with(RetentionDelta::empty)
    }
}

impl<S: Scheme, D: Digest> Default for ControlOverflow<S, D> {
    fn default() -> Self {
        Self {
            chunks: VecDeque::new(),
            tail: None,
            certificates: BTreeMap::new(),
        }
    }
}

impl<S: Scheme, D: Digest> Overflow<Message<S, D>> for ControlOverflow<S, D> {
    fn is_empty(&self) -> bool {
        self.chunks.is_empty() && self.tail.is_none() && self.certificates.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<S, D>) -> Option<Message<S, D>>,
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
            return;
        }
        while let Some((chain, certificate)) = self.certificates.pop_first() {
            if let Some(Message::RetainCertificate { certificate }) =
                push(Message::RetainCertificate { certificate })
            {
                self.certificates.insert(chain, certificate);
                return;
            }
        }
    }
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    type Overflow = ControlOverflow<S, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        match message {
            Self::Resolve(_)
            | Self::Cancel { .. }
            | Self::Reject { .. }
            | Self::ResolveCertificate(_)
            | Self::CancelCertificate { .. }
            | Self::RejectCertificate { .. } => {
                if let Some(delta) = overflow.tail.take() {
                    overflow.chunks.push_back(OverflowChunk::Retention(delta));
                }
                overflow.chunks.push_back(OverflowChunk::Job(message));
            }
            Self::Retain { proof } => overflow.back_delta().retain(proof),
            Self::Prune { through } => overflow.back_delta().prune(through),
            Self::RetainCertificate { certificate } => {
                let chain = certificate.header().chain();
                let higher = overflow
                    .certificates
                    .get(&chain)
                    .is_none_or(|held| held.header().height() < certificate.header().height());
                if higher {
                    overflow.certificates.insert(chain, certificate);
                }
            }
        }
    }
}

/// A best-effort request for one locally retained view proof.
pub(crate) struct Serve<S: Scheme, D: Digest> {
    /// The requested view.
    pub(crate) view: View,
    /// Receives the retained proof covering `view`, if any.
    pub(crate) responder: oneshot::Sender<Option<Arc<ViewProof<S, D>>>>,
}

impl<S: Scheme, D: Digest> UnreliablePolicy for Serve<S, D> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

/// Typed control endpoint of the resolver.
pub(crate) struct Mailbox<S: Scheme, D: Digest> {
    control: mailbox::Sender<Message<S, D>>,
    #[cfg_attr(
        not(any(test, feature = "mocks")),
        expect(
            dead_code,
            reason = "only tests and mocks query retained proofs locally"
        )
    )]
    server: Server<S, D>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Wraps the sending halves of the resolver's control and query queues.
    pub(crate) const fn new(
        control: mailbox::Sender<Message<S, D>>,
        queries: mailbox::UnreliableSender<Serve<S, D>>,
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
    pub(crate) fn retain(&self, proof: ViewProof<S, D>) -> Feedback {
        self.control.enqueue(Message::Retain { proof })
    }

    /// Retires the retained exits at or below `through`.
    pub(crate) fn prune(&self, through: View) -> Feedback {
        self.control.enqueue(Message::Prune { through })
    }

    /// Resolves one machine-issued DA-certificate request.
    pub(crate) fn resolve_certificate(&self, request: CertificateRequest) -> Feedback {
        self.control.enqueue(Message::ResolveCertificate(request))
    }

    /// Retracts one machine-owned DA-certificate request.
    pub(crate) fn cancel_certificate(&self, job: CertificateJob) -> Feedback {
        self.control.enqueue(Message::CancelCertificate { job })
    }

    /// Rejects the DA certificate a peer returned for one request.
    pub(crate) fn reject_certificate(&self, job: CertificateJob) -> Feedback {
        self.control.enqueue(Message::RejectCertificate { job })
    }

    /// Serves one durable DA certificate to peers.
    pub(crate) fn retain_certificate(&self, certificate: DaCertificate<S, D>) -> Feedback {
        self.control
            .enqueue(Message::RetainCertificate { certificate })
    }

    /// Returns a handle that only serves retained proofs.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn server(&self) -> Server<S, D> {
        self.server.clone()
    }
}

/// A cloneable handle that reads the view proofs the resolver retains.
pub(crate) struct Server<S: Scheme, D: Digest> {
    queries: mailbox::UnreliableSender<Serve<S, D>>,
}

impl<S: Scheme, D: Digest> Clone for Server<S, D> {
    fn clone(&self) -> Self {
        Self {
            queries: self.queries.clone(),
        }
    }
}

#[cfg(any(test, feature = "mocks"))]
impl<S: Scheme, D: Digest> Server<S, D> {
    /// Requests the retained proof covering `view`.
    ///
    /// The receiver resolves to `None` when nothing covers `view`, and closes when the resolver is
    /// stopped or its query queue is full.
    pub(crate) fn serve(&self, view: View) -> oneshot::Receiver<Option<Arc<ViewProof<S, D>>>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.queries.enqueue(Serve { view, responder });
        receiver
    }
}
