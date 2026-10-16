//! Control and query messages accepted by the resolver.

use crate::{
    multimmit::{
        actors::util::reliable_policy,
        machine::{ResolutionJob, RetrievalKey},
        types::{Artifact, ChainId},
    },
    types::{Height, Round, View},
};
use commonware_actor::{
    Feedback,
    mailbox::{self, UnreliablePolicy},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, sync::Arc};
use tracing::Span;

/// One machine-issued resolver request.
pub(crate) struct ResolveRequest<D: Digest> {
    /// The root span that owns terminal failures from this request.
    pub(crate) root: Span,
    /// The issuing tracing span.
    pub(crate) span: Span,
    /// The round that issued the request.
    pub(crate) round: Round,
    /// The machine-issued job.
    pub(crate) job: ResolutionJob<D>,
}

/// Reliable local control accepted by the resolver.
pub(crate) enum Message<V: Variant, D: Digest> {
    /// Resolve one machine-issued retrieval.
    Resolve(ResolveRequest<D>),
    /// Retract one machine-owned request.
    ///
    /// Peer deliveries still awaiting the machine's verdict on this job settle as valid.
    Cancel { job: ResolutionJob<D> },
    /// Reject content returned by the queried peer.
    Reject { job: ResolutionJob<D> },
    /// Serve one machine-verified artifact to peers.
    Retain { artifact: Arc<Artifact<V, D>> },
    /// Retire served evidence and outstanding retrievals for views at or below `through`.
    ///
    /// Peer deliveries still awaiting the machine's verdict on a retired retrieval settle as
    /// valid.
    Prune { through: View },
    /// Stop serving the headers of `chain` at or below `height`.
    SettleHeaders { chain: ChainId, height: Height },
}

// The machine relies on every control message: a lost cancellation would leak a request, and a lost
// retention would stop serving evidence peers need.
reliable_policy!(impl<V: Variant, D: Digest> for Message<V, D>);

/// A best-effort request for one locally retained artifact.
pub(crate) struct Serve<V: Variant, D: Digest> {
    /// The requested key.
    pub(crate) key: RetrievalKey<D>,
    /// Receives the retained artifact `key` names, if any.
    pub(crate) responder: oneshot::Sender<Option<Arc<Artifact<V, D>>>>,
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
        not(test),
        expect(dead_code, reason = "only tests query retained artifacts locally")
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

    /// Resolves one machine-issued retrieval.
    pub(crate) fn resolve(&self, request: ResolveRequest<D>) -> Feedback {
        self.control.enqueue(Message::Resolve(request))
    }

    /// Retracts one machine-owned request; see [`Message::Cancel`].
    pub(crate) fn cancel(&self, job: ResolutionJob<D>) -> Feedback {
        self.control.enqueue(Message::Cancel { job })
    }

    /// Rejects the content a peer returned for one request.
    pub(crate) fn reject(&self, job: ResolutionJob<D>) -> Feedback {
        self.control.enqueue(Message::Reject { job })
    }

    /// Serves one machine-verified artifact to peers.
    pub(crate) fn retain(&self, artifact: Arc<Artifact<V, D>>) -> Feedback {
        self.control.enqueue(Message::Retain { artifact })
    }

    /// Retires served evidence and outstanding retrievals for views at or below `through`; see
    /// [`Message::Prune`].
    pub(crate) fn prune(&self, through: View) -> Feedback {
        self.control.enqueue(Message::Prune { through })
    }

    /// Stops serving the headers of `chain` at or below `height`.
    pub(crate) fn settle_headers(&self, chain: ChainId, height: Height) -> Feedback {
        self.control
            .enqueue(Message::SettleHeaders { chain, height })
    }

    /// Returns a handle that only serves retained artifacts.
    #[cfg(test)]
    pub(crate) fn server(&self) -> Server<V, D> {
        self.server.clone()
    }
}

/// A cloneable handle that reads the artifacts the resolver retains.
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

#[cfg(test)]
impl<V: Variant, D: Digest> Server<V, D> {
    /// Requests the retained artifact `key` names.
    ///
    /// The receiver resolves to `None` when nothing is retained under `key`, and closes when the
    /// resolver is stopped or its query queue is full.
    pub(crate) fn serve(
        &self,
        key: RetrievalKey<D>,
    ) -> oneshot::Receiver<Option<Arc<Artifact<V, D>>>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.queries.enqueue(Serve { key, responder });
        receiver
    }
}
