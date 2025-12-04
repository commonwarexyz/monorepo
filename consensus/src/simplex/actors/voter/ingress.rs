use crate::simplex::{
    signing_scheme::Scheme,
    types::{Certificate, Proposal},
};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};
use tracing::error;

/// Messages sent to the [super::actor::Actor].
pub enum Message<S: Scheme, D: Digest> {
    /// Leader's proposal from batcher.
    Proposal(Proposal<D>),
    /// Certificate from batcher or resolver.
    ///
    /// The boolean indicates if the certificate came from the resolver.
    /// When true, the voter will not send it back to the resolver (to avoid "boomerang").
    Verified(Certificate<S, D>, bool),
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a leader's proposal.
    pub async fn proposal(&mut self, proposal: Proposal<D>) {
        if let Err(err) = self.sender.send(Message::Proposal(proposal)).await {
            error!(?err, "failed to send proposal message");
        }
    }

    /// Send a recovered certificate.
    pub async fn recovered(&mut self, certificate: Certificate<S, D>) {
        if let Err(err) = self
            .sender
            .send(Message::Verified(certificate, false))
            .await
        {
            error!(?err, "failed to send certificate message");
        }
    }

    /// Send a resolved certificate.
    pub async fn resolved(&mut self, certificate: Certificate<S, D>) {
        if let Err(err) = self.sender.send(Message::Verified(certificate, true)).await {
            error!(?err, "failed to send resolved message");
        }
    }
}
