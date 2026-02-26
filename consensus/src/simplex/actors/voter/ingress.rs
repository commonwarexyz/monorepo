use crate::{
    simplex::{
        metrics::TimeoutReason,
        types::{Certificate, Proposal},
    },
    types::View,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc};

/// Messages sent to the [super::actor::Actor].
pub enum Message<S: Scheme, D: Digest> {
    /// Leader's proposal from batcher.
    Proposal(Proposal<D>),
    /// Signal that the current view should be nullified (if not already).
    Timeout(View, TimeoutReason),
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
        self.sender.send_lossy(Message::Proposal(proposal)).await;
    }

    /// Signal that the current view should timeout (if not already).
    pub async fn timeout(&mut self, view: View, reason: TimeoutReason) {
        self.sender.send_lossy(Message::Timeout(view, reason)).await;
    }

    /// Send a recovered certificate.
    pub async fn recovered(&mut self, certificate: Certificate<S, D>) {
        self.sender
            .send_lossy(Message::Verified(certificate, false))
            .await;
    }

    /// Send a resolved certificate.
    pub async fn resolved(&mut self, certificate: Certificate<S, D>) {
        self.sender
            .send_lossy(Message::Verified(certificate, true))
            .await;
    }
}
