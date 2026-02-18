use crate::simplex::types::{Certificate, Proposal};
use crate::types::View;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc};

/// Messages sent to the [super::actor::Actor].
pub enum Message<S: Scheme, D: Digest> {
    /// Leader's proposal from batcher.
    Proposal(Proposal<D>),
    /// Hint from batcher that the current leader has broadcast `nullify(v)`.
    ///
    /// The voter can use this to fast-path timeout in `v` rather than waiting
    /// for the local leader timeout.
    LeaderNullify(View),
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

    /// Hint that the current leader broadcast a nullify vote for `view`.
    pub async fn leader_nullify(&mut self, view: View) {
        self.sender.send_lossy(Message::LeaderNullify(view)).await;
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
