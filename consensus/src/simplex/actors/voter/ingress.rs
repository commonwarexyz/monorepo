use crate::{
    simplex::{
        metrics::TimeoutReason,
        types::{Certificate, Proposal, Vote},
    },
    types::View,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc};

/// Messages sent to the [super::actor::Actor].
pub enum Message<S: Scheme, D: Digest> {
    /// Leader's proposal from batcher.
    Proposal(Proposal<D>),
    /// Signal that the current view should timeout (if not already).
    Timeout(View, TimeoutReason),
    /// Certificate from batcher or resolver.
    ///
    /// The boolean indicates if the certificate came from the resolver.
    /// When true, the voter will not send it back to the resolver (to avoid "boomerang").
    Verified(Certificate<S, D>, bool),
    /// Directly inject a proposal as if this node built it (leader path).
    ///
    /// Used by the replayer to set the proposer's internal state without
    /// triggering the automaton's propose() or relay broadcast.
    #[cfg(any(test, feature = "mocks"))]
    Proposed(Proposal<D>),
    /// Replay a vote that this node constructed, setting the voter's
    /// broadcast flags (via state.replay) and forwarding to the batcher.
    #[cfg(any(test, feature = "mocks"))]
    Replayed(Vote<S, D>),
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

    /// Inject a proposal as if this node built it (leader path).
    #[cfg(any(test, feature = "mocks"))]
    pub async fn proposed(&mut self, proposal: Proposal<D>) {
        self.sender
            .send_lossy(Message::Proposed(proposal))
            .await;
    }

    /// Replay a vote this node constructed, setting broadcast flags and
    /// forwarding to the batcher.
    #[cfg(any(test, feature = "mocks"))]
    pub async fn replayed(&mut self, vote: Vote<S, D>) {
        self.sender.send_lossy(Message::Replayed(vote)).await;
    }
}
