//! Mailbox and message types for the batcher actor.

use crate::{
    minimmit::types::Vote,
    types::{Participant, View},
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_utils::channels::fallible::AsyncFallibleExt;
use futures::channel::{mpsc, oneshot};

/// Messages that can be sent to the batcher actor.
pub enum Message<S: Scheme, D: Digest> {
    /// Update batcher state with new view info.
    Update {
        current: View,
        leader: Participant,
        finalized: View,
        active: oneshot::Sender<bool>,
    },
    /// A vote was constructed and should be broadcast.
    Constructed(Vote<S, D>),
}

/// Mailbox for sending messages to the batcher actor.
#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox with the given sender.
    pub const fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    /// Send an update message to the batcher.
    pub async fn update(&mut self, current: View, leader: Participant, finalized: View) -> bool {
        self.sender
            .request_or(
                |active| Message::Update {
                    current,
                    leader,
                    finalized,
                    active,
                },
                true,
            )
            .await
    }

    /// Notify the batcher that a vote was constructed.
    pub async fn constructed(&mut self, vote: Vote<S, D>) {
        self.sender.send_lossy(Message::Constructed(vote)).await;
    }
}
