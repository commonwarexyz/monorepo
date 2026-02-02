use crate::{
    simplex::types::Vote,
    types::{Participant, View},
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc, oneshot};

/// Messages sent to the [super::actor::Actor].
pub enum Message<S: Scheme, D: Digest> {
    /// View update with leader info.
    Update {
        current: View,
        leader: Participant,
        finalized: View,

        active: oneshot::Sender<bool>,
    },
    /// A constructed vote (needed for quorum).
    Constructed(Vote<S, D>),
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

    /// Send an update message.
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

    /// Send a constructed vote.
    pub async fn constructed(&mut self, message: Vote<S, D>) {
        self.sender.send_lossy(Message::Constructed(message)).await;
    }
}
