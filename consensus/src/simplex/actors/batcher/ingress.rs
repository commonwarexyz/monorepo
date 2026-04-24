use crate::{
    simplex::{
        metrics::TimeoutReason,
        types::{Proposal, Vote},
    },
    types::{Participant, View},
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc, oneshot, request};

/// Messages sent to the [super::actor::Actor].
pub enum Message<S: Scheme, D: Digest> {
    /// View update with leader info.
    Update {
        current: View,
        leader: Participant,
        finalized: View,
        forwardable_proposal: Option<Proposal<D>>,

        response: oneshot::Sender<Option<TimeoutReason>>,
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
    ///
    /// Returns `None` if the leader is active, or `Some(reason)` if the round
    /// should be nullified.
    #[cfg(test)]
    pub async fn update(
        &mut self,
        current: View,
        leader: Participant,
        finalized: View,
        forwardable_proposal: Option<Proposal<D>>,
    ) -> Option<TimeoutReason>
    where
        Message<S, D>: Send + 'static,
    {
        let (_, response) = self
            .update_deferred(current, leader, finalized, forwardable_proposal)
            .await;
        response
    }

    /// Send an update message without blocking the caller's event loop.
    ///
    /// The returned future owns the bounded send and acknowledgement receiver.
    /// Actors should poll it alongside mailbox input instead of awaiting it
    /// inline.
    pub fn update_deferred(
        &mut self,
        current: View,
        leader: Participant,
        finalized: View,
        forwardable_proposal: Option<Proposal<D>>,
    ) -> request::Pending<(View, Option<TimeoutReason>)>
    where
        Message<S, D>: Send + 'static,
    {
        let pending = request::pending(&self.sender, move |response| Message::Update {
            current,
            leader,
            finalized,
            forwardable_proposal,
            response,
        });
        request::Pending::from_future(async move { (current, pending.await.flatten()) })
    }

    /// Send a constructed vote.
    pub async fn constructed(&mut self, message: Vote<S, D>) {
        self.sender.send_lossy(Message::Constructed(message)).await;
    }
}
