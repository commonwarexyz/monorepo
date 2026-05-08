use crate::{
    simplex::types::{Attributable, Proposal, Vote},
    types::{Participant, View},
    Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_utils::channel::{actor::{self, ActorMailbox, Backpressure}, Feedback};

#[derive(Clone, Copy, PartialEq, Eq)]
enum VoteKind {
    Notarize,
    Nullify,
    Finalize,
}

/// Messages sent to the [super::actor::Actor].
pub enum Message<S: Scheme, D: Digest> {
    /// View update with leader info.
    Update {
        current: View,
        leader: Participant,
        finalized: View,
        forwardable_proposal: Option<Proposal<D>>,
    },
    /// A constructed vote (needed for quorum).
    Constructed(Vote<S, D>),
}

fn vote_key<S: Scheme, D: Digest>(vote: &Vote<S, D>) -> (VoteKind, View, Participant) {
    match vote {
        Vote::Notarize(vote) => (VoteKind::Notarize, vote.view(), vote.signer()),
        Vote::Nullify(vote) => (VoteKind::Nullify, vote.view(), vote.signer()),
        Vote::Finalize(vote) => (VoteKind::Finalize, vote.view(), vote.signer()),
    }
}

impl<S: Scheme, D: Digest> Backpressure for Message<S, D> {
    fn handle(overflow: &mut actor::Overflow<'_, Self>, message: Self) -> Feedback {
        match &message {
            Self::Update { .. } => {
                let result = overflow.replace_last(message, |pending| {
                    matches!(pending, Self::Update { .. })
                });
                overflow.replace_or_spill(result)
            }
            Self::Constructed(vote) => {
                let key = vote_key(vote);
                let result = overflow.replace_last(message, |pending| {
                    matches!(pending, Self::Constructed(pending) if vote_key(pending) == key)
                });
                overflow.replace_or_spill(result)
            }
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: ActorMailbox<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: ActorMailbox<Message<S, D>>) -> Self {
        Self { sender }
    }

    /// Send an update message.
    ///
    /// Timeout hints are delivered asynchronously to the voter.
    pub fn update(
        &mut self,
        current: View,
        leader: Participant,
        finalized: View,
        forwardable_proposal: Option<Proposal<D>>,
    ) -> Feedback {
        self.sender.enqueue(Message::Update {
            current,
            leader,
            finalized,
            forwardable_proposal,
        })
    }

    /// Send a constructed vote.
    pub fn constructed(&mut self, message: Vote<S, D>) -> Feedback {
        self.sender.enqueue(Message::Constructed(message))
    }

}
