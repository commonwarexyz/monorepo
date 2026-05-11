use crate::{
    simplex::types::{Attributable, Proposal, Vote},
    types::{Participant, View},
    Viewable,
};
use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use std::collections::VecDeque;

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

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match &message {
            Self::Update { .. } => {
                if let Some(index) = overflow
                    .iter()
                    .rposition(|pending| matches!(pending, Self::Update { .. }))
                {
                    overflow.remove(index);
                }
            }
            Self::Constructed(vote) => {
                let key = vote_key(vote);
                if let Some(index) = overflow.iter().rposition(
                    |pending| matches!(pending, Self::Constructed(pending) if vote_key(pending) == key),
                ) {
                    overflow.remove(index);
                }
            }
        }
        overflow.push_back(message);
        true
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mailbox::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: mailbox::Sender<Message<S, D>>) -> Self {
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
