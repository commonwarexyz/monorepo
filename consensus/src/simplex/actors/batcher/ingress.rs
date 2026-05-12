use crate::{
    simplex::types::{Proposal, Vote},
    types::{Participant, View},
    Viewable,
};
use commonware_actor::mailbox::{Policy, Sender};
use commonware_cryptography::{certificate::Scheme, Digest};
use std::collections::VecDeque;

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

impl<S: Scheme, D: Digest> Message<S, D> {
    fn newer_update_than(&self, current: View) -> bool {
        matches!(
            self,
            Self::Update {
                current: pending,
                ..
            } if *pending > current
        )
    }

    fn pruned_by_update(&self, current: View, finalized: View) -> bool {
        match self {
            Self::Update {
                current: pending, ..
            } => *pending <= current,
            Self::Constructed(vote) => vote.view() < current || vote.view() <= finalized,
        }
    }

    fn prunes_constructed_view(&self, view: View) -> bool {
        matches!(
            self,
            Self::Update {
                current,
                finalized,
                ..
            } if view < *current || view <= *finalized
        )
    }
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match message {
            Self::Update {
                current,
                leader,
                finalized,
                forwardable_proposal,
            } => {
                // A newer pending update already advances the batcher further.
                // Delivering this older update later would only reintroduce stale state.
                let mut useless = false;

                // The update is the overflow floor: older updates and constructed votes
                // below the current or finalized view cannot affect future aggregation.
                overflow.retain(|pending| {
                    if pending.newer_update_than(current) {
                        useless = true;
                        return true;
                    }
                    !pending.pruned_by_update(current, finalized)
                });
                if useless {
                    return false;
                }
                overflow.push_back(Self::Update {
                    current,
                    leader,
                    finalized,
                    forwardable_proposal,
                });
                true
            }
            Self::Constructed(vote) => {
                let view = vote.view();
                // If a queued update would make this vote stale before delivery, drop it
                // instead of letting the actor discard it later.
                if overflow
                    .iter()
                    .any(|pending| pending.prunes_constructed_view(view))
                {
                    return false;
                }
                overflow.push_back(Self::Constructed(vote));
                true
            }
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    /// Send an update message.
    ///
    /// Returns `None` if the leader is active, or `Some(reason)` if the round
    /// should be nullified.
    pub fn update(
        &mut self,
        current: View,
        leader: Participant,
        finalized: View,
        forwardable_proposal: Option<Proposal<D>>,
    ) {
        let _ = self.sender.enqueue(Message::Update {
            current,
            leader,
            finalized,
            forwardable_proposal,
        });
    }

    /// Send a constructed vote.
    pub fn constructed(&mut self, message: Vote<S, D>) {
        let _ = self.sender.enqueue(Message::Constructed(message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{Nullify, Vote},
        },
        types::{Epoch, Round},
    };
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_utils::test_rng;

    type TestScheme = ed25519::Scheme;
    const EPOCH: Epoch = Epoch::new(1);

    fn scheme() -> TestScheme {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, b"batcher-policy", 5);
        schemes.into_iter().next().expect("missing scheme")
    }

    fn vote(view: View) -> Vote<TestScheme, Sha256Digest> {
        Vote::Nullify(
            Nullify::sign::<Sha256Digest>(&scheme(), Round::new(EPOCH, view)).expect("nullify"),
        )
    }

    fn update(current: View, finalized: View) -> Message<TestScheme, Sha256Digest> {
        Message::Update {
            current,
            leader: Participant::new(0),
            finalized,
            forwardable_proposal: None,
        }
    }

    #[test]
    fn update_prunes_stale_constructed_messages() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(vote(View::new(2)))
        ));
        assert!(Message::handle(
            &mut overflow,
            update(View::new(3), View::new(2))
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Update {
                current,
                finalized,
                ..
            }) if current == View::new(3) && finalized == View::new(2)
        ));
    }

    #[test]
    fn constructed_message_after_update_is_dropped_when_stale() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            update(View::new(3), View::new(2))
        ));
        assert!(!Message::handle(
            &mut overflow,
            Message::Constructed(vote(View::new(2)))
        ));

        assert_eq!(overflow.len(), 1);
    }

    #[test]
    fn update_replaces_older_update_but_keeps_current_constructed_message() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            update(View::new(2), View::new(1))
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(vote(View::new(3)))
        ));
        assert!(Message::handle(
            &mut overflow,
            update(View::new(3), View::new(1))
        ));

        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Constructed(vote)) if vote.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Update { current, .. }) if current == View::new(3)
        ));
    }

    #[test]
    fn stale_update_is_dropped_when_newer_update_is_pending() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            update(View::new(5), View::new(4))
        ));
        assert!(!Message::handle(
            &mut overflow,
            update(View::new(4), View::new(3))
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Update { current, .. }) if current == View::new(5)
        ));
    }
}
