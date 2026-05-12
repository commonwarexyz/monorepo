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

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match &message {
            Self::Update {
                current, finalized, ..
            } => {
                let current = *current;
                let finalized = *finalized;
                let mut remove = Vec::new();
                let mut absorb_idx = None;
                for (index, p) in overflow.iter().enumerate() {
                    match p {
                        Self::Update { current: pc, .. } if *pc > current => return false,
                        Self::Update { current: pc, .. } if *pc < current => remove.push(index),
                        Self::Update { .. } => absorb_idx = Some(index),
                        Self::Constructed(vote) if vote_pruned(vote, current, finalized) => {
                            remove.push(index);
                        }
                        Self::Constructed(_) => {}
                    }
                }
                for r in remove.into_iter().rev() {
                    overflow.remove(r);
                    if let Some(idx) = absorb_idx {
                        if r < idx {
                            absorb_idx = Some(idx - 1);
                        }
                    }
                }
                if let Some(idx) = absorb_idx {
                    overflow[idx] = message;
                } else {
                    overflow.push_back(message);
                }
                true
            }
            Self::Constructed(vote) => {
                if overflow.iter().any(|p| {
                    matches!(p, Self::Update { current, finalized, .. }
                        if vote_pruned(vote, *current, *finalized))
                }) {
                    return false;
                }
                overflow.push_back(message);
                true
            }
        }
    }
}

// A queued update is a pruning floor for overflow. It drops only constructed
// votes that the batcher actor would discard once the update is delivered.
fn vote_pruned<S: Scheme, D: Digest>(vote: &Vote<S, D>, current: View, finalized: View) -> bool {
    let view = vote.view();
    match vote {
        // Notarize votes are only useful for the current view
        Vote::Notarize(_) => view < current || view <= finalized,
        // Nullify and finalize votes for prior non-finalized views can still
        // combine after the voter skips forward
        Vote::Nullify(_) | Vote::Finalize(_) => view <= finalized,
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
            types::{Finalize, Notarize, Nullify, Vote},
        },
        types::{Epoch, Round},
    };
    use commonware_actor::mailbox::Policy;
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_utils::test_rng;
    use std::collections::VecDeque;

    type TestScheme = ed25519::Scheme;
    const EPOCH: Epoch = Epoch::new(1);

    fn scheme() -> TestScheme {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, b"batcher-policy", 5);
        schemes.into_iter().next().expect("missing scheme")
    }

    fn proposal(view: View) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(EPOCH, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        )
    }

    fn nullify_vote(view: View) -> Vote<TestScheme, Sha256Digest> {
        Vote::Nullify(
            Nullify::sign::<Sha256Digest>(&scheme(), Round::new(EPOCH, view)).expect("nullify"),
        )
    }

    fn notarize_vote(view: View) -> Vote<TestScheme, Sha256Digest> {
        Vote::Notarize(Notarize::sign(&scheme(), proposal(view)).expect("notarize"))
    }

    fn finalize_vote(view: View) -> Vote<TestScheme, Sha256Digest> {
        Vote::Finalize(Finalize::sign(&scheme(), proposal(view)).expect("finalize"))
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
            Message::Constructed(nullify_vote(View::new(2)))
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
            Message::Constructed(nullify_vote(View::new(2)))
        ));

        assert_eq!(overflow.len(), 1);
    }

    #[test]
    fn update_replaces_older_update_and_keeps_current_constructed_message() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            update(View::new(2), View::new(1))
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(nullify_vote(View::new(3)))
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

    #[test]
    fn stale_update_does_not_prune_retained_constructed_finalization() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            update(View::new(5), View::zero())
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(finalize_vote(View::new(3)))
        ));
        assert!(!Message::handle(
            &mut overflow,
            update(View::new(4), View::new(4))
        ));

        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Update { current, .. }) if current == View::new(5)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Constructed(vote))
                if matches!(vote, Vote::Finalize(_)) && vote.view() == View::new(3)
        ));
    }

    #[test]
    fn update_keeps_constructed_finalization_above_finalized() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(finalize_vote(View::new(4)))
        ));
        assert!(Message::handle(
            &mut overflow,
            update(View::new(5), View::new(3))
        ));

        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Constructed(vote))
                if matches!(vote, Vote::Finalize(_)) && vote.view() == View::new(4)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Update { current, .. }) if current == View::new(5)
        ));
    }

    #[test]
    fn update_prunes_constructed_notarization_below_current() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(notarize_vote(View::new(4)))
        ));
        assert!(Message::handle(
            &mut overflow,
            update(View::new(5), View::new(3))
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Update { current, .. }) if current == View::new(5)
        ));
    }
}
