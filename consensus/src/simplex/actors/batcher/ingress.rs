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
    fn duplicates(&self, pending: &Self) -> bool {
        matches!(
            (self, pending),
            (Self::Update { current: x, .. }, Self::Update { current: y, .. }) if x == y
        )
    }

    // A queued update is a pruning floor for overflow. Returns true when this
    // update would drop `vote` once the batcher actor delivers the update.
    fn prunes(&self, vote: &Vote<S, D>) -> bool {
        let Self::Update {
            current, finalized, ..
        } = self
        else {
            return false;
        };
        let view = vote.view();
        match vote {
            // Notarize and nullify votes are only useful for the current view
            Vote::Notarize(_) | Vote::Nullify(_) => view < *current || view <= *finalized,
            // Finalize votes for prior non-finalized views can still combine
            // after the voter skips forward
            Vote::Finalize(_) => view <= *finalized,
        }
    }
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match &message {
            Self::Update { current, .. } => {
                let current = *current;
                let mut remove = Vec::new();

                // Keep at most one useful pending update. A higher-view update
                // already queued makes this one stale, while lower-view updates
                // and votes pruned by this update can be removed.
                for (index, p) in overflow.iter().enumerate() {
                    match p {
                        Self::Update { current: pc, .. } if *pc > current => return false,
                        p if message.duplicates(p) => return true,
                        Self::Update { .. } => remove.push(index),
                        Self::Constructed(vote) if message.prunes(vote) => remove.push(index),
                        Self::Constructed(_) => {}
                    }
                }

                // Remove from the back so indexes collected during the scan
                // stay valid.
                for r in remove.into_iter().rev() {
                    overflow.remove(r);
                }
                overflow.push_back(message);
                true
            }
            Self::Constructed(vote) => {
                // If a pending update would make this vote stale, drop it now
                // instead of delivering it after that update.
                if overflow.iter().any(|p| p.prunes(vote)) {
                    return false;
                }
                overflow.push_back(message);
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
            update(View::new(3), View::new(1))
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Update {
                current,
                finalized,
                ..
            }) if current == View::new(3) && finalized == View::new(1)
        ));
    }

    #[test]
    fn constructed_message_after_update_is_dropped_when_stale() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            update(View::new(3), View::new(1))
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
    fn duplicate_update_is_ignored() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            update(View::new(5), View::new(3))
        ));
        assert!(Message::handle(
            &mut overflow,
            update(View::new(5), View::new(4))
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Update {
                current,
                finalized,
                ..
            }) if current == View::new(5) && finalized == View::new(3)
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
