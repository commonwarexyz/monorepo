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
    // Overflow is kept in canonical delivery order: at most one update at the
    // front, followed by retained constructed votes in arrival order. The
    // update carries the strongest current/finalized floor seen while it is
    // pending, so later inserts only need to compare against that front item.
    fn prunes(current: View, finalized: View, vote: &Vote<S, D>) -> bool {
        let view = vote.view();
        match vote {
            // Notarize and nullify votes are only useful for the current view
            Vote::Notarize(_) | Vote::Nullify(_) => view < current || view <= finalized,
            // Finalize votes for prior non-finalized views can still combine
            // after the voter skips forward
            Vote::Finalize(_) => view <= finalized,
        }
    }
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match message {
            mut update @ Self::Update {
                current,
                finalized: update_finalized,
                ..
            } => {
                let (current, finalized) = if let Some(Self::Update {
                    current: pending_current,
                    finalized: pending_finalized,
                    ..
                }) = overflow.front()
                {
                    let pending_current = *pending_current;
                    let pending_finalized = *pending_finalized;
                    let exact = current == pending_current && update_finalized == pending_finalized;
                    let improves_current = current > pending_current;
                    let improves_finalized = update_finalized > pending_finalized;
                    if !improves_current && !improves_finalized {
                        return exact;
                    }

                    let retained_finalized = update_finalized.max(pending_finalized);
                    if improves_current || current == pending_current {
                        let Self::Update { finalized, .. } = &mut update else {
                            unreachable!("update matched above");
                        };
                        *finalized = retained_finalized;
                        *overflow.front_mut().expect("front checked above") = update;
                        (current, retained_finalized)
                    } else {
                        let Some(Self::Update { finalized, .. }) = overflow.front_mut() else {
                            unreachable!("front checked above");
                        };
                        *finalized = retained_finalized;
                        (pending_current, retained_finalized)
                    }
                } else {
                    overflow.push_front(update);
                    (current, update_finalized)
                };

                // A new update changes the pruning floor. Retain order is
                // enough because constructed votes stay in arrival order.
                overflow.retain(|message| match message {
                    Self::Update { .. } => true,
                    Self::Constructed(vote) => !Self::prunes(current, finalized, vote),
                });
                true
            }
            Self::Constructed(vote) => {
                if matches!(
                    overflow.front(),
                    Some(Self::Update {
                        current,
                        finalized,
                        ..
                    }) if Self::prunes(*current, *finalized, &vote)
                ) {
                    return false;
                }

                if overflow.iter().any(|message| {
                    matches!(
                        message,
                        Self::Constructed(pending)
                            if pending.view() == vote.view()
                                && std::mem::discriminant(pending)
                                    == std::mem::discriminant(&vote)
                    )
                }) {
                    return true;
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
            Some(Message::Update { current, .. }) if current == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Constructed(vote)) if vote.view() == View::new(3)
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
    fn update_replaces_same_current_when_finalized_advances() {
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
            }) if current == View::new(5) && finalized == View::new(4)
        ));
    }

    #[test]
    fn duplicate_constructed_message_is_ignored() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(nullify_vote(View::new(5)))
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(nullify_vote(View::new(5)))
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Constructed(vote))
                if matches!(vote, Vote::Nullify(_)) && vote.view() == View::new(5)
        ));
    }

    #[test]
    fn lower_current_update_advances_finalized_floor() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            update(View::new(5), View::zero())
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(finalize_vote(View::new(3)))
        ));
        assert!(Message::handle(
            &mut overflow,
            update(View::new(4), View::new(4))
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Update {
                current,
                finalized,
                ..
            }) if current == View::new(5) && finalized == View::new(4)
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
            Some(Message::Update { current, .. }) if current == View::new(5)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Constructed(vote))
                if matches!(vote, Vote::Finalize(_)) && vote.view() == View::new(4)
        ));
    }

    #[test]
    fn constructed_finalizations_remain_in_arrival_order_after_update() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(finalize_vote(View::new(4)))
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Constructed(finalize_vote(View::new(2)))
        ));
        assert!(Message::handle(
            &mut overflow,
            update(View::new(3), View::new(1))
        ));

        assert_eq!(overflow.len(), 3);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Update { current, .. }) if current == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Constructed(vote))
                if matches!(vote, Vote::Finalize(_)) && vote.view() == View::new(4)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Constructed(vote))
                if matches!(vote, Vote::Finalize(_)) && vote.view() == View::new(2)
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
