use crate::{
    simplex::{
        metrics::TimeoutReason,
        types::{Certificate, Proposal},
    },
    types::View,
    Viewable,
};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::{certificate::Scheme, Digest};
use std::collections::VecDeque;

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
}

impl<S: Scheme, D: Digest> Message<S, D> {
    // Return the message view used for pruning and deduplication.
    fn view(&self) -> View {
        match self {
            Self::Proposal(p) => p.view(),
            Self::Timeout(v, _) => *v,
            Self::Verified(c, _) => c.view(),
        }
    }
}

/// Pending voter messages retained after the mailbox fills.
pub struct Pending<S: Scheme, D: Digest> {
    finalization: Option<Message<S, D>>,
    messages: VecDeque<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Default for Pending<S, D> {
    fn default() -> Self {
        Self {
            finalization: None,
            messages: VecDeque::new(),
        }
    }
}

impl<S: Scheme, D: Digest> Overflow<Message<S, D>> for Pending<S, D> {
    fn is_empty(&self) -> bool {
        self.finalization.is_none() && self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<S, D>) -> Option<Message<S, D>>,
    {
        if let Some(finalization) = self.finalization.take() {
            if let Some(finalization) = push(finalization) {
                self.finalization = Some(finalization);
            }
            return;
        }

        if let Some(message) = self.messages.pop_front() {
            if let Some(message) = push(message) {
                self.messages.push_front(message);
            }
        }
    }
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    type Overflow = Pending<S, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Ignore the message if there exists a queued finalization
        // with a view greater than or equal to the new view
        let new_view = message.view();
        if matches!(
            overflow.finalization.as_ref(),
            Some(Self::Verified(Certificate::Finalization(old_finalized), _))
                if old_finalized.view() >= new_view
        ) {
            return;
        }

        // Retain only the highest-view finalization and any messages with a view greater than the new view
        if matches!(&message, Self::Verified(Certificate::Finalization(_), _)) {
            overflow
                .messages
                .retain(|old_message| old_message.view() > new_view);
            overflow.finalization = Some(message);
            return;
        }

        // Ignore the message if it is a duplicate
        if overflow
            .messages
            .iter()
            .any(|old_message| match (&message, old_message) {
                (Self::Proposal(new_proposal), Self::Proposal(old_proposal)) => {
                    new_proposal.view() == old_proposal.view()
                }
                (Self::Timeout(new_view, _), Self::Timeout(old_view, _)) => new_view == old_view, // only retain the first queued timeout reason
                (Self::Verified(new_certificate, _), Self::Verified(old_certificate, _)) => {
                    new_certificate.view() == old_certificate.view()
                        && matches!(
                            (new_certificate, old_certificate),
                            (Certificate::Notarization(_), Certificate::Notarization(_))
                                | (Certificate::Nullification(_), Certificate::Nullification(_))
                                | (Certificate::Finalization(_), Certificate::Finalization(_))
                        )
                }
                _ => false,
            })
        {
            return;
        }
        overflow.messages.push_back(message);
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

    /// Send a leader's proposal.
    pub fn proposal(&mut self, proposal: Proposal<D>) {
        let _ = self.sender.enqueue(Message::Proposal(proposal));
    }

    /// Signal that the current view should timeout (if not already).
    pub fn timeout(&mut self, view: View, reason: TimeoutReason) {
        let _ = self.sender.enqueue(Message::Timeout(view, reason));
    }

    /// Send a recovered certificate.
    pub fn recovered(&mut self, certificate: Certificate<S, D>) {
        let _ = self.sender.enqueue(Message::Verified(certificate, false));
    }

    /// Send a resolved certificate.
    pub fn resolved(&mut self, certificate: Certificate<S, D>) {
        let _ = self.sender.enqueue(Message::Verified(certificate, true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{Certificate, Finalization, Finalize, Nullification, Nullify, Proposal},
        },
        types::{Epoch, Round},
    };
    use commonware_actor::mailbox::Policy;
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use std::collections::VecDeque;

    type TestScheme = ed25519::Scheme;
    const EPOCH: Epoch = Epoch::new(1);

    fn fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, b"voter-policy", 5);
        (schemes, verifier)
    }

    fn proposal(view: View) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(EPOCH, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        )
    }

    fn nullification(view: View) -> Certificate<TestScheme, Sha256Digest> {
        let (schemes, verifier) = fixture();
        let round = Round::new(EPOCH, view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).expect("nullify"))
            .collect();
        Certificate::Nullification(
            Nullification::from_nullifies(&verifier, &votes, &Sequential).expect("nullification"),
        )
    }

    fn finalization(view: View) -> Certificate<TestScheme, Sha256Digest> {
        let (schemes, verifier) = fixture();
        let proposal = proposal(view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize"))
            .collect();
        Certificate::Finalization(
            Finalization::from_finalizes(&verifier, &votes, &Sequential).expect("finalization"),
        )
    }

    fn drain(
        mut overflow: Pending<TestScheme, Sha256Digest>,
    ) -> VecDeque<Message<TestScheme, Sha256Digest>> {
        let mut messages = VecDeque::new();
        while !overflow.is_empty() {
            Overflow::drain(&mut overflow, |message| {
                messages.push_back(message);
                None
            });
        }
        messages
    }

    #[test]
    fn finalization_prunes_stale_overflow() {
        let mut overflow = Pending::default();
        Message::handle(&mut overflow, Message::Proposal(proposal(View::new(2))));
        Message::handle(
            &mut overflow,
            Message::Timeout(View::new(2), TimeoutReason::LeaderTimeout),
        );
        Message::handle(
            &mut overflow,
            Message::Verified(nullification(View::new(2)), false),
        );
        Message::handle(&mut overflow, Message::Proposal(proposal(View::new(4))));
        Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(3)), false),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified(Certificate::Finalization(f), false))
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Proposal(p)) if p.view() == View::new(4)
        ));
    }

    #[test]
    fn duplicate_certificate_is_ignored() {
        let mut overflow = Pending::default();
        let certificate = nullification(View::new(5));
        Message::handle(&mut overflow, Message::Verified(certificate.clone(), false));
        Message::handle(&mut overflow, Message::Verified(certificate, true));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified(Certificate::Nullification(n), false))
                if n.view() == View::new(5)
        ));
    }

    #[test]
    fn queued_finalization_rejects_covered_messages() {
        let mut overflow = Pending::default();
        Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(3)), false),
        );

        Message::handle(&mut overflow, Message::Proposal(proposal(View::new(3))));
        Message::handle(
            &mut overflow,
            Message::Timeout(View::new(2), TimeoutReason::LeaderTimeout),
        );
        Message::handle(
            &mut overflow,
            Message::Verified(nullification(View::new(2)), false),
        );
        Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(2)), false),
        );
        Message::handle(&mut overflow, Message::Proposal(proposal(View::new(4))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified(Certificate::Finalization(f), false))
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Proposal(p)) if p.view() == View::new(4)
        ));
    }

    #[test]
    fn duplicate_finalization_is_dropped() {
        let mut overflow = Pending::default();
        Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(3)), false),
        );
        Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(3)), true),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified(Certificate::Finalization(f), false))
                if f.view() == View::new(3)
        ));
    }

    #[test]
    fn newer_finalization_replaces_older_pruning_floor() {
        let mut overflow = Pending::default();
        Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(3)), false),
        );
        Message::handle(&mut overflow, Message::Proposal(proposal(View::new(4))));
        Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(5)), false),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified(Certificate::Finalization(f), false))
                if f.view() == View::new(5)
        ));
    }

    #[test]
    fn duplicate_proposals_and_timeouts_are_deduplicated() {
        let mut overflow = Pending::<TestScheme, Sha256Digest>::default();
        Message::handle(&mut overflow, Message::Proposal(proposal(View::new(4))));
        Message::handle(&mut overflow, Message::Proposal(proposal(View::new(4))));
        Message::handle(
            &mut overflow,
            Message::Timeout(View::new(4), TimeoutReason::LeaderTimeout),
        );
        Message::handle(
            &mut overflow,
            Message::Timeout(View::new(4), TimeoutReason::Inactivity),
        );

        let overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
    }
}
