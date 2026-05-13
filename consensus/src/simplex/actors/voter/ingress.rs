use crate::{
    simplex::{
        metrics::TimeoutReason,
        types::{Certificate, Proposal},
    },
    types::View,
    Viewable,
};
use commonware_actor::mailbox::{Policy, Sender};
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
    fn view(&self) -> View {
        match self {
            Self::Proposal(p) => p.view(),
            Self::Timeout(v, _) => *v,
            Self::Verified(c, _) => c.view(),
        }
    }

    fn duplicates(&self, pending: &Self) -> bool {
        match (self, pending) {
            (Self::Proposal(x), Self::Proposal(y)) => x.view() == y.view(),
            (Self::Timeout(x, _), Self::Timeout(y, _)) => x == y,
            (Self::Verified(a, _), Self::Verified(b, _)) if a.view() == b.view() => matches!(
                (a, b),
                (Certificate::Notarization(_), Certificate::Notarization(_))
                    | (Certificate::Nullification(_), Certificate::Nullification(_))
                    | (Certificate::Finalization(_), Certificate::Finalization(_))
            ),
            _ => false,
        }
    }
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        // Overflow is kept in delivery order: an optional finalization pruning
        // floor at the front, then retained higher-view messages in arrival
        // order. The finalization must be delivered first because it advances
        // the voter's current/finalized view; otherwise retained higher-view
        // timeouts or proposals could be ignored as not yet current.
        let new_view = message.view();
        if let Self::Verified(Certificate::Finalization(_), _) = &message {
            if matches!(
                overflow.front(),
                Some(Self::Verified(Certificate::Finalization(pending), _))
                    if pending.view() >= new_view
            ) {
                return false;
            }
            overflow.retain(|pending| pending.view() > new_view);
            overflow.push_front(message);
            return true;
        }

        let start = match overflow.front() {
            Some(Self::Verified(Certificate::Finalization(p), _)) if p.view() >= new_view => {
                return false
            }
            Some(Self::Verified(Certificate::Finalization(_), _)) => 1,
            _ => 0,
        };
        if overflow
            .iter()
            .skip(start)
            .any(|pending| message.duplicates(pending))
        {
            return true;
        }
        overflow.push_back(message);
        true
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

    #[test]
    fn finalization_prunes_stale_overflow() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            Message::Proposal(proposal(View::new(2)))
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Timeout(View::new(2), TimeoutReason::LeaderTimeout)
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Verified(nullification(View::new(2)), false)
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Proposal(proposal(View::new(4)))
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(3)), false)
        ));

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
        let mut overflow = VecDeque::new();
        let certificate = nullification(View::new(5));
        assert!(Message::handle(
            &mut overflow,
            Message::Verified(certificate.clone(), false)
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Verified(certificate, true)
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified(Certificate::Nullification(n), false))
                if n.view() == View::new(5)
        ));
    }

    #[test]
    fn queued_finalization_rejects_covered_messages() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(3)), false)
        ));

        assert!(!Message::handle(
            &mut overflow,
            Message::Proposal(proposal(View::new(3)))
        ));
        assert!(!Message::handle(
            &mut overflow,
            Message::Timeout(View::new(2), TimeoutReason::LeaderTimeout)
        ));
        assert!(!Message::handle(
            &mut overflow,
            Message::Verified(nullification(View::new(2)), false)
        ));
        assert!(!Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(2)), false)
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Proposal(proposal(View::new(4)))
        ));

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
    fn newer_finalization_replaces_older_pruning_floor() {
        let mut overflow = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(3)), false)
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Proposal(proposal(View::new(4)))
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Verified(finalization(View::new(5)), false)
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified(Certificate::Finalization(f), false))
                if f.view() == View::new(5)
        ));
    }

    #[test]
    fn duplicate_proposals_and_timeouts_are_deduplicated() {
        let mut overflow: VecDeque<Message<TestScheme, Sha256Digest>> = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            Message::Proposal(proposal(View::new(4)))
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Proposal(proposal(View::new(4)))
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Timeout(View::new(4), TimeoutReason::LeaderTimeout)
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Timeout(View::new(4), TimeoutReason::Inactivity)
        ));

        assert_eq!(overflow.len(), 2);
    }
}
