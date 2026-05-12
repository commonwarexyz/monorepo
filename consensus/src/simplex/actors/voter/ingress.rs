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
    const fn is_finalization(certificate: &Certificate<S, D>) -> bool {
        matches!(certificate, Certificate::Finalization(_))
    }

    const fn same_certificate_variant(
        first: &Certificate<S, D>,
        second: &Certificate<S, D>,
    ) -> bool {
        matches!(
            (first, second),
            (Certificate::Notarization(_), Certificate::Notarization(_))
                | (Certificate::Nullification(_), Certificate::Nullification(_))
                | (Certificate::Finalization(_), Certificate::Finalization(_))
        )
    }

    fn view(&self) -> View {
        match self {
            Self::Proposal(proposal) => proposal.view(),
            Self::Timeout(view, _) => *view,
            Self::Verified(certificate, _) => certificate.view(),
        }
    }

    fn finalization_floor(&self) -> Option<View> {
        match self {
            Self::Verified(certificate, _) if Self::is_finalization(certificate) => {
                Some(certificate.view())
            }
            _ => None,
        }
    }

    fn pruned_by_finalization(&self, finalized: View) -> bool {
        self.view() <= finalized
    }

    fn same_queue_effect(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Proposal(a), Self::Proposal(b)) => a.view() == b.view(),
            (Self::Timeout(a, _), Self::Timeout(b, _)) => a == b,
            (Self::Verified(a, _), Self::Verified(b, _)) => {
                Self::same_certificate_variant(a, b) && a.view() == b.view()
            }
            _ => false,
        }
    }

    const fn merge_same_effect(&mut self, incoming: &Self) -> bool {
        match (self, incoming) {
            (Self::Verified(_, pending_from_resolver), Self::Verified(_, true))
                if !*pending_from_resolver =>
            {
                *pending_from_resolver = true;
                true
            }
            _ => false,
        }
    }
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        if let Some(floor) = message.finalization_floor() {
            // Keep the highest queued finalization as the pruning floor.
            // Lower finalizations cannot advance the voter any further.
            let mut useless = false;
            // A finalization conclusively advances past all work at or below its view.
            overflow.retain(|pending| {
                if pending
                    .finalization_floor()
                    .is_some_and(|pending_floor| pending_floor >= floor)
                {
                    useless = true;
                    return true;
                }
                !pending.pruned_by_finalization(floor)
            });
            if useless {
                return false;
            }
            overflow.push_back(message);
            return true;
        }

        let mut same_effect = None;
        for (index, pending) in overflow.iter().enumerate() {
            // A queued finalization at this view or higher makes this message redundant.
            if pending
                .finalization_floor()
                .is_some_and(|floor| floor >= message.view())
            {
                return false;
            }
            if same_effect.is_none() && pending.same_queue_effect(&message) {
                same_effect = Some(index);
            }
        }

        if let Some(index) = same_effect {
            // One queued proposal/timeout/certificate for a given effect is enough.
            // Resolver-origin certificates can upgrade the pending item in place.
            return overflow[index].merge_same_effect(&message);
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
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

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
        assert!(overflow
            .iter()
            .any(|message| matches!(message, Message::Proposal(p) if p.view() == View::new(4))));
        assert!(overflow.iter().any(|message| {
            matches!(message, Message::Verified(Certificate::Finalization(f), false) if f.view() == View::new(3))
        }));
    }

    #[test]
    fn duplicate_certificate_keeps_resolver_origin() {
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
            Some(Message::Verified(Certificate::Nullification(n), true))
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
        assert!(overflow.iter().any(|message| {
            matches!(message, Message::Verified(Certificate::Finalization(f), false) if f.view() == View::new(3))
        }));
        assert!(overflow
            .iter()
            .any(|message| matches!(message, Message::Proposal(p) if p.view() == View::new(4))));
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
    fn duplicate_proposals_and_timeouts_are_dropped() {
        let mut overflow: VecDeque<Message<TestScheme, Sha256Digest>> = VecDeque::new();
        assert!(Message::handle(
            &mut overflow,
            Message::Proposal(proposal(View::new(4)))
        ));
        assert!(!Message::handle(
            &mut overflow,
            Message::Proposal(proposal(View::new(4)))
        ));
        assert!(Message::handle(
            &mut overflow,
            Message::Timeout(View::new(4), TimeoutReason::LeaderTimeout)
        ));
        assert!(!Message::handle(
            &mut overflow,
            Message::Timeout(View::new(4), TimeoutReason::Inactivity)
        ));

        assert_eq!(overflow.len(), 2);
    }
}
