use crate::{simplex::types::Certificate, types::View, Viewable};
use bytes::Bytes;
use commonware_actor::mailbox::{Policy, Sender};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::{p2p::Producer, Consumer};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    sequence::U64,
};
use std::collections::VecDeque;

/// Messages sent to the resolver actor from the voter.
pub enum MailboxMessage<S: Scheme, D: Digest> {
    /// A certificate was received or produced.
    Certificate(Certificate<S, D>),
    /// Certification result for a view.
    Certified { view: View, success: bool },
}

impl<S: Scheme, D: Digest> MailboxMessage<S, D> {
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
            Self::Certificate(certificate) => certificate.view(),
            Self::Certified { view, .. } => *view,
        }
    }

    fn pruned_by_finalization(&self, finalized: View) -> bool {
        self.view() <= finalized
    }

    fn finalization_floor(&self) -> Option<View> {
        match self {
            Self::Certificate(certificate) if Self::is_finalization(certificate) => {
                Some(certificate.view())
            }
            _ => None,
        }
    }

    fn same_queue_effect(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Certificate(a), Self::Certificate(b)) => {
                Self::same_certificate_variant(a, b) && a.view() == b.view()
            }
            (Self::Certified { view: a, .. }, Self::Certified { view: b, .. }) => a == b,
            _ => false,
        }
    }

    fn replace_same_effect(overflow: &mut VecDeque<Self>, index: usize, message: Self) -> bool {
        match message {
            Self::Certificate(certificate) => {
                // Replace in place so a later Certified(success) callback still observes
                // the certificate before the callback is processed.
                overflow[index] = Self::Certificate(certificate);
            }
            Self::Certified { view, success } => {
                // Certification should resolve once per view; keep only the latest result
                // if duplicate callbacks race into overflow.
                overflow.remove(index);
                overflow.push_back(Self::Certified { view, success });
            }
        }
        true
    }
}

impl<S: Scheme, D: Digest> Policy for MailboxMessage<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        if let Some(floor) = message.finalization_floor() {
            // Keep the highest queued finalization as the resolver floor.
            // Older certificates and certified results cannot change state once it lands.
            let mut useless = false;
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
            // Any queued finalization at this view or higher already satisfies this message.
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
            return Self::replace_same_effect(overflow, index, message);
        }

        overflow.push_back(message);
        true
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: Sender<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: Sender<MailboxMessage<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a certificate.
    pub fn updated(&mut self, certificate: Certificate<S, D>) {
        let _ = self
            .sender
            .enqueue(MailboxMessage::Certificate(certificate));
    }

    /// Notify the resolver of a certification result.
    pub fn certified(&mut self, view: View, success: bool) {
        let _ = self
            .sender
            .enqueue(MailboxMessage::Certified { view, success });
    }
}

#[derive(Debug)]
pub enum HandlerMessage {
    Deliver {
        view: View,
        data: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

#[derive(Clone)]
pub struct Handler {
    sender: mpsc::Sender<HandlerMessage>,
}

impl Handler {
    pub const fn new(sender: mpsc::Sender<HandlerMessage>) -> Self {
        Self { sender }
    }
}

impl Consumer for Handler {
    type Key = U64;
    type Value = Bytes;

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        self.sender
            .request_or(
                |response| HandlerMessage::Deliver {
                    view: View::new(key.into()),
                    data: value,
                    response,
                },
                false,
            )
            .await
    }
}

impl Producer for Handler {
    type Key = U64;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(HandlerMessage::Produce {
                view: View::new(key.into()),
                response,
            })
            .await;
        receiver
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
        } = ed25519::fixture(&mut rng, b"resolver-policy", 5);
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
    fn finalization_prunes_stale_certificates_and_results() {
        let mut overflow = VecDeque::new();
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(2)))
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(2),
                success: false,
            }
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(5)))
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(5),
                success: false,
            }
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(3)))
        ));

        assert_eq!(overflow.len(), 3);
        assert!(overflow.iter().any(|message| {
            matches!(message, MailboxMessage::Certificate(Certificate::Nullification(n)) if n.view() == View::new(5))
        }));
        assert!(overflow.iter().any(|message| {
            matches!(message, MailboxMessage::Certified { view, success: false } if *view == View::new(5))
        }));
        assert!(overflow.iter().any(|message| {
            matches!(message, MailboxMessage::Certificate(Certificate::Finalization(f)) if f.view() == View::new(3))
        }));
    }

    #[test]
    fn certified_result_replaces_same_view() {
        let mut overflow: VecDeque<MailboxMessage<TestScheme, Sha256Digest>> = VecDeque::new();
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(4),
                success: false,
            }
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(4),
                success: true,
            }
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                view,
                success: true,
            }) if view == View::new(4)
        ));
    }

    #[test]
    fn queued_finalization_rejects_covered_messages() {
        let mut overflow = VecDeque::new();
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(3)))
        ));

        assert!(!MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(2)))
        ));
        assert!(!MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(2),
                success: false,
            }
        ));
        assert!(!MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(2)))
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(4)))
        ));

        assert_eq!(overflow.len(), 2);
        assert!(overflow.iter().any(|message| {
            matches!(message, MailboxMessage::Certificate(Certificate::Finalization(f)) if f.view() == View::new(3))
        }));
        assert!(overflow.iter().any(|message| {
            matches!(message, MailboxMessage::Certificate(Certificate::Nullification(n)) if n.view() == View::new(4))
        }));
    }

    #[test]
    fn newer_finalization_replaces_older_pruning_floor() {
        let mut overflow = VecDeque::new();
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(3)))
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(4)))
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(4),
                success: false,
            }
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(5)))
        ));

        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate(Certificate::Finalization(f)))
                if f.view() == View::new(5)
        ));
    }

    #[test]
    fn duplicate_certificate_replacement_preserves_order() {
        let mut overflow = VecDeque::new();
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(4)))
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(4),
                success: true,
            }
        ));
        assert!(MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(4)))
        ));

        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate(Certificate::Nullification(n)))
                if n.view() == View::new(4)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                view,
                success: true,
            }) if view == View::new(4)
        ));
    }
}
