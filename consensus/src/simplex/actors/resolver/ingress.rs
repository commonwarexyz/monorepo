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

impl<S: Scheme, D: Digest> Policy for MailboxMessage<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        let new_view = match &message {
            Self::Certificate(c) => c.view(),
            Self::Certified { view, .. } => *view,
        };
        let new_is_finalization =
            matches!(&message, Self::Certificate(Certificate::Finalization(_)));
        let mut remove = Vec::new();
        let mut absorb_idx = None;
        for (index, p) in overflow.iter().enumerate() {
            let p_view = match p {
                Self::Certificate(c) => c.view(),
                Self::Certified { view, .. } => *view,
            };
            // A queued finalization is the resolver floor. Certificates and
            // certification results at or below that view cannot alter
            // resolver state after the finalization lands
            if matches!(p, Self::Certificate(Certificate::Finalization(_))) && p_view >= new_view {
                return false;
            }
            if new_is_finalization && p_view <= new_view {
                remove.push(index);
                continue;
            }
            if absorb_idx.is_none() && same_queue(p, &message) {
                absorb_idx = Some(index);
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
            match message {
                Self::Certificate(c) => {
                    // Replace in place so a later Certified(success) callback
                    // still observes the certificate before the callback runs
                    overflow[idx] = Self::Certificate(c);
                }
                Self::Certified { view, success } => {
                    // Certification should resolve once per view. Keep the
                    // latest result and move it behind any earlier certificate
                    // work
                    overflow.remove(idx);
                    overflow.push_back(Self::Certified { view, success });
                }
            }
        } else {
            overflow.push_back(message);
        }
        true
    }
}

fn same_queue<S: Scheme, D: Digest>(a: &MailboxMessage<S, D>, b: &MailboxMessage<S, D>) -> bool {
    match (a, b) {
        (
            MailboxMessage::Certificate(Certificate::Notarization(x)),
            MailboxMessage::Certificate(Certificate::Notarization(y)),
        ) => x.view() == y.view(),
        (
            MailboxMessage::Certificate(Certificate::Nullification(x)),
            MailboxMessage::Certificate(Certificate::Nullification(y)),
        ) => x.view() == y.view(),
        (
            MailboxMessage::Certificate(Certificate::Finalization(x)),
            MailboxMessage::Certificate(Certificate::Finalization(y)),
        ) => x.view() == y.view(),
        (
            MailboxMessage::Certified { view: x, .. },
            MailboxMessage::Certified { view: y, .. },
        ) => x == y,
        _ => false,
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
