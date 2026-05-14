use crate::{simplex::types::Certificate, types::View, Viewable};
use bytes::Bytes;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
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
    // Return the message view used for pruning and deduplication.
    fn view(&self) -> View {
        match self {
            Self::Certificate(c) => c.view(),
            Self::Certified { view, .. } => *view,
        }
    }
}

/// Pending resolver messages retained after the mailbox fills.
pub struct Pending<S: Scheme, D: Digest> {
    finalization: Option<MailboxMessage<S, D>>,
    messages: VecDeque<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Default for Pending<S, D> {
    fn default() -> Self {
        Self {
            finalization: None,
            messages: VecDeque::new(),
        }
    }
}

impl<S: Scheme, D: Digest> Overflow<MailboxMessage<S, D>> for Pending<S, D> {
    fn is_empty(&self) -> bool {
        self.finalization.is_none() && self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(MailboxMessage<S, D>) -> Option<MailboxMessage<S, D>>,
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

impl<S: Scheme, D: Digest> Policy for MailboxMessage<S, D> {
    type Overflow = Pending<S, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Ignore the message if there exists a queued finalization
        // with a view greater than or equal to the new view
        let new_view = message.view();
        if matches!(
            overflow.finalization.as_ref(),
            Some(Self::Certificate(Certificate::Finalization(old_finalized)))
                if old_finalized.view() >= new_view
        ) {
            return;
        }

        // Retain only the highest-view finalization and any messages with a view greater than the new view
        if matches!(&message, Self::Certificate(Certificate::Finalization(_))) {
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
                (Self::Certificate(new_certificate), Self::Certificate(old_certificate)) => {
                    new_certificate.view() == old_certificate.view()
                        && matches!(
                            (new_certificate, old_certificate),
                            (Certificate::Notarization(_), Certificate::Notarization(_))
                                | (Certificate::Nullification(_), Certificate::Nullification(_))
                                | (Certificate::Finalization(_), Certificate::Finalization(_))
                        )
                }
                (
                    Self::Certified { view: new_view, .. },
                    Self::Certified { view: old_view, .. },
                ) => new_view == old_view,
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

    fn drain(
        mut overflow: Pending<TestScheme, Sha256Digest>,
    ) -> VecDeque<MailboxMessage<TestScheme, Sha256Digest>> {
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
    fn finalization_prunes_stale_certificates_and_results() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(2))),
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(2),
                success: false,
            },
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(5))),
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(5),
                success: false,
            },
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(3))),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 3);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate(Certificate::Finalization(f)))
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate(Certificate::Nullification(n)))
                if n.view() == View::new(5)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                view,
                success: false
            }) if view == View::new(5)
        ));
    }

    #[test]
    fn duplicate_certified_result_is_ignored() {
        let mut overflow = Pending::<TestScheme, Sha256Digest>::default();
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(4),
                success: false,
            },
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(4),
                success: true,
            },
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                view,
                success: false,
            }) if view == View::new(4)
        ));
    }

    #[test]
    fn queued_finalization_rejects_covered_messages() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(3))),
        );

        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(2))),
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(2),
                success: false,
            },
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(2))),
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(4))),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate(Certificate::Finalization(f)))
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate(Certificate::Nullification(n)))
                if n.view() == View::new(4)
        ));
    }

    #[test]
    fn duplicate_finalization_is_dropped() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(3))),
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(3))),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate(Certificate::Finalization(f)))
                if f.view() == View::new(3)
        ));
    }

    #[test]
    fn newer_finalization_replaces_older_pruning_floor() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(3))),
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(4))),
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(4),
                success: false,
            },
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(finalization(View::new(5))),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate(Certificate::Finalization(f)))
                if f.view() == View::new(5)
        ));
    }

    #[test]
    fn duplicate_certificate_is_ignored() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(4))),
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certified {
                view: View::new(4),
                success: true,
            },
        );
        MailboxMessage::handle(
            &mut overflow,
            MailboxMessage::Certificate(nullification(View::new(4))),
        );

        let mut overflow = drain(overflow);
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
