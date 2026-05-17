use crate::Originator;
use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_p2p::Recipients;
use std::collections::VecDeque;

/// Messages that can be sent to a [Mailbox].
pub enum Message<P: PublicKey, R: Committable + Digestible + Codec> {
    Send {
        request: R,
        recipients: Recipients<P>,
    },
    Cancel {
        commitment: R::Commitment,
    },
}

impl<P: PublicKey, R: Committable + Digestible + Codec> Policy for Message<P, R> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) -> bool {
        match message {
            Self::Send {
                request,
                recipients,
            } => {
                // Commitment identifies the collection, not necessarily the encoded request.
                // Keep payloads separate so peers never receive bytes intended for another send.
                overflow.push_back(Self::Send {
                    request,
                    recipients,
                });
            }
            Self::Cancel { commitment } => {
                // Drop queued sends that this cancel supersedes. Keep the cancel itself because
                // the actor may already have in-flight state for the commitment.
                overflow.retain(|message| {
                    !matches!(
                        message,
                        Self::Send { request, .. } if request.commitment() == commitment
                    )
                });
                overflow.push_back(Self::Cancel { commitment });
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{Message, Policy};
    use crate::p2p::mocks::types::Request;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Committable, Signer,
    };
    use commonware_p2p::Recipients;
    use std::collections::VecDeque;

    fn peer(seed: u64) -> PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    fn handle(
        overflow: &mut VecDeque<Message<PublicKey, Request>>,
        message: Message<PublicKey, Request>,
    ) {
        <Message<PublicKey, Request> as Policy>::handle(overflow, message);
    }

    #[test]
    fn cancel_prunes_queued_sends_and_is_retained() {
        let request1 = Request { id: 1, data: 10 };
        let request2 = Request { id: 2, data: 20 };
        let commitment1 = request1.commitment();
        let mut overflow = VecDeque::new();

        handle(
            &mut overflow,
            Message::Send {
                request: request1,
                recipients: Recipients::One(peer(1)),
            },
        );
        handle(
            &mut overflow,
            Message::Send {
                request: request2.clone(),
                recipients: Recipients::One(peer(2)),
            },
        );
        handle(
            &mut overflow,
            Message::Cancel {
                commitment: commitment1,
            },
        );

        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            Message::Send { request, .. } if request.commitment() == request2.commitment()
        ));
        assert!(matches!(
            &overflow[1],
            Message::Cancel { commitment } if commitment == &commitment1
        ));
    }

    #[test]
    fn send_same_request_keeps_recipients_separate() {
        let request = Request { id: 1, data: 10 };
        let peer1 = peer(1);
        let peer2 = peer(2);
        let mut overflow = VecDeque::new();

        handle(
            &mut overflow,
            Message::Send {
                request: request.clone(),
                recipients: Recipients::One(peer1.clone()),
            },
        );
        handle(
            &mut overflow,
            Message::Send {
                request: request.clone(),
                recipients: Recipients::One(peer2.clone()),
            },
        );

        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            Message::Send { request: queued, recipients: Recipients::One(peer), .. }
                if queued == &request && peer == &peer1
        ));
        assert!(matches!(
            &overflow[1],
            Message::Send { request: queued, recipients: Recipients::One(peer), .. }
                if queued == &request && peer == &peer2
        ));
    }

    #[test]
    fn send_same_commitment_different_digest_keeps_payloads_separate() {
        let request1 = Request { id: 1, data: 10 };
        let request2 = Request { id: 1, data: 20 };
        let peer1 = peer(1);
        let peer2 = peer(2);
        let mut overflow = VecDeque::new();

        handle(
            &mut overflow,
            Message::Send {
                request: request1.clone(),
                recipients: Recipients::One(peer1.clone()),
            },
        );
        handle(
            &mut overflow,
            Message::Send {
                request: request2.clone(),
                recipients: Recipients::One(peer2.clone()),
            },
        );

        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            Message::Send { request, recipients: Recipients::One(peer), .. }
                if request == &request1 && peer == &peer1
        ));
        assert!(matches!(
            &overflow[1],
            Message::Send { request, recipients: Recipients::One(peer), .. }
                if request == &request2 && peer == &peer2
        ));
    }

    #[test]
    fn send_with_all_recipients_keeps_payloads_separate() {
        let request = Request { id: 1, data: 10 };
        let mut overflow = VecDeque::new();

        handle(
            &mut overflow,
            Message::Send {
                request: request.clone(),
                recipients: Recipients::One(peer(1)),
            },
        );
        handle(
            &mut overflow,
            Message::Send {
                request,
                recipients: Recipients::All,
            },
        );

        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            Message::Send {
                recipients: Recipients::One(_),
                ..
            }
        ));
        assert!(matches!(
            &overflow[1],
            Message::Send {
                recipients: Recipients::All,
                ..
            }
        ));
    }
}

/// A mailbox that can be used to send and receive [Message]s.
#[derive(Clone)]
pub struct Mailbox<P: PublicKey, R: Committable + Digestible + Codec> {
    sender: mailbox::Sender<Message<P, R>>,
}

impl<P: PublicKey, R: Committable + Digestible + Codec> Mailbox<P, R> {
    /// Creates a new [Mailbox] with the given [mailbox::Sender].
    pub const fn new(sender: mailbox::Sender<Message<P, R>>) -> Self {
        Self { sender }
    }
}

impl<P: PublicKey, R: Committable + Digestible + Codec> Originator for Mailbox<P, R> {
    type Request = R;
    type PublicKey = P;

    fn send(&mut self, recipients: Recipients<P>, request: R) -> Feedback {
        self.sender.enqueue(Message::Send {
            request,
            recipients,
        })
    }

    fn cancel(&mut self, commitment: R::Commitment) -> Feedback {
        self.sender.enqueue(Message::Cancel { commitment })
    }
}
