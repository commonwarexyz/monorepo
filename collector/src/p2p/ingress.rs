use crate::Originator;
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_codec::Codec;
use commonware_cryptography::{Committable, PublicKey};
use commonware_p2p::Recipients;
use std::collections::VecDeque;

/// Messages that can be sent to a [Mailbox].
pub(crate) enum Message<P: PublicKey, R: Committable + Codec> {
    /// Sends `request` to `recipients`. `commitment` is computed when the request is enqueued so
    /// the overflow policy can skip recomputing the commitments of queued requests.
    Send {
        commitment: R::Commitment,
        request: R,
        recipients: Recipients<P>,
    },
    /// Cancels the collection for `commitment`.
    Cancel { commitment: R::Commitment },
}

impl<P: PublicKey, R: Committable + Codec> Policy for Message<P, R> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        match message {
            Self::Send { .. } => {
                // Commitment identifies the collection, not necessarily the encoded request.
                // Keep payloads separate so peers never receive bytes intended for another send.
                overflow.push_back(message);
            }
            Self::Cancel { commitment } => {
                // Drop queued sends that this cancel supersedes, and queue this cancel unless one
                // for the same commitment is already queued. A cancel must stay queued because the
                // engine may already have a collection for the commitment.
                let mut canceled = false;
                overflow.retain(|message| match message {
                    Self::Send {
                        commitment: queued, ..
                    } => queued != &commitment,
                    Self::Cancel { commitment: queued } => {
                        canceled |= queued == &commitment;
                        true
                    }
                });
                if !canceled {
                    overflow.push_back(Self::Cancel { commitment });
                }
            }
        }
    }
}

/// Enqueues requests and cancellations for an [Engine](super::Engine).
#[derive(Clone)]
pub struct Mailbox<P: PublicKey, R: Committable + Codec> {
    sender: mailbox::Sender<Message<P, R>>,
}

impl<P: PublicKey, R: Committable + Codec> Mailbox<P, R> {
    /// Creates a new [Mailbox] with the given [mailbox::Sender].
    pub(super) const fn new(sender: mailbox::Sender<Message<P, R>>) -> Self {
        Self { sender }
    }
}

impl<P: PublicKey, R: Committable + Codec> Originator for Mailbox<P, R> {
    type Request = R;
    type PublicKey = P;

    fn send(&mut self, recipients: Recipients<P>, request: R) -> Feedback {
        self.sender.enqueue(Message::Send {
            commitment: request.commitment(),
            request,
            recipients,
        })
    }

    fn cancel(&mut self, commitment: R::Commitment) -> Feedback {
        self.sender.enqueue(Message::Cancel { commitment })
    }
}

#[cfg(test)]
mod tests {
    use super::{Message, Policy};
    use crate::p2p::mocks::types::Request;
    use commonware_cryptography::{
        Committable, Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_p2p::Recipients;
    use rstest::rstest;
    use std::collections::VecDeque;

    fn peer(seed: u64) -> PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    /// Returns the message a [super::Mailbox] enqueues to send `request` to `recipients`.
    fn send(request: Request, recipients: Recipients<PublicKey>) -> Message<PublicKey, Request> {
        Message::Send {
            commitment: request.commitment(),
            request,
            recipients,
        }
    }

    fn handle(
        overflow: &mut VecDeque<Message<PublicKey, Request>>,
        message: Message<PublicKey, Request>,
    ) {
        <Message<PublicKey, Request> as Policy>::handle(overflow, message);
    }

    #[test]
    fn cancel_prunes_queued_sends_and_is_retained() {
        // Two requests with distinct commitments.
        let request1 = Request { id: 1, data: 10 };
        let request2 = Request { id: 2, data: 20 };
        let commitment1 = request1.commitment();
        let mut overflow = VecDeque::new();

        // Queue a send for each, then cancel the first.
        handle(&mut overflow, send(request1, Recipients::One(peer(1))));
        handle(
            &mut overflow,
            send(request2.clone(), Recipients::One(peer(2))),
        );
        handle(
            &mut overflow,
            Message::Cancel {
                commitment: commitment1,
            },
        );

        // The other send remains, followed by the cancel.
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            Message::Send { request, .. } if request == &request2
        ));
        assert!(matches!(
            &overflow[1],
            Message::Cancel { commitment } if commitment == &commitment1
        ));
    }

    #[test]
    fn cancel_coalesces_duplicate_cancels_in_place() {
        // Two requests with distinct commitments.
        let request1 = Request { id: 1, data: 10 };
        let request2 = Request { id: 2, data: 20 };
        let commitment1 = request1.commitment();
        let commitment2 = request2.commitment();
        let mut overflow = VecDeque::new();

        // Queue a cancel for each, a send for the first, and a second cancel for the first.
        handle(
            &mut overflow,
            Message::Cancel {
                commitment: commitment1,
            },
        );
        handle(
            &mut overflow,
            Message::Cancel {
                commitment: commitment2,
            },
        );
        handle(&mut overflow, send(request1, Recipients::One(peer(1))));
        handle(
            &mut overflow,
            Message::Cancel {
                commitment: commitment1,
            },
        );

        // The send is dropped, and the first cancel keeps its place.
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            Message::Cancel { commitment } if commitment == &commitment1
        ));
        assert!(matches!(
            &overflow[1],
            Message::Cancel { commitment } if commitment == &commitment2
        ));
    }

    /// Sends that share a commitment stay separate and in order.
    #[rstest]
    // The second send carries the same request.
    #[case::same_request(Request { id: 1, data: 10 })]
    // The second send carries a different payload with the same commitment.
    #[case::different_payload(Request { id: 1, data: 20 })]
    fn send_same_commitment_keeps_sends_separate(#[case] second: Request) {
        // One request for the first peer.
        let first = Request { id: 1, data: 10 };
        let peer1 = peer(1);
        let peer2 = peer(2);
        let mut overflow = VecDeque::new();

        // Queue a send to each peer.
        handle(
            &mut overflow,
            send(first.clone(), Recipients::One(peer1.clone())),
        );
        handle(
            &mut overflow,
            send(second.clone(), Recipients::One(peer2.clone())),
        );

        // Both sends remain in order, each with its own payload and peer.
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            Message::Send { request, recipients: Recipients::One(peer), .. }
                if request == &first && peer == &peer1
        ));
        assert!(matches!(
            &overflow[1],
            Message::Send { request, recipients: Recipients::One(peer), .. }
                if request == &second && peer == &peer2
        ));
    }

    #[test]
    fn send_with_all_recipients_keeps_payloads_separate() {
        // One request for two sends.
        let request = Request { id: 1, data: 10 };
        let mut overflow = VecDeque::new();

        // Queue a send to one peer, then the same request to all peers.
        handle(
            &mut overflow,
            send(request.clone(), Recipients::One(peer(1))),
        );
        handle(&mut overflow, send(request, Recipients::All));

        // Both sends remain.
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

    #[test]
    fn cancel_prunes_every_queued_send_for_the_commitment() {
        // Same commitment, different payloads and recipients.
        let request1 = Request { id: 1, data: 10 };
        let request2 = Request { id: 1, data: 20 };
        let commitment = request1.commitment();
        let mut overflow = VecDeque::new();

        // Queue both sends, then the cancel.
        handle(&mut overflow, send(request1, Recipients::One(peer(1))));
        handle(&mut overflow, send(request2, Recipients::One(peer(2))));
        handle(&mut overflow, Message::Cancel { commitment });

        // Only the cancel remains.
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            &overflow[0],
            Message::Cancel { commitment: queued } if queued == &commitment
        ));
    }
}
