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

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
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
