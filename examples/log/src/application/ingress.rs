use commonware_actor::{
    mailbox::{Policy, Sender},
    Feedback,
};
use commonware_consensus::{
    simplex::{types::Context, Plan},
    types::Epoch,
    Automaton as Au, CertifiableAutomaton as CAu, Relay as Re,
};
use commonware_cryptography::{ed25519::PublicKey, Digest};
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

pub enum Message<D: Digest> {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<D>,
    },
    Propose {
        response: oneshot::Sender<D>,
    },
    Verify {
        response: oneshot::Sender<bool>,
    },
}

impl<D: Digest> Policy for Message<D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        overflow.push_back(message);
    }
}

/// Mailbox for the application.
#[derive(Clone)]
pub struct Mailbox<D: Digest> {
    pub(super) sender: Sender<Message<D>>,
}

impl<D: Digest> Mailbox<D> {
    pub(super) const fn new(sender: Sender<Message<D>>) -> Self {
        Self { sender }
    }
}

impl<D: Digest> Au for Mailbox<D> {
    type Digest = D;
    type Context = Context<Self::Digest, PublicKey>;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Genesis { epoch, response })
                .processed(),
            "Failed to send genesis"
        );
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(
        &mut self,
        _: Context<Self::Digest, PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        // If we linked payloads to their parent, we would include
        // the parent in the `Context` in the payload.
        let (response, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Propose { response })
                .processed(),
            "Failed to send propose"
        );
        receiver
    }

    async fn verify(
        &mut self,
        _: Context<Self::Digest, PublicKey>,
        _: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // Digests are already verified by consensus, so we don't need to check they are valid.
        //
        // If we linked payloads to their parent, we would verify
        // the parent included in the payload matches the provided `Context`.
        let (response, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Verify { response })
                .processed(),
            "Failed to send verify"
        );
        receiver
    }
}

impl<D: Digest> CAu for Mailbox<D> {
    // Uses default certify implementation which always returns true
}

impl<D: Digest> Re for Mailbox<D> {
    type Digest = D;
    type PublicKey = PublicKey;
    type Plan = Plan<PublicKey>;

    fn broadcast(&mut self, _: Self::Digest, _: Self::Plan) -> Feedback {
        // We don't broadcast our raw messages to other peers.
        //
        // If we were building an EVM blockchain, for example, we'd
        // send the block to other peers here.
        Feedback::Ok
    }
}
