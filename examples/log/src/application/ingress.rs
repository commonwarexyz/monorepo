use commonware_consensus::{
    simplex::{types::Context, Plan},
    types::Epoch,
    Automaton as Au, CertifiableAutomaton as CAu, Relay as Re,
};
use commonware_cryptography::{ed25519::PublicKey, Digest};
use commonware_utils::channel::{
    actor::{ActorMailbox, FullPolicy, MessagePolicy},
    oneshot,
};

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

impl<D: Digest> MessagePolicy for Message<D> {
    fn kind(&self) -> &'static str {
        match self {
            Self::Genesis { .. } => "genesis",
            Self::Propose { .. } => "propose",
            Self::Verify { .. } => "verify",
        }
    }

    fn full_policy(&self) -> FullPolicy {
        FullPolicy::Retain
    }
}

/// Mailbox for the application.
#[derive(Clone)]
pub struct Mailbox<D: Digest> {
    sender: ActorMailbox<Message<D>>,
}

impl<D: Digest> Mailbox<D> {
    pub(super) const fn new(sender: ActorMailbox<Message<D>>) -> Self {
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
                .accepted(),
            "Failed to enqueue genesis"
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
                .accepted(),
            "Failed to enqueue propose"
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
            self.sender.enqueue(Message::Verify { response }).accepted(),
            "Failed to enqueue verify"
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

    async fn broadcast(&mut self, _: Self::Digest, _: Self::Plan) {
        // We don't broadcast our raw messages to other peers.
        //
        // If we were building an EVM blockchain, for example, we'd
        // send the block to other peers here.
    }
}
