use crate::Scheme;
use commonware_actor::{
    mailbox::{Policy, Sender},
    Feedback,
};
use commonware_consensus::{
    simplex::{
        types::{Activity, Context},
        Plan,
    },
    types::{Epoch, Round},
    Automaton as Au, CertifiableAutomaton as CAu, Relay as Re, Reporter,
};
use commonware_cryptography::{ed25519::PublicKey, Digest};
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

#[allow(clippy::large_enum_variant)]
pub enum Message<D: Digest> {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<D>,
    },
    Propose {
        round: Round,
        response: oneshot::Sender<D>,
    },
    Verify {
        payload: D,
        response: oneshot::Sender<bool>,
    },
    Report {
        activity: Activity<Scheme, D>,
    },
}

impl<D: Digest> Policy for Message<D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        overflow.push_back(message);
        true
    }
}

/// Mailbox for the application.
#[derive(Clone)]
pub struct Mailbox<D: Digest> {
    sender: Sender<Message<D>>,
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
                .accepted(),
            "Failed to send genesis"
        );
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(
        &mut self,
        context: Context<Self::Digest, PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        // If we linked payloads to their parent, we would include
        // the parent in the `Context` in the payload.
        let (response, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Propose {
                    round: context.round,
                    response,
                })
                .accepted(),
            "Failed to send propose"
        );
        receiver
    }

    async fn verify(
        &mut self,
        _: Context<Self::Digest, PublicKey>,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // If we linked payloads to their parent, we would verify
        // the parent included in the payload matches the provided `Context`.
        let (response, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Verify { payload, response })
                .accepted(),
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

impl<D: Digest> Reporter for Mailbox<D> {
    type Activity = Activity<Scheme, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.sender.enqueue(Message::Report { activity })
    }
}
