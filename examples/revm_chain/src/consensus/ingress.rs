use super::{ConsensusDigest, PublicKey};
use commonware_consensus::{
    simplex::types::{Activity, Context},
    types::Epoch,
    Automaton as ConsensusAutomaton, Relay as ConsensusRelay, Reporter as ConsensusReporter,
};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt as _,
};

#[allow(clippy::large_enum_variant)]
pub enum IngressMessage {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<ConsensusDigest>,
    },
    Propose {
        context: Context<ConsensusDigest, PublicKey>,
        response: oneshot::Sender<ConsensusDigest>,
    },
    Verify {
        context: Context<ConsensusDigest, PublicKey>,
        digest: ConsensusDigest,
        response: oneshot::Sender<bool>,
    },
    Broadcast {
        digest: ConsensusDigest,
    },
    Report {
        activity: Activity<
            commonware_consensus::simplex::signing_scheme::bls12381_threshold::Scheme<
                PublicKey,
                commonware_cryptography::bls12381::primitives::variant::MinSig,
            >,
            ConsensusDigest,
        >,
    },
}

/// Mailbox for the chain application.
#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<IngressMessage>,
}

impl Mailbox {
    pub(crate) const fn new(sender: mpsc::Sender<IngressMessage>) -> Self {
        Self { sender }
    }
}

impl ConsensusAutomaton for Mailbox {
    type Context = Context<ConsensusDigest, PublicKey>;
    type Digest = ConsensusDigest;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(IngressMessage::Genesis { epoch, response })
            .await
            .expect("failed to send genesis");
        receiver.await.expect("failed to receive genesis")
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(IngressMessage::Propose { context, response })
            .await
            .is_err()
        {
            return receiver;
        }
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(IngressMessage::Verify {
                context,
                digest: payload,
                response,
            })
            .await
            .is_err()
        {
            return receiver;
        }
        receiver
    }
}

impl ConsensusRelay for Mailbox {
    type Digest = ConsensusDigest;

    async fn broadcast(&mut self, payload: Self::Digest) {
        let _ = self
            .sender
            .send(IngressMessage::Broadcast { digest: payload })
            .await;
    }
}

impl ConsensusReporter for Mailbox {
    type Activity = Activity<
        commonware_consensus::simplex::signing_scheme::bls12381_threshold::Scheme<
            PublicKey,
            commonware_cryptography::bls12381::primitives::variant::MinSig,
        >,
        ConsensusDigest,
    >;

    async fn report(&mut self, activity: Self::Activity) {
        let _ = self
            .sender
            .send(IngressMessage::Report { activity })
            .await;
    }
}
