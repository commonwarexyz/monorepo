use super::{ConsensusDigest, Message, PublicKey};
use crate::types::StateRoot;
use alloy_evm::revm::primitives::{Address, U256};
use bytes::Bytes;
use commonware_consensus::{
    simplex::types::{Activity, Context},
    types::Epoch,
    Automaton as ConsensusAutomaton, Relay as ConsensusRelay, Reporter as ConsensusReporter,
};
use commonware_codec::Encode as _;
use commonware_p2p::{Recipients, Sender as P2pSender};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt as _,
};
use std::sync::{Arc, Mutex};

use super::store::ChainStore;

/// Mailbox for the chain application.
#[derive(Clone)]
pub struct Mailbox<S> {
    sender: mpsc::Sender<Message>,
    gossip: S,
    store: Arc<Mutex<ChainStore>>,
}

impl<S> Mailbox<S> {
    pub(super) fn new(sender: mpsc::Sender<Message>, gossip: S, store: Arc<Mutex<ChainStore>>) -> Self {
        Self {
            sender,
            gossip,
            store,
        }
    }

    pub async fn deliver_block(&self, from: PublicKey, bytes: Bytes) {
        let mut sender = self.sender.clone();
        let _ = sender
            .send(Message::BlockReceived { from, bytes })
            .await;
    }

    pub async fn query_balance(&self, digest: ConsensusDigest, address: Address) -> Option<U256> {
        let (response, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        let _ = sender
            .send(Message::QueryBalance {
                digest,
                address,
                response,
            })
            .await;
        receiver.await.unwrap_or(None)
    }

    pub async fn query_state_root(&self, digest: ConsensusDigest) -> Option<StateRoot> {
        let (response, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        let _ = sender
            .send(Message::QueryStateRoot { digest, response })
            .await;
        receiver.await.unwrap_or(None)
    }
}

impl<S> ConsensusAutomaton for Mailbox<S>
where
    S: Clone + Send + Sync + 'static,
{
    type Context = Context<ConsensusDigest, PublicKey>;
    type Digest = ConsensusDigest;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { epoch, response })
            .await
            .expect("failed to send genesis");
        receiver.await.expect("failed to receive genesis")
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Propose { context, response })
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
            .send(Message::Verify {
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

impl<S> ConsensusRelay for Mailbox<S>
where
    S: P2pSender<PublicKey = PublicKey> + Clone + Send + Sync + 'static,
{
    type Digest = ConsensusDigest;

    async fn broadcast(&mut self, payload: Self::Digest) {
        let bytes = {
            let store = self.store.lock().expect("store lock poisoned");
            store
                .get_by_digest(&payload)
                .map(|entry| entry.block.encode())
        };
        let Some(bytes) = bytes else {
            return;
        };

        let _ = self
            .gossip
            .send(Recipients::All, Bytes::copy_from_slice(bytes.as_ref()), true)
            .await;
    }
}

impl<S> ConsensusReporter for Mailbox<S>
where
    S: Clone + Send + Sync + 'static,
{
    type Activity = Activity<
        commonware_consensus::simplex::signing_scheme::bls12381_threshold::Scheme<
            PublicKey,
            commonware_cryptography::bls12381::primitives::variant::MinSig,
        >,
        ConsensusDigest,
    >;

    async fn report(&mut self, activity: Self::Activity) {
        let _ = self.sender.send(Message::Report { activity }).await;
    }
}
