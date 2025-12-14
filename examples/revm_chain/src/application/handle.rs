use super::ApplicationRequest;
use crate::{
    consensus::{ConsensusDigest, PublicKey},
    types::StateRoot,
};
use alloy_evm::revm::primitives::{Address, B256, U256};
use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt as _,
};

#[derive(Clone)]
pub struct Handle {
    sender: mpsc::Sender<ApplicationRequest>,
}

impl Handle {
    pub(crate) const fn new(sender: mpsc::Sender<ApplicationRequest>) -> Self {
        Self { sender }
    }

    pub async fn deliver_block(&self, from: PublicKey, bytes: Bytes) {
        let mut sender = self.sender.clone();
        let _ = sender
            .send(ApplicationRequest::BlockReceived { from, bytes })
            .await;
    }

    pub async fn query_balance(&self, digest: ConsensusDigest, address: Address) -> Option<U256> {
        let (response, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        let _ = sender
            .send(ApplicationRequest::QueryBalance {
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
            .send(ApplicationRequest::QueryStateRoot { digest, response })
            .await;
        receiver.await.unwrap_or(None)
    }

    pub async fn query_seed(&self, digest: ConsensusDigest) -> Option<B256> {
        let (response, receiver) = oneshot::channel();
        let mut sender = self.sender.clone();
        let _ = sender
            .send(ApplicationRequest::QuerySeed { digest, response })
            .await;
        receiver.await.unwrap_or(None)
    }
}
